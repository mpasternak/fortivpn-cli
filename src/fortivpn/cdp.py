"""Dependency-free Chrome DevTools Protocol (CDP) transport for FortiClient.

What this is
------------
``CDPSession`` is a tiny, VPN-agnostic CDP client. It discovers FortiClient's
Electron renderer target over the ``/json`` HTTP endpoint, opens a raw WebSocket
to it, and runs ``Runtime.evaluate`` so callers can drive the in-page
``window.guimessenger`` API. It knows nothing about VPN profiles or state — that
lives one layer up in ``controller.py``. It is a promotion of the empirically
validated spike client (``/tmp/cdp_eval.py``); see ``docs/how-it-works.md`` for the
findings this is built on.

Why it is a hand-rolled raw WebSocket (and not a library)
---------------------------------------------------------
Two constraints force a stdlib-only, hand-written WebSocket:

* **Zero runtime dependencies** is a hard design requirement (design spec
  sections 2 and 8): no ``websocket-client``, no ``aiohttp`` — just ``socket``,
  ``json``, ``urllib.request``, ``base64``, ``struct`` and ``os``.
* The obvious "use the platform's WebSocket" escape hatch is closed here: the
  Node/Electron runtime FortiClient ships (node v20) has **no global**
  ``WebSocket``, and we are *attach-only* — we never spawn our own JS context,
  we connect to an already-running FortiClient. So there is no JS-side WebSocket
  to borrow either. Hence a ~40-line raw RFC 6455 framing layer in Python.

How the framing is factored (for testability)
----------------------------------------------
RFC 6455 framing is the failure-prone part, so it lives in two pure
module-level functions — :func:`encode_frame` and :func:`decode_frame` — that
take/return bytes and a ``recv_exact`` callable. They are unit-tested directly,
across all three payload-length encodings, with no socket involved. Socket I/O
is routed through the :meth:`CDPSession._send` / :meth:`CDPSession._recv` seam so
``evaluate()`` can be driven by a fake transport in tests.

See ``docs/how-it-works.md`` sections 1-2 for the launch command and the
``window.guimessenger`` API surface this transport exists to reach.

Why the ``NotRunningError`` message stays factual
-------------------------------------------------
``NotRunningError`` here reports only *what failed* (the URL it could not reach
and the underlying reason) — it deliberately carries **no** launch instructions
or doc pointers. Telling the user *how to fix it* (run ``forti startserver``,
the exact launch command, where to download FortiClient) is the CLI's job
(``cli.py``), which has access to ``launcher`` to detect the installed
executable and tailor the advice. Keeping the transport decoupled means the
same exception is reusable by non-CLI callers that want to phrase their own
guidance.
"""

import base64
import json
import os
import socket
import struct
import urllib.request
from collections.abc import Callable

from fortivpn.errors import CDPEvaluateError, NotRunningError

# WebSocket opcodes (RFC 6455 section 5.2) we care about.
_OPCODE_TEXT = 0x1
_OPCODE_BINARY = 0x2
_OPCODE_CLOSE = 0x8


def encode_frame(text: str) -> bytes:
    """Encode ``text`` as a single masked client text frame (RFC 6455).

    Why masked: the RFC requires every client-to-server frame to set the mask
    bit and XOR its payload with a 4-byte key; servers (including Chrome/CDP)
    reject unmasked client frames. The length is encoded in one of three ways
    depending on size — 7-bit, 16-bit (``126`` marker), or 64-bit (``127``
    marker) — and this function picks the right one.

    Returns the complete frame bytes ready to hand to ``sendall``.
    """
    payload = text.encode("utf-8")
    n = len(payload)
    header = bytearray([0x80 | _OPCODE_TEXT])  # FIN bit + text opcode.
    if n < 126:
        header.append(0x80 | n)  # 0x80 = mask bit; low 7 bits hold the length.
    elif n < 65536:
        header.append(0x80 | 126)  # 126 marker -> 16-bit extended length follows.
        header += struct.pack(">H", n)
    else:
        header.append(0x80 | 127)  # 127 marker -> 64-bit extended length follows.
        header += struct.pack(">Q", n)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def decode_frame(recv_exact: Callable[[int], bytes]) -> tuple[int, bytes]:
    """Read and decode one WebSocket frame using ``recv_exact(n) -> bytes``.

    ``recv_exact`` must return exactly ``n`` bytes (blocking until it can) or
    raise; routing all reads through it keeps this function pure and lets tests
    feed frames from an in-memory buffer. Server-to-client frames are normally
    unmasked, but a mask is honoured if present (the RFC permits either way of
    framing on read).

    Returns ``(opcode, payload_bytes)``. The caller inspects the opcode (e.g.
    ``0x8`` close, ``0x1`` text) and decodes the payload as needed.
    """
    b0, b1 = recv_exact(2)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(8))[0]
    mask = recv_exact(4) if masked else None
    data = recv_exact(length) if length else b""
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


class CDPSession:
    """A single attach-only CDP connection to a running FortiClient renderer.

    Lifecycle: construct with the debugging ``port``/``host``, call
    :meth:`connect` to discover the renderer target and open the WebSocket, then
    :meth:`evaluate` JS expressions, then :meth:`close`. Usable as a context
    manager, which closes on exit. The class is pure transport — it has no
    knowledge of VPN profiles or ``window.guimessenger`` semantics.
    """

    def __init__(self, port: int = 9222, host: str = "127.0.0.1"):
        """Configure where to attach.

        :param port: the ``--remote-debugging-port`` FortiClient was launched on.
        :param host: the loopback host the debugging endpoint binds to.
        """
        self.port = port
        self.host = host
        self._sock: socket.socket | None = None
        self._msg_id = 0

    # -- target discovery ---------------------------------------------------

    def discover_target(self) -> dict:
        """Find the renderer ``page`` target via ``GET http://host:port/json``.

        Prefers a target of type ``page`` that exposes a ``webSocketDebuggerUrl``
        (FortiClient's renderer is the single ``base.html`` page; see
        docs/how-it-works.md section 1), falling back to any other target that
        carries a debugger URL.

        :returns: the chosen target dict (has a ``webSocketDebuggerUrl`` key).
        :raises NotRunningError: if the HTTP endpoint is unreachable, or no
            target exposes a ``webSocketDebuggerUrl`` (FortiClient is not running
            with CDP enabled). The message is factual only (the URL + the
            reason); the CLI layers on the actionable "how to launch" guidance.
        """
        url = f"http://{self.host}:{self.port}/json"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                targets = json.loads(resp.read())
        except OSError as exc:
            # OSError covers ConnectionRefusedError, URLError's socket failures,
            # timeouts, DNS errors — i.e. "nothing is listening on the port".
            # FACTUAL message only: name the URL and the reason. The CLI adds the
            # "run forti startserver / launch command / download" guidance.
            raise NotRunningError(
                f"Cannot reach FortiClient's CDP endpoint at {url}: {exc}."
            ) from exc

        debuggable = [t for t in targets if t.get("webSocketDebuggerUrl")]
        if not debuggable:
            raise NotRunningError(
                f"Cannot reach a debuggable page target at {url} "
                f"(got {len(targets)} target(s), none with a webSocketDebuggerUrl)."
            )
        for target in debuggable:
            if target.get("type") == "page":
                return target
        # No 'page' type, but some target is debuggable — attach to it anyway.
        return debuggable[0]

    # -- connection ---------------------------------------------------------

    def connect(self) -> None:
        """Discover the renderer target and open the raw WebSocket to it.

        Idempotent: returns immediately if already connected, so it is safe to
        call both implicitly (via ``__enter__``) and explicitly.

        :raises NotRunningError: when FortiClient's CDP endpoint is unreachable
            or exposes no debuggable page target (see :meth:`discover_target`).
        """
        if self._sock is not None:
            return  # already connected; connect() is idempotent
        target = self.discover_target()
        self._sock = self._open_websocket(target["webSocketDebuggerUrl"])

    def _open_websocket(self, ws_url: str) -> socket.socket:
        """Open a TCP socket to ``ws_url`` and perform the RFC 6455 handshake.

        ``ws_url`` looks like ``ws://host:port/devtools/page/<id>``. We send the
        ``Upgrade: websocket`` request by hand (stdlib has no WebSocket client)
        and require a ``101 Switching Protocols`` status before returning the
        live socket.
        """
        if not ws_url.startswith("ws://"):
            raise NotRunningError(f"Unexpected non-ws debugger URL: {ws_url!r}")
        rest = ws_url[len("ws://") :]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        port = int(port or 80)

        sock = socket.create_connection((host, port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(request.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise NotRunningError("Socket closed during WebSocket handshake.")
            buf += chunk
        status_line = buf.split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            raise NotRunningError(f"WebSocket upgrade failed: {status_line!r}")
        return sock

    # -- I/O seam (monkeypatched in tests) ----------------------------------

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly ``n`` bytes from the socket or raise on early close."""
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise CDPEvaluateError("CDP socket closed mid-frame.")
            buf += chunk
        return buf

    def _send(self, text: str) -> None:
        """Send one text frame over the WebSocket (the socket-I/O seam)."""
        assert self._sock is not None
        self._sock.sendall(encode_frame(text))

    def _recv(self) -> tuple[int, bytes]:
        """Read one WebSocket frame from the socket (the socket-I/O seam)."""
        return decode_frame(self._recv_exact)

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, expression: str, await_promise: bool = True):
        """Run ``expression`` via ``Runtime.evaluate`` and return its value.

        The evaluate flags are the validated ones from the spike:
        ``returnByValue:true`` (so the JS value comes back serialised, not as a
        remote object ref), ``userGesture:true`` (FortiClient gates some
        ``guimessenger`` calls behind a user gesture), and ``awaitPromise`` —
        because every ``window.guimessenger`` method returns a Promise resolving
        to a JSON string (see docs/how-it-works.md section 2).

        :param expression: the JavaScript to evaluate in the renderer.
        :param await_promise: wait for a returned Promise to settle (default
            ``True``); pass ``False`` for synchronous expressions.
        :returns: the parsed JS value (``result.result.value``), or the result
            object itself when the response carries no ``value`` (e.g. an
            un-serialised object reference).
        :raises CDPEvaluateError: if the renderer reports ``exceptionDetails``
            (the in-page call threw), the response carries a top-level CDP
            ``error``, or the peer closes the connection instead of replying.
        """
        self._msg_id += 1
        msg_id = self._msg_id
        command = {
            "id": msg_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
                "userGesture": True,
            },
        }
        self._send(json.dumps(command))

        # CDP multiplexes async events and other replies on the same socket;
        # read until we see the reply whose id matches our request.
        while True:
            opcode, data = self._recv()
            if opcode == _OPCODE_CLOSE:
                raise CDPEvaluateError("CDP connection closed by FortiClient before reply.")
            if opcode not in (_OPCODE_TEXT, _OPCODE_BINARY):
                continue  # Ignore ping/pong/continuation frames.
            message = json.loads(data.decode("utf-8"))
            if message.get("id") == msg_id:
                return self._parse_evaluate_reply(message, expression)

    @staticmethod
    def _parse_evaluate_reply(message: dict, expression: str):
        """Extract the value from a matched ``Runtime.evaluate`` reply or raise."""
        if "error" in message:
            err = message["error"]
            raise CDPEvaluateError(
                f"CDP error evaluating {expression!r}: "
                f"{err.get('message', err)} (code {err.get('code')})"
            )
        result = message.get("result", {})
        if result.get("exceptionDetails"):
            details = result["exceptionDetails"]
            exc = details.get("exception", {})
            description = exc.get("description") or details.get("text") or json.dumps(details)
            raise CDPEvaluateError(f"JS exception evaluating {expression!r}: {description}")
        value = result.get("result", {})
        if "value" in value:
            return value["value"]
        return value

    # -- teardown -----------------------------------------------------------

    def close(self) -> None:
        """Close the WebSocket/socket if open; safe to call more than once."""
        sock = self._sock
        self._sock = None
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass  # socket already torn down — closing a dead socket is not an error

    def __enter__(self) -> "CDPSession":
        # Entering the context opens the connection — the idiomatic session
        # contract, so `with CDPSession() as s: s.evaluate(...)` works without a
        # separate connect() call. A real consumer (tests/manual/test_live.py)
        # relied on this; the CLI also calls connect() explicitly, which is now a
        # safe no-op thanks to connect()'s idempotence.
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
