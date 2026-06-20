"""Tests for the dependency-free CDP transport (``fortivpn.cdp``).

These are CI-safe: they never touch a real FortiClient or a real network. The
module is deliberately factored so the two failure-prone parts can be tested in
isolation:

* the WebSocket framing — exercised here directly as pure functions, across the
  three payload-length encodings (7-bit, 16-bit, 64-bit) and with the masking
  the RFC requires of clients;
* the higher-level ``CDPSession`` — exercised by faking ``urllib.request.urlopen``
  (target discovery) and by monkeypatching the socket-I/O helpers (``evaluate``),
  so a canned CDP response drives the parse/raise logic without a socket.
"""

import io
import json
import struct

import pytest

from fortivpn import cdp
from fortivpn.errors import CDPEvaluateError, NotRunningError

# ---------------------------------------------------------------------------
# WebSocket framing — pure functions.
# ---------------------------------------------------------------------------

# Payloads that straddle the three length encodings the RFC defines:
#   < 126        -> length packed in the 7 low bits of byte 1
#   126 .. 65535 -> 0x7e marker + 2-byte (>H) extended length
#   >= 65536     -> 0x7f marker + 8-byte (>Q) extended length
BOUNDARY_LENGTHS = [0, 1, 125, 126, 127, 65535, 65536, 70000]


def _reader_for(data: bytes):
    """Return a ``recv_exact(n)``-style callable backed by an in-memory buffer."""
    buf = io.BytesIO(data)

    def recv_exact(n):
        chunk = buf.read(n)
        if len(chunk) != n:
            raise AssertionError("reader underflow: frame asked for more than was fed")
        return chunk

    return recv_exact


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_frame_roundtrip_across_length_boundaries(length):
    text = "x" * length
    frame = cdp.encode_frame(text)
    opcode, payload = cdp.decode_frame(_reader_for(frame))
    assert opcode == 0x1  # text frame
    assert payload.decode("utf-8") == text


@pytest.mark.parametrize("length", BOUNDARY_LENGTHS)
def test_client_frames_are_masked(length):
    # RFC 6455: every frame a client sends MUST set the mask bit and mask the
    # payload. Servers reject unmasked client frames, so this is load-bearing.
    frame = cdp.encode_frame("y" * length)
    mask_and_len_byte = frame[1]
    assert mask_and_len_byte & 0x80, "mask bit (0x80) must be set on client frames"


def test_encode_frame_uses_7bit_length_below_126():
    frame = cdp.encode_frame("hello")  # 5 bytes
    assert frame[0] == 0x81  # FIN + text opcode
    assert frame[1] & 0x7F == 5  # length in the low 7 bits
    assert frame[1] & 0x80  # mask bit set


def test_encode_frame_uses_16bit_length_at_126():
    frame = cdp.encode_frame("z" * 126)
    assert frame[1] & 0x7F == 126  # marker for 16-bit extended length
    assert struct.unpack(">H", frame[2:4])[0] == 126


def test_encode_frame_uses_64bit_length_at_65536():
    frame = cdp.encode_frame("z" * 65536)
    assert frame[1] & 0x7F == 127  # marker for 64-bit extended length
    assert struct.unpack(">Q", frame[2:10])[0] == 65536


def test_decode_frame_unmasks_server_frames():
    # Build a server->client (unmasked) frame by hand and confirm decode reads it.
    payload = b"server-says-hi"
    frame = bytes([0x81, len(payload)]) + payload
    opcode, data = cdp.decode_frame(_reader_for(frame))
    assert opcode == 0x1
    assert data == payload


def test_decode_frame_reports_close_opcode():
    frame = bytes([0x88, 0x00])  # FIN + close opcode, empty payload
    opcode, data = cdp.decode_frame(_reader_for(frame))
    assert opcode == 0x8
    assert data == b""


# ---------------------------------------------------------------------------
# Target discovery — fake ``urllib.request.urlopen``.
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    """Minimal stand-in for the object ``urlopen`` yields as a context manager."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _json_body(targets):
    return _FakeHTTPResponse(json.dumps(targets).encode("utf-8"))


def test_discover_target_picks_the_page_target(monkeypatch):
    targets = [
        {"type": "other", "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/other"},
        {
            "type": "page",
            "title": "base.html",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/ABC",
        },
    ]
    monkeypatch.setattr(cdp.urllib.request, "urlopen", lambda url, timeout=5: _json_body(targets))

    sess = cdp.CDPSession(port=9222)
    target = sess.discover_target()
    assert target["type"] == "page"
    assert target["webSocketDebuggerUrl"].endswith("/devtools/page/ABC")


def test_discover_target_uses_configured_host_and_port(monkeypatch):
    seen = {}

    def fake_urlopen(url, timeout=5):
        seen["url"] = url
        return _json_body([{"type": "page", "webSocketDebuggerUrl": "ws://h:1/devtools/page/X"}])

    monkeypatch.setattr(cdp.urllib.request, "urlopen", fake_urlopen)
    cdp.CDPSession(port=1234, host="example.test").discover_target()
    assert seen["url"] == "http://example.test:1234/json"


def test_connect_raises_not_running_when_endpoint_unreachable(monkeypatch):
    def boom(url, timeout=5):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(cdp.urllib.request, "urlopen", boom)

    sess = cdp.CDPSession(port=9222)
    with pytest.raises(NotRunningError) as excinfo:
        sess.connect()
    # The message must be actionable: tell the user how to launch FortiClient.
    assert "remote-debugging-port" in str(excinfo.value)


def test_connect_raises_not_running_when_no_debuggable_page(monkeypatch):
    # Targets exist but none of type 'page' carries a webSocketDebuggerUrl.
    targets = [{"type": "service_worker", "title": "sw"}]
    monkeypatch.setattr(cdp.urllib.request, "urlopen", lambda url, timeout=5: _json_body(targets))

    sess = cdp.CDPSession(port=9222)
    with pytest.raises(NotRunningError):
        sess.connect()


def test_discover_target_raises_not_running_on_empty_list(monkeypatch):
    monkeypatch.setattr(cdp.urllib.request, "urlopen", lambda url, timeout=5: _json_body([]))
    with pytest.raises(NotRunningError):
        cdp.CDPSession(port=9222).discover_target()


# ---------------------------------------------------------------------------
# evaluate() — fake the send/recv layer with a canned CDP response.
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Captures sent commands and replays a queued list of CDP responses.

    Installed onto a ``CDPSession`` by overriding its ``_send``/``_recv``
    seam, so ``evaluate()`` runs end-to-end without a socket.
    """

    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    def send(self, session, text):
        self.sent.append(json.loads(text))

    def recv(self, session):
        return self.responses.pop(0)


def _wire_transport(session, responses):
    fake = _FakeTransport(responses)
    session._send = lambda text: fake.send(session, text)
    session._recv = lambda: fake.recv(session)
    # Mark as "connected" so evaluate() does not try to open a socket.
    session._sock = object()
    return fake


def test_evaluate_returns_parsed_value(monkeypatch):
    sess = cdp.CDPSession()
    # Runtime.evaluate with returnByValue puts the JS value at result.result.value.
    response = (0x1, json.dumps({"id": 1, "result": {"result": {"value": "true"}}}).encode())
    fake = _wire_transport(sess, [response])

    out = sess.evaluate("window.guimessenger.SetGuiHandle()")
    assert out == "true"

    # The command we sent must carry the validated evaluate flags.
    sent = fake.sent[0]
    assert sent["method"] == "Runtime.evaluate"
    params = sent["params"]
    assert params["expression"] == "window.guimessenger.SetGuiHandle()"
    assert params["awaitPromise"] is True
    assert params["returnByValue"] is True
    assert params["userGesture"] is True


def test_evaluate_returns_structured_object_when_no_value(monkeypatch):
    sess = cdp.CDPSession()
    # No 'value' key -> return the result object itself (e.g. an unserialised ref).
    inner = {"type": "object", "className": "Promise"}
    response = (0x1, json.dumps({"id": 1, "result": {"result": inner}}).encode())
    _wire_transport(sess, [response])

    out = sess.evaluate("window.guimessenger")
    assert out == inner


def test_evaluate_can_disable_await_promise(monkeypatch):
    sess = cdp.CDPSession()
    response = (0x1, json.dumps({"id": 1, "result": {"result": {"value": 7}}}).encode())
    fake = _wire_transport(sess, [response])

    sess.evaluate("1 + 1", await_promise=False)
    assert fake.sent[0]["params"]["awaitPromise"] is False


def test_evaluate_skips_unrelated_messages_until_matching_id(monkeypatch):
    sess = cdp.CDPSession()
    responses = [
        # An async CDP event (no id) and a stale reply (different id) come first.
        (0x1, json.dumps({"method": "Runtime.consoleAPICalled", "params": {}}).encode()),
        (0x1, json.dumps({"id": 99, "result": {"result": {"value": "stale"}}}).encode()),
        (0x1, json.dumps({"id": 1, "result": {"result": {"value": "fresh"}}}).encode()),
    ]
    _wire_transport(sess, responses)
    assert sess.evaluate("expr") == "fresh"


def test_evaluate_raises_on_exception_details(monkeypatch):
    sess = cdp.CDPSession()
    response = (
        0x1,
        json.dumps(
            {
                "id": 1,
                "result": {
                    "result": {"type": "object"},
                    "exceptionDetails": {
                        "text": "Uncaught",
                        "exception": {"description": "Error: boom"},
                    },
                },
            }
        ).encode(),
    )
    _wire_transport(sess, [response])

    with pytest.raises(CDPEvaluateError) as excinfo:
        sess.evaluate("throw new Error('boom')")
    assert "boom" in str(excinfo.value)


def test_evaluate_raises_on_toplevel_cdp_error(monkeypatch):
    sess = cdp.CDPSession()
    response = (
        0x1,
        json.dumps({"id": 1, "error": {"code": -32000, "message": "Cannot evaluate"}}).encode(),
    )
    _wire_transport(sess, [response])

    with pytest.raises(CDPEvaluateError) as excinfo:
        sess.evaluate("bad")
    assert "Cannot evaluate" in str(excinfo.value)


def test_evaluate_raises_on_peer_close(monkeypatch):
    sess = cdp.CDPSession()
    # Peer sends a close frame (opcode 0x8) instead of a reply.
    _wire_transport(sess, [(0x8, b"")])
    with pytest.raises(CDPEvaluateError):
        sess.evaluate("expr")


# ---------------------------------------------------------------------------
# Context manager / close.
# ---------------------------------------------------------------------------


class _FakeSocket:
    def __init__(self, close_raises=None):
        self.closed = False
        self._close_raises = close_raises

    def close(self):
        self.closed = True
        if self._close_raises is not None:
            raise self._close_raises


def test_close_is_idempotent_and_closes_socket():
    sess = cdp.CDPSession()
    sock = _FakeSocket()
    sess._sock = sock
    sess.close()
    assert sock.closed is True
    assert sess._sock is None
    # Second close must be a no-op, not an error.
    sess.close()


def test_close_suppresses_oserror_from_torn_down_socket():
    sess = cdp.CDPSession()
    sess._sock = _FakeSocket(close_raises=OSError("socket already torn down"))
    # Must not propagate: teardown of an already-dead socket is not an error.
    sess.close()
    assert sess._sock is None


_FAKE_TARGET = {"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/abc"}


def test_enter_connects(monkeypatch):
    # `with CDPSession() as s:` must open the connection (idiomatic CM contract).
    sock = _FakeSocket()
    monkeypatch.setattr(cdp.CDPSession, "discover_target", lambda self: _FAKE_TARGET)
    monkeypatch.setattr(cdp.CDPSession, "_open_websocket", lambda self, url: sock)
    with cdp.CDPSession() as sess:
        assert sess._sock is sock


def test_connect_is_idempotent(monkeypatch):
    calls = {"discover": 0, "open": 0}
    sock = _FakeSocket()

    def disc(self):
        calls["discover"] += 1
        return _FAKE_TARGET

    def opn(self, url):
        calls["open"] += 1
        return sock

    monkeypatch.setattr(cdp.CDPSession, "discover_target", disc)
    monkeypatch.setattr(cdp.CDPSession, "_open_websocket", opn)
    sess = cdp.CDPSession()
    sess.connect()
    sess.connect()  # second call must be a no-op, not a second socket
    assert calls == {"discover": 1, "open": 1}
    assert sess._sock is sock


def test_context_manager_closes_on_exit(monkeypatch):
    sock = _FakeSocket()
    # neutralise the real connect() so __enter__ does no I/O; just verify teardown.
    monkeypatch.setattr(cdp.CDPSession, "connect", lambda self: setattr(self, "_sock", sock))
    with cdp.CDPSession() as sess:
        assert sess._sock is sock  # __enter__ connected
    assert sock.closed is True  # __exit__ closed
