"""High-level FortiClient controller — the ``window.guimessenger`` contract.

What this is
------------
``FortiVPN`` wraps a connected :class:`~fortivpn.cdp.CDPSession` and turns the
raw, validated ``window.guimessenger`` calls into a small, typed API:
``profiles()``, ``state()``, ``connect()``, ``disconnect()`` and friends. The
transport layer (``cdp.py``) knows nothing about VPNs; all the
FortiClient-specific knowledge — the call names, the argument shapes, the
connect ordering, and the v1 guards — lives here.

This module is a direct promotion of the empirically validated spike
(``/tmp/forti_connect.py``; findings in ``docs/how-it-works.md``). Two non-obvious facts it
encodes are worth stating up front because nothing in the code would let a
reader infer them:

Why every guimessenger return value is ``json.loads``-ed
--------------------------------------------------------
``CDPSession.evaluate()`` already unwraps the CDP ``Runtime.evaluate`` reply and
hands back the *JS value*. But the FortiClient renderer's ``window.guimessenger``
methods do not return JS objects — they return a **JSON string** (a Promise
resolving to a string of JSON; see docs/how-it-works.md section 2). So ``evaluate()`` returns
that string verbatim, and this layer must ``json.loads`` it to recover the actual
list/dict. Every helper below therefore does ``json.loads(self._eval(...))``.

Why ``SetGuiHandle()`` must be called before ``ConnectTunnel``
--------------------------------------------------------------
The validated connect sequence calls ``SetGuiHandle()`` *first*. This registers
the GUI handle the daemon routes XAUTH/state callbacks to. Skipping it is not a
loud failure: ``ConnectTunnel`` still returns its ``["1"]`` ack, but the daemon
never begins negotiating and ``getConnectionState`` stays pinned at ``0``
forever (reproduced in the spike; see docs/how-it-works.md section 3 and design spec 4.2).
:meth:`FortiVPN.connect` therefore always evaluates ``SetGuiHandle()`` before
``ConnectTunnel`` — the ordering is load-bearing, not cosmetic.

Why several reads need a JSON argument
--------------------------------------
``GetIPSecGeneralInfo``, ``getConnectionIP`` and ``getConnectionInfo`` require a
``JSON.stringify({connection_name, connection_type})`` argument; without it the
renderer raises "Error in native callback" (docs/how-it-works.md section 2). We build that
argument the same way the GUI does and the same way the spike validated — see
:meth:`_eval_with_json_arg`.
"""

import json
import time
from dataclasses import dataclass

from fortivpn import keychain
from fortivpn.errors import ConnectFailed, ConnectTimeout, UnsupportedError

# Connection-state enum reported in ``ipsec_state`` (docs/how-it-works.md section 2 / design
# spec 4.2). These integers come straight from the daemon; the labels are ours.
_DISCONNECTED = 0
_CONNECTING = 1
_CONNECTED = 2
_XAUTH = 3
_RECONNECTING = 4

_STATE_LABELS = {
    _DISCONNECTED: "DISCONNECTED",
    _CONNECTING: "CONNECTING",
    _CONNECTED: "CONNECTED",
    _XAUTH: "XAUTH",
    _RECONNECTING: "RECONNECTING",
}


@dataclass
class Profile:
    """One VPN profile as reported by ``GetVPNConnectionList``.

    :param name: the profile's ``connection_name`` (what the user passes to
        ``connect``/``disconnect``).
    :param type: ``"ipsec"`` or ``"ssl"`` — only ``ipsec`` is supported in v1.
    :param raw: the untouched source entry, so callers can reach fields this
        dataclass does not surface (``cloud_vpn``, ``corporate``, ...).
    """

    name: str
    type: str
    raw: dict

    @classmethod
    def from_entry(cls, entry: dict) -> "Profile":
        """Build a :class:`Profile` from one ``GetVPNConnectionList`` entry.

        ``name`` is taken from the entry's ``connection_name`` key and ``type``
        from its ``type`` key; the whole entry is preserved in ``raw``.
        """
        return cls(name=entry.get("connection_name"), type=entry.get("type"), raw=entry)


@dataclass
class ConnectionState:
    """A snapshot of the tunnel state from ``getConnectionState``.

    :param ipsec_state: the IPsec state enum (0..4); see :attr:`state_label`.
    :param ssl_state: the SSL state enum (unused in v1 but carried for parity).
    :param name: the ``connection_name`` the daemon associates with this state.
    :param raw: the untouched ``getConnectionState`` dict.
    """

    ipsec_state: int
    ssl_state: int
    name: str
    raw: dict

    @property
    def state_label(self) -> str:
        """Human label for :attr:`ipsec_state` (``DISCONNECTED`` ... ``RECONNECTING``).

        Returns ``"UNKNOWN(<n>)"`` for any value outside the validated 0..4 range
        rather than raising, so an unexpected daemon state never masks the real
        status with a ``KeyError``.
        """
        return _STATE_LABELS.get(self.ipsec_state, f"UNKNOWN({self.ipsec_state})")

    @classmethod
    def from_payload(cls, payload: dict) -> "ConnectionState":
        """Build a :class:`ConnectionState` from a ``getConnectionState`` dict.

        Missing numeric states default to ``0`` (DISCONNECTED) so a partial
        payload is treated as "not connected" rather than crashing.
        """
        return cls(
            ipsec_state=payload.get("ipsec_state", 0),
            ssl_state=payload.get("ssl_state", 0),
            name=payload.get("connection_name", ""),
            raw=payload,
        )


class FortiVPN:
    """Typed controller over the validated ``window.guimessenger`` flow.

    Wraps a *connected* :class:`~fortivpn.cdp.CDPSession`. Each public method
    maps to one or more ``window.guimessenger`` calls, parsing the JSON-string
    returns into Python objects (see the module docstring for why parsing is
    required). The class holds no VPN credentials beyond the lifetime of a single
    :meth:`connect` call.
    """

    def __init__(self, session):
        """Wrap an already-connected ``CDPSession``.

        :param session: a connected ``CDPSession`` (``connect()`` already called),
            or any object exposing a compatible ``evaluate(expression)`` — the
            seam the tests drive with a fake.
        """
        self._session = session

    # -- low-level evaluate seam -------------------------------------------

    def _eval(self, expression: str):
        """Evaluate ``expression`` and ``json.loads`` the JSON-string result.

        Centralises the "every guimessenger method returns a JSON string"
        contract (module docstring): the renderer hands back a string of JSON, so
        we parse it here and every caller works with real Python objects.

        :returns: the parsed value (``list``/``dict``/scalar).
        """
        return json.loads(self._session.evaluate(expression))

    def _eval_with_json_arg(self, method: str, obj: dict):
        """Evaluate ``window.guimessenger.<method>(<json-arg>)`` and parse the result.

        ``GetIPSecGeneralInfo``/``getConnectionIP``/``getConnectionInfo`` (and
        ``ConnectTunnel``/``DisconnectTunnel``) take a single argument that must
        itself be a *JSON string*. We reproduce the spike's exact double-encoding:
        ``inner = json.dumps(obj)`` produces the JSON string the daemon expects,
        then ``json.dumps(inner)`` wraps it as a JS string literal so the
        evaluated expression is syntactically valid JavaScript (docs/how-it-works.md section 2).
        """
        inner = json.dumps(obj)  # the JSON string the daemon wants as the argument
        js_literal = json.dumps(inner)  # wrap as a JS string literal for evaluate()
        return self._eval(f"window.guimessenger.{method}({js_literal})")

    # -- reads --------------------------------------------------------------

    def profiles(self) -> list[Profile]:
        """List configured VPN profiles via ``GetVPNConnectionList``.

        :returns: one :class:`Profile` per configured connection, in the order
            the daemon reports them.
        :raises CDPEvaluateError: if the underlying ``evaluate`` call throws.
        """
        entries = self._eval("window.guimessenger.GetVPNConnectionList()")
        return [Profile.from_entry(entry) for entry in entries]

    def profile_info(self, name: str, ctype: str = "ipsec") -> dict:
        """Return ``GetIPSecGeneralInfo`` for ``name`` (gateway, username, ...).

        Requires the JSON argument (module docstring / docs/how-it-works.md section 2).

        :param name: the profile's ``connection_name``.
        :param ctype: ``connection_type`` (``"ipsec"`` in v1).
        :returns: the parsed info dict (``remote_gateway``, ``username``, ...).
        """
        return self._eval_with_json_arg(
            "GetIPSecGeneralInfo",
            {"connection_name": name, "connection_type": ctype},
        )

    def state(self) -> ConnectionState:
        """Return the current tunnel state via ``getConnectionState``.

        :returns: a :class:`ConnectionState`; check ``.ipsec_state`` /
            ``.state_label``.
        """
        return ConnectionState.from_payload(self._eval("window.guimessenger.getConnectionState()"))

    def connection_ip(self, name: str, ctype: str) -> dict:
        """Return the tunnel's assigned IP via ``getConnectionIP`` (JSON arg).

        :returns: e.g. ``{"vpn_ip": "172.16.200.2"}``.
        """
        return self._eval_with_json_arg(
            "getConnectionIP",
            {"connection_name": name, "connection_type": ctype},
        )

    def connection_info(self, name: str, ctype: str) -> dict:
        """Return tunnel statistics via ``getConnectionInfo`` (JSON arg).

        :returns: e.g. ``{"duration": ..., "traffic_in": ..., "traffic_out": ...}``.
        """
        return self._eval_with_json_arg(
            "getConnectionInfo",
            {"connection_name": name, "connection_type": ctype},
        )

    # -- connect ------------------------------------------------------------

    def connect(
        self,
        name: str,
        *,
        username: str | None = None,
        password: str | None = None,
        wait: bool = True,
        timeout: float = 30.0,
        poll: float = 1.0,
    ) -> ConnectionState:
        """Connect IPsec profile ``name`` using the validated flow.

        Algorithm (design spec 4.2 / docs/how-it-works.md section 3):

        1. Resolve the :class:`Profile` from :meth:`profiles`; if its ``type`` is
           not ``"ipsec"`` raise :class:`UnsupportedError` *before* touching the
           daemon (SSL is out of scope for v1).
        2. ``username`` ← the argument, else ``profile_info(name)["username"]``.
        3. ``password`` ← the argument, else ``keychain.get_password(name, username)``.
        4. ``SetGuiHandle()`` — evaluated **before** ``ConnectTunnel`` because the
           daemon will not negotiate without it (module docstring).
        5. ``ConnectTunnel(JSON.stringify({...}))`` with the validated field set.
        6. If ``wait``: poll :meth:`state` every ``poll`` seconds until the
           deadline:
           - ``ipsec_state == 2`` (CONNECTED) → return the state;
           - ``ipsec_state == 3`` (XAUTH) → :class:`UnsupportedError`
             (``"2FA not supported in v1"``);
           - dropped back to ``0`` *after* having reached a non-zero state →
             :class:`ConnectFailed` (active rejection, e.g. bad credentials);
           - ``timeout`` elapses first — **including the state never leaving
             ``0``** (silent rejection) → :class:`ConnectTimeout`.
           If ``wait`` is ``False`` return the post-``ConnectTunnel`` state read
           immediately, without polling.

        Security: ``password`` is held only in a local variable, passed straight
        into the ``ConnectTunnel`` argument, and never logged, never placed in an
        exception message, and never put in a repr.

        :returns: the terminal :class:`ConnectionState` (CONNECTED on success, or
            the immediate state when ``wait=False``).
        :raises UnsupportedError: ssl profile, or the daemon enters XAUTH (2FA).
        :raises ConnectFailed: the tunnel negotiated then dropped to disconnected.
        :raises ConnectTimeout: the tunnel did not reach CONNECTED within ``timeout``
            (including never leaving DISCONNECTED).
        :raises KeychainError: the password is needed but the Keychain lookup fails.
        """
        # 1. Resolve and guard on profile type BEFORE any daemon side effects.
        profile = self._resolve_profile(name)
        if profile.type != "ipsec":
            raise UnsupportedError(
                f"Profile {name!r} has type {profile.type!r}; only 'ipsec' is "
                f"supported in v1 (SSL VPN is out of scope)."
            )

        # 2-3. Resolve credentials. The password lives only in this local.
        if username is None:
            username = self.profile_info(name)["username"]
        if password is None:
            password = keychain.get_password(name, username)

        # 4. Register the GUI handle FIRST — load-bearing ordering (module docstring).
        self._session.evaluate("window.guimessenger.SetGuiHandle()")

        # 5. Issue the connect with the validated field set. Build the argument
        #    by hand (not via _eval_with_json_arg) so it is unambiguous which
        #    object — including the secret — is encoded here.
        connect_obj = {
            "connection_name": name,
            "connection_type": "ipsec",
            "username": username,
            "password": password,
            "save_password": "0",
            "always_up": "0",
            "auto_connect": "0",
            "saml_error": 1,
        }
        inner = json.dumps(connect_obj)
        js_literal = json.dumps(inner)
        self._session.evaluate(f"window.guimessenger.ConnectTunnel({js_literal})")

        # 6. Either wait for a terminal state or return the immediate snapshot.
        if not wait:
            return self.state()
        return self._wait_for_connection(timeout=timeout, poll=poll)

    def _resolve_profile(self, name: str) -> Profile:
        """Find the :class:`Profile` named ``name``, else raise.

        :raises UnsupportedError: when no configured profile matches ``name`` —
            there is nothing to connect, and silently calling ConnectTunnel with an
            unknown name is exactly the not-supported, won't-negotiate case.
        """
        for profile in self.profiles():
            if profile.name == name:
                return profile
        raise UnsupportedError(
            f"No VPN profile named {name!r} (run `forti list` to see configured profiles)."
        )

    def _wait_for_connection(self, *, timeout: float, poll: float) -> ConnectionState:
        """Poll :meth:`state` until a terminal outcome or the deadline.

        Uses ``time.monotonic()`` for the deadline (immune to wall-clock jumps)
        and ``time.sleep(poll)`` between polls; both are module-level ``time``
        attributes so tests can monkeypatch them for instant, deterministic runs.

        ``seen_active`` records whether the tunnel ever left DISCONNECTED, which is
        what distinguishes a :class:`ConnectFailed` (negotiated then dropped) from
        a :class:`ConnectTimeout` (never moved). See :meth:`connect` for the full
        contract.
        """
        deadline = time.monotonic() + timeout
        seen_active = False
        while True:
            state = self.state()
            ipsec_state = state.ipsec_state

            if ipsec_state == _CONNECTED:
                return state
            if ipsec_state == _XAUTH:
                raise UnsupportedError(
                    "2FA not supported in v1 (the daemon entered the XAUTH state)."
                )
            if ipsec_state != _DISCONNECTED:
                seen_active = True
            elif seen_active:
                # Reached a non-zero state and then dropped back to 0: the gateway
                # actively rejected the tunnel (e.g. bad credentials, policy deny).
                raise ConnectFailed(
                    "The tunnel started negotiating but dropped back to disconnected "
                    "(check credentials / gateway policy)."
                )

            if time.monotonic() >= deadline:
                # Timed out. This INCLUDES the state never leaving 0 — a silent
                # rejection where the daemon never even began negotiating.
                raise ConnectTimeout(
                    f"Tunnel did not reach CONNECTED within {timeout:g}s "
                    f"(last ipsec_state={ipsec_state})."
                )
            time.sleep(poll)

    # -- teardown -----------------------------------------------------------

    def disconnect(self, name: str, ctype: str = "ipsec") -> None:
        """Disconnect profile ``name`` via ``DisconnectTunnel`` (JSON arg).

        :param name: the profile's ``connection_name``.
        :param ctype: ``connection_type`` (``"ipsec"`` in v1).
        :raises CDPEvaluateError: if the underlying ``evaluate`` call throws.
        """
        self._eval_with_json_arg(
            "DisconnectTunnel",
            {"connection_name": name, "connection_type": ctype},
        )

    def cancel(self) -> None:
        """Abort an in-progress connect via ``CancelTunnel`` (no argument).

        :raises CDPEvaluateError: if the underlying ``evaluate`` call throws.
        """
        self._eval("window.guimessenger.CancelTunnel()")

    def hide_window(self) -> None:
        """Hide FortiClient's main window to the tray, over CDP.

        Why this exists: ``--hide-gui`` only suppresses the window at startup. On a
        successful connect the renderer calls ``focusWindow()`` — it pops the main
        window (with the Disconnect button) — and ``--hide-gui`` does not gate that
        path. This calls ``window.forticlient.closeMainWindow()``, a separate preload
        bridge reachable in the same renderer world as ``window.guimessenger``. Its
        main-process handler closes the window, and the window's ``close`` is
        intercepted into ``hide()`` — so it goes to the tray *without quitting the
        app* (unlike ``forticlient.quit`` → ``app.quit()``). See docs/how-it-works.md.

        Tolerant by design: the expression guards on the bridge being present, so a
        renderer without ``window.forticlient`` is a no-op rather than an error. Not
        routed through :meth:`_eval` because ``closeMainWindow()`` resolves to
        ``undefined`` (no JSON string to parse).

        :raises CDPEvaluateError: only if ``closeMainWindow()`` itself throws.
        """
        self._session.evaluate(
            "window.forticlient && window.forticlient.closeMainWindow"
            " ? window.forticlient.closeMainWindow() : null"
        )
