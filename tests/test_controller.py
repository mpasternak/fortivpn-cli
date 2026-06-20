"""Tests for the high-level ``FortiVPN`` controller.

These tests are CI-safe: there is NO real FortiClient, no real CDP socket, and
no real Keychain. A :class:`FakeSession` stands in for a connected
``CDPSession`` — its ``evaluate()`` returns scripted JSON **strings** keyed by
the JavaScript expression (mirroring the real ``window.guimessenger`` contract,
which always returns a Promise resolving to a JSON string) and records the order
in which expressions were evaluated. ``keychain.get_password`` is monkeypatched
so the developer's real login Keychain is never touched, and both
``time.monotonic`` and ``time.sleep`` are monkeypatched so the polling loop runs
instantly and deterministically.

What they pin down (the contract the rest of the system depends on):

* ``profiles()`` parses a ``GetVPNConnectionList`` payload into ``Profile``s;
* ``state()`` parses ``getConnectionState`` and maps the enum to a label;
* the validated connect flow — ``SetGuiHandle()`` is evaluated BEFORE
  ``ConnectTunnel`` (without that ordering the daemon never negotiates; see
  docs/how-it-works.md), the ``ConnectTunnel`` JSON arg carries the right fields,
  and the password comes from the Keychain (never an argument the test passed in
  by hand);
* the v1 guards — ssl profile and XAUTH state both raise ``UnsupportedError``,
  a drop back to ``0`` after activity raises ``ConnectFailed``, and a state that
  never leaves ``0`` until the deadline raises ``ConnectTimeout``;
* ``disconnect()`` / ``cancel()`` issue the expected evaluate expressions.
"""

import json

import pytest

from fvpnctl import controller as controller_module
from fvpnctl.controller import ConnectionState, FortiVPN, Profile
from fvpnctl.errors import ConnectFailed, ConnectTimeout, UnsupportedError


class FakeSession:
    """A stand-in for a connected ``CDPSession``.

    ``responses`` maps a JavaScript expression to either a single return value
    or a *list* of values consumed one per call (so the polling loop can be
    scripted to walk through a sequence of states). Values that the real
    guimessenger would hand back as a JSON string are stored already
    ``json.dumps``-ed, because the controller is contractually required to
    ``json.loads`` everything ``evaluate()`` returns.

    Every evaluated expression is appended to ``calls`` so tests can assert both
    *that* a call happened and the *order* relative to other calls.
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def evaluate(self, expression, await_promise=True):
        self.calls.append(expression)
        value = self._lookup(expression)
        if isinstance(value, list):
            # A scripted sequence: pop the next value, holding the last one once
            # the list is exhausted so over-polling is harmless.
            if len(value) > 1:
                return value.pop(0)
            return value[0]
        return value

    def _lookup(self, expression):
        for key, value in self.responses.items():
            if expression.startswith(key):
                return value
        raise AssertionError(f"unexpected evaluate(): {expression!r}")


# Helpers --------------------------------------------------------------------


def _connect_tunnel_arg(session):
    """Return the parsed object the controller passed to ``ConnectTunnel``.

    The controller builds ``ConnectTunnel("<json-string>")`` where the argument
    is a JS string literal whose contents are the JSON the daemon expects.
    ``json.loads`` twice unwraps the JS-literal layer and then the JSON object.
    """
    for call in session.calls:
        if call.startswith("window.guimessenger.ConnectTunnel("):
            inner = call[len("window.guimessenger.ConnectTunnel(") : -1]
            js_literal = json.loads(inner)  # JS string literal -> the JSON string
            return json.loads(js_literal)  # the JSON string -> the object
    raise AssertionError("ConnectTunnel was never called")


def _disconnect_tunnel_arg(session):
    """Return the parsed object the controller passed to ``DisconnectTunnel``.

    Same double-``json.loads`` unwrapping as :func:`_connect_tunnel_arg` (JS string
    literal → JSON string → object); used to assert *which* profile was torn down.
    """
    for call in session.calls:
        if call.startswith("window.guimessenger.DisconnectTunnel("):
            inner = call[len("window.guimessenger.DisconnectTunnel(") : -1]
            js_literal = json.loads(inner)  # JS string literal -> the JSON string
            return json.loads(js_literal)  # the JSON string -> the object
    raise AssertionError("DisconnectTunnel was never called")


def _called(session, needle):
    """True if any evaluated expression contains ``needle``."""
    return any(needle in call for call in session.calls)


def _index_of(session, needle):
    """Index of the first evaluated expression containing ``needle``."""
    for i, call in enumerate(session.calls):
        if needle in call:
            return i
    raise AssertionError(f"{needle!r} was never evaluated")


@pytest.fixture
def fixed_clock(monkeypatch):
    """Freeze ``time`` so the polling loop is instant and deterministic.

    ``monotonic`` advances by one synthetic second per call and ``sleep`` is a
    no-op, so a loop that polls "every poll seconds until timeout" terminates
    immediately while still exercising the real deadline arithmetic.
    """
    ticks = {"now": 0.0}

    def fake_monotonic():
        ticks["now"] += 1.0
        return ticks["now"]

    monkeypatch.setattr(controller_module.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(controller_module.time, "sleep", lambda _seconds: None)
    return ticks


# profiles() -----------------------------------------------------------------


def test_profiles_parses_connection_list():
    payload = [
        {"connection_name": "office", "type": "ipsec", "cloud_vpn": 0},
        {"connection_name": "WebPortal", "type": "ssl", "corporate": 1},
    ]
    session = FakeSession({"window.guimessenger.GetVPNConnectionList()": json.dumps(payload)})

    profiles = FortiVPN(session).profiles()

    assert [type(p) for p in profiles] == [Profile, Profile]
    assert [(p.name, p.type) for p in profiles] == [("office", "ipsec"), ("WebPortal", "ssl")]
    # raw carries the full source entry untouched.
    assert profiles[0].raw == payload[0]


# state() --------------------------------------------------------------------


def test_state_parses_and_labels():
    state_payload = {
        "ipsec_state": 2,
        "ssl_state": 0,
        "connection_name": "office",
        "saml_vpn_name": "",
    }
    session = FakeSession({"window.guimessenger.getConnectionState()": json.dumps(state_payload)})

    state = FortiVPN(session).state()

    assert isinstance(state, ConnectionState)
    assert state.ipsec_state == 2
    assert state.ssl_state == 0
    assert state.name == "office"
    assert state.state_label == "CONNECTED"
    assert state.raw == state_payload


@pytest.mark.parametrize(
    "value,label",
    [
        (0, "DISCONNECTED"),
        (1, "CONNECTING"),
        (2, "CONNECTED"),
        (3, "XAUTH"),
        (4, "RECONNECTING"),
    ],
)
def test_state_label_maps_every_enum_value(value, label):
    state = ConnectionState(ipsec_state=value, ssl_state=0, name="X", raw={})
    assert state.state_label == label


# connect() happy path -------------------------------------------------------


def test_connect_happy_path(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    info = {"username": "alice", "remote_gateway": "vpn.example"}
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.GetIPSecGeneralInfo(": json.dumps(info),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 2, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )

    keychain_calls = []

    def fake_get_password(profile, username):
        keychain_calls.append((profile, username))
        return "s3cret-from-keychain"

    monkeypatch.setattr(controller_module.keychain, "get_password", fake_get_password)

    state = FortiVPN(session).connect("office")

    assert state.state_label == "CONNECTED"
    # SetGuiHandle MUST precede ConnectTunnel — without it the daemon acks but
    # never negotiates (docs/how-it-works.md).
    assert _index_of(session, "SetGuiHandle") < _index_of(session, "ConnectTunnel")
    # The password came from the (monkeypatched) keychain, keyed by profile+user.
    assert keychain_calls == [("office", "alice")]
    # The ConnectTunnel JSON arg carried the validated fields.
    arg = _connect_tunnel_arg(session)
    assert arg["connection_name"] == "office"
    assert arg["connection_type"] == "ipsec"
    assert arg["username"] == "alice"
    assert arg["password"] == "s3cret-from-keychain"
    assert arg["save_password"] == "0"
    assert arg["always_up"] == "0"
    assert arg["auto_connect"] == "0"
    assert arg["saml_error"] == 1


def test_connect_explicit_credentials_skip_keychain(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 2, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )

    def boom(*_args, **_kwargs):
        raise AssertionError("keychain must not be consulted when password is explicit")

    monkeypatch.setattr(controller_module.keychain, "get_password", boom)

    FortiVPN(session).connect("office", username="someone", password="explicit-pw")

    arg = _connect_tunnel_arg(session)
    assert arg["username"] == "someone"
    assert arg["password"] == "explicit-pw"
    # profile_info (GetIPSecGeneralInfo) is unnecessary when username is supplied.
    assert not _called(session, "GetIPSecGeneralInfo")


def test_connect_no_wait_returns_immediately(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 1, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    state = FortiVPN(session).connect("office", username="u", wait=False)

    # Returns whatever the single post-connect state read reported, no polling.
    assert state.state_label == "CONNECTING"


# connect() guards -----------------------------------------------------------


def test_connect_ssl_profile_is_unsupported_and_never_connects(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "WebPortal", "type": "ssl"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    with pytest.raises(UnsupportedError):
        FortiVPN(session).connect("WebPortal", username="u")

    # The guard must fire BEFORE any side effects on the daemon.
    assert not _called(session, "ConnectTunnel")
    assert not _called(session, "SetGuiHandle")


def test_connect_xauth_state_is_unsupported(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 3, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    with pytest.raises(UnsupportedError) as excinfo:
        FortiVPN(session).connect("office", username="u")

    assert "2FA" in str(excinfo.value)


def test_connect_drop_to_zero_after_activity_is_connect_failed(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            # Up-front read (nothing active → no preemptive disconnect); then the
            # first poll is CONNECTING (1) and it drops back to DISCONNECTED (0).
            "window.guimessenger.getConnectionState()": [
                json.dumps({"ipsec_state": 0, "ssl_state": 0, "connection_name": ""}),
                json.dumps({"ipsec_state": 1, "ssl_state": 0, "connection_name": "office"}),
                json.dumps({"ipsec_state": 0, "ssl_state": 0, "connection_name": "office"}),
            ],
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    with pytest.raises(ConnectFailed):
        FortiVPN(session).connect("office", username="u")


def test_connect_never_leaves_zero_times_out(monkeypatch, fixed_clock):
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            # Stays at DISCONNECTED forever — a silent rejection.
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 0, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    with pytest.raises(ConnectTimeout):
        # fixed_clock advances monotonic by 1s per call, so a 3s timeout elapses
        # after a couple of polls — instantly, with no real sleeping.
        FortiVPN(session).connect("office", username="u", timeout=3.0)


# connect() one-tunnel-at-a-time --------------------------------------------


def test_connect_disconnects_other_active_profile_first(monkeypatch, fixed_clock):
    # FortiClient holds at most one tunnel at a time: connecting "office" while
    # "apoz" is up must tear "apoz" down FIRST, otherwise the new ConnectTunnel is
    # silently rejected (the daemon stays pinned on the old tunnel).
    profiles = [
        {"connection_name": "apoz", "type": "ipsec"},
        {"connection_name": "office", "type": "ipsec"},
    ]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.GetIPSecGeneralInfo(": json.dumps({"username": "alice"}),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.DisconnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": [
                # 1) up-front read: a DIFFERENT profile is currently active.
                json.dumps({"ipsec_state": 2, "ssl_state": 0, "connection_name": "apoz"}),
                # 2) wait-for-disconnect: the daemon has torn it down.
                json.dumps({"ipsec_state": 0, "ssl_state": 0, "connection_name": "apoz"}),
                # 3) wait-for-connect: the new tunnel comes up.
                json.dumps({"ipsec_state": 2, "ssl_state": 0, "connection_name": "office"}),
            ],
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    state = FortiVPN(session).connect("office")

    assert state.state_label == "CONNECTED"
    assert state.name == "office"
    # The old tunnel was disconnected BEFORE the new connect sequence began.
    assert _index_of(session, "DisconnectTunnel") < _index_of(session, "SetGuiHandle")
    assert _index_of(session, "SetGuiHandle") < _index_of(session, "ConnectTunnel")
    # And it tore down the previously-active profile, not the one being connected.
    assert _disconnect_tunnel_arg(session)["connection_name"] == "apoz"


def test_connect_same_active_profile_is_not_disconnected(monkeypatch, fixed_clock):
    # Connecting the profile that is ALREADY active must not tear it down first —
    # the one-tunnel rule only preempts a *different* connection.
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.GetIPSecGeneralInfo(": json.dumps({"username": "alice"}),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 2, "ssl_state": 0, "connection_name": "office"}
            ),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    FortiVPN(session).connect("office")

    # No DisconnectTunnel response is even scripted: calling it would blow up the
    # fake. The assertion makes the intent explicit regardless.
    assert not _called(session, "DisconnectTunnel")


def test_connect_from_disconnected_does_not_disconnect(monkeypatch, fixed_clock):
    # Nothing active → no preemptive disconnect, just the normal connect flow.
    profiles = [{"connection_name": "office", "type": "ipsec"}]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.GetIPSecGeneralInfo(": json.dumps({"username": "alice"}),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.getConnectionState()": [
                json.dumps({"ipsec_state": 0, "ssl_state": 0, "connection_name": ""}),
                json.dumps({"ipsec_state": 2, "ssl_state": 0, "connection_name": "office"}),
            ],
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    state = FortiVPN(session).connect("office")

    assert state.state_label == "CONNECTED"
    assert not _called(session, "DisconnectTunnel")


def test_connect_previous_tunnel_never_disconnects_raises(monkeypatch, fixed_clock):
    # The active OTHER tunnel refuses to go down: we must NOT fire the new connect
    # (it would just be rejected) and must fail loudly instead.
    profiles = [
        {"connection_name": "apoz", "type": "ipsec"},
        {"connection_name": "office", "type": "ipsec"},
    ]
    session = FakeSession(
        {
            "window.guimessenger.GetVPNConnectionList()": json.dumps(profiles),
            "window.guimessenger.GetIPSecGeneralInfo(": json.dumps({"username": "alice"}),
            "window.guimessenger.SetGuiHandle()": json.dumps(True),
            "window.guimessenger.DisconnectTunnel(": json.dumps(["1"]),
            "window.guimessenger.ConnectTunnel(": json.dumps(["1"]),
            # The previously-active tunnel never leaves CONNECTED.
            "window.guimessenger.getConnectionState()": json.dumps(
                {"ipsec_state": 2, "ssl_state": 0, "connection_name": "apoz"}
            ),
        }
    )
    monkeypatch.setattr(controller_module.keychain, "get_password", lambda *_a, **_k: "pw")

    with pytest.raises(ConnectFailed):
        FortiVPN(session).connect("office", timeout=3.0)

    # The new tunnel must never be attempted while the old one is still up.
    assert not _called(session, "ConnectTunnel")
    assert not _called(session, "SetGuiHandle")


# disconnect() / cancel() ----------------------------------------------------


def test_disconnect_issues_expected_expression():
    session = FakeSession({"window.guimessenger.DisconnectTunnel(": json.dumps(["1"])})

    FortiVPN(session).disconnect("office")

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call.startswith("window.guimessenger.DisconnectTunnel(")
    inner = call[len("window.guimessenger.DisconnectTunnel(") : -1]
    arg = json.loads(json.loads(inner))
    assert arg == {"connection_name": "office", "connection_type": "ipsec"}


def test_cancel_issues_expected_expression():
    session = FakeSession({"window.guimessenger.CancelTunnel()": json.dumps(["1"])})

    FortiVPN(session).cancel()

    assert session.calls == ["window.guimessenger.CancelTunnel()"]
