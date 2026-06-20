"""Tests for the ``forti`` CLI (``fortivpn.cli.main``).

These tests are CI-safe: there is NO real FortiClient, no real CDP socket, and
no real Keychain. The CLI references ``CDPSession`` and ``FortiVPN`` as
module-level names (``fortivpn.cli.CDPSession`` / ``fortivpn.cli.FortiVPN``), so
every test monkeypatches those two seams:

* ``CDPSession`` is replaced by :class:`FakeSession` — a no-op context manager
  that merely records the ``port``/``host`` it was constructed with (so we can
  assert ``--port`` / ``FORTI_CDP_PORT`` are threaded through), and whose
  ``connect()`` does nothing.
* ``FortiVPN`` is replaced by a :class:`FakeController` factory that returns a
  fake whose methods return canned data or raise on demand. This lets us assert
  *which* controller method a subcommand routed to and *with what arguments*,
  without any of the real ``window.guimessenger`` machinery.

What they pin down (the CLI contract from design spec sections 4.5 and 5):

* each subcommand routes to the right controller method with the right args;
* the ``FortiError`` subtype → process exit-code mapping;
* ``--port`` and the ``FORTI_CDP_PORT`` env var both feed the session port;
* ``--json`` output for ``list`` and ``status`` is valid JSON of the right shape;
* ``ip`` when not connected exits ``1`` with ``not connected`` on stderr;
* argparse usage errors (unknown subcommand / missing arg) exit ``2``.

``main([...])`` is always called directly with an ``argv`` list and the returned
int is asserted, so nothing here depends on ``sys.argv`` or a real process exit.
"""

import json

import pytest

from fortivpn import cli
from fortivpn.errors import (
    ConnectTimeout,
    FortiError,
    KeychainError,
    NotRunningError,
    UnsupportedError,
)


class FakeSession:
    """No-op stand-in for ``CDPSession`` — records construction args.

    The CLI constructs ``CDPSession(port, host)``, uses it as a context manager,
    and calls ``connect()`` on it. This fake records ``port``/``host`` on a
    module-level list so tests can assert the global ``--port`` / ``--host`` /
    env handling, and otherwise does nothing — there is no real socket.
    """

    instances = []

    def __init__(self, port=9222, host="127.0.0.1"):
        self.port = port
        self.host = host
        FakeSession.instances.append(self)

    def connect(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class FakeState:
    """A stand-in for ``ConnectionState`` exposing only what the CLI reads."""

    def __init__(self, ipsec_state, name="office", state_label="CONNECTED", raw=None):
        self.ipsec_state = ipsec_state
        self.name = name
        self.state_label = state_label
        self.raw = raw if raw is not None else {}


class FakeController:
    """Configurable fake ``FortiVPN`` — records calls, returns/raises on demand.

    Constructed by the CLI as ``FortiVPN(session)``; this fake captures the
    session and exposes the same method surface the CLI uses. Each method appends
    ``(name, args, kwargs)`` to ``calls`` and then returns the canned value
    configured for it — or, if that value is an ``Exception`` (instance or
    class), raises it. That single mechanism covers both the "routes with the
    right args" tests and the "exception → exit code" tests.
    """

    # Per-test configuration injected by the ``patched`` fixture.
    config = {}
    last = None

    def __init__(self, session):
        self.session = session
        self.calls = []
        FakeController.last = self

    def _dispatch(self, _name, *args, **kwargs):
        self.calls.append((_name, args, kwargs))
        result = FakeController.config.get(_name)
        if isinstance(result, type) and issubclass(result, BaseException):
            raise result(f"boom: {_name}")
        if isinstance(result, BaseException):
            raise result
        return result

    def profiles(self):
        return self._dispatch("profiles")

    def profile_info(self, name, ctype="ipsec"):
        return self._dispatch("profile_info", name, ctype)

    def state(self):
        return self._dispatch("state")

    def connection_info(self, name, ctype):
        return self._dispatch("connection_info", name, ctype)

    def connection_ip(self, name, ctype):
        return self._dispatch("connection_ip", name, ctype)

    def connect(self, name, *, username=None, wait=True, timeout=30.0):
        return self._dispatch("connect", name, username=username, wait=wait, timeout=timeout)

    def disconnect(self, name, ctype="ipsec"):
        return self._dispatch("disconnect", name, ctype)


class _FakeProfile:
    """Minimal profile object with the ``.name`` / ``.type`` the CLI reads."""

    def __init__(self, name, type):
        self.name = name
        self.type = type


@pytest.fixture(autouse=True)
def patched(monkeypatch):
    """Swap the two seams and reset per-test state.

    Every test gets fresh ``FakeSession.instances`` and ``FakeController.config``
    so assertions about construction args / routed calls never bleed between
    tests. The ``FORTI_CDP_PORT`` env var is cleared so the default-port tests
    are not perturbed by the developer's environment.
    """
    FakeSession.instances = []
    FakeController.config = {}
    FakeController.last = None
    monkeypatch.setattr(cli, "CDPSession", FakeSession)
    monkeypatch.setattr(cli, "FortiVPN", FakeController)
    monkeypatch.delenv("FORTI_CDP_PORT", raising=False)
    return FakeController


# -- routing: each subcommand calls the right controller method --------------


def test_list_routes_to_profiles(capsys):
    FakeController.config["profiles"] = [
        _FakeProfile("office", "ipsec"),
        _FakeProfile("WebPortal", "ssl"),
    ]
    FakeController.config["profile_info"] = {"remote_gateway": "vpn.example.com"}

    rc = cli.main(["list"])

    assert rc == 0
    assert FakeController.last.calls[0][0] == "profiles"
    out = capsys.readouterr().out
    assert "office" in out
    assert "ipsec" in out
    assert "vpn.example.com" in out
    # ssl profiles get a blank server column (profile_info only queried for ipsec).
    assert "WebPortal" in out


def test_status_connected_merges_info_and_ip(capsys):
    FakeController.config["state"] = FakeState(
        ipsec_state=2, name="office", state_label="CONNECTED", raw={"connection_name": "office"}
    )
    FakeController.config["connection_info"] = {
        "duration": "00:01:45",
        "traffic_in": 1616,
        "traffic_out": 0,
    }
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["status"])

    assert rc == 0
    names = [c[0] for c in FakeController.last.calls]
    assert names[0] == "state"
    assert "connection_info" in names
    assert "connection_ip" in names
    out = capsys.readouterr().out
    assert "CONNECTED" in out
    assert "172.16.200.2" in out


def test_status_disconnected(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=0, name="", state_label="DISCONNECTED")

    rc = cli.main(["status"])

    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "DISCONNECTED"
    # No connection_info/connection_ip when disconnected.
    names = [c[0] for c in FakeController.last.calls]
    assert names == ["state"]


def test_connect_routes_with_exact_args(capsys):
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["connect", "office", "-u", "bob", "--timeout", "5", "--no-wait"])

    assert rc == 0
    connect_calls = [c for c in FakeController.last.calls if c[0] == "connect"]
    assert len(connect_calls) == 1
    _name, args, kwargs = connect_calls[0]
    assert args == ("office",)
    assert kwargs == {"username": "bob", "wait": False, "timeout": 5.0}


def test_connect_no_wait_prints_connecting(capsys):
    FakeController.config["connect"] = FakeState(ipsec_state=1, name="office")

    rc = cli.main(["connect", "office", "--no-wait"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "connecting" in out.lower()
    assert "office" in out
    # With --no-wait the CLI does not fetch the IP.
    names = [c[0] for c in FakeController.last.calls]
    assert "connection_ip" not in names


def test_connect_waited_prints_connected_with_ip(capsys):
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["connect", "office"])

    assert rc == 0
    # Default wait=True is threaded through.
    connect_calls = [c for c in FakeController.last.calls if c[0] == "connect"]
    assert connect_calls[0][2] == {"username": None, "wait": True, "timeout": 30.0}
    out = capsys.readouterr().out
    assert "CONNECTED" in out
    assert "office" in out
    assert "172.16.200.2" in out


def test_connect_never_echoes_password(capsys):
    """A password must never appear in CLI output (there is no flag for it)."""
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    cli.main(["connect", "office"])

    captured = capsys.readouterr()
    # connect() is called without any password kwarg from the CLI.
    connect_calls = [c for c in FakeController.last.calls if c[0] == "connect"]
    assert "password" not in connect_calls[0][2]
    assert "password" not in captured.out.lower()
    assert "password" not in captured.err.lower()


def test_disconnect_routes_and_prints(capsys):
    FakeController.config["disconnect"] = None

    rc = cli.main(["disconnect", "office"])

    assert rc == 0
    disconnect_calls = [c for c in FakeController.last.calls if c[0] == "disconnect"]
    # The CLI passes the profile as the first positional arg (ctype is left to
    # the controller's "ipsec" default).
    assert disconnect_calls[0][1][0] == "office"
    out = capsys.readouterr().out.strip()
    assert out == "DISCONNECTED office"


def test_ip_connected_prints_vpn_ip(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["ip"])

    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "172.16.200.2"


def test_ip_not_connected_exits_1_with_stderr(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    rc = cli.main(["ip"])

    assert rc == 1
    captured = capsys.readouterr()
    assert "not connected" in captured.err.lower()
    assert captured.out.strip() == ""


# -- exception → exit-code mapping -------------------------------------------


@pytest.mark.parametrize(
    "exc,expected_code",
    [
        (NotRunningError, 3),
        (KeychainError, 4),
        (UnsupportedError, 5),
        (ConnectTimeout, 7),
        (FortiError, 1),
    ],
)
def test_exception_maps_to_exit_code(capsys, exc, expected_code):
    """A controller raising a ``FortiError`` subtype exits with its mapped code.

    We route through ``status`` (whose first call is ``state()``) and make
    ``state()`` raise; the top-level handler in ``main()`` must translate the
    type to ``e.exit_code`` and print the message to stderr.
    """
    FakeController.config["state"] = exc

    rc = cli.main(["status"])

    assert rc == expected_code
    captured = capsys.readouterr()
    assert captured.err.strip() != ""  # the message went to stderr
    assert captured.out.strip() == ""


def test_connect_failure_maps_exit_code(capsys):
    """Mapping also holds on the connect path (UnsupportedError -> 5)."""
    FakeController.config["connect"] = UnsupportedError

    rc = cli.main(["connect", "WebPortal"])

    assert rc == 5
    assert capsys.readouterr().err.strip() != ""


# -- port / host threading ---------------------------------------------------


def test_default_port_is_9222():
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    cli.main(["status"])

    assert FakeSession.instances[0].port == 9222
    assert FakeSession.instances[0].host == "127.0.0.1"


def test_port_flag_feeds_session():
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    cli.main(["--port", "9333", "status"])

    assert FakeSession.instances[0].port == 9333


def test_host_flag_feeds_session():
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    cli.main(["--host", "localhost", "status"])

    assert FakeSession.instances[0].host == "localhost"


def test_env_port_feeds_session(monkeypatch):
    monkeypatch.setenv("FORTI_CDP_PORT", "9444")
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    cli.main(["status"])

    assert FakeSession.instances[0].port == 9444


def test_port_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("FORTI_CDP_PORT", "9444")
    FakeController.config["state"] = FakeState(ipsec_state=0, name="")

    cli.main(["--port", "9555", "status"])

    assert FakeSession.instances[0].port == 9555


# -- --json output -----------------------------------------------------------


def test_list_json_shape(capsys):
    FakeController.config["profiles"] = [
        _FakeProfile("office", "ipsec"),
        _FakeProfile("WebPortal", "ssl"),
    ]
    FakeController.config["profile_info"] = {"remote_gateway": "vpn.example.com"}

    rc = cli.main(["list", "--json"])

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert data[0] == {"name": "office", "type": "ipsec", "server": "vpn.example.com"}
    # ssl profile: blank server, no profile_info lookup.
    assert data[1]["name"] == "WebPortal"
    assert data[1]["type"] == "ssl"
    assert data[1]["server"] == ""


def test_status_json_shape(capsys):
    FakeController.config["state"] = FakeState(
        ipsec_state=2,
        name="office",
        state_label="CONNECTED",
        raw={"ipsec_state": 2, "connection_name": "office"},
    )
    FakeController.config["connection_info"] = {
        "duration": "00:01:45",
        "traffic_in": 1616,
        "traffic_out": 0,
    }
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["status", "--json"])

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, dict)
    # The merged dict carries the raw state plus the info/ip fields.
    assert data["ipsec_state"] == 2
    assert data["vpn_ip"] == "172.16.200.2"
    assert data["duration"] == "00:01:45"


def test_status_json_disconnected_shape(capsys):
    FakeController.config["state"] = FakeState(
        ipsec_state=0, name="", state_label="DISCONNECTED", raw={"ipsec_state": 0}
    )

    rc = cli.main(["status", "--json"])

    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, dict)
    assert data["ipsec_state"] == 0
    assert "vpn_ip" not in data


# -- argparse usage errors ---------------------------------------------------


def test_unknown_subcommand_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["frobnicate"])
    assert excinfo.value.code == 2


def test_missing_required_arg_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["connect"])  # missing <profile>
    assert excinfo.value.code == 2


def test_no_subcommand_exits_2():
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2
