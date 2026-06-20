"""Tests for the ``fvpnctl`` CLI (``fvpnctl.cli.main``).

These tests are CI-safe: there is NO real FortiClient, no real CDP socket, and
no real Keychain. The CLI references ``CDPSession`` and ``FortiVPN`` as
module-level names (``fvpnctl.cli.CDPSession`` / ``fvpnctl.cli.FortiVPN``), so
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

from fvpnctl import cli
from fvpnctl.errors import (
    CDPEvaluateError,
    ConnectTimeout,
    FortiClientNotFoundError,
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

    def hide_window(self):
        return self._dispatch("hide_window")


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


def test_monitor_routes_to_monitor_run(monkeypatch):
    """``monitor`` delegates to ``monitor.run(fvpnctl, interval=...)``.

    The real poll/render loop is tested in ``test_monitor.py``; here we only pin
    that the subcommand wires the controller and the default interval through,
    patching ``cli.monitor`` so nothing actually loops.
    """
    calls = {}

    def fake_run(fvpnctl, *, interval, stream=None):
        calls["fvpnctl"] = fvpnctl
        calls["interval"] = interval
        return 0

    monkeypatch.setattr(cli.monitor, "run", fake_run)

    rc = cli.main(["monitor"])

    assert rc == 0
    assert calls["interval"] == 2.0
    # It received the FortiVPN built around the (fake) session.
    assert calls["fvpnctl"] is FakeController.last


def test_monitor_interval_flag_is_threaded(monkeypatch):
    captured = {}

    def fake_run(fvpnctl, *, interval, stream=None):
        captured["interval"] = interval
        return 0

    monkeypatch.setattr(cli.monitor, "run", fake_run)

    rc = cli.main(["monitor", "-n", "0.5"])

    assert rc == 0
    assert captured["interval"] == 0.5


def test_monitor_error_maps_to_exit_code(monkeypatch, capsys):
    """A ``CDPEvaluateError`` escaping the loop maps to its exit code (6)."""

    def boom(fvpnctl, *, interval, stream=None):
        raise CDPEvaluateError("FortiClient quit mid-watch")

    monkeypatch.setattr(cli.monitor, "run", boom)

    rc = cli.main(["monitor"])

    assert rc == 6
    assert capsys.readouterr().err.strip() != ""


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


def test_connect_hides_window_by_default():
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["connect", "office"])

    assert rc == 0
    names = [c[0] for c in FakeController.last.calls]
    assert "hide_window" in names


def test_connect_show_window_keeps_window():
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}

    rc = cli.main(["connect", "office", "--show-window"])

    assert rc == 0
    names = [c[0] for c in FakeController.last.calls]
    assert "hide_window" not in names


def test_connect_no_wait_does_not_hide_window():
    FakeController.config["connect"] = FakeState(ipsec_state=1, name="office")

    rc = cli.main(["connect", "office", "--no-wait"])

    assert rc == 0
    names = [c[0] for c in FakeController.last.calls]
    assert "hide_window" not in names


def test_connect_hide_failure_does_not_fail_connect(capsys):
    # Hiding is cosmetic: a CDPEvaluateError from hide_window must not fail an
    # otherwise-successful connect.
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="office")
    FakeController.config["connection_ip"] = {"vpn_ip": "172.16.200.2"}
    FakeController.config["hide_window"] = CDPEvaluateError("boom")

    rc = cli.main(["connect", "office"])

    assert rc == 0
    assert "CONNECTED" in capsys.readouterr().out


def test_hide_window_command_routes():
    rc = cli.main(["hide-window"])

    assert rc == 0
    names = [c[0] for c in FakeController.last.calls]
    assert "hide_window" in names


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


# -- verbose / quiet ---------------------------------------------------------
#
# The contract: verbose progress goes to STDERR only; stdout stays the
# machine-readable result. --verbose is the default (ON); --quiet wins.


def test_verbose_is_default_and_writes_progress_to_stderr(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=0, name="", state_label="DISCONNECTED")

    rc = cli.main(["status"])

    assert rc == 0
    captured = capsys.readouterr()
    # The machine-readable result is on stdout, unchanged by verbosity.
    assert captured.out.strip() == "DISCONNECTED"
    # Progress appears on stderr (the "attaching" line names host/port).
    assert "9222" in captured.err
    assert captured.err.strip() != ""


def test_quiet_silences_stderr_progress_but_keeps_stdout(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=0, name="", state_label="DISCONNECTED")

    rc = cli.main(["--quiet", "status"])

    assert rc == 0
    captured = capsys.readouterr()
    # stdout result identical to the verbose case...
    assert captured.out.strip() == "DISCONNECTED"
    # ...but no progress chatter on stderr.
    assert captured.err.strip() == ""


def test_quiet_wins_when_both_flags_given(capsys):
    FakeController.config["state"] = FakeState(ipsec_state=0, name="", state_label="DISCONNECTED")

    rc = cli.main(["--verbose", "--quiet", "status"])

    assert rc == 0
    assert capsys.readouterr().err.strip() == ""


def test_quiet_does_not_pollute_json_stdout(capsys):
    FakeController.config["state"] = FakeState(
        ipsec_state=0, name="", state_label="DISCONNECTED", raw={"ipsec_state": 0}
    )

    rc = cli.main(["--verbose", "status", "--json"])

    assert rc == 0
    # stdout must be parseable JSON even with verbose progress on stderr.
    data = json.loads(capsys.readouterr().out)
    assert data["ipsec_state"] == 0


# -- startserver -------------------------------------------------------------


class _FakeLauncher:
    """Stand-in for ``fvpnctl.cli.launcher`` capturing start_server's call."""

    def __init__(self):
        self.calls = []
        self.start_error = None

    def start_server(self, host, port, *, wait, on_info=None):
        self.calls.append({"host": host, "port": port, "wait": wait, "on_info": on_info})
        if self.start_error is not None:
            raise self.start_error
        # Exercise the on_info channel so we confirm it is wired to the reporter.
        if on_info is not None:
            on_info("fake launcher progress")

    # The NotRunningError-guidance tests patch these too.
    def find_forticlient(self):
        return None

    def download_hint(self):
        return "install it from somewhere"


def test_startserver_routes_to_launcher_with_host_port(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)

    rc = cli.main(["--port", "9400", "--host", "localhost", "startserver"])

    assert rc == 0
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["host"] == "localhost"
    assert call["port"] == 9400
    assert call["wait"] == 10.0
    # Success line on stdout names the endpoint.
    out = capsys.readouterr().out
    assert "localhost:9400" in out


def test_startserver_no_wait_passes_zero_wait(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)

    rc = cli.main(["startserver", "--no-wait"])

    assert rc == 0
    assert fake.calls[0]["wait"] == 0


def test_startserver_does_not_open_cdp_session(monkeypatch):
    # startserver is the bootstrap command: it must NOT attach to CDP (there may
    # be nothing to attach to yet).
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)

    cli.main(["startserver"])

    assert FakeSession.instances == []


def test_startserver_quiet_keeps_only_result_on_stdout(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)

    rc = cli.main(["--quiet", "startserver"])

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.err.strip() == ""
    assert "127.0.0.1:9222" in captured.out


def test_startserver_not_found_exits_8(monkeypatch, capsys):
    fake = _FakeLauncher()
    fake.start_error = FortiClientNotFoundError("not installed: get it from URL")
    monkeypatch.setattr(cli, "launcher", fake)

    rc = cli.main(["startserver"])

    assert rc == 8
    captured = capsys.readouterr()
    assert captured.err.strip() != ""
    assert captured.out.strip() == ""


# -- NotRunningError guidance ------------------------------------------------


def test_not_running_guidance_suggests_startserver_no_spike(monkeypatch, capsys):
    # find_forticlient returns a path -> show the exact launch command.
    fake = _FakeLauncher()
    monkeypatch.setattr(fake, "find_forticlient", lambda: "/Applications/FortiClient.app/x")
    monkeypatch.setattr(cli, "launcher", fake)
    FakeController.config["state"] = NotRunningError

    rc = cli.main(["status"])

    assert rc == 3
    err = capsys.readouterr().err
    # The factual message + actionable guidance, all on stderr.
    assert "fvpnctl startserver" in err
    # Because the executable was found, the exact launch command is shown.
    assert "--remote-debugging-port=9222" in err
    assert "/Applications/FortiClient.app/x" in err
    # No legacy doc reference.
    assert "SPIKE" not in err


def test_not_running_guidance_shows_download_hint_when_not_installed(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(fake, "find_forticlient", lambda: None)
    monkeypatch.setattr(fake, "download_hint", lambda: "DOWNLOAD-HINT-SENTINEL")
    monkeypatch.setattr(cli, "launcher", fake)
    FakeController.config["state"] = NotRunningError

    rc = cli.main(["status"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "fvpnctl startserver" in err
    assert "DOWNLOAD-HINT-SENTINEL" in err
    assert "SPIKE" not in err


def test_global_flags_after_subcommand():
    # Users naturally write `fvpnctl status --quiet`; the global flags must parse in
    # that position, not only before the subcommand. Regression for the
    # "unrecognized arguments: --quiet" bug.
    parser = cli._build_parser()
    assert parser.parse_args(["status", "--quiet"]).verbose is False
    assert parser.parse_args(["status", "--port", "1234"]).port == 1234


def test_global_flags_before_subcommand():
    parser = cli._build_parser()
    assert parser.parse_args(["--quiet", "status"]).verbose is False
    assert parser.parse_args(["--port", "1234", "status"]).port == 1234


def test_top_level_port_not_clobbered_by_subparser_default():
    # The argparse `parents` gotcha: a subparser re-declaring --port must not reset
    # a value supplied before the subcommand. SUPPRESS defaults guard against it.
    parser = cli._build_parser()
    assert parser.parse_args(["--port", "1234", "status"]).port == 1234


def test_unset_global_flags_absent_so_main_supplies_defaults():
    # SUPPRESS keeps unset global flags out of the namespace, so main()'s getattr
    # fallbacks (port from $FORTI_CDP_PORT/9222, verbose=True) take effect.
    parser = cli._build_parser()
    ns = parser.parse_args(["status"])
    assert not hasattr(ns, "port")
    assert not hasattr(ns, "verbose")
