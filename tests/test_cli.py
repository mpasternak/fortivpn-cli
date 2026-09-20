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

    The CLI constructs ``CDPSession(port, host)``, calls ``connect()`` on it, and
    then uses it as a context manager. This fake records ``port``/``host`` on a
    module-level list so tests can assert the global ``--port`` / ``--host`` /
    env handling, and otherwise does nothing — there is no real socket.

    Two class-level knobs let a test make the *attach* fail (as an unreachable
    FortiClient does), which is what the ``--start-fvpn`` autostart path keys off:

    * ``connect_errors`` — a queue of exceptions raised by successive
      ``connect()`` calls, one each, until it runs dry and connects succeed. Use
      it to model "fails, then works after the relaunch".
    * ``connect_error`` — a single exception raised by *every* ``connect()``.
      Use it to model "never comes up".

    ``evaluate_results`` plays the same role one layer up, for the post-launch
    readiness probe (``typeof window.guimessenger``): a queue of values returned
    by successive ``evaluate()`` calls — an entry that is an exception is raised
    instead — falling back to ``"object"`` (ready) once drained. Use it to model
    a renderer that is still loading right after FortiClient starts.
    """

    instances = []
    connect_errors = []
    connect_error = None
    evaluate_results = []

    def __init__(self, port=9222, host="127.0.0.1"):
        self.port = port
        self.host = host
        self.closed = False
        FakeSession.instances.append(self)

    def connect(self):
        if FakeSession.connect_errors:
            raise FakeSession.connect_errors.pop(0)
        if FakeSession.connect_error is not None:
            raise FakeSession.connect_error
        return None

    def evaluate(self, expression, await_promise=True):
        result = FakeSession.evaluate_results.pop(0) if FakeSession.evaluate_results else "object"
        if isinstance(result, BaseException):
            raise result
        return result

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
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
def patched(monkeypatch, tmp_path):
    """Swap the two seams and reset per-test state.

    Every test gets fresh ``FakeSession.instances`` and ``FakeController.config``
    so assertions about construction args / routed calls never bleed between
    tests. The ``FORTI_CDP_PORT`` env var is cleared so the default-port tests
    are not perturbed by the developer's environment. ``FVPNCTL_STATE_DIR`` is
    pointed at a throwaway ``tmp_path`` so the connect-time history the CLI now
    reads/writes never touches the developer's real state dir.
    """
    FakeSession.instances = []
    FakeSession.connect_errors = []
    FakeSession.connect_error = None
    FakeSession.evaluate_results = []
    FakeController.config = {}
    FakeController.last = None
    monkeypatch.setattr(cli, "CDPSession", FakeSession)
    monkeypatch.setattr(cli, "FortiVPN", FakeController)
    monkeypatch.delenv("FORTI_CDP_PORT", raising=False)
    monkeypatch.setenv("FVPNCTL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
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


def test_disconnect_no_arg_uses_active_profile(capsys):
    # No profile given → read state(), disconnect whatever the daemon reports.
    FakeController.config["state"] = FakeState(ipsec_state=2, name="apoz")
    FakeController.config["disconnect"] = None

    rc = cli.main(["disconnect"])

    assert rc == 0
    disconnect_calls = [c for c in FakeController.last.calls if c[0] == "disconnect"]
    assert disconnect_calls[0][1][0] == "apoz"
    assert capsys.readouterr().out.strip() == "DISCONNECTED apoz"


def test_disconnect_no_arg_when_nothing_connected(capsys):
    # Idempotent: nothing active → say so, never call DisconnectTunnel, exit 0.
    FakeController.config["state"] = FakeState(ipsec_state=0, name="", state_label="DISCONNECTED")

    rc = cli.main(["disconnect"])

    assert rc == 0
    assert [c for c in FakeController.last.calls if c[0] == "disconnect"] == []
    assert "no active" in capsys.readouterr().err.lower()


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


def test_connect_records_duration_for_next_time():
    # A successful waited connect persists its duration (isolated tmp state dir),
    # so the NEXT connect can show a progress bar.
    from fvpnctl import history

    FakeController.config["connect"] = FakeState(ipsec_state=2, name="apoz")
    FakeController.config["connection_ip"] = {"vpn_ip": "10.0.0.2"}

    assert history.average("apoz") is None  # nothing recorded yet
    rc = cli.main(["connect", "apoz"])

    assert rc == 0
    assert history.average("apoz") is not None  # one measurement now stored


def test_connect_with_history_succeeds_via_progress_bar_branch(capsys):
    # Pre-seeded history → eta is not None → the ProgressBar branch is taken.
    # Output is captured (non-TTY) so the bar renders as its static line; the
    # connect must still succeed and print the machine-readable result.
    from fvpnctl import history

    history.record("apoz", 8.0)
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="apoz")
    FakeController.config["connection_ip"] = {"vpn_ip": "10.0.0.2"}

    rc = cli.main(["connect", "apoz"])

    assert rc == 0
    assert "CONNECTED apoz 10.0.0.2" in capsys.readouterr().out


def test_connect_history_failure_does_not_break_connect(monkeypatch, capsys):
    # A corrupt/unreadable history store must never block a connect: the ETA read
    # degrades to the throbber and the connect still succeeds.
    from fvpnctl import history

    def boom(_profile):
        raise ValueError("corrupt history")

    monkeypatch.setattr(history, "average", boom)
    FakeController.config["connect"] = FakeState(ipsec_state=2, name="apoz")
    FakeController.config["connection_ip"] = {"vpn_ip": "10.0.0.2"}

    rc = cli.main(["connect", "apoz"])

    assert rc == 0
    assert "CONNECTED apoz" in capsys.readouterr().out


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


# -- --start-fvpn autostart --------------------------------------------------


def test_start_fvpn_launches_forticlient_and_retries(monkeypatch, capsys):
    # The attach fails once (FortiClient not running); --start-fvpn launches it
    # through the launcher and the command then runs normally.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    FakeSession.connect_errors = [NotRunningError("cannot reach CDP endpoint")]
    FakeController.config["state"] = FakeState(
        ipsec_state=0, name="", state_label="DISCONNECTED", raw={"ipsec_state": 0}
    )

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 0
    # The launcher was asked to start FortiClient on the same host/port.
    assert len(fake.calls) == 1
    assert fake.calls[0]["host"] == "127.0.0.1"
    assert fake.calls[0]["port"] == 9222
    # And the command produced its normal output after the relaunch.
    assert "DISCONNECTED" in capsys.readouterr().out


def test_start_fvpn_uses_the_requested_host_and_port(monkeypatch):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    FakeSession.connect_errors = [NotRunningError("nope")]
    FakeController.config["state"] = FakeState(ipsec_state=0, state_label="DISCONNECTED")

    rc = cli.main(["--port", "9400", "--host", "localhost", "--start-fvpn", "status"])

    assert rc == 0
    assert fake.calls[0] == {
        "host": "localhost",
        "port": 9400,
        "wait": cli._AUTOSTART_WAIT,
        "on_info": cli.report,
    }


def test_start_fvpn_does_not_launch_when_already_reachable(monkeypatch):
    # Idempotence at the CLI level: if the attach succeeds, --start-fvpn is inert
    # and the launcher is never touched.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    FakeController.config["state"] = FakeState(ipsec_state=0, state_label="DISCONNECTED")

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 0
    assert fake.calls == []


def test_start_fvpn_retries_the_attach_until_the_page_target_appears(monkeypatch):
    # start_server returns as soon as /json/version answers, but the debuggable
    # page target can lag a moment — the attach is retried, not failed.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    FakeSession.connect_errors = [
        NotRunningError("port closed"),  # initial attach -> triggers the launch
        NotRunningError("no page target yet"),  # first post-launch retry
        NotRunningError("no page target yet"),  # second post-launch retry
    ]
    FakeController.config["state"] = FakeState(ipsec_state=0, state_label="DISCONNECTED")

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 0
    assert len(fake.calls) == 1  # launched once, attached repeatedly
    assert len(FakeSession.instances) == 4


def test_start_fvpn_gives_up_and_exits_3_when_the_attach_never_succeeds(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    monkeypatch.setattr(cli, "_POST_LAUNCH_WINDOW", 0.0)
    FakeSession.connect_error = NotRunningError("still nothing there")
    FakeController.config["state"] = FakeState(ipsec_state=0, state_label="DISCONNECTED")

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "still nothing there" in err
    # It already tried the automatic launch, so don't tell the user to use the flag
    # again (the verbose progress line naming it is a different thing).
    assert "re-run the same command with --start-fvpn" not in err
    assert "fvpnctl startserver" in err


def test_start_fvpn_exits_8_when_forticlient_is_not_installed(monkeypatch, capsys):
    fake = _FakeLauncher()
    fake.start_error = FortiClientNotFoundError("not installed: get it from URL")
    monkeypatch.setattr(cli, "launcher", fake)
    FakeSession.connect_error = NotRunningError("cannot reach CDP endpoint")

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 8
    captured = capsys.readouterr()
    assert "not installed" in captured.err
    assert captured.out.strip() == ""


def test_not_running_guidance_suggests_the_start_fvpn_flag(monkeypatch, capsys):
    # Without the flag the behaviour is unchanged except that the guidance now
    # points at --start-fvpn as the one-shot fix.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    FakeSession.connect_error = NotRunningError("cannot reach CDP endpoint")

    rc = cli.main(["status"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "--start-fvpn" in err
    assert "fvpnctl startserver" in err
    # Nothing was launched: the flag is opt-in.
    assert fake.calls == []


def test_start_fvpn_parses_before_and_after_the_subcommand():
    parser = cli._build_parser()
    assert parser.parse_args(["--start-fvpn", "status"]).start_fvpn is True
    assert parser.parse_args(["status", "--start-fvpn"]).start_fvpn is True
    # Unset stays out of the namespace so main()'s getattr default (False) applies.
    assert not hasattr(parser.parse_args(["status"]), "start_fvpn")


def test_start_fvpn_waits_for_the_renderer_before_running_the_command(monkeypatch, capsys):
    # Real-world case: the debug port opens ~1s after launch and the page target
    # attaches, but the renderer is still swapping in FortiClient's real page, so
    # an evaluate blows up with "Execution context was destroyed". The session
    # must be dropped and re-attached, not handed to the command.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    monkeypatch.setattr(cli.time, "sleep", lambda _s: None)
    FakeSession.connect_errors = [NotRunningError("port closed")]
    FakeSession.evaluate_results = [
        CDPEvaluateError("Execution context was destroyed."),  # still loading
        "undefined",  # blank page: attached, but no guimessenger yet
        "object",  # ready -> this session is the one the command gets
    ]
    FakeController.config["state"] = FakeState(ipsec_state=0, state_label="DISCONNECTED")

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 0
    # Four sessions: the failed initial attach + three post-launch attempts.
    assert len(FakeSession.instances) == 4
    # The two unusable sessions were closed rather than leaked.
    assert [s.closed for s in FakeSession.instances[1:3]] == [True, True]
    assert "DISCONNECTED" in capsys.readouterr().out


def test_start_fvpn_exits_3_when_the_renderer_never_becomes_ready(monkeypatch, capsys):
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    monkeypatch.setattr(cli, "_POST_LAUNCH_WINDOW", 0.0)
    FakeSession.connect_errors = [NotRunningError("port closed")]
    FakeSession.evaluate_results = [CDPEvaluateError("Execution context was destroyed.")]

    rc = cli.main(["--start-fvpn", "status"])

    assert rc == 3
    err = capsys.readouterr().err
    assert "renderer was still not ready" in err
    assert "window.guimessenger" in err


def test_renderer_ready_reports_false_instead_of_raising():
    # The probe answers a yes/no question: an evaluate failure is "not ready yet",
    # not an error to propagate.
    FakeSession.evaluate_results = [CDPEvaluateError("Execution context was destroyed.")]
    assert cli._renderer_ready(FakeSession()) is False

    FakeSession.evaluate_results = ["undefined"]
    assert cli._renderer_ready(FakeSession()) is False

    FakeSession.evaluate_results = ["object"]
    assert cli._renderer_ready(FakeSession()) is True


def test_start_vpn_is_accepted_as_an_alias_for_start_fvpn():
    # "fvpn" vs "vpn" is an easy slip to make, and argparse's "unrecognized
    # arguments" error gives no hint, so --start-vpn maps to the same flag.
    parser = cli._build_parser()
    assert parser.parse_args(["--start-vpn", "status"]).start_fvpn is True
    assert parser.parse_args(["status", "--start-vpn"]).start_fvpn is True


def test_start_vpn_alias_launches_forticlient(monkeypatch, capsys):
    # The alias is not just parsed: it drives the same autostart path end to end.
    fake = _FakeLauncher()
    monkeypatch.setattr(cli, "launcher", fake)
    FakeSession.connect_errors = [NotRunningError("cannot reach CDP endpoint")]
    FakeController.config["state"] = FakeState(
        ipsec_state=0, name="", state_label="DISCONNECTED", raw={"ipsec_state": 0}
    )

    rc = cli.main(["--start-vpn", "status"])

    assert rc == 0
    assert len(fake.calls) == 1
    assert "DISCONNECTED" in capsys.readouterr().out
