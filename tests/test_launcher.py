"""Tests for FortiClient detection + the CDP-server launcher (``fortivpn.launcher``).

These are CI-safe: there is NO real FortiClient on disk, no real network, no
real subprocess, and no real clock. Every external touchpoint is mocked:

* the filesystem (``pathlib.Path.exists`` / ``plistlib.load``) for
  :func:`find_forticlient`;
* ``urllib.request.urlopen`` for :func:`cdp_reachable`;
* ``subprocess.Popen`` and ``time.sleep`` / ``time.monotonic`` for
  :func:`start_server`.

What they pin down: bundle search order + ``CFBundleExecutable`` resolution; the
reachability probe's success/refused behaviour; and the four
:func:`start_server` paths — already-reachable (no launch), happy launch,
not-installed (``FortiClientNotFoundError``), and launched-but-port-never-opened
(``FortiError``). The launch argv (``--hide-gui`` +
``--remote-debugging-port=<port>``) is asserted explicitly because it is the
load-bearing contract with FortiClient.
"""

import urllib.error

import pytest

from fortivpn import launcher
from fortivpn.errors import FortiClientNotFoundError, FortiError

# ---------------------------------------------------------------------------
# find_forticlient — monkeypatch path existence + plistlib.
# ---------------------------------------------------------------------------


def test_find_forticlient_returns_none_when_nothing_installed(monkeypatch):
    # Nothing on disk: no .app bundle and no executable exists.
    monkeypatch.setattr(launcher.pathlib.Path, "exists", lambda self: False)
    assert launcher.find_forticlient() is None


def test_find_forticlient_reads_cfbundleexecutable(monkeypatch):
    # First bundle exists; its Info.plist names a non-default executable.
    app = launcher.pathlib.Path("/Applications/FortiClient.app")
    exe = app / "Contents" / "MacOS" / "FortiClientLauncher"

    monkeypatch.setattr(
        launcher.pathlib.Path,
        "exists",
        lambda self: self in (app, exe),
    )
    monkeypatch.setattr(
        launcher.plistlib,
        "load",
        lambda fh: {"CFBundleExecutable": "FortiClientLauncher"},
    )
    # Stub open() on the plist so plistlib.load gets *something* file-like.
    monkeypatch.setattr(launcher.pathlib.Path, "open", lambda self, mode="rb": _DummyFile())

    found = launcher.find_forticlient()
    assert found == exe


def test_find_forticlient_falls_back_to_app_stem(monkeypatch):
    # Info.plist is missing/unreadable -> executable name defaults to the app stem.
    app = launcher.pathlib.Path("/Applications/FortiClient.app")
    exe = app / "Contents" / "MacOS" / "FortiClient"

    monkeypatch.setattr(launcher.pathlib.Path, "exists", lambda self: self in (app, exe))

    def boom_open(self, mode="rb"):
        raise FileNotFoundError(self)

    monkeypatch.setattr(launcher.pathlib.Path, "open", boom_open)

    found = launcher.find_forticlient()
    assert found == exe


def test_find_forticlient_search_order_skips_missing(monkeypatch):
    # First two bundles do not exist; the third ("FortiClient VPN.app") does.
    app = launcher.pathlib.Path("/Applications/FortiClient VPN.app")
    exe = app / "Contents" / "MacOS" / "FortiClient VPN"
    monkeypatch.setattr(launcher.pathlib.Path, "exists", lambda self: self in (app, exe))

    def boom_open(self, mode="rb"):
        raise FileNotFoundError(self)

    monkeypatch.setattr(launcher.pathlib.Path, "open", boom_open)

    found = launcher.find_forticlient()
    assert found == exe


def test_find_forticlient_skips_bundle_without_executable(monkeypatch):
    # The bundle dir exists but the resolved executable file does NOT -> keep
    # looking; with nothing else present this yields None.
    app = launcher.pathlib.Path("/Applications/FortiClient.app")
    monkeypatch.setattr(launcher.pathlib.Path, "exists", lambda self: self == app)

    def boom_open(self, mode="rb"):
        raise FileNotFoundError(self)

    monkeypatch.setattr(launcher.pathlib.Path, "open", boom_open)

    assert launcher.find_forticlient() is None


class _DummyFile:
    """Minimal file-like context manager for stubbing ``Path.open`` in plist reads."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# download_hint / DOWNLOAD_URL.
# ---------------------------------------------------------------------------


def test_download_hint_mentions_url_and_not_installed():
    hint = launcher.download_hint()
    assert launcher.DOWNLOAD_URL in hint
    assert "FortiClient" in hint
    # It should read as multi-line guidance.
    assert "\n" in hint


def test_download_url_points_at_fortinet():
    assert launcher.DOWNLOAD_URL == "https://www.fortinet.com/support/product-downloads#vpn"


# ---------------------------------------------------------------------------
# cdp_reachable — monkeypatch urllib.
# ---------------------------------------------------------------------------


class _FakeHTTPResponse:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b'{"Browser": "Chrome"}'


def test_cdp_reachable_true_on_success(monkeypatch):
    seen = {}

    def fake_urlopen(url, timeout=None):
        seen["url"] = url
        seen["timeout"] = timeout
        return _FakeHTTPResponse()

    monkeypatch.setattr(launcher.urllib.request, "urlopen", fake_urlopen)
    assert launcher.cdp_reachable("127.0.0.1", 9222) is True
    assert seen["url"] == "http://127.0.0.1:9222/json/version"
    # Probe must use a short timeout so a dead port fails fast.
    assert seen["timeout"] is not None and seen["timeout"] <= 2


def test_cdp_reachable_false_on_connection_refused(monkeypatch):
    def boom(url, timeout=None):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(launcher.urllib.request, "urlopen", boom)
    assert launcher.cdp_reachable("127.0.0.1", 9222) is False


def test_cdp_reachable_false_on_urlerror(monkeypatch):
    def boom(url, timeout=None):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(launcher.urllib.request, "urlopen", boom)
    assert launcher.cdp_reachable("127.0.0.1", 9222) is False


# ---------------------------------------------------------------------------
# start_server — mock cdp_reachable, subprocess.Popen, and the clock.
# ---------------------------------------------------------------------------


class _FakePopen:
    """Records the argv + kwargs Popen was constructed with."""

    instances = []

    def __init__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        _FakePopen.instances.append(self)


@pytest.fixture(autouse=True)
def _reset_popen():
    _FakePopen.instances = []
    yield
    _FakePopen.instances = []


def _patch_clock(monkeypatch):
    """Make time.sleep a no-op and time.monotonic advance by 1s per call."""
    ticks = {"t": 0.0}

    def fake_monotonic():
        ticks["t"] += 1.0
        return ticks["t"]

    monkeypatch.setattr(launcher.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(launcher.time, "sleep", lambda s: None)


def test_start_server_noop_when_already_reachable(monkeypatch):
    monkeypatch.setattr(launcher, "cdp_reachable", lambda host, port: True)
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakePopen)
    infos = []

    launcher.start_server("127.0.0.1", 9222, on_info=infos.append)

    # Already reachable -> no launch at all, and an informative message.
    assert _FakePopen.instances == []
    assert any("reachable" in m.lower() for m in infos)


def test_start_server_launches_with_correct_argv(monkeypatch):
    # Not reachable on the first probe, reachable on the next -> launch + succeed.
    calls = {"n": 0}

    def reachable(host, port):
        calls["n"] += 1
        return calls["n"] > 1  # False first, True after launch

    monkeypatch.setattr(launcher, "cdp_reachable", reachable)
    monkeypatch.setattr(
        launcher, "find_forticlient", lambda: launcher.pathlib.Path("/Applications/FC.app/x")
    )
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakePopen)
    _patch_clock(monkeypatch)

    launcher.start_server("127.0.0.1", 9333, on_info=lambda m: None)

    assert len(_FakePopen.instances) == 1
    argv = _FakePopen.instances[0].argv
    assert "--hide-gui" in argv
    assert "--remote-debugging-port=9333" in argv
    assert argv[0] == "/Applications/FC.app/x"
    # Detached launch: new session + output discarded.
    kwargs = _FakePopen.instances[0].kwargs
    assert kwargs.get("start_new_session") is True
    assert "stdout" in kwargs
    assert "stderr" in kwargs


def test_start_server_raises_not_found_when_no_executable(monkeypatch):
    monkeypatch.setattr(launcher, "cdp_reachable", lambda host, port: False)
    monkeypatch.setattr(launcher, "find_forticlient", lambda: None)
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakePopen)

    with pytest.raises(FortiClientNotFoundError) as excinfo:
        launcher.start_server("127.0.0.1", 9222)

    # Nothing was launched, and the message guides the user to install it.
    assert _FakePopen.instances == []
    assert launcher.DOWNLOAD_URL in str(excinfo.value)


def test_start_server_raises_forti_error_when_port_never_opens(monkeypatch):
    # Reachable never returns True even after launching -> timeout -> FortiError.
    monkeypatch.setattr(launcher, "cdp_reachable", lambda host, port: False)
    monkeypatch.setattr(
        launcher, "find_forticlient", lambda: launcher.pathlib.Path("/Applications/FC.app/x")
    )
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakePopen)
    _patch_clock(monkeypatch)

    with pytest.raises(FortiError) as excinfo:
        launcher.start_server("127.0.0.1", 9222, wait=3.0, poll=0.5)

    # It WAS launched...
    assert len(_FakePopen.instances) == 1
    # ...but the message must explain the timeout and the single-instance caveat,
    # and must NOT be the not-found subtype.
    assert not isinstance(excinfo.value, FortiClientNotFoundError)
    msg = str(excinfo.value).lower()
    assert "single" in msg or "instance" in msg or "tray" in msg


def test_start_server_zero_wait_does_not_poll(monkeypatch):
    # wait=0 (the --no-wait path): launch and return without polling/raising even
    # though the port is not (yet) reachable.
    monkeypatch.setattr(launcher, "cdp_reachable", lambda host, port: False)
    monkeypatch.setattr(
        launcher, "find_forticlient", lambda: launcher.pathlib.Path("/Applications/FC.app/x")
    )
    monkeypatch.setattr(launcher.subprocess, "Popen", _FakePopen)
    _patch_clock(monkeypatch)

    # Should not raise: with wait=0 there is no deadline to miss.
    launcher.start_server("127.0.0.1", 9222, wait=0.0, on_info=lambda m: None)
    assert len(_FakePopen.instances) == 1
