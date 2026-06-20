"""Detect the installed FortiClient and launch it as a headless CDP server.

What this is
------------
The rest of this package is strictly *attach-only*: it connects to a FortiClient
that is already running with ``--remote-debugging-port`` and never starts one.
This module is the single, opt-in exception. ``fvpnctl startserver`` calls
:func:`start_server`, which locates the installed FortiClient executable and
launches it headless with the Chrome DevTools Protocol enabled, so the
attach-only commands have something to attach to.

Why it lives apart from the transport
-------------------------------------
Keeping launching out of ``cdp.py``/``controller.py`` preserves the attach-only
guarantee everywhere else (a script can import and drive the controller knowing
it will never spawn a process). Launching is a separate, explicit verb.

The single-instance caveat (why a launch can "succeed" yet the port stay closed)
-------------------------------------------------------------------------------
FortiClient is effectively single-instance on macOS: if a tray/GUI instance is
already running *without* ``--remote-debugging-port``, a second invocation with
the flag does not open a new debugging port — it just foregrounds the existing
instance. So :func:`start_server` can launch the binary and still time out
waiting for the port. The :class:`~fvpnctl.errors.FortiError` it raises in that
case says so explicitly, because "quit the running tray instance, then retry" is
the actual fix. See docs/how-it-works.md section 1.

Why the launch is detached (``start_new_session=True`` + discarded output)
--------------------------------------------------------------------------
We want FortiClient to keep running as a CDP server *after* ``fvpnctl
startserver`` exits — it is a long-lived background daemon, not a child whose
lifetime is tied to ours. ``start_new_session=True`` puts it in its own process
group/session so it is not killed when our process group gets a SIGINT (Ctrl-C
in the launching shell) and is not reaped as our child. Its stdout/stderr are
sent to ``DEVNULL`` because FortiClient is chatty and none of it is ours to
relay; the CLI's own progress goes through ``on_info`` to stderr instead.

Testability
-----------
``find_forticlient`` resolves through ``pathlib`` + ``plistlib`` (both patched in
tests). The reachability probe, ``subprocess.Popen``, and the clock
(``time.monotonic``/``time.sleep``) are all referenced as module attributes so
the test suite can monkeypatch them and run with no real FortiClient, network,
subprocess, or wall-clock delay.
"""

import pathlib
import plistlib
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable

from fvpnctl import errors

# Where FortiClient installs its app bundle on macOS, in the order we try them.
# The product ships under a few names across versions/editions; the first bundle
# that actually exists on disk wins.
_APP_BUNDLES = (
    "/Applications/FortiClient.app",
    "/Applications/FortiClientVPN.app",
    "/Applications/FortiClient VPN.app",
)

# Fortinet's product-download page (the free VPN-only client lives under the
# #vpn anchor). Surfaced in :func:`download_hint` / FortiClientNotFoundError.
DOWNLOAD_URL = "https://www.fortinet.com/support/product-downloads#vpn"


def find_forticlient() -> pathlib.Path | None:
    """Return the path to the installed FortiClient executable, or ``None``.

    Searches the known ``/Applications/FortiClient*.app`` bundles in
    :data:`_APP_BUNDLES` order. For each bundle that exists, the executable is
    ``<App>.app/Contents/MacOS/<CFBundleExecutable>`` — where
    ``CFBundleExecutable`` is read from the bundle's ``Contents/Info.plist`` via
    :mod:`plistlib`. If the plist is missing/unreadable or omits that key, the
    executable name falls back to the app bundle's stem (e.g. ``FortiClient``),
    which is the macOS convention and the common case. The resolved executable
    is returned only if it actually exists; otherwise the search continues. If no
    bundle yields an existing executable, returns ``None`` (the caller turns that
    into a :class:`~fvpnctl.errors.FortiClientNotFoundError` with a download
    hint).
    """
    for bundle in _APP_BUNDLES:
        app = pathlib.Path(bundle)
        if not app.exists():
            continue
        exe_name = _bundle_executable_name(app)
        exe = app / "Contents" / "MacOS" / exe_name
        if exe.exists():
            return exe
        # Bundle present but the resolved executable is missing — keep looking.
    return None


def _bundle_executable_name(app: pathlib.Path) -> str:
    """Read ``CFBundleExecutable`` from ``<app>/Contents/Info.plist``.

    Falls back to ``app.stem`` (the bundle name without ``.app``, e.g.
    ``FortiClient``) when the plist cannot be read or does not carry the key —
    that is the macOS default and the overwhelmingly common case, so a missing
    Info.plist is not treated as an error.
    """
    plist = app / "Contents" / "Info.plist"
    try:
        with plist.open("rb") as fh:
            data = plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException):
        # Plist absent or malformed: fall back to the conventional default. This
        # is expected, not an error, so we deliberately suppress and move on.
        return app.stem
    return data.get("CFBundleExecutable") or app.stem


def download_hint() -> str:
    """Return a short multi-line "FortiClient isn't installed; get it here" note.

    Used both in :class:`~fvpnctl.errors.FortiClientNotFoundError` messages and
    by the CLI when it cannot find the executable, so the user is always pointed
    at the free VPN client rather than left guessing.
    """
    return (
        "FortiClient does not appear to be installed in /Applications.\n"
        "Install the free FortiClient VPN client, then retry:\n"
        f"    {DOWNLOAD_URL}"
    )


def cdp_reachable(host: str, port: int) -> bool:
    """Return ``True`` iff a CDP server answers at ``http://host:port/json/version``.

    A quick liveness probe (~1s timeout) used both to make :func:`start_server`
    idempotent (don't relaunch when something already answers) and to poll for
    the port coming up after a launch. ``/json/version`` is the cheapest CDP
    endpoint — it returns a tiny JSON blob and never opens a WebSocket.

    Returns ``False`` on any ``OSError`` (``ConnectionRefusedError``, timeouts,
    DNS errors) or :class:`urllib.error.URLError` — i.e. "nothing is listening".
    These specific types are caught (not a broad ``except``) and mapped to a
    boolean *by design*: this function answers a yes/no question, so an
    unreachable port is an expected ``False``, not an error to propagate.
    """
    url = f"http://{host}:{port}/json/version"
    try:
        with urllib.request.urlopen(url, timeout=1.0) as resp:
            resp.read()
        return True
    except (OSError, urllib.error.URLError):
        # Expected "not listening / not yet up" outcomes — report as False rather
        # than raising. URLError is listed explicitly because not every URLError
        # is an OSError on every Python build.
        return False


def start_server(
    host: str,
    port: int,
    *,
    wait: float = 10.0,
    poll: float = 0.5,
    on_info: Callable[[str], None] | None = None,
) -> None:
    """Ensure a FortiClient's debug port is open on ``host:port``; launch if not.

    Steps:

    1. If :func:`cdp_reachable` already answers, do nothing (idempotent) — report
       via ``on_info`` and return. Calling ``startserver`` twice is harmless.
    2. Otherwise locate the executable with :func:`find_forticlient`; if there is
       none, raise :class:`~fvpnctl.errors.FortiClientNotFoundError` carrying
       :func:`download_hint` (exit code 8 — "install it").
    3. Launch it detached and headless:
       ``<exe> --hide-gui --remote-debugging-port=<port>`` with
       ``start_new_session=True`` and stdout/stderr to ``DEVNULL`` (see the
       module docstring for why detached).
    4. Poll :func:`cdp_reachable` every ``poll`` seconds for up to ``wait``
       seconds. If the port comes up, report success via ``on_info`` and return.
       If ``wait`` elapses first, raise :class:`~fvpnctl.errors.FortiError`
       explaining that the binary was launched but the port never opened — most
       often because FortiClient is single-instance and a tray/GUI instance is
       already running without the debugging flag and must be quit first.

    ``wait=0`` (the ``--no-wait`` path) launches and returns immediately without
    polling, so there is no deadline to miss and no timeout error.

    :param on_info: optional ``Callable[[str], None]`` for verbose progress
        (the CLI wires this to its stderr reporter); ``None`` is silent.
    :raises FortiClientNotFoundError: no FortiClient executable is installed.
    :raises FortiError: launched, but the CDP port did not open within ``wait``.
    """

    def _info(msg: str) -> None:
        if on_info is not None:
            on_info(msg)

    # 1. Idempotent fast path: something already answers, nothing to do.
    if cdp_reachable(host, port):
        _info(f"FortiClient debug port already reachable at {host}:{port}; nothing to launch.")
        return

    # 2. Need to launch — but only if FortiClient is actually installed.
    exe = find_forticlient()
    if exe is None:
        raise errors.FortiClientNotFoundError(
            "FortiClient executable not found.\n" + download_hint()
        )

    # 3. Launch detached + headless with CDP enabled. See module docstring for
    #    why start_new_session / DEVNULL (long-lived background daemon).
    argv = [str(exe), "--hide-gui", f"--remote-debugging-port={port}"]
    _info("Launching FortiClient headless: " + " ".join(argv))
    subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    # With --no-wait there is nothing to poll for; the caller accepts that the
    # port may not be up yet.
    if wait <= 0:
        _info(f"FortiClient launched; not waiting for {host}:{port} (--no-wait).")
        return

    # 4. Poll for the debugging port to come up, using monotonic time so a
    #    wall-clock jump cannot extend or cut short the wait. Both time.* names
    #    are module attributes so tests can monkeypatch them for instant runs.
    _info(f"Waiting up to {wait:g}s for FortiClient CDP on {host}:{port}…")
    deadline = time.monotonic() + wait
    while True:
        if cdp_reachable(host, port):
            _info(f"FortiClient debug port is up on {host}:{port}.")
            return
        if time.monotonic() >= deadline:
            raise errors.FortiError(
                f"Launched FortiClient but its CDP port {host}:{port} did not open "
                f"within {wait:g}s. FortiClient is single-instance: if a tray/GUI "
                "instance is already running without --remote-debugging-port, quit "
                "it first (right-click the tray icon → Quit), then retry."
            )
        time.sleep(poll)
