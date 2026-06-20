"""The ``forti`` command-line interface — argparse over the ``FortiVPN`` controller.

What this is
------------
``main(argv)`` is the entry point behind the ``forti`` console script
(``forti = fortivpn.cli:main``). It parses arguments, opens an attach-only
:class:`~fortivpn.cdp.CDPSession` to an already-running FortiClient, wraps it in
a :class:`~fortivpn.controller.FortiVPN`, and dispatches one of the five
subcommands (``list``, ``status``, ``connect``, ``disconnect``, ``ip``) to the
matching controller method. The subcommands map 1:1 to controller calls; this
module owns only argument parsing, human/JSON formatting, and the error→exit-code
translation. See design spec sections 4.5 and 5.

Why attach-only
---------------
The tool never starts, stops, or restarts FortiClient. It connects to a
FortiClient the user already launched headless with ``--remote-debugging-port``
(see docs/how-it-works.md section 1). If the debugging port is unreachable,
``CDPSession`` raises :class:`~fortivpn.errors.NotRunningError`; the CLI surfaces
the factual message as a stderr line + exit code 3 and then prints actionable
guidance (suggesting ``forti startserver`` or the exact launch command). The one
exception to attach-only is the explicit ``startserver`` subcommand, which uses
``launcher`` to start FortiClient headless — see :func:`_cmd_startserver`.

The type → exit-code contract
-----------------------------
Every *expected* failure is a :class:`~fortivpn.errors.FortiError` subclass that
carries its own ``exit_code`` (defined in ``errors.py`` to match design spec
section 5). :func:`main` catches ``FortiError`` once, prints its message to
stderr, and returns ``e.exit_code``. So the failure *type* selects the exit code:

* ``0`` success · ``2`` usage (argparse) · ``3`` ``NotRunningError`` ·
  ``4`` ``KeychainError`` · ``5`` ``UnsupportedError`` ·
  ``6`` ``ConnectFailed`` / ``CDPEvaluateError`` · ``7`` ``ConnectTimeout`` ·
  ``1`` any other ``FortiError``.

A ``KeyboardInterrupt`` (Ctrl-C) returns ``130`` by Unix convention. Genuine
bugs (anything that is not a ``FortiError``) are left to propagate as ordinary
tracebacks rather than being swallowed (project error-handling policy / design
spec section 6).

Security
--------
No subcommand accepts or echoes a password. ``connect`` resolves the secret
inside the controller (from the Keychain) and never receives, prints, or logs
it here.

``CDPSession``, ``FortiVPN`` and ``launcher`` are referenced as module-level
names so the test suite can monkeypatch ``fortivpn.cli.CDPSession`` /
``fortivpn.cli.FortiVPN`` / ``fortivpn.cli.launcher`` with CI-safe fakes (no real
socket, no real FortiClient, no real subprocess).

Verbose / quiet
---------------
``--verbose`` (default ON) emits concise progress to **stderr** via
:func:`report`; ``--quiet`` turns it off (and wins if both are given). stdout is
reserved for the machine-readable result only, so ``--json`` and shell pipelines
are unaffected by verbosity.
"""

import argparse
import json
import os
import sys

from fortivpn import launcher
from fortivpn.cdp import CDPSession
from fortivpn.controller import FortiVPN
from fortivpn.errors import CDPEvaluateError, FortiError, NotRunningError

# IPsec ``ipsec_state`` value meaning "tunnel up" (docs/how-it-works.md section 2
# / design spec 4.2). The CLI only needs the CONNECTED sentinel; the controller
# owns the full enum.
_CONNECTED = 2

# Connection type for v1. Only IPsec is supported (SSL is out of scope); the CLI
# always queries/derives with this type. See design spec section 2.
_IPSEC = "ipsec"

# Verbosity flag toggled by ``main`` from ``--verbose``/``--quiet``. Module-level
# (rather than threaded through every call) so ``report`` can be passed straight
# to ``launcher.start_server(on_info=report)`` as a plain ``Callable[[str], None]``
# without binding extra state. Default ON: progress is the friendly default.
_VERBOSE = True


def report(msg: str) -> None:
    """Write one progress line to **stderr** when verbose; no-op when quiet.

    Why stderr (never stdout): stdout is the machine-readable channel — the JSON
    blob, the IP, the status line that scripts parse. Routing all human progress
    to stderr keeps ``forti ... --json`` and shell pipelines byte-for-byte
    identical whether the user runs verbose or quiet. Doubles as the
    ``on_info`` callback for :func:`launcher.start_server`, so launch progress
    flows through the same gate.
    """
    if _VERBOSE:
        print(msg, file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser: global ``--port``/``--host`` + five subcommands.

    The default port comes from ``FORTI_CDP_PORT`` when set, else ``9222`` — so an
    env var can pre-seed it while an explicit ``--port`` still wins (argparse
    applies the flag value over the default). Each subcommand stores its handler
    on ``func`` via ``set_defaults`` so :func:`main` can dispatch generically.
    """
    # Global options accepted both BEFORE and AFTER the subcommand (users naturally
    # write `forti status --quiet`). They live on a shared parent parser applied to
    # the top-level parser AND every subparser. Defaults are argparse.SUPPRESS so a
    # subparser re-declaring them does not clobber a value given at the top level
    # (the classic argparse `parents` gotcha); main() applies the real defaults via
    # getattr. The port default still honours $FORTI_CDP_PORT (resolved in main()).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--port",
        type=int,
        default=argparse.SUPPRESS,
        help="FortiClient CDP debugging port (default 9222, or $FORTI_CDP_PORT).",
    )
    common.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="Host the CDP debugging endpoint binds to (default 127.0.0.1).",
    )
    # --verbose (default ON) / --quiet both write the same ``verbose`` dest, so
    # "--quiet wins" falls out of order. SUPPRESS keeps an unset flag out of the
    # namespace so main() can default it to True.
    common.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Print progress to stderr (default). stdout stays machine-readable.",
    )
    common.add_argument(
        "--quiet",
        dest="verbose",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Silence stderr progress (wins over --verbose). stdout is unchanged.",
    )

    parser = argparse.ArgumentParser(
        prog="forti",
        parents=[common],
        description=(
            "Control an already-running FortiClient IPsec VPN over the Chrome "
            "DevTools Protocol (attach-only; the one exception is `startserver`)."
        ),
    )

    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser(
        "list", parents=[common], help="List configured VPN profiles (name, type, server)."
    )
    p_list.add_argument("--json", action="store_true", help="Emit a JSON array of profile dicts.")
    p_list.set_defaults(func=_cmd_list)

    p_status = sub.add_parser("status", parents=[common], help="Show the current tunnel status.")
    p_status.add_argument(
        "--json", action="store_true", help="Emit the merged state as a JSON object."
    )
    p_status.set_defaults(func=_cmd_status)

    p_connect = sub.add_parser("connect", parents=[common], help="Connect an IPsec profile.")
    p_connect.add_argument("profile", help="The profile (connection_name) to connect.")
    p_connect.add_argument(
        "-u",
        "--user",
        default=None,
        help="Override the username (default: the profile's configured username).",
    )
    p_connect.add_argument(
        "--no-wait",
        action="store_true",
        help="Issue the connect and return immediately without polling for CONNECTED.",
    )
    p_connect.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for CONNECTED before giving up (default 30).",
    )
    p_connect.add_argument(
        "--show-window",
        action="store_true",
        help=(
            "Keep FortiClient's window visible after connecting. By default the "
            "window FortiClient pops on connect is hidden again over CDP."
        ),
    )
    p_connect.set_defaults(func=_cmd_connect)

    p_disconnect = sub.add_parser("disconnect", parents=[common], help="Disconnect a profile.")
    p_disconnect.add_argument("profile", help="The profile (connection_name) to disconnect.")
    p_disconnect.set_defaults(func=_cmd_disconnect)

    p_ip = sub.add_parser(
        "ip", parents=[common], help="Print the current tunnel's assigned VPN IP."
    )
    p_ip.set_defaults(func=_cmd_ip)

    p_hide = sub.add_parser(
        "hide-window",
        parents=[common],
        help="Hide FortiClient's main window to the tray (over CDP).",
        description=(
            "Hide FortiClient's main window via window.forticlient.closeMainWindow(). "
            "FortiClient pops its window on connect even under --hide-gui; this hides "
            "it again without quitting the app. `connect` does this automatically "
            "unless you pass --show-window."
        ),
    )
    p_hide.set_defaults(func=_cmd_hide_window)

    p_startserver = sub.add_parser(
        "startserver",
        parents=[common],
        help="Launch FortiClient headless with the CDP debugging port enabled.",
        description=(
            "Start FortiClient headless with the Chrome DevTools Protocol enabled so "
            "the other (attach-only) commands have something to attach to. Idempotent: "
            "if a CDP server already answers on the port, it does nothing. If "
            "FortiClient is not installed it exits 8 with a download hint. This is the "
            "one command that launches FortiClient; every other command is attach-only."
        ),
    )
    p_startserver.add_argument(
        "--no-wait",
        action="store_true",
        help="Launch and return immediately without waiting for the CDP port to open.",
    )
    p_startserver.set_defaults(func=_cmd_startserver)

    return parser


def _cmd_list(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti list`` — print profiles as a table (or JSON with ``--json``).

    ``server`` is the IPsec gateway (``profile_info(name)["remote_gateway"]``);
    it is only queried for ``ipsec`` profiles and left blank otherwise, since
    ``GetIPSecGeneralInfo`` is IPsec-specific.
    """
    profiles = forti.profiles()
    rows = []
    for profile in profiles:
        server = ""
        if profile.type == _IPSEC:
            server = forti.profile_info(profile.name).get("remote_gateway", "")
        rows.append({"name": profile.name, "type": profile.type, "server": server})

    if args.json:
        print(json.dumps(rows))
        return 0

    _print_table(rows)
    return 0


def _print_table(rows: list[dict]) -> None:
    """Print profile rows as a simple aligned ``name / type / server`` table.

    Column widths are sized to the widest cell (header included) so the output
    stays readable regardless of profile-name length. Pure formatting; no I/O
    beyond ``print``.
    """
    headers = {"name": "NAME", "type": "TYPE", "server": "SERVER"}
    widths = {
        col: max(len(headers[col]), *(len(str(row[col])) for row in rows))
        if rows
        else len(headers[col])
        for col in ("name", "type", "server")
    }
    line = "  ".join(headers[col].ljust(widths[col]) for col in ("name", "type", "server"))
    print(line.rstrip())
    for row in rows:
        print(
            "  ".join(
                str(row[col]).ljust(widths[col]) for col in ("name", "type", "server")
            ).rstrip()
        )


def _cmd_status(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti status`` — print the tunnel state, enriched when connected.

    Reads ``state()``. When ``ipsec_state == 2`` (CONNECTED) it derives the
    profile name from the state and merges ``connection_info`` + ``connection_ip``
    so the human line / JSON object carry IP, duration and traffic counters. When
    not connected it reports just the state label.
    """
    state = forti.state()

    if state.ipsec_state != _CONNECTED:
        if args.json:
            print(json.dumps(state.raw))
        else:
            print(state.state_label)
        return 0

    name = state.name
    info = forti.connection_info(name, _IPSEC)
    ip = forti.connection_ip(name, _IPSEC)

    if args.json:
        # Merge the raw state with the info/ip dicts into one object.
        merged = dict(state.raw)
        merged.update(info)
        merged.update(ip)
        print(json.dumps(merged))
        return 0

    vpn_ip = ip.get("vpn_ip", "")
    duration = info.get("duration", "")
    traffic_in = info.get("traffic_in", "")
    traffic_out = info.get("traffic_out", "")
    # e.g. "CONNECTED office 172.16.200.2 (00:01:45, in=1616 out=0)"
    print(f"{state.state_label} {name} {vpn_ip} ({duration}, in={traffic_in} out={traffic_out})")
    return 0


def _cmd_connect(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti connect <profile>`` — connect, optionally waiting for CONNECTED.

    Routes to ``connect(profile, username=..., wait=not --no-wait,
    timeout=...)``. With ``--no-wait`` it prints a ``connecting`` progress line
    and returns; otherwise, on a CONNECTED terminal state, it fetches the VPN IP
    and prints ``CONNECTED <profile> <ip>``. The password is resolved inside the
    controller (from the Keychain) and is never accepted or printed here.
    """
    wait = not args.no_wait
    report(f"Connecting profile {args.profile}…")
    state = forti.connect(
        args.profile,
        username=args.user,
        wait=wait,
        timeout=args.timeout,
    )

    if not wait:
        print(f"connecting {args.profile} ...")
        return 0

    if state.ipsec_state == _CONNECTED:
        ip = forti.connection_ip(args.profile, _IPSEC)
        vpn_ip = ip.get("vpn_ip", "")
        # FortiClient pops its window on connect even under --hide-gui; hide it
        # again (over CDP) unless the user asked to keep it. Only meaningful in the
        # waited path: with --no-wait the popup happens after we return.
        if not args.show_window:
            _hide_window_best_effort(forti)
        report(f"Connected: {vpn_ip}")
        print(f"CONNECTED {args.profile} {vpn_ip}")
    else:
        # Reached here only with wait=True and a non-connected terminal state the
        # controller chose not to raise on (e.g. wait semantics changed); report
        # the label rather than silently claiming success.
        print(f"{state.state_label} {args.profile}")
    return 0


def _cmd_disconnect(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti disconnect <profile>`` — tear down the tunnel and confirm."""
    forti.disconnect(args.profile)
    print(f"DISCONNECTED {args.profile}")
    return 0


def _cmd_ip(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti ip`` — print the VPN IP, or exit 1 with ``not connected`` on stderr.

    Reads ``state()``; only when ``ipsec_state == 2`` does it print the assigned
    IP. Otherwise it writes ``not connected`` to stderr and returns ``1`` so the
    value can be used safely in shell pipelines (a non-IP line never reaches
    stdout).
    """
    state = forti.state()
    if state.ipsec_state != _CONNECTED:
        print("not connected", file=sys.stderr)
        return 1
    ip = forti.connection_ip(state.name, _IPSEC)
    print(ip.get("vpn_ip", ""))
    return 0


def _hide_window_best_effort(forti: FortiVPN) -> None:
    """Hide FortiClient's main window — best effort, never fails the caller.

    Hiding is cosmetic (the tunnel is already up by the time this runs), so a
    ``CDPEvaluateError`` is reported when verbose and swallowed rather than
    propagated. See :meth:`FortiVPN.hide_window` for why the window needs hiding.
    """
    report("Hiding FortiClient window…")
    try:
        forti.hide_window()
    except CDPEvaluateError as e:
        # Cosmetic step; don't let it fail an otherwise-successful command.
        report(f"(could not hide FortiClient window: {e})")


def _cmd_hide_window(forti: FortiVPN, args: argparse.Namespace) -> int:
    """``forti hide-window`` — hide FortiClient's main window to the tray.

    For when the window is up (e.g. a connect run with ``--show-window``, or
    FortiClient popped it itself). Unlike the best-effort hide after connect,
    errors propagate here since hiding is this command's whole purpose.
    """
    forti.hide_window()
    report("FortiClient window hidden.")
    return 0


def _cmd_startserver(args: argparse.Namespace) -> int:
    """``forti startserver`` — launch FortiClient headless with CDP enabled.

    The one non-attach-only command. It does **not** open a ``CDPSession`` (there
    may be nothing to attach to yet); :func:`main` dispatches it before the
    session is created. Routes to ``launcher.start_server`` with ``wait=0`` when
    ``--no-wait`` is given, else the default 10s, wiring :func:`report` as the
    ``on_info`` progress channel. On success prints a short stdout line naming the
    endpoint. ``launcher`` is referenced as ``cli.launcher`` so tests can
    monkeypatch it; failures (``FortiClientNotFoundError`` → exit 8, or a
    ``FortiError`` timeout → exit 1) propagate to the top-level handler.
    """
    wait = 0.0 if args.no_wait else 10.0
    launcher.start_server(args.host, args.port, wait=wait, on_info=report)
    print(f"FortiClient CDP listening on {args.host}:{args.port}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse ``argv``, run the chosen subcommand, return the process exit code.

    Opens a single attach-only ``CDPSession`` (context manager, closed on exit),
    wraps it in a ``FortiVPN``, and dispatches. All *expected* failures arrive as
    ``FortiError`` subclasses: caught once here, printed to stderr, and turned
    into ``e.exit_code`` (the type → exit-code contract; see the module
    docstring). ``KeyboardInterrupt`` returns ``130``. Argparse usage errors
    exit ``2`` on their own (``parser.error`` raises ``SystemExit``), which is
    why parsing happens *outside* the ``FortiError`` try block. Anything that is
    not a ``FortiError`` is a genuine bug and is left to propagate.
    """
    global _VERBOSE

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # No subcommand given: print usage and exit 2 (argparse usage-error code).
        parser.error("a subcommand is required")

    # Resolve the global options' real defaults. They use argparse.SUPPRESS (so a
    # subparser copy doesn't clobber a top-level value), so an unset flag is absent
    # from the namespace — getattr supplies the default. Write them back onto args
    # so every downstream command (incl. startserver) sees concrete values.
    # --quiet wins automatically: both flags target ``verbose``; whichever is parsed
    # last lands, and an unset pair defaults to True (verbose on).
    _VERBOSE = getattr(args, "verbose", True)
    args.port = getattr(args, "port", int(os.environ.get("FORTI_CDP_PORT", "9222")))
    args.host = getattr(args, "host", "127.0.0.1")

    try:
        if args.command == "startserver":
            # Bootstrap command: it LAUNCHES FortiClient, so it must not attach to
            # a CDP session (there may be nothing to attach to yet). Dispatched
            # here, before any CDPSession is opened.
            return _cmd_startserver(args)

        report(f"Attaching to FortiClient CDP at {args.host}:{args.port}…")
        with CDPSession(args.port, args.host) as session:
            session.connect()
            forti = FortiVPN(session)
            return args.func(forti, args)
    except NotRunningError as e:
        # FortiClient's CDP endpoint is unreachable. The exception message is
        # factual only (cdp.py keeps the transport decoupled); the CLI owns the
        # actionable "how to fix it" guidance, printed to stderr below.
        print(e, file=sys.stderr)
        _print_not_running_guidance(args.port)
        return e.exit_code
    except FortiError as e:
        # Expected, user-facing failure: the type carries the exit code and the
        # message is what the user should see. Never a bare traceback.
        print(e, file=sys.stderr)
        return e.exit_code
    except KeyboardInterrupt:
        # Ctrl-C: conventional 128 + SIGINT(2). Print a newline-free notice so a
        # partially written line is not left dangling on the terminal.
        print("interrupted", file=sys.stderr)
        return 130


def _print_not_running_guidance(port: int) -> None:
    """Print actionable "how to reach FortiClient" advice to stderr.

    Complements the factual :class:`~fortivpn.errors.NotRunningError` message
    (which only names the unreachable URL). Always suggests ``forti startserver``.
    Then, if :func:`launcher.find_forticlient` locates the installed executable,
    it shows the exact manual launch command for users who prefer to run it
    themselves; if FortiClient is not installed at all, it shows
    :func:`launcher.download_hint` instead. ``launcher`` is referenced via the
    module global so tests can monkeypatch ``cli.launcher``. This guidance is
    independent of verbosity — a hard error always explains how to recover.
    """
    print("To start it, run:  forti startserver", file=sys.stderr)
    exe = launcher.find_forticlient()
    if exe is not None:
        print(
            f'Or launch it yourself:  "{exe}" --hide-gui --remote-debugging-port={port}',
            file=sys.stderr,
        )
    else:
        print(launcher.download_hint(), file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
