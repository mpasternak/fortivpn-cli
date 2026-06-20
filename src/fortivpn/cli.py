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
(see SPIKE.md section 1). If the debugging port is unreachable, ``CDPSession``
raises :class:`~fortivpn.errors.NotRunningError` and the CLI surfaces that as a
stderr line + exit code 3 — it does not try to launch anything.

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

``CDPSession`` and ``FortiVPN`` are imported as module-level names so the test
suite can monkeypatch ``fortivpn.cli.CDPSession`` / ``fortivpn.cli.FortiVPN``
with CI-safe fakes (no real socket, no real FortiClient).
"""

import argparse
import json
import os
import sys

from fortivpn.cdp import CDPSession
from fortivpn.controller import FortiVPN
from fortivpn.errors import FortiError

# IPsec ``ipsec_state`` value meaning "tunnel up" (SPIKE.md section 2 / design
# spec 4.2). The CLI only needs the CONNECTED sentinel; the controller owns the
# full enum.
_CONNECTED = 2

# Connection type for v1. Only IPsec is supported (SSL is out of scope); the CLI
# always queries/derives with this type. See design spec section 2.
_IPSEC = "ipsec"


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser: global ``--port``/``--host`` + five subcommands.

    The default port comes from ``FORTI_CDP_PORT`` when set, else ``9222`` — so an
    env var can pre-seed it while an explicit ``--port`` still wins (argparse
    applies the flag value over the default). Each subcommand stores its handler
    on ``func`` via ``set_defaults`` so :func:`main` can dispatch generically.
    """
    parser = argparse.ArgumentParser(
        prog="forti",
        description=(
            "Control an already-running FortiClient IPsec VPN over the Chrome "
            "DevTools Protocol (attach-only; never launches FortiClient)."
        ),
    )
    # Default port: env override, else 9222. An explicit --port beats the env var
    # because argparse uses the flag value in preference to this default.
    default_port = int(os.environ.get("FORTI_CDP_PORT", "9222"))
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help="FortiClient CDP debugging port (default 9222, or $FORTI_CDP_PORT).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host the CDP debugging endpoint binds to (default 127.0.0.1).",
    )

    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="List configured VPN profiles (name, type, server).")
    p_list.add_argument("--json", action="store_true", help="Emit a JSON array of profile dicts.")
    p_list.set_defaults(func=_cmd_list)

    p_status = sub.add_parser("status", help="Show the current tunnel status.")
    p_status.add_argument(
        "--json", action="store_true", help="Emit the merged state as a JSON object."
    )
    p_status.set_defaults(func=_cmd_status)

    p_connect = sub.add_parser("connect", help="Connect an IPsec profile.")
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
    p_connect.set_defaults(func=_cmd_connect)

    p_disconnect = sub.add_parser("disconnect", help="Disconnect a profile.")
    p_disconnect.add_argument("profile", help="The profile (connection_name) to disconnect.")
    p_disconnect.set_defaults(func=_cmd_disconnect)

    p_ip = sub.add_parser("ip", help="Print the current tunnel's assigned VPN IP.")
    p_ip.set_defaults(func=_cmd_ip)

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
        print(f"CONNECTED {args.profile} {ip.get('vpn_ip', '')}")
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
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        # No subcommand given: print usage and exit 2 (argparse usage-error code).
        parser.error("a subcommand is required")

    try:
        with CDPSession(args.port, args.host) as session:
            session.connect()
            forti = FortiVPN(session)
            return args.func(forti, args)
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


if __name__ == "__main__":
    sys.exit(main())
