# fvpnctl — control your FortiClient VPN from the macOS command line

[![CI](https://github.com/mpasternak/fortivpn-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/mpasternak/fortivpn-cli/actions/workflows/ci.yml)

A small command-line tool (`fvpnctl`) and Python library for **connecting, disconnecting,
and checking the status of FortiClient VPN profiles from the terminal** — handy for scripts,
automation, and headless or over-SSH use, with no GUI needed. It works with a FortiClient you
already have running, talking to it over a local debugging port.

- Zero runtime dependencies (Python standard library only).
- Python ≥ 3.11, macOS only.
- Attach-only by default: commands attach to a running FortiClient; the one explicit
  exception is `fvpnctl startserver`, an opt-in launcher you invoke yourself.

> **Disclaimer.** This is an independent, unofficial project. It is **not affiliated with,
> endorsed by, or sponsored by Fortinet, Inc.** "FortiClient" and "Fortinet" are registered
> trademarks of Fortinet, Inc. (<https://www.fortinet.com>); they are used here only to
> identify the software this tool interoperates with. This software is provided **"as is",
> without warranty of any kind**: you use it **entirely at your own risk**, and the author
> accepts **no liability** for any damage, data loss, dropped VPN connections, or other
> losses arising from its use. It relies on a local debugging interface that may change
> between FortiClient versions. Ensure your use complies with your organization's policies
> and with Fortinet's licensing terms. See [LICENSE](LICENSE) for the full warranty/liability
> disclaimer.

---

## What it is

[FortiClient](https://www.fortinet.com/products/endpoint-security/forticlient) is excellent,
mature, full-featured security and VPN software — `fvpnctl` doesn't replace any of it. It
simply adds a thin, scriptable command line on top, so you can bring VPN profiles up and down
and check their status from the terminal, from a script, or over SSH, without opening the GUI.

It does this by talking to a FortiClient that you launch yourself, over a local debugging
port — so there is no UI scraping and the behaviour is deterministic: a command issues a
request and reads back a clear connection state. Tested against FortiClient 7.4.x on macOS.

### Running FortiClient with the debugging port

`fvpnctl` attaches to a running FortiClient over a local debugging port, which FortiClient
exposes when it is launched with `--remote-debugging-port=<port>` (this is off in the normal
tray-GUI mode). So **you launch FortiClient yourself with that flag**, and `fvpnctl` attaches
to it.

The tool is **attach-only by default**: it never *automatically* launches, quits, or restarts
FortiClient. That is a deliberate safety choice — FortiClient owns the tunnel and the system
network configuration, and a CLI silently bouncing it would be surprising and could drop a
live connection. The single explicit exception is `fvpnctl startserver`, which you run on
purpose to start FortiClient headless (handy for ad-hoc use). Otherwise lifecycle is yours (a
LaunchAgent does it once, at login). If nothing is listening on the debug port, every *other*
command fails fast with exit code `3` and tells you exactly how to start it — including the
`fvpnctl startserver` shortcut.

The recommended launch is either `fvpnctl startserver` or, equivalently, by hand:

```bash
/Applications/FortiClient.app/Contents/MacOS/FortiClient --hide-gui --remote-debugging-port=9222
```

`--hide-gui` runs it without the tray window (you drive everything through `fvpnctl`), and
`--remote-debugging-port=9222` exposes the debugging port on `127.0.0.1:9222`.

---

## Install

The project is managed with [`uv`](https://docs.astral.sh/uv/) and has **no runtime
dependencies**. The PyPI package is `fvpnctl`; the command it installs is `fvpnctl`.

**From PyPI:**

```bash
uv tool install fvpnctl   # puts the `fvpnctl` command on your PATH
fvpnctl list
```

Or run it once, without installing, with `uvx`:

```bash
uvx fvpnctl list
```

(`pipx install fvpnctl` / `pip install fvpnctl` work too.)

**From source (this checkout):**

```bash
uv tool install .       # install the `fvpnctl` command from the local tree
uv run fvpnctl list       # or run it in place, without installing
```

Requirements: macOS, Python ≥ 3.11.

---

## Setup

Two one-time setup steps: make FortiClient run headless + debug at login, and put your VPN
password into the Keychain.

### 1. Run FortiClient headless + debug at login (LaunchAgent)

This tool only attaches; something has to start FortiClient in debug mode. The clean way
is a per-user LaunchAgent that launches it once at login. A ready-to-use plist ships in
[`contrib/com.fvpnctl.headless.plist`](./contrib/com.fvpnctl.headless.plist):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fvpnctl.headless</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/FortiClient.app/Contents/MacOS/FortiClient</string>
        <string>--hide-gui</string>
        <string>--remote-debugging-port=9222</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Install and load it:

```bash
cp contrib/com.fvpnctl.headless.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.fvpnctl.headless.plist
```

`RunAtLoad` starts it at login; `KeepAlive` relaunches it if it exits, so the debug port is
always available. To stop using it:

```bash
launchctl unload -w ~/Library/LaunchAgents/com.fvpnctl.headless.plist
```

**Important — this replaces the normal tray-GUI mode.** FortiClient is a single-instance
app: it cannot run twice. Running it headless + debug means you are *not* running the
ordinary tray-GUI FortiClient at the same time. Switching between the two modes (e.g.
quitting the headless instance and reopening the GUI app, or vice versa) **drops any active
tunnel** — restarting the FortiClient process tears the connection down. So pick one mode;
if you adopt this tool, let the LaunchAgent own FortiClient and drive everything through
`fvpnctl`.

> If you customise the port, keep it consistent: pass `--port`/`FORTI_CDP_PORT` to `fvpnctl`
> (see Usage) so it matches the `--remote-debugging-port` in the plist.

### 2. Add your VPN credentials to the Keychain

The password is never passed on the command line. It lives in the macOS **login Keychain**
as a generic-password item and is read inside the process at connect time. Add one item per
profile:

```bash
security add-generic-password -s forti-vpn-<profile> -a <username> -w
# security will prompt for the password interactively (the -w with no value).
```

For example, for an IPsec profile named `office` with username `alice`:

```bash
security add-generic-password -s forti-vpn-office -a alice -w
```

**The `forti-vpn-<profile>` service-name convention.** The Keychain *service* name (`-s`)
is always `forti-vpn-` followed by the exact profile name, and the *account* name (`-a`) is
the VPN username. This convention is shared verbatim with the sibling AppleScript tool, so
**any Keychain item you already created for that tool works here unchanged** — it is the
same item, looked up the same way. At connect time `fvpnctl` runs
`security find-generic-password -s forti-vpn-<profile> -a <username> -w` to read it back.

If the item is missing or access is denied, `connect` fails with exit code `4`
(`KeychainError`) and prints the exact `security add-generic-password …` command to fix it.

---

## Usage

```
fvpnctl [--port N] [--host H] <command> ...
```

Global options:

- `--port N` — FortiClient debug port (default `9222`). Overridable by the `FORTI_CDP_PORT`
  environment variable. Must match the `--remote-debugging-port` FortiClient was launched
  with.
- `--host H` — debug host (default `127.0.0.1`).
- `--verbose` / `--quiet` — progress messages. Verbose is **on by default** and writes
  progress to **stderr**; `--quiet` silences it. Either way `stdout` carries only the
  machine-readable result, so `--json` output and shell pipelines are byte-identical.

`list` and `status` additionally accept `--json` for machine-readable output.

### `fvpnctl list`

List configured VPN profiles.

```console
$ fvpnctl list
NAME    TYPE   SERVER
office    ipsec  vpn.example.com
acme    ipsec  gw.acme.example
```

```console
$ fvpnctl list --json
[{"connection_name": "office", "type": "ipsec", ...}, ...]
```

### `fvpnctl status`

Show the current tunnel state. When connected, it also reports the tunnel IP, duration, and
traffic.

```console
$ fvpnctl status
CONNECTED office 172.16.200.2 (00:01:45, ↓1.6KB ↑0)
```

```console
$ fvpnctl status
DISCONNECTED
```

```console
$ fvpnctl status --json
{"ipsec_state": 2, "ssl_state": 0, "connection_name": "office", ...}
```

### `fvpnctl connect <profile> [-u USER] [--no-wait] [--timeout S]`

Connect an IPsec profile. The username defaults to the one stored in the profile; the
password is read from the Keychain. By default it waits until the tunnel reaches CONNECTED.

```console
$ fvpnctl connect office
connecting office...
CONNECTED office 172.16.200.2
```

Options:

- `-u USER` / `--user USER` — override the username (also selects the Keychain account).
- `--no-wait` — issue the connect and return immediately without polling for CONNECTED.
- `--timeout S` — how long to wait for CONNECTED before giving up (default 30s). A tunnel
  that never leaves DISCONNECTED (a silent rejection) ends in a timeout (exit `7`); a
  tunnel that started negotiating and then dropped (e.g. bad credentials) is a connect
  failure (exit `6`).
- `--show-window` — keep FortiClient's window visible after connecting (see the note below).

By default, after a successful connect `fvpnctl` **hides FortiClient's window**. FortiClient
pops its main window on connect even under `--hide-gui`, so `connect` sends it back to the
tray for you (without quitting the app) — best effort, so a failure to hide never fails an
otherwise-successful connect. Pass `--show-window` to keep the window up. (This only applies
in the waited path; with `--no-wait` the popup happens after the command returns.)

### `fvpnctl disconnect <profile>`

Disconnect an IPsec profile.

```console
$ fvpnctl disconnect office
DISCONNECTED office
```

### `fvpnctl ip`

Print just the assigned tunnel IP — handy in scripts. Exits `1` with a message on stderr if
not connected.

```console
$ fvpnctl ip
172.16.200.2
```

### `fvpnctl hide-window`

Hide FortiClient's main window to the tray (without quitting the app). `connect` already does
this by default; run it manually when the window is up for another reason (e.g. a
`connect --show-window`, or FortiClient popped it itself).

```console
$ fvpnctl hide-window
```

### `fvpnctl startserver`

Launch FortiClient headless with the debug port enabled, so the attach-only commands have something to
attach to. **This is the one command that starts FortiClient** — every other command only
attaches. It is idempotent (does nothing if the port already answers), and if FortiClient is
not installed it prints a download hint and exits `8`.

```console
$ fvpnctl startserver
FortiClient debug port ready on 127.0.0.1:9222
```

Use it for ad-hoc sessions; for a permanent setup prefer the LaunchAgent above. FortiClient
is single-instance: if an ordinary tray-GUI FortiClient is already running, quit it first —
starting a second instance just forwards its arguments to the first, which won't open the
debug port.

- `--no-wait` — launch and return immediately without waiting for the port to open.

---

## Exit codes

The exit code is selected by the *type* of failure, so scripts can branch on it. These
match [`src/fvpnctl/errors.py`](./src/fvpnctl/errors.py).

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Usage error (bad arguments; from argparse) |
| `3` | FortiClient not running / not reachable on the debug port (`NotRunningError`) |
| `4` | Keychain lookup failed — item missing or access denied (`KeychainError`) |
| `5` | Unsupported in v1 — SSL profile or 2FA/XAUTH required (`UnsupportedError`) |
| `6` | Connect failed (negotiated then dropped) or an internal call to FortiClient failed (`ConnectFailed` / `CDPEvaluateError`) |
| `7` | Timed out waiting for CONNECTED, including never leaving DISCONNECTED (`ConnectTimeout`) |
| `8` | FortiClient is not installed — `startserver` could not find the app (`FortiClientNotFoundError`) |
| `1` | Any other `FortiError` |

---

## Security note

Your VPN password is treated as a long-lived secret and is handled carefully:

- It is read from the **login Keychain inside the process** at connect time and held only
  in a local variable for the duration of that one connect call.
- It is **never printed, never logged, and never placed in an exception message** — error
  messages are built only from non-secret identifiers (profile and username).
- It is **never put into argv or the environment**: the command line carries only the
  profile name and (optionally) the username, never the password. Only Apple's `security`
  tool and FortiClient itself ever hold the secret.

---

## Limitations (v1)

This release deliberately covers only the path that was empirically validated. Out of
scope, with a clear error rather than a guess:

- **IPsec only.** Connecting an SSL VPN profile raises `UnsupportedError` (exit `5`); SSL
  was untested in the spike.
- **No 2FA.** If the daemon enters the XAUTH state (a token/OTP is required), `connect`
  raises `UnsupportedError("2FA not supported in v1")` (exit `5`) instead of prompting.
- **No profile management.** No create / delete / rename / import — profiles are managed in
  FortiClient itself.
- **No automatic lifecycle management.** Commands never auto-start, quit, or restart
  FortiClient. The one explicit launcher is `fvpnctl startserver` (or install the LaunchAgent
  above); the tool still never quits or restarts a *running* FortiClient.
- **No default profile / config file.** The profile name is always passed explicitly.

For more on how it works, see [`docs/how-it-works.md`](./docs/how-it-works.md).

---

## Development

```bash
uv sync                 # create the venv and install dev dependencies (pytest)
uv run pytest           # run the test suite
uv run ruff check .     # lint
uv run ruff format .    # format
```

Pre-commit hooks (ruff lint + format) are configured in `.pre-commit-config.yaml`:

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

The unit suite runs entirely without FortiClient (the connection is mocked). An
**attended** integration test lives in [`tests/manual/test_live.py`](./tests/manual/test_live.py);
it is skipped by default and only runs when you set `FORTI_LIVE=1` against a real
headless + debug FortiClient — note that it **breaks the live tunnel** (connect →
status → disconnect). See that file's docstring for how to run it.
