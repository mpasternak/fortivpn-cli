# fortivpn — control FortiClient IPsec VPN on macOS via the Chrome DevTools Protocol

A macOS command-line tool (`forti`) and reusable Python library that **connects,
disconnects, and reports the status of FortiClient IPsec VPN profiles — with no GUI
automation at all.** Instead of clicking buttons through Accessibility APIs, it attaches
to the running FortiClient over the Chrome DevTools Protocol (CDP) and drives the Electron
renderer's own internal `window.guimessenger` API directly.

- Zero runtime dependencies (Python standard library only).
- Python ≥ 3.11, macOS only.
- Attach-only: the tool never starts, stops, or restarts FortiClient.

> **Disclaimer.** This is an independent, unofficial project. It is **not affiliated with,
> endorsed by, or sponsored by Fortinet, Inc.** "FortiClient" and "Fortinet" are registered
> trademarks of Fortinet, Inc. (<https://www.fortinet.com>); they are used here only to
> identify the software this tool interoperates with. This software is provided **"as is",
> without warranty of any kind**: you use it **entirely at your own risk**, and the author
> accepts **no liability** for any damage, data loss, dropped VPN connections, or other
> losses arising from its use. It depends on FortiClient's internal, undocumented API, which
> may change or break at any time. Ensure your use complies with your organization's policies
> and with Fortinet's licensing terms. See [LICENSE](LICENSE) for the full warranty/liability
> disclaimer.

---

## What it is, and why this approach

FortiClient on macOS is an Electron app. Its UI talks to the underlying VPN daemon through
an in-page JavaScript bridge, `window.guimessenger` — the same object the buttons in the
tray GUI call. This tool reaches that object directly over CDP and calls its methods
(`GetVPNConnectionList`, `SetGuiHandle`, `ConnectTunnel`, `getConnectionState`, …) instead
of synthesising clicks.

### Why not GUI automation?

The obvious alternative — driving the tray menu with AppleScript / the Accessibility (AX)
API — is what the sibling project (`fortivpn-cli-macos`) does. It works, but it is:

- **Fragile.** It depends on window geometry, menu labels, localisation, and the
  Accessibility permission. A FortiClient UI redesign breaks it.
- **Non-deterministic.** Clicks race the UI; you wait on pixels and spinners.
- **Not headless-friendly.** It needs the GUI on screen to click.

Driving `window.guimessenger` over CDP avoids all of that:

- **No Accessibility permission, no clicking.** We call the same functions the UI calls.
- **Deterministic.** We issue an API call and poll an integer state enum
  (`0=DISCONNECTED 1=CONNECTING 2=CONNECTED 3=XAUTH 4=RECONNECTING`) — no UI timing.
- **Scriptable and headless.** It runs against a FortiClient launched with `--hide-gui`,
  so it works over SSH and in unattended scripts.

This control path was validated empirically against a live tunnel (FortiClient 7.4.3.4323,
macOS). See [`SPIKE.md`](./SPIKE.md) for the "why it works" walkthrough and
[`docs/superpowers/specs/2026-06-20-fortivpn-cli-via-cdp-design.md`](./docs/superpowers/specs/2026-06-20-fortivpn-cli-via-cdp-design.md)
for the full design.

### Why FortiClient must run headless with `--remote-debugging-port`

CDP is only reachable when the Electron process is started with
`--remote-debugging-port=<port>`. FortiClient does not enable it in normal tray-GUI mode,
so **you must launch FortiClient yourself with that flag** for this tool to attach.

The tool is deliberately **attach-only**: it never launches, quits, or restarts
FortiClient. That is a safety decision — the VPN client owns the tunnel and the system
network configuration, and a CLI silently bouncing it would be surprising and could drop a
live connection. So lifecycle is your responsibility (a LaunchAgent does it once, at
login), and the tool only ever attaches to what is already running. If nothing is
listening on the debug port, every command fails fast with exit code `3`
(`NotRunningError`) and a message telling you how to start it.

The recommended launch is:

```bash
/Applications/FortiClient.app/Contents/MacOS/FortiClient --hide-gui --remote-debugging-port=9222
```

`--hide-gui` runs it without the tray window (you don't need the UI; the CLI is the UI),
and `--remote-debugging-port=9222` exposes CDP on `127.0.0.1:9222`.

---

## Install

The project is managed with [`uv`](https://docs.astral.sh/uv/). It has **no runtime
dependencies**, so installation is just the package itself.

Install the `forti` command onto your PATH:

```bash
uv tool install .
```

Or run it without installing, straight from a checkout:

```bash
uv run forti list
```

Requirements: macOS, Python ≥ 3.11.

---

## Setup

Two one-time setup steps: make FortiClient run headless + debug at login, and put your VPN
password into the Keychain.

### 1. Run FortiClient headless + debug at login (LaunchAgent)

This tool only attaches; something has to start FortiClient in debug mode. The clean way
is a per-user LaunchAgent that launches it once at login. A ready-to-use plist ships in
[`contrib/com.fortivpn.headless.plist`](./contrib/com.fortivpn.headless.plist):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fortivpn.headless</string>
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
cp contrib/com.fortivpn.headless.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.fortivpn.headless.plist
```

`RunAtLoad` starts it at login; `KeepAlive` relaunches it if it exits, so the debug port is
always available. To stop using it:

```bash
launchctl unload -w ~/Library/LaunchAgents/com.fortivpn.headless.plist
```

**Important — this replaces the normal tray-GUI mode.** FortiClient is a single-instance
app: it cannot run twice. Running it headless + debug means you are *not* running the
ordinary tray-GUI FortiClient at the same time. Switching between the two modes (e.g.
quitting the headless instance and reopening the GUI app, or vice versa) **drops any active
tunnel** — restarting the FortiClient process tears the connection down. So pick one mode;
if you adopt this tool, let the LaunchAgent own FortiClient and drive everything through
`forti`.

> If you customise the port, keep it consistent: pass `--port`/`FORTI_CDP_PORT` to `forti`
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
same item, looked up the same way. At connect time `forti` runs
`security find-generic-password -s forti-vpn-<profile> -a <username> -w` to read it back.

If the item is missing or access is denied, `connect` fails with exit code `4`
(`KeychainError`) and prints the exact `security add-generic-password …` command to fix it.

---

## Usage

```
forti [--port N] [--host H] <command> ...
```

Global options:

- `--port N` — CDP debug port (default `9222`). Overridable by the `FORTI_CDP_PORT`
  environment variable. Must match the `--remote-debugging-port` FortiClient was launched
  with.
- `--host H` — CDP host (default `127.0.0.1`).

`list` and `status` additionally accept `--json` for machine-readable output.

### `forti list`

List configured VPN profiles.

```console
$ forti list
NAME    TYPE   SERVER
office    ipsec  vpn.example.com
acme    ipsec  gw.acme.example
```

```console
$ forti list --json
[{"connection_name": "office", "type": "ipsec", ...}, ...]
```

### `forti status`

Show the current tunnel state. When connected, it also reports the tunnel IP, duration, and
traffic.

```console
$ forti status
CONNECTED office 172.16.200.2 (00:01:45, ↓1.6KB ↑0)
```

```console
$ forti status
DISCONNECTED
```

```console
$ forti status --json
{"ipsec_state": 2, "ssl_state": 0, "connection_name": "office", ...}
```

### `forti connect <profile> [-u USER] [--no-wait] [--timeout S]`

Connect an IPsec profile. The username defaults to the one stored in the profile; the
password is read from the Keychain. By default it waits until the tunnel reaches CONNECTED.

```console
$ forti connect office
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

### `forti disconnect <profile>`

Disconnect an IPsec profile.

```console
$ forti disconnect office
DISCONNECTED office
```

### `forti ip`

Print just the assigned tunnel IP — handy in scripts. Exits `1` with a message on stderr if
not connected.

```console
$ forti ip
172.16.200.2
```

---

## Exit codes

The exit code is selected by the *type* of failure, so scripts can branch on it. These
match [`src/fortivpn/errors.py`](./src/fortivpn/errors.py).

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Usage error (bad arguments; from argparse) |
| `3` | FortiClient not running / not reachable on the debug port (`NotRunningError`) |
| `4` | Keychain lookup failed — item missing or access denied (`KeychainError`) |
| `5` | Unsupported in v1 — SSL profile or 2FA/XAUTH required (`UnsupportedError`) |
| `6` | Connect failed (negotiated then dropped) or a CDP evaluation threw (`ConnectFailed` / `CDPEvaluateError`) |
| `7` | Timed out waiting for CONNECTED, including never leaving DISCONNECTED (`ConnectTimeout`) |
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
- **No profile management.** No create / delete / rename / import, even though the
  underlying API exposes it. Profiles are managed in FortiClient itself.
- **No lifecycle management.** The tool never starts or stops FortiClient; you install the
  LaunchAgent above yourself.
- **No default profile / config file.** The profile name is always passed explicitly.

For the validated control path and the rationale, see [`SPIKE.md`](./SPIKE.md) and the
[design spec](./docs/superpowers/specs/2026-06-20-fortivpn-cli-via-cdp-design.md).

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

The unit suite runs entirely without FortiClient (the CDP session is mocked). An
**attended** integration test lives in [`tests/manual/test_live.py`](./tests/manual/test_live.py);
it is skipped by default and only runs when you set `FORTI_LIVE=1` against a real
headless + debug FortiClient — note that it **breaks the live tunnel** (connect →
status → disconnect). See that file's docstring for how to run it.
