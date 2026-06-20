# How fvpnctl works

`fvpnctl` is a thin command-line layer over FortiClient. It does **not** replace FortiClient,
reimplement the VPN, or automate its GUI — it asks a FortiClient that you are already running
to do the work, and reports the result back to your terminal.

## The model

- **You run FortiClient.** You launch it yourself so that it exposes a local debugging port
  (`--remote-debugging-port`), the same kind of local interface many desktop apps offer. This
  is off in the normal tray-GUI mode, so you opt into it explicitly (see the README's Setup
  section, or use `fvpnctl startserver`).
- **`fvpnctl` attaches and asks.** It connects to that local port and asks FortiClient to
  bring a profile up or down and to report its current state. There is no clicking, no
  Accessibility automation, and no reimplementation of the tunnel — FortiClient and its
  privileged daemon do all of the actual VPN work.
- **It reads back a clear status.** Rather than watching the UI, `fvpnctl` reads FortiClient's
  connection state as a simple value, which makes the behaviour deterministic and scriptable.

This was developed and tested against FortiClient 7.4.x on macOS.

## Connecting

1. `fvpnctl` reads the profile's password from the macOS **login Keychain** at connect time
   (see the convention below). The password is never placed on the command line, in the
   environment, or in logs.
2. It asks FortiClient to connect the named profile, supplying the username and password.
3. It then polls the connection state until the tunnel reports **CONNECTED**.

Connection state is a small integer that `fvpnctl` maps to a label:

| Value | State |
|-------|-------|
| `0` | DISCONNECTED |
| `1` | CONNECTING |
| `2` | CONNECTED |
| `3` | XAUTH |
| `4` | RECONNECTING |

Polling this value (rather than waiting on UI spinners) is what makes `connect` deterministic
and gives the clear exit codes the CLI documents.

## The window on connect

FortiClient shows its main window on a successful connect, even when it was launched with
`--hide-gui`. After connecting, `fvpnctl` sends that window back to the tray for you — without
quitting the app — unless you pass `--show-window`. This is best-effort: if it can't hide the
window, your connection is still up and the command still succeeds.

## Launching FortiClient (`startserver`) and the single-instance caveat

FortiClient is a single-instance application: it can only run once. Running it headless with
the debugging port therefore means you are **not** also running the ordinary tray-GUI
FortiClient — and switching between the two modes restarts the process, which **drops any
active tunnel.** So pick one mode; if you adopt `fvpnctl`, let it (or a LaunchAgent) own the
headless instance.

`fvpnctl startserver` launches FortiClient headless with the debugging port enabled. It is
idempotent — if the port is already answering, it does nothing — and if FortiClient isn't
installed it exits with a clear download hint.

## Credentials and the Keychain convention

The VPN password is read from the macOS login Keychain at connect time using a service-name
convention shared with the sibling AppleScript tool, so any Keychain item you already created
for that tool works here unchanged:

```bash
security find-generic-password -s forti-vpn-<profile> -a <username> -w
```

The *service* name (`-s`) is `forti-vpn-` followed by the exact profile name, and the
*account* name (`-a`) is the VPN username.

## Scope and caveats

- **IPsec profiles, no 2FA** are the supported, validated case. An SSL profile or a profile
  that requires a token/OTP is rejected with a clear "unsupported" error rather than a guess.
- **Attach-only by default.** No command auto-starts, quits, or restarts FortiClient; the one
  explicit launcher is `startserver`. The tool never tears down a running FortiClient.
- **Don't trust `DevToolsActivePort`.** The file
  `~/Library/Application Support/FortiClient/DevToolsActivePort` can be stale; `fvpnctl`
  checks the live port instead of relying on it.
