# How it works: controlling FortiClient over the Chrome DevTools Protocol

This document explains the technical control path that `fortivpn` uses to drive
FortiClient's IPsec VPN without any GUI automation. It is the engineer-facing "why
it works" reference behind the design.

The control path was validated empirically on 2026-06-20 against FortiClient
7.4.3.4323 on macOS, against a live tunnel: a full connect / status / disconnect
cycle was driven headless through the Chrome DevTools Protocol (CDP), with no
clicking in the GUI.

## Overview

FortiClient on macOS is an Electron app. Its renderer talks to the underlying VPN
daemon through an in-page JavaScript bridge, `window.guimessenger` — the same object
the buttons in the tray GUI call. By attaching to the renderer over CDP and invoking
those methods directly, we can connect, report status, and disconnect IPsec tunnels
deterministically, without depending on window geometry, menu labels, localisation,
or the Accessibility permission.

Every `window.guimessenger` method is invoked via the CDP `Runtime.evaluate` command
with `awaitPromise: true` and `returnByValue: true`. The methods return a Promise that
resolves to a **JSON string**, so the caller parses each result with `JSON.parse`.

## Launching FortiClient with CDP enabled

CDP is only reachable when the Electron process is started with
`--remote-debugging-port=<port>`. FortiClient does not enable it in normal tray-GUI
mode, so the process must be launched explicitly with that flag:

```bash
/Applications/FortiClient.app/Contents/MacOS/FortiClient --hide-gui --remote-debugging-port=9222
```

`--hide-gui` runs FortiClient without the tray window, and
`--remote-debugging-port=9222` exposes CDP on `127.0.0.1:9222`.

Notes on launching:

- FortiClient is a single-instance app and uses a single-instance lock that forwards
  `argv` to the first instance. To launch it cleanly with new flags, the existing
  instance must be quit first (and its `Contents/MacOS/FortiClient*` processes allowed
  to exit) before relaunching.
- Restarting the FortiClient process **tears down any active tunnel.** This was
  confirmed: after quitting, `ipsec_state` returned to `0` (DISCONNECTED).

### Discovering the renderer target

Query the CDP target list and use the single debuggable page:

```
GET http://127.0.0.1:9222/json
```

This returns one `page` target (`base.html`); use its `webSocketDebuggerUrl` to open
the WebSocket session.

**Do not trust `DevToolsActivePort`.** The file
`~/Library/Application Support/FortiClient/DevToolsActivePort` can be **stale** — it is
left over from a previous launch and may not reflect the port the current process is
actually listening on. Probe the port (via `/json`) rather than reading that file.

## The `window.guimessenger` API surface

The methods below are the ones this tool relies on. All return a Promise resolving to a
JSON string.

| Purpose | Call | Returns |
|---------|------|---------|
| List profiles | `GetVPNConnectionList()` | `[{connection_name, type: "ipsec"\|"ssl", cloud_vpn, corporate}]` |
| Profile info | `GetIPSecGeneralInfo(JSON.stringify({connection_name, connection_type: "ipsec"}))` | `{remote_gateway, username, authentication, authentication_method, sso_enabled, save_password, ...}` |
| Connection state | `getConnectionState()` | `{ipsec_state, ssl_state, connection_name, saml_vpn_name}` |
| Connection statistics | `getConnectionInfo(JSON.stringify({connection_name, connection_type}))` | `{duration, traffic_in, traffic_out}` |
| Tunnel IP | `getConnectionIP(JSON.stringify({connection_name, connection_type}))` | `{vpn_ip}` |
| Current user | `getVPNUserName()` | `{username}` |

`connection_type` is always one of the strings `"ipsec"` or `"ssl"`.

**JSON-argument requirement.** `getConnectionIP`, `getConnectionInfo`, and
`GetIPSecGeneralInfo` require a JSON string argument built with
`JSON.stringify({connection_name, connection_type})`. Calling them without it fails with
"Error in native callback".

### The full surface

`window.guimessenger` exposes 139 methods in total, including profile-management calls
such as `CreateProfileVPN`, `DeleteProfileVPN`, `RenameProfileVPN`, `ImportVPNConfig`,
`UpdateVPNOptions`, and `verifyPassword`. The complete list can be recovered from the
renderer's `bundle.min.js` (search for `(e=window.guimessenger).X.apply`). Only the
subset above is used by this tool.

## The connect sequence

The order of calls matters. It was reconstructed from the `onConnect` handler in
`bundle.min.js`.

### 1. Register the GUI handle first

```js
window.guimessenger.SetGuiHandle()   // -> true
```

**`SetGuiHandle()` must be called before `ConnectTunnel`.** Without it, `ConnectTunnel`
still returns an acknowledgement (`["1"]`), but the daemon never starts negotiation and
the connection state stays at `0` (DISCONNECTED). This is the single most important
ordering constraint in the whole flow.

### 2. Connect the tunnel

For the non-SSO path (`getConnObj`), the username and password are passed inline in the
argument object:

```js
window.guimessenger.ConnectTunnel(JSON.stringify({
  connection_name: "<profile>",
  connection_type: "ipsec",
  username:        "<user>",
  password:        "<password from Keychain>",
  save_password:   "0",
  always_up:       "0",
  auto_connect:    "0",
  saml_error:      1
}))   // -> ["1"] (acknowledgement)
```

### 3. Poll for the connected state

Poll `getConnectionState()` until `ipsec_state == 2` (CONNECTED).

For a profile with `authentication: "save"` and no 2FA, XAUTH completes without any GUI
form: the state was observed to transition `0 → 2` immediately.

## Reading state and disconnecting

State is read with `getConnectionState()` (see the API table above). To disconnect or
to abort a connect in progress:

```js
// Disconnect an established tunnel:
window.guimessenger.DisconnectTunnel(JSON.stringify({connection_name, connection_type}))

// Cancel a connect that is still in progress:
window.guimessenger.CancelTunnel()
```

## Connection-state enum

`ipsec_state` (and `ssl_state`) use this integer enum:

| Value | State |
|-------|-------|
| `0` | DISCONNECTED |
| `1` | CONNECTING |
| `2` | CONNECTED |
| `3` | XAUTH |
| `4` | RECONNECTING |

Polling this integer is what makes the connect flow deterministic — there is no UI
timing or spinner to wait on.

## Credentials and the Keychain convention

The VPN password is read from the macOS login Keychain at connect time and is never
placed on the command line, in the environment, or in logs. The lookup follows the
service-name convention shared with the sibling AppleScript tool:

```bash
security find-generic-password -s forti-vpn-<profile> -a <username> -w
```

The Keychain *service* name (`-s`) is `forti-vpn-` followed by the exact profile name,
and the *account* name (`-a`) is the VPN username. Because this convention is identical
to the sibling tool's, any Keychain item already created for that tool works here
unchanged.

## 2FA / token (not tested)

The validated profile had no 2FA, so the token flow was not exercised. From the
renderer code, a profile that requires an OTP/token has the GUI re-issue `ConnectTunnel`
with a `token` field (for example `"FTM_PUSH_CLICKED"`), or call `SendToken(...)`. The
exact sequence remains to be confirmed against a 2FA-enabled profile.

## Hiding the window on connect

`--hide-gui` only suppresses FortiClient's window at startup. On a successful connect the
renderer calls `focusWindow()` and the main window pops up (with the Disconnect button) —
`--hide-gui` does not gate that path.

A *second* preload bridge, `window.forticlient`, is exposed in the same renderer world as
`window.guimessenger`, so it can be driven the same way over CDP. It includes window
controls:

- `window.forticlient.closeMainWindow()` — closes the main window; the window's `close`
  handler is intercepted into `hide()`, so it goes to the **tray without quitting the app**.
- `window.forticlient.focusMainWindow()` — shows/raises the window (what connect triggers).
- `window.forticlient.isMainWindowVisible()` — whether it is currently visible.
- `window.forticlient.quit()` — **maps to `app.quit()` and quits FortiClient entirely**
  (not just the window); do not confuse it with `closeMainWindow()`.

So the post-connect popup is hidden by calling `window.forticlient.closeMainWindow()` over
CDP — no patching of the app, and the CDP session and the tunnel are unaffected. (Verified
live: focus → visible, close → hidden, CDP still alive.)

## Notes and gotchas

- **Stale `DevToolsActivePort`.** Do not read the debug port from
  `~/Library/Application Support/FortiClient/DevToolsActivePort`; it can be left over
  from a previous launch. Probe `http://127.0.0.1:<port>/json` instead.
- **JSON-argument requirement.** `getConnectionIP`, `getConnectionInfo`, and
  `GetIPSecGeneralInfo` must be called with a `JSON.stringify({...})` argument; without
  it they fail with "Error in native callback".
- **`SetGuiHandle()` before `ConnectTunnel`.** Otherwise the daemon acknowledges the
  connect but never negotiates, and the state stays at `0`.
- **Restart drops the tunnel.** Restarting (or switching modes of) FortiClient tears
  down any active tunnel, so the tool is deliberately attach-only and never starts,
  stops, or restarts the process.
- **Raw-WebSocket CDP client (node v20 rationale).** The CDP client is implemented as a
  dependency-free raw WebSocket. Node v20 on the validation machine has no global
  `WebSocket`, which is why the client was built directly on a stdlib socket rather than
  relying on a runtime-provided WebSocket.
