# Design: `fortivpn` — Python library + `forti` CLI controlling FortiClient via CDP

**Date:** 2026-06-20
**Status:** Approved (brainstorming)
**Validated foundation:** see [`SPIKE.md`](../../../SPIKE.md) — the control path below was
exercised empirically on a live tunnel (FortiClient 7.4.3.4323, macOS).

## 1. Goal

A macOS command-line tool (and reusable Python library) that connects, disconnects,
and reports status of FortiClient IPsec VPN profiles **without any GUI automation** —
driving the Electron renderer's internal `window.guimessenger` API over the Chrome
DevTools Protocol (CDP). Separate project from the AppleScript/AX variant
(`~/Programowanie/fortivpn-cli-macos`).

## 2. Scope

### In scope (v1)
- **Attach-only** CDP client: connects to an already-running FortiClient that was
  launched with `--remote-debugging-port`. The tool never starts, stops, or restarts
  FortiClient.
- IPsec profiles with credentials in the login Keychain, **no 2FA** (the validated case).
- Commands: `list`, `status`, `connect`, `disconnect`, `ip`.
- Zero runtime dependencies (Python stdlib only).

### Out of scope (v1) — explicit non-goals
- **Lifecycle management / autostart.** No `setup`/`up`/`down`, no LaunchAgent command.
  README ships a sample LaunchAgent plist for the user to install manually.
- **SSL VPN.** Untested in the spike; `connect` on an `ssl` profile raises
  `UnsupportedError`.
- **2FA / token / OTP.** If the daemon enters the `XAUTH` state, `connect` raises
  `UnsupportedError("2FA not supported in v1")` rather than prompting.
- **Default profile / config file.** Profile name is always passed explicitly.
- **Profile management** (create/delete/rename/import), even though the API exposes it.

## 3. Validated foundation (from spike)

- Launch (user's responsibility): `FortiClient --hide-gui --remote-debugging-port=9222`.
- Renderer target: `GET http://127.0.0.1:<port>/json` → the single `page`
  (`base.html`); use its `webSocketDebuggerUrl`.
- All `window.guimessenger` methods are invoked via `Runtime.evaluate`
  (`awaitPromise:true, returnByValue:true`) and return a **Promise → JSON string**.
- Connect sequence (order matters): **`SetGuiHandle()` first** (without it
  `ConnectTunnel` returns `["1"]` but the daemon never negotiates and state stays `0`),
  then `ConnectTunnel(JSON.stringify(obj))`, then poll `getConnectionState()`.
- `connection_type` is `"ipsec"` / `"ssl"`. State enum:
  `0=DISCONNECTED 1=CONNECTING 2=CONNECTED 3=XAUTH 4=RECONNECTING`.
- `getConnectionIP` / `getConnectionInfo` / `GetIPSecGeneralInfo` require a JSON arg
  `JSON.stringify({connection_name, connection_type})`.
- Node on this machine is v20 (no global `WebSocket`) → CDP client is a stdlib raw
  WebSocket implementation.

## 4. Architecture

Five small, independently-testable modules under `src/fortivpn/`:

### 4.1 `cdp.py` — `CDPSession` (transport, VPN-agnostic)
Promotion of the spike's `cdp_eval.py`. Dependency-free raw-WebSocket CDP client.

```
class CDPSession:
    def __init__(self, port: int = 9222, host: str = "127.0.0.1"): ...
    def connect(self) -> None              # discover renderer target via /json, open WS
    def evaluate(self, expression: str, await_promise: bool = True) -> Any
                                           # returnByValue; returns parsed JS value
    def close(self) -> None
    def __enter__/__exit__                  # context manager
```
- `connect()` raises `NotRunningError` when the port is unreachable or no debuggable
  `page` target exists.
- `evaluate()` raises `CDPEvaluateError` when the renderer reports `exceptionDetails`.
- Knows nothing about VPN — pure transport.

### 4.2 `controller.py` — `FortiVPN` (the `window.guimessenger` contract)
Wraps a `CDPSession`; encodes the validated flow and the v1 guards.

```
@dataclass
class Profile: name: str; type: str; raw: dict
@dataclass
class ConnectionState: ipsec_state: int; ssl_state: int; name: str; raw: dict
    @property state_label: str           # mapped enum name

class FortiVPN:
    def __init__(self, session: CDPSession): ...
    def profiles(self) -> list[Profile]                       # GetVPNConnectionList
    def profile_info(self, name: str, ctype="ipsec") -> dict  # GetIPSecGeneralInfo
    def state(self) -> ConnectionState                        # getConnectionState
    def connection_ip(self, name, ctype) -> dict              # getConnectionIP
    def connection_info(self, name, ctype) -> dict            # getConnectionInfo
    def connect(self, name, *, username=None, password=None,
                wait=True, timeout=30.0, poll=1.0) -> ConnectionState
    def disconnect(self, name, ctype="ipsec") -> None         # DisconnectTunnel
    def cancel(self) -> None                                  # CancelTunnel
```

`connect()` algorithm:
1. Resolve the `Profile`; if `type != "ipsec"` → `UnsupportedError`.
2. `username` ← arg or `profile_info(name)["username"]`.
3. `password` ← arg or `keychain.get_password(name, username)`.
4. `SetGuiHandle()` (assert truthy).
5. `ConnectTunnel(JSON.stringify({connection_name, connection_type:"ipsec", username,
   password, save_password:"0", always_up:"0", auto_connect:"0", saml_error:1}))`.
6. If `wait`: poll `state()` until `ipsec_state==2` (→ return), `==3` (XAUTH) →
   `UnsupportedError("2FA not supported in v1")`, or back to `0` after activity →
   `ConnectFailed`; on timeout → `ConnectTimeout`.
   The password is held only in a local; never logged.

### 4.3 `keychain.py`
```
def get_password(profile: str, username: str) -> str
```
Runs `security find-generic-password -s forti-vpn-<profile> -a <username> -w`.
Non-zero exit → `KeychainError` with guidance (how to add the item). Returns the
secret to the caller only; nothing printed.

### 4.4 `errors.py`
`FortiError` (base) → `NotRunningError`, `CDPEvaluateError`, `UnsupportedError`,
`KeychainError`, `ConnectFailed`, `ConnectTimeout`. Each carries a human message.

### 4.5 `cli.py` — `main()` (argparse, stdlib)
Subcommands map 1:1 to controller calls. Global options: `--port` (default 9222,
overridable by `FORTI_CDP_PORT`), `--host`. Per-command `--json` for `list`/`status`.
Top-level handler catches `FortiError`, prints the message to stderr, and exits with
the mapped code. No silent excepts; suppression only with a narrow type + comment.

## 5. CLI specification

| Command | Behaviour | Output (human) | `--json` |
|---------|-----------|----------------|----------|
| `forti list` | `profiles()` | table: name, type, server (`remote_gateway` via `profile_info`) | array of profile dicts |
| `forti status` | `state()`; if connected, derive `connection_name`/`type` from it and add `connection_info`/`connection_ip` | `CONNECTED office 172.16.200.2 (00:01:45, ↓1.6KB ↑0)` or `DISCONNECTED` | state dict |
| `forti connect <profile> [-u USER] [--no-wait] [--timeout S]` | `connect()` | progress line(s) → `CONNECTED <profile> <vpn_ip>` | — |
| `forti disconnect <profile>` | `disconnect()` | `DISCONNECTED <profile>` | — |
| `forti ip` | read `state()`; if `ipsec_state==2`, `connection_ip(name, "ipsec")` using that state's `connection_name`; else exit non-zero with "not connected" | `172.16.200.2` | — |

### Exit codes
`0` success · `2` usage (argparse) · `3` `NotRunningError` · `4` `KeychainError` ·
`5` `UnsupportedError` · `6` `ConnectFailed` / `CDPEvaluateError` · `7` `ConnectTimeout` ·
`1` any other `FortiError`.

## 6. Error handling policy

Per the user's global rule: no bare/silent `except`. Every external failure surfaces a
specific `FortiError` subclass with an actionable message; the CLI translates it to a
stderr line + exit code. The only suppression allowed is narrow and commented (e.g.
ignoring `OSError` on socket close during teardown).

## 7. Testing

- **Unit (CI-safe, no FortiClient):**
  - `cdp.py`: WebSocket frame encode/decode across length boundaries (<126, 126, 127)
    and masking; handshake parsing; target discovery against a fake `/json`.
  - `controller.py`: connect-object construction; state parsing + enum mapping; v1
    guards (ssl → `UnsupportedError`, XAUTH → `UnsupportedError`, drop-to-0 →
    `ConnectFailed`). `CDPSession` mocked.
  - `keychain.py`: command construction and error mapping (`subprocess` mocked).
  - `cli.py`: arg routing and exception→exit-code mapping (controller mocked).
- **Attended integration:** `tests/manual/` scripts that hit a real headless+debug
  FortiClient (connect/disconnect/status). Skipped by default (`FORTI_LIVE=1` to run);
  documented as breaking the tunnel.

## 8. Packaging & repo layout

```
fortivpn-cli-via-rdp/
  pyproject.toml          # uv-managed; project.scripts: forti = "fortivpn.cli:main"
  README.md               # usage + sample LaunchAgent plist (headless+debug autostart)
  SPIKE.md                # validated findings (exists)
  .pre-commit-config.yaml # ruff (lint+format)
  src/fortivpn/{__init__,cdp,controller,keychain,errors,cli}.py
  tests/{test_cdp,test_controller,test_keychain,test_cli}.py
  tests/manual/           # attended live tests, skipped by default
  docs/superpowers/specs/2026-06-20-fortivpn-cli-via-cdp-design.md
```
- Tooling: uv + `pyproject.toml`, ruff (lint+format), pre-commit, pytest, Python 3.11+.
- **Zero runtime dependencies** (`socket`, `json`, `urllib`, `subprocess`, `argparse`).

## 9. Future / deferred

SSL VPN support; interactive 2FA (XAUTH state + `token`/`SendToken`, needs an attended
test on a 2FA profile); default-profile config; profile management commands. Each is a
separate spec → plan cycle.
