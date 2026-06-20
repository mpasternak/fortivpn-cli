# Design: `fvpnctl` — Python library + `fvpnctl` CLI for controlling FortiClient VPN

**Date:** 2026-06-20
**Status:** Approved (brainstorming)
**Validated foundation:** see [`docs/how-it-works.md`](../../how-it-works.md) — the
control path below was exercised empirically on a live tunnel (FortiClient 7.4.3.4323,
macOS).

## 1. Goal

A macOS command-line tool (and reusable Python library) that connects, disconnects,
and reports the status of FortiClient IPsec VPN profiles from the terminal **without any
GUI automation** — by attaching to a running FortiClient over its local debugging port.
Separate project from the AppleScript/AX variant (`~/Programowanie/fortivpn-cli-macos`).

## 2. Scope

### In scope (v1)
- **Attach-only by default** CDP client: connects to an already-running FortiClient
  launched with `--remote-debugging-port`. The only command that launches FortiClient is
  the explicit `startserver`; commands never auto-start, quit, or restart it.
- IPsec profiles with credentials in the login Keychain, **no 2FA** (the validated case).
- Commands: `list`, `status`, `connect`, `disconnect`, `ip`, `startserver`, `hide-window`.
- Verbose progress on stderr by default (`--quiet` silences); stdout stays machine-readable.
- FortiClient app detection (powers `startserver` and the actionable not-running guidance).
- Window hiding: `connect` sends FortiClient's window back to the tray (it pops on connect
  even under `--hide-gui`); `--show-window` opts out, plus a standalone `hide-window`.
- Zero runtime dependencies (Python stdlib only).

### Out of scope (v1) — explicit non-goals
- **Automatic lifecycle management.** `startserver` launches FortiClient on explicit
  request, but nothing auto-starts it and the tool never quits or restarts a *running*
  FortiClient. README also ships a LaunchAgent plist for permanent setups.
- **SSL VPN.** Untested in the spike; `connect` on an `ssl` profile raises
  `UnsupportedError`.
- **2FA / token / OTP.** If the daemon enters the `XAUTH` state, `connect` raises
  `UnsupportedError("2FA not supported in v1")` rather than prompting.
- **Default profile / config file.** Profile name is always passed explicitly.
- **Profile management** (create/delete/rename/import), even though the API exposes it.

## 3. Validated foundation

The control path was validated against FortiClient 7.4.x on macOS: a full
connect / status / disconnect cycle was driven through FortiClient's local debugging
port, headless, with no GUI automation. `fvpnctl` attaches to a FortiClient the user
launches with `--remote-debugging-port`, asks it to perform the VPN operation, and reads
back the connection state (a small integer: `0=DISCONNECTED 1=CONNECTING 2=CONNECTED
3=XAUTH 4=RECONNECTING`). The transport is a dependency-free stdlib client (the runtime
FortiClient ships has no global `WebSocket`). See [`docs/how-it-works.md`](../../how-it-works.md)
for the conceptual overview.

## 4. Architecture

Five small, independently-testable modules under `src/fvpnctl/`:

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

### 4.2 `controller.py` — `FortiVPN` (the FortiClient operations)
Wraps a `CDPSession`; maps high-level VPN operations onto FortiClient and encodes the
v1 guards.

```
@dataclass
class Profile: name: str; type: str; raw: dict
@dataclass
class ConnectionState: ipsec_state: int; ssl_state: int; name: str; raw: dict
    @property state_label: str           # mapped enum name

class FortiVPN:
    def __init__(self, session: CDPSession): ...
    def profiles(self) -> list[Profile]
    def profile_info(self, name: str, ctype="ipsec") -> dict
    def state(self) -> ConnectionState
    def connection_ip(self, name, ctype) -> dict
    def connection_info(self, name, ctype) -> dict
    def connect(self, name, *, username=None, password=None,
                wait=True, timeout=30.0, poll=1.0) -> ConnectionState
    def disconnect(self, name, ctype="ipsec") -> None
    def cancel(self) -> None
```

`connect()` algorithm:
1. Resolve the `Profile`; if `type != "ipsec"` → `UnsupportedError`.
2. `username` ← arg or `profile_info(name)["username"]`.
3. `password` ← arg or `keychain.get_password(name, username)`.
4. Register the session with FortiClient (a required pre-step — without it the daemon
   accepts the request but never starts negotiating).
5. Submit the connect request to FortiClient with the profile, type, username, password
   and the relevant connect options.
6. If `wait`: poll `state()` every `poll`s until `ipsec_state==2` (→ return);
   `==3` (XAUTH) → `UnsupportedError("2FA not supported in v1")`; dropped back to `0`
   *after* having reached a non-zero state → `ConnectFailed`; if `timeout` elapses
   first — **including the state never leaving `0`** (silent rejection) → `ConnectTimeout`.
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
| `fvpnctl list` | `profiles()` | table: name, type, server (`remote_gateway` via `profile_info`) | array of profile dicts |
| `fvpnctl status` | `state()`; if connected, derive `connection_name`/`type` from it and add `connection_info`/`connection_ip` | `CONNECTED office 172.16.200.2 (00:01:45, ↓1.6KB ↑0)` or `DISCONNECTED` | state dict |
| `fvpnctl connect <profile> [-u USER] [--no-wait] [--timeout S]` | `connect()` | progress line(s) → `CONNECTED <profile> <vpn_ip>` | — |
| `fvpnctl disconnect <profile>` | `disconnect()` | `DISCONNECTED <profile>` | — |
| `fvpnctl ip` | read `state()`; if `ipsec_state==2`, `connection_ip(name, "ipsec")` using that state's `connection_name`; else exit `1` with "not connected" on stderr | `172.16.200.2` | — |

### Exit codes
`0` success · `2` usage (argparse) · `3` `NotRunningError` · `4` `KeychainError` ·
`5` `UnsupportedError` · `6` `ConnectFailed` / `CDPEvaluateError` · `7` `ConnectTimeout` ·
`8` `FortiClientNotFoundError` · `1` any other `FortiError`.

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
  pyproject.toml          # uv-managed; project.scripts: fvpnctl = "fvpnctl.cli:main"
  README.md               # usage + sample LaunchAgent plist (headless+debug autostart)
  .pre-commit-config.yaml # ruff (lint+format)
  src/fvpnctl/{__init__,cdp,controller,keychain,errors,cli}.py
  tests/{test_cdp,test_controller,test_keychain,test_cli}.py
  tests/manual/           # attended live tests, skipped by default
  docs/how-it-works.md    # validated control path / "why it works"
  docs/superpowers/specs/2026-06-20-fortivpn-cli-via-cdp-design.md
```
- Tooling: uv + `pyproject.toml`, ruff (lint+format), pre-commit, pytest, Python 3.11+.
- **Zero runtime dependencies** (`socket`, `json`, `urllib`, `subprocess`, `argparse`).

## 9. Documentation (how **and** why)

Documentation is a first-class deliverable, not an afterthought. Every artifact must
explain **how** it works *and* **why** it is built that way — rationale, not just usage.

- **README.md** — what the tool does and **why this approach** (attach-only, no GUI
  automation; why FortiClient must run headless + `--remote-debugging-port`); setup
  **how-to** (sample LaunchAgent plist, adding the `forti-vpn-<profile>` Keychain item);
  per-command usage; the security note (credentials never logged / not in argv/env);
  links to `docs/how-it-works.md` as the "why it works" reference.
- **Module docstrings** — each module opens with a docstring covering its purpose, how
  it works, and the *why* behind non-obvious choices: `cdp.py` (a dependency-free
  stdlib transport, because the runtime FortiClient ships lacks a global `WebSocket`),
  `controller.py` (why the session must be registered with FortiClient before the connect
  call — otherwise the daemon won't begin negotiating).
- **Inline comments** — for every empirically-derived constant or ordering that a reader
  couldn't infer from the code alone, with a one-line "why" (and a pointer to
  `docs/how-it-works.md`).
- **Docstrings on public functions/classes** — describe contract, returns, and raised
  errors.

## 10. Future / deferred

SSL VPN support; interactive 2FA (needs an attended test on a 2FA profile);
default-profile config; profile management commands. Each is a separate spec → plan cycle.
