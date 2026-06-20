# SPIKE — sterowanie FortiClientem przez CDP (bez automatyzacji GUI)

**Zweryfikowane empirycznie 2026-06-20 na FortiClient 7.4.3.4323, macOS.**
**Wynik: SUKCES** — pełny connect / status / (dis)connect IPsec sterowalny headless
przez Chrome DevTools Protocol → `window.guimessenger`, bez klikania w GUI.

## 1. Uruchomienie instancji z CDP

```bash
# singleInstanceLock przekazuje argv do pierwszej instancji, więc najpierw ubij:
osascript -e 'tell application "FortiClient" to quit'
# poczekaj aż znikną procesy Contents/MacOS/FortiClient*, potem:
/Applications/FortiClient.app/Contents/MacOS/FortiClient --hide-gui --remote-debugging-port=9222
```

- Target renderera: `GET http://127.0.0.1:9222/json` → jeden `page` (`base.html`),
  użyj jego `webSocketDebuggerUrl`.
- **UWAGA:** `~/Library/Application Support/FortiClient/DevToolsActivePort` bywa
  **nieaktualny** (zostaje po poprzednim uruchomieniu) — nie ufaj mu, sonduj port.
- Restart FortiClienta **zrywa aktywny tunel** (potwierdzone: po quit `ipsec_state=0`).

## 2. API renderera (`window.guimessenger`)

Wszystkie wołane przez `Runtime.evaluate` z `awaitPromise:true, returnByValue:true`.
Metody zwracają Promise → **string JSON** (parsuj `JSON.parse`).

| Cel | Wywołanie | Zwraca |
|-----|-----------|--------|
| Lista profili | `GetVPNConnectionList()` | `[{connection_name, type:"ipsec"\|"ssl", cloud_vpn, corporate}]` |
| Info profilu | `GetIPSecGeneralInfo(JSON.stringify({connection_name, connection_type:"ipsec"}))` | `{remote_gateway, username, authentication, authentication_method, sso_enabled, save_password, ...}` |
| Stan | `getConnectionState()` | `{ipsec_state, ssl_state, connection_name, saml_vpn_name}` |
| Statystyki | `getConnectionInfo(JSON.stringify({connection_name, connection_type}))` | `{duration, traffic_in, traffic_out}` |
| IP tunelu | `getConnectionIP(JSON.stringify({connection_name, connection_type}))` | `{vpn_ip}` — **wymaga argu JSON**, inaczej "Error in native callback" |
| Użytkownik | `getVPNUserName()` | `{username}` |

Stany połączenia: `0=DISCONNECTED 1=CONNECTING 2=CONNECTED 3=XAUTH 4=RECONNECTING`.
`connection_type` to stringi **`"ipsec"` / `"ssl"`**.

## 3. Połączenie (ZWERYFIKOWANE)

Kolejność jest istotna — odtworzona z `onConnect` w `bundle.min.js`:

```js
// 1) NAJPIERW zarejestruj uchwyt GUI — bez tego ConnectTunnel zwraca ["1"],
//    ale demon nie rusza negocjacji i stan zostaje na 0.
window.guimessenger.SetGuiHandle()                       // -> true

// 2) Hasło + username lecą OD RAZU w obiekcie (ścieżka nie-SSO, getConnObj):
window.guimessenger.ConnectTunnel(JSON.stringify({
  connection_name: "<Profil>",
  connection_type: "ipsec",
  username: "<user>",
  password: "<hasło z Keychaina>",
  save_password: "0",
  always_up:    "0",
  auto_connect: "0",
  saml_error:   1
}))                                                      // -> ["1"] (ack)

// 3) Poll getConnectionState() aż ipsec_state==2.
```

- Dla profilu z `authentication:"save"` i bez 2FA **XAUTH domyka się bez formularza GUI**
  (potwierdzone: stan przeszedł 0→2 natychmiast).

## 4. Rozłączenie / anulowanie

```js
window.guimessenger.DisconnectTunnel(JSON.stringify({connection_name, connection_type}))
window.guimessenger.CancelTunnel()   // przerwanie trwającego connectu
```

## 5. 2FA / token (NIE testowane — office bez 2FA)

Jeśli profil wymaga OTP/tokenu, GUI ponawia `ConnectTunnel` z polem `token`
(np. `"FTM_PUSH_CLICKED"`) lub woła `SendToken(...)`. Do ustalenia przy profilu z 2FA.

## 6. Poświadczenia

Konwencja z repo AppleScript (potwierdzona, działa):
```bash
security find-generic-password -s forti-vpn-<Profil> -a <username> -w
```

## 7. Narzędzia spike (na razie w /tmp, do przeniesienia przy budowie CLI)

- `cdp_eval.py` — bezzależnościowy klient CDP (surowy WebSocket; **node v20 nie ma
  globalnego `WebSocket`**, stąd Python).
- `forti_connect.py` — SetGuiHandle → ConnectTunnel (hasło z Keychaina, nigdy nie
  trafia do argv/env/logów) → polling stanu.
- `relaunch_forti.sh` — czysty restart do trybu headless+debug.

## 8. Pełna powierzchnia API

139 metod `window.guimessenger` (m.in. `CreateProfileVPN`, `DeleteProfileVPN`,
`RenameProfileVPN`, `ImportVPNConfig`, `UpdateVPNOptions`, `verifyPassword`).
Pełną listę można odtworzyć z `bundle.min.js` (`(e=window.guimessenger).X.apply`).
