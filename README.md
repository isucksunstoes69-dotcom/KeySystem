# MC License System

A cryptographically-signed licensing / HWID-lock system for Minecraft **Fabric**
mods (works unchanged for Bukkit/Velocity too — the client is pure JDK).

Modelled on the KeyAuth-style layout you referenced (HWID grabber, session,
auth client), but hardened: **every server response is Ed25519-signed and bound
to the requesting machine + a one-time nonce.** Redirecting the license domain
to a fake "always valid" server does **not** work, because the attacker cannot
forge a signature without the private key.

Verified: `dev.license.Demo` runs the real server over localhost and asserts
**16/16** security properties (see “Testing”).

---

## How it works

```
  ┌─────────────── your Fabric mod (ships PUBLIC key only) ───────────────┐
  │ HWIDGrabber ── hwid                                                    │
  │ Protection.enforce() ─► AuthClient ── POST product,key,hwid,nonce ───► │
  │                                                                        │
  │            ◄── signed{valid,reason,expiry,uid,…,nonce,signature} ──────┤
  │ AuthClient.verify():                                                    │
  │   1 echoed key/hwid/nonce == what we sent   (no replay/cross-machine)  │
  │   2 Ed25519 signature valid (embedded pubkey) (no forged server)       │
  │   3 issuedAt is fresh                         (bounded replay window)   │
  │   4 valid == true, not expired                                         │
  └────────────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │  holds PRIVATE key, signs answers
                     ┌──────────────┴───────────────┐
                     │  LicenseServer (JDK HttpServer)│
                     │  LicenseAuthority + LicenseStore│  licenses.properties
                     └────────────────────────────────┘
```

**Binding model:** auto-bind to the first HWID that activates a key. Move a
customer to a new PC with `rebind`. Optional manual HWID allowlist per key.
Keys support expiry and revocation.

---

## Which files go where

**Ship inside the mod (client-side, public):**
`Canonical.java`, `Crypto.java`, `Form.java`, `HWIDGrabber.java`, `Session.java`,
`LicenseRequest.java`, `LicenseResponse.java`, `LicenseResult.java`,
`AuthClient.java`, `Protection.java`  — plus your entrypoint (see
`fabric-integration/`). No extra dependencies; nothing to shade.

**Server only (NEVER ship these, they don't need to be secret but keep them
off the client):**
`LicenseStore.java`, `LicenseAuthority.java`, `LicenseServer.java`, `KeyGen.java`.

**Secret:** `privatekey.txt` lives on the server only. If it leaks, anyone can
mint valid licenses — rotate keys immediately.

---

## Setup

Requires JDK 17+ (Ed25519 needs 15+; MC 1.20.5/1.21 uses Java 21).

Data is stored in **SQLite** (`data/license.db`) via the bundled `lib/sqlite-jdbc`
driver, so every command has `lib/*` on the classpath. Classpath separator is
`;` on Windows and `:` on Linux/macOS — examples below use `:`.

### 1. Generate keys
```
javac -cp "lib/*" -d out src/dev/license/*.java
java  -cp "out:lib/*" dev.license.KeyGen server/publickey.txt server/privatekey.txt
```
(On Windows: `.\build.cmd`, or use `out;lib/*`.)

### 2. Run the server
```
export LICENSE_ADMIN_TOKEN="$(head -c 32 /dev/urandom | base64)"   # keep this
LICENSE_PORT=8080 \
LICENSE_PRIVATE_KEY_FILE=server/privatekey.txt \
LICENSE_PUBLIC_KEY_FILE=server/publickey.txt \
LICENSE_DB=data/license.db \
java -cp "out:lib/*" dev.license.LicenseServer
```
(On Windows just double-click `run-server.cmd`.)

> **Put it behind TLS.** The built-in server speaks plain HTTP. In production
> run it behind nginx/Caddy (or Cloudflare) terminating HTTPS, and point the mod
> at `https://…`. TLS isn’t what makes this secure (the signature is), but it
> stops key/HWID snooping and tampering with the transport.

### 3. Wire up the mod
- Copy the client-side `dev.license` classes into your mod source.
- Copy an entrypoint from `fabric-integration/` (`ExampleClientInit` or
  `ExampleServerInit`), set `BASE_URL`, `PRODUCT`, `MOD_VERSION`, and paste
  `publickey.txt` into `PUBLIC_KEY`.
- Merge `fabric.mod.json.snippet` into your `fabric.mod.json`.
- Gate every feature behind `FEATURES_ENABLED`.

### 4. Sell a license
```
cd server
LICENSE_ADMIN_TOKEN=... ./admin.sh create MyMod "Buyer Name" buyer@email.com 30
# -> created 86VTL-MSKVV-Q9Z95-TUC2F
```
Give that key to the buyer; they paste it into `config/mymod-license.txt`.

---

## Web dashboard

The server also serves a browser dashboard (the FEZ-themed UI in `web/`) from the
same origin as the API — no CORS, no second host. Create / list / revoke / rebind
licenses from a purple admin panel instead of curl.

Run it:
```
export LICENSE_ADMIN_TOKEN="your-secret-token"
LICENSE_PRIVATE_KEY_FILE=server/privatekey.txt \
LICENSE_DB=data/license.db \
LICENSE_WEB_DIR=web \
java -cp "out:lib/*" dev.license.LicenseServer
```
Open `http://localhost:8080/`, log in with that admin token, and you get:
- live stats (total / active / revoked / expired),
- searchable, filterable license cards (copy key, revoke, rebind),
- a "New License" modal with an animated create button.

The login just stores the admin token in the browser and sends it as
`X-Admin-Token`. **Run behind HTTPS in production** (nginx/Caddy) so the token
isn't sent in the clear. Set `LICENSE_WEB_DIR` to disable/relocate the UI; if the
dir is absent the dashboard is simply off and only the API runs.

> A ready-to-run preview launcher is at `../.claude/launch.json` (name
> `license-server`, port 8090, dev token `previewtoken`). Change the token before
> exposing it anywhere.

## Admin API

All admin calls require header `X-Admin-Token: <token>`.
Add `format=json` (query or form field) to `create` / `list` / `revoke` /
`rebind` to get JSON back (what the dashboard uses); omit it for plain text.

| Method | Path | Form fields | Purpose |
|---|---|---|---|
| POST | `/api/admin/create` | `product, owner, email, days` (0=perpetual), opt `hwid` | make a key |
| POST | `/api/admin/revoke` | `licenseKey` | kill a key |
| POST | `/api/admin/rebind` | `licenseKey` | clear bound HWID (move PC) |
| GET  | `/api/admin/list`   | — | list all keys |
| POST | `/api/validate` (public) | `product, licenseKey, hwid, nonce` | what the mod calls |

Helper: `server/admin.sh` (bash/curl) wraps all of these.

### Rejection reasons (`result.reason`)
`OK`, `UNKNOWN_KEY`, `REVOKED`, `PRODUCT_MISMATCH`, `EXPIRED`, `HWID_MISMATCH`,
`BAD_SIGNATURE`, `ECHO_*`, `STALE_RESPONSE`, `NETWORK_ERROR`, `BAD_CONFIG`.

---

## Resellers & the download API (multi-tenant)

Resellers are tenants who resell your products. The super-admin (you) creates a
reseller; each gets an **API key** and their own panel at `/reseller.html`, and
only ever sees their own licenses.

Flow: a reseller uploads their mod `.jar`, then points their store/downloader at
the download API. Each customer download **bakes a unique key into the jar** (a
`license.key` entry) and is **idempotent per customer** — the same customer
always gets the same key.

**Super-admin (X-Admin-Token):**
```
./admin.sh reseller-create "Cheat Co"     # -> {"id":"rs_...","apiKey":"rk_..."}
./admin.sh reseller-list
```
Or use the admin panel → **Resellers** → **New Reseller** (the API key is shown
once — copy it).

**Reseller API (header `X-Api-Key: rk_...`):**
| Method | Path | Params | Purpose |
|---|---|---|---|
| POST | `/api/reseller/upload?product=NAME` | body = raw `.jar` | upload/replace a product jar |
| POST | `/api/reseller/download` | `product, customer` | mint-or-reuse a key, return the keyed jar (`X-License-Key` header) |
| POST | `/api/reseller/reset` | `product, customer` | customer HWID self-reset, once / 7 days (429 on cooldown) |
| GET  | `/api/reseller/licenses` | — | this reseller's licenses (JSON) |
| GET  | `/api/reseller/me` | — | reseller id + name |

**Downloader integration** (what a reseller wires into their store):
```
curl -X POST "https://your-server/api/reseller/download?product=MyMod&customer=ORDER_ID" \
  -H "X-Api-Key: rk_..." -o MyMod.jar
```
The returned jar is self-licensing — the mod reads `/license.key` from its own jar
(the `readLicenseKey()` in the fabric examples checks that resource first, then
falls back to `config/mymod-license.txt` for manual installs).

Server dirs/env: resellers/licenses/users/bans all live in the SQLite db
(`LICENSE_DB`); uploaded jars under `LICENSE_DOWNLOADS_DIR`
(default `downloads/<resellerId>/<product>.jar` + `.injected.jar`).

## Accounts, auth API & bans (KeyAuth-style)

On top of bare-key validation there's an optional account layer: end users can
**register / login with username + password + a license key**, or keep using a
bare key. Every path that grants access still returns the **Ed25519-signed
license**, so the SDK verifies it — a spoofed server can't fake a login.

**Auth endpoint** — `POST /api/auth`, `type` selects the action (KeyAuth-shaped
JSON `{success, status, message, license:{…signed…}}`):

| type | params | purpose |
|---|---|---|
| `init` | `name, ver` | handshake; returns a `sessionid` |
| `license` | `key, hwid` | bare license key check |
| `register` | `username, pass, key, hwid` | create account bound to a key |
| `login` | `username, pass, hwid` | log in; returns the signed license |
| `check` | `sessionid` | lightweight session ping |

**Java SDK** ([KeyAuthClient.java](src/dev/license/KeyAuthClient.java)):
```java
KeyAuthClient auth = new KeyAuthClient(BASE_URL, PUBLIC_KEY, 300_000L);
auth.init("MyMod", "1.0");
KeyAuthClient.AuthResult r = auth.login("bob", "secret");   // or register(...) / license(key)
if (r.ok) enableFeatures(r.session);   // r.session is populated only after the signature verifies
```

**Bans** (super-admin) — refused at register/login/license:
```
./admin.sh ban  hwid  <hwid>  "chargeback"
./admin.sh ban  user  bob
./admin.sh unban user  bob
./admin.sh bans
```
Accounts and bans live in the SQLite db (`LICENSE_DB`). Passwords are stored as
salted PBKDF2 hashes.

## Deploying (Docker + SQLite volume)

Vercel/serverless can't run this (it's a stateful JVM app that needs a JDK for
injection + a persistent disk). Use a Docker host — **Railway, Render, or Fly** —
with a volume mounted at `/data` (holds the SQLite db + uploaded jars).

1. Generate keys locally: `java -cp "out:lib/*" dev.license.KeyGen`.
2. Deploy the `Dockerfile`. Set these as **secrets/env vars** on the host:
   - `LICENSE_ADMIN_TOKEN` — your master token
   - `LICENSE_PRIVATE_KEY` — contents of `privatekey.txt` (base64; **secret**)
   - `LICENSE_PUBLIC_KEY` — contents of `publickey.txt` (base64)
   - `LICENSE_PUBLIC_URL` — the public https URL the mods call back to
     (e.g. `https://you.up.railway.app`)
3. Add a **volume mounted at `/data`** (the Dockerfile points `LICENSE_DB` and
   `LICENSE_DOWNLOADS_DIR` there).
4. The static dashboards can also be hosted on **Vercel** if you prefer — point
   their fetches at this backend's URL.

Platform notes: **Railway/Render** — add the repo, they build the `Dockerfile`,
then add a volume + the env vars in the dashboard. **Fly** — see
`deploy/fly.toml`; `fly volumes create license_data --size 1`, `fly secrets set …`,
`fly deploy`. Keys/token are never baked into the image (`.dockerignore` excludes
them); they arrive as env vars at runtime.

## Testing
```
java -cp "out:lib/*" dev.license.Demo         # core        (Windows: out;lib/*)
java -cp "out:lib/*" dev.license.ResellerDemo  # reseller/download API
java -cp "out:lib/*" dev.license.AuthDemo      # accounts + bans
java -cp "out:lib/*" dev.license.InjectDemo    # jar injection (class-loads + enforces)
```
`Demo` checks: valid auto-bind, HWID mismatch, unknown key, tampered signature,
nonce replay, **forged (wrong-key) server**, stale response, server + client
expiry, revoke, product mismatch, network-fail-closed, and the `Protection`
façade. All four suites exit 0 when green (53 checks total).

---

## Honest threat model — read this

This stops **casual** piracy (sharing a key, running on many PCs, a fake auth
server, replay). It does **not** make client-side code uncrackable — that is
impossible. A skilled person can decompile the mod and delete the license check.
Mitigations, strongest first:

1. **Keep real logic server-side.** The strongest protection: have the license
   server return data/config the mod genuinely needs to work (not just a
   yes/no). Then a cracked client is missing functionality, not just a check.
2. **Obfuscate** the released jar (e.g. via your build) so the check isn’t a
   one-line patch, and scatter/duplicate the `FEATURES_ENABLED` checks.
3. **Rotate keys** if `privatekey.txt` ever leaks.
4. **Rate-limit** `/api/validate` and log HWIDs per key to spot sharing.

Also: pick your offline policy deliberately. The examples fail-closed (no
verified response → disabled), with keep-alive that ignores transient network
errors so a brief outage won’t kick paying users.
