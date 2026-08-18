# Spike 2a — WebAuthn ES256 + PRF from an MV3 extension origin

Task: `.superpowers/sdd/2026-08-18-warden-phase0-scaffold-spikes/task-3-brief.md`.

## Part (a) — automated (virtual authenticator) results

**Result: PASS.** `spikes/02-webauthn/out/assertion.json` was produced by a real
`navigator.credentials.create()` / `.get()` round-trip against a CDP virtual
authenticator, from an actual `chrome-extension://` origin, ES256-only,
PRF extension included.

- **Extension origin / RP ID used:** `chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi`
  — `rpId` in the credential request equals `location.hostname`, i.e. the
  extension id itself (`maikadpaobbjkmaomnpnhjglpabllaoi`), matching the
  brief's design (extension ids are valid WebAuthn RP IDs from a
  `chrome-extension://` origin — Chrome does not require an RP ID to look like
  a DNS name for non-http(s) origins).
- **alg −7 (ES256) confirmed:** `create()` response's
  `getPublicKeyAlgorithm()` returned `-7`; asserted in the test
  (`expect(created.alg).toBe(-7)`). `pubkeyDerSpki` decodes to a 91-byte
  SPKI DER blob, the expected size for an uncompressed P-256 public key
  wrapped in the standard EC SPKI header.
- **PRF enabled?** Yes, in the virtual-authenticator harness:
  `WebAuthn.addVirtualAuthenticator` accepted `hasPrf: true` on this Chromium
  build (no fallback needed), `getClientExtensionResults().prf.enabled` was
  `true` on create, and `prf.results.first` was present (32 bytes, base64) on
  get — `out/assertion.json`'s `prfFirst` is non-null. **This only proves the
  virtual (software-simulated) authenticator implements PRF correctly — it
  is not evidence a real platform authenticator (Touch ID / Windows Hello /
  synced Google Password Manager passkey) supports PRF from an extension
  origin.** That must be checked on real hardware — see the owner checklist
  in part (b) below.
- **Exact `origin` string in `clientDataJSON`** (needed by Task 4):
  ```json
  {"type":"webauthn.get","challenge":"-_m3j03gLOyF_VbZ-QSLy5ZDPLbDWNoc3lUIiHR8yFo","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}
  ```
  i.e. `origin` = `"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"` — no
  trailing slash, no port. Task 4's on-chain/off-chain verifier must expect
  this exact non-HTTPS scheme string in `clientDataJSON.origin` (and match it
  against `rpId` = the extension id, not a domain).
- **Full `out/assertion.json`:**
  ```json
  {
    "pubkeyDerSpki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAED74+mIYAAUqbVJMlzptEN2xrwWqsVYjaKNcGXuwhmi/rm9y+0rFnbzxBxgXIbGDYQ6e5pM0H8D7oUFfbuUrkVQ==",
    "authenticatorData": "vlxK98up2TYOCUeXAktaOj3Z9DeqmFIpFlbntbXZ2jQFAAAAAg==",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiLV9tM2owM2dMT3lGX1ZiWi1RU0x5NVpEUExiRFdOb2MzbFVJaUhSOHlGbyIsIm9yaWdpbiI6ImNocm9tZS1leHRlbnNpb246Ly9tYWlrYWRwYW9iYmprbWFvbW5wbmhqZ2xwYWJsbGFvaSIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
    "signatureDer": "MEQCIGhzDn7bjCDl24UaXitT7KSYeNmWOWlEvzjvs6669BbfAiBNgW0qf77sTBnuXQ0DH0+Ybu+SCNfJwiv0YWGu9cyr9Q==",
    "challenge": "-_m3j03gLOyF_VbZ-QSLy5ZDPLbDWNoc3lUIiHR8yFo",
    "prfFirst": "sMJ2avSSpAAqmHP+QcsXhnb6SjCrGlOA0W6Xrqr3+HU=",
    "origin": "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
    "rpId": "maikadpaobbjkmaomnpnhjglpabllaoi",
    "virtualAuthenticatorId": "96750731-2188-449d-896c-b211038f98c1"
  }
  ```
  Byte lengths (decoded): `pubkeyDerSpki` 91B, `authenticatorData` 37B
  (32B rpIdHash + 1B flags + 4B signCount, no attested-credential-data — as
  expected for a `.get()` assertion), `signatureDer` 70B (ASN.1 DER ECDSA
  signature). Test re-run twice more after the first pass; extension id and
  overall shape were stable across runs.

### Chromium version / caveats

- Installed via `npx playwright install chromium` →
  **Chrome for Testing 151.0.7922.34** (Playwright chromium build `1234`,
  cached at `/root/.cache/ms-playwright/chromium-1234`). This is a very
  recent Chromium; PRF and MV3-extension-in-headless support are both
  new-ish (headless MV3 extension loading landed around Chromium 136+, PRF
  virtual-authenticator support is also recent) — an older pinned Chromium
  may not reproduce this pass.
- `channel: "chromium"` was **dropped** from `launchPersistentContext` (not
  used at all) — this host's Playwright install has no separate "chromium"
  channel binary registered beyond the default install, and the brief
  permits dropping it if it errors; omitting it entirely was simplest and
  worked first try.
- **`hasPrf` on `WebAuthn.addVirtualAuthenticator` was accepted, not
  rejected** — no fallback to "PRF not testable virtually" was needed on
  this Chromium build. (The brief anticipated CDP might reject it; the code
  still contains a `try`/`catch` fallback path that retries without
  `hasPrf` and records `hasPrf accepted by CDP: false` in the test log,
  should a different Chromium build reject it later.)

## Fiddly bits encountered and how they were resolved

1. **Extension id discovery.** Three methods were tried in order, two ruled
   out on this build, one kept:
   - `ctx.backgroundPages()` / `ctx.waitForEvent("serviceworker")` with the
     brief's original zero-permission manifest: **never fires** — an MV3
     extension with no `"background"` key registers no service worker, so
     there is nothing to discover an id from.
   - `page.goto("chrome://extensions")` (and `chrome://extensions/`,
     `chrome://version`, driving the navigation directly via CDP
     `Page.navigate` to route around Playwright's own URL-scheme validation):
     **all fail** with `net::ERR_INVALID_URL` / land on
     `chrome-error://chromewebdata/` — Chrome-for-Testing builds under
     `--headless=new` do not serve `chrome://` WebUI pages at all in this
     configuration. Confirmed by direct CDP experiment (`Page.navigate`
     returns `errorText: "net::ERR_INVALID_URL"` for every `chrome://*` URL
     tried, `about:blank` navigates fine).
   - `cdp.send("Extensions.loadUnpacked", { path: EXT })`: **not available**
     — `'Extensions.loadUnpacked' wasn't found` (this CDP domain/method is
     not implemented in Chromium 151's Chrome-for-Testing build).
   - **Chosen, deterministic method:** the brief explicitly sanctions adding
     a trivial `background.service_worker` to the manifest "ONLY if needed
     to discover the id" — that condition was met, so `ext/manifest.json`
     now declares `"background": { "service_worker": "background.js" }`
     and `ext/background.js` is an empty/comment-only file with no logic.
     The test then does `ctx.waitForEvent("serviceworker")` and reads the
     id from `sw.url().split("/")[2]`. This is 100% deterministic given a
     fixed extension source path (Chrome derives unpacked-extension ids via
     `SHA256(absolute path)` re-alphabetized to `a`–`p`) and was stable
     across three separate test runs (`maikadpaobbjkmaomnpnhjglpabllaoi`
     every time).
2. **`hasPrf` on the virtual authenticator.** Not rejected on Chromium 151 —
   no fallback needed (see above); fallback code path retained regardless.
3. **A second, undocumented-in-the-brief fiddly bit:** passing
   `headless: true` to `chromium.launchPersistentContext(...)` **silently
   breaks extension loading** when `--headless=new` is also present in
   `args` — no error is thrown, the browser simply never loads the
   extension, so no service worker, no popup page, nothing. Confirmed by
   isolated repro: identical launch args with `headless: false` (letting
   `--headless=new` alone drive headless mode) load the extension
   correctly every time; `headless: true` reproducibly does not, even with
   the exact same `args` array. Fix applied: `launchPersistentContext(""，
   { headless: false, args: [..., "--headless=new"] })`. This is called out
   in a comment at the launch site in `test/webauthn.spec.ts`.

## Files changed

- `ext/manifest.json`, `ext/popup.html`, `ext/popup.js` — as specified in the
  brief, plus a trivial `background.service_worker` (see point 1 above).
- `ext/background.js` — new, trivial, comment-only (id-discovery aid).
- `ts/package.json`, `ts/playwright.config.ts` — as specified in the brief.
- `ts/test/webauthn.spec.ts` — as specified in the brief, with the extension-
  id-discovery block replaced by the service-worker method (point 1) and the
  `headless: false` fix (point 3) plus the `hasPrf` try/catch fallback.
- `ts/.gitignore` — local, ignores `node_modules/`, `test-results/`,
  `playwright-report/`.
- `out/assertion.json` — committed; consumed by Task 4.

## Part (b) — manual real-device checklist (owner)

This spike only proves the virtual (CDP-simulated) authenticator path. PRF
support in particular varies by real authenticator/platform and must be
checked by hand:

1. Open `chrome://extensions`, enable Developer Mode, "Load unpacked" →
   select `spikes/02-webauthn/ext`, in **both Chrome and Brave**.
2. Open the extension's popup, click **create** with a **platform
   authenticator** (macOS Touch ID or Windows Hello) — confirm `alg: -7` and
   note `prfEnabled` in the on-screen JSON.
3. Also create a credential using a **Google Password Manager synced
   passkey** (choose "Save to Google Password Manager" instead of the
   platform authenticator when prompted) — repeat step 2's checks.
4. For each of the two credentials, click **get**, and save the full JSON
   shown in the popup as `spikes/02-webauthn/out/assertion-real-<device-or-method>.json`
   (e.g. `assertion-real-macos-touchid.json`, `assertion-real-gpm-synced.json`).
5. Report back whether `prfFirst` was non-null in each case. **If it does not
   arrive, Task 9 must mark PRF as "UNVERIFIED on real devices → Argon2id
   fallback stays in scope."**
