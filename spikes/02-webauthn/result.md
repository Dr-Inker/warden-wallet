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
- **Exact `origin` string in `clientDataJSON`** (needed by Task 4; this is the
  committed `out/assertion.json`'s actual decoded `clientDataJSON`):
  ```json
  {"type":"webauthn.get","challenge":"WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q","origin":"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi","crossOrigin":false}
  ```
  i.e. `origin` = `"chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi"` — no
  trailing slash, no port. Task 4's on-chain/off-chain verifier must expect
  this exact non-HTTPS scheme string in `clientDataJSON.origin` (and match it
  against `rpId` = the extension id, not a domain).
- **`out/assertion.json`** (committed evidence file, byte-for-byte as
  currently committed — do not confuse with any local re-run's output,
  see "Evidence file discipline" below):
  ```json
{
  "pubkeyDerSpki": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJtXW53xiUt5nudmh0X8yGfC38QEIkIUcPEXlGCN9oj69Kfxd6ehW/c8exKrtBIuD0Bh+rIRvH5psv7tC9AByNA==",
  "authenticatorData": "vlxK98up2TYOCUeXAktaOj3Z9DeqmFIpFlbntbXZ2jQFAAAAAg==",
  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiV1Bnb0htYzZLZUFGNHlZUktNcWw4bFYwLWh3OEdhNGJWNU5pYlJfN3RfUSIsIm9yaWdpbiI6ImNocm9tZS1leHRlbnNpb246Ly9tYWlrYWRwYW9iYmprbWFvbW5wbmhqZ2xwYWJsbGFvaSIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
  "signatureDer": "MEYCIQDFg9AyRiNb47GnnoTduRBJi67KNlKqWHBpAweKNMRnagIhALWbP+PVGdCLgk3in5V5aWLYKCIT6N105Q5L/esdIIRm",
  "challenge": "WPgoHmc6KeAF4yYRKMql8lV0-hw8Ga4bV5NibR_7t_Q",
  "prfFirst": "muy2N5IEqGLFlcXViDVsIHE0nPxc+KP3uLKZ7bR3/hQ=",
  "origin": "chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi",
  "rpId": "maikadpaobbjkmaomnpnhjglpabllaoi",
  "virtualAuthenticatorId": "f31366de-237e-456e-8b6b-fd97bb66b913"
}
  ```
  Byte lengths (decoded): `pubkeyDerSpki` 91B, `authenticatorData` 37B
  (32B rpIdHash + 1B flags + 4B signCount, no attested-credential-data — as
  expected for a `.get()` assertion), `signatureDer` ~70-72B (ASN.1 DER
  ECDSA signature, length varies slightly run-to-run per normal DER integer
  encoding). Every field's *shape* (byte lengths, origin/rpId strings,
  clientDataJSON structure) was stable and re-verified across multiple test
  runs; the actual random challenge/signature/PRF bytes differ per run by
  design (fresh `crypto.getRandomValues()` challenge each `.get()`).

### Evidence file discipline (WRITE_ASSERTION gate)

`spikes/02-webauthn/out/assertion.json` is committed evidence consumed by
Task 4; every test run otherwise mints a fresh random challenge/signature and
would silently overwrite it. The test now writes to
`out/assertion.latest.json` by default (gitignored via `out/.gitignore`,
scratch/inspection only) and only writes `out/assertion.json` when invoked as
`WRITE_ASSERTION=1 pnpm test` — an explicit, intentional opt-in to regenerate
the committed evidence file. Round-1 fix runs used the default path; the
committed `out/assertion.json` was verified byte-identical (`git diff`
empty) before and after every test run in this round.

### PRF and clientDataJSON assertions (round-1 fix)

The original test only *logged* `prfEnabled`/`prfFirst` — a build where CDP
silently degrades or drops PRF would still pass. Fixed:
`expect(created.prfEnabled).toBe(true)` and
`expect(assertion.prfFirst).not.toBeNull()` now run whenever the CDP
`hasPrf: true` call succeeded (the normal case on this Chromium build), plus
new `clientDataJSON` invariant checks — decode the base64, then assert
`type === "webauthn.get"`, `origin` starts with `chrome-extension://`, and
`challenge` matches the assertion's recorded `challenge` field exactly (not
just presence). If CDP instead *rejects* `hasPrf: true` (not observed on this
build, but the brief's named fallback), the test takes the documented
recorded-fallback branch: it logs `"PRF not testable virtually — CDP
rejected WebAuthn.addVirtualAuthenticator hasPrf:true..."`, pushes a
`test.info().annotations` entry so it shows up in the Playwright report, and
skips only the PRF-specific `expect`s — ES256 create/get evidence is still
produced and written, since that part is independent of PRF support. (A
literal `test.skip()` was considered but rejected: it would abort the whole
test before `out/assertion.json` could be written, which would silently stop
producing the ES256 evidence Task 4 needs even when only PRF is unavailable.)

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
  id-discovery block replaced by the service-worker method (point 1), the
  `headless: false` fix (point 3), the `hasPrf` try/catch fallback, real
  `expect`-based PRF and `clientDataJSON` assertions, and the
  `WRITE_ASSERTION` evidence-file gate (round-1 fix — see above).
- `ts/.gitignore` — local, ignores `node_modules/`, `test-results/`,
  `playwright-report/`.
- `out/.gitignore` — new (round-1 fix), ignores `assertion.latest.json` only.
- `out/assertion.json` — committed; consumed by Task 4. **Not touched in
  round 1** — verified `git diff` empty after every test run this round.

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

---

# Spike 2b — on-chain verification of the assertion (secp256r1 precompile + Instructions sysvar)

Task: `.superpowers/sdd/2026-08-18-warden-phase0-scaffold-spikes/task-4-brief.md`.
Artefacts: `spikes/02-webauthn/ts/src/prep.ts`, `spikes/02-webauthn/out/raw.json`,
`spikes/02-webauthn/onchain/{Cargo.toml,src/lib.rs,tests/verify.rs}`.

## Part (c) — on-chain verification results

**Result: PASS.** A native SBF program, running in LiteSVM, bound the *real*
Task-3 WebAuthn assertion to a `Secp256r1SigVerify1111111111111111111111111`
precompile instruction in the same transaction: it located the precompile
instruction through the Instructions sysvar, matched `(pubkey, message)`
byte-for-byte against its own expectations, and parsed `authenticatorData` /
`clientDataJSON`.

### ⚠ Correction to the spec: what `rpIdHash` actually hashes

**Chrome's effective RP ID for a `chrome-extension://` origin is the FULL
ORIGIN STRING, not the bare extension id.** Task 3's `result.md` (above) says
"`rpId` in the credential request equals `location.hostname`, i.e. the extension
id itself" — that is true of the *request*, but the RP ID that ends up hashed
into `authenticatorData[0..32]` is the whole `chrome-extension://<id>` URL:

```
signed authenticatorData[0..32]            = be5c4af7cba9d9360e094797024b5a3a3dd9f437aa9852291656e7b5b5d9da34
SHA-256("chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi")  = be5c4af7cba9d9360e094797024b5a3a3dd9f437aa9852291656e7b5b5d9da34   ✅ MATCH
SHA-256("maikadpaobbjkmaomnpnhjglpabllaoi")                      = 68dd094e7a73750c0036e8a840b1bc086208d82ebb86e13320879d995a2cf051   ❌ NO MATCH
```

**Phase 1 consequence:** the wallet account must store
`SHA-256(full origin string)` as the expected `rpIdHash`. An implementation that
follows the plain reading of the WebAuthn spec — "rpIdHash = SHA-256(RP ID)",
with RP ID = the extension id — produces `68dd094e…` and **every assertion will
be rejected**. Because the extension id is derived from the unpacked path /
signing key, this constant also changes between a dev-loaded and a
store-published extension; it must be a configurable, per-build value, not a
hard-coded literal.

This was caught by review after the first round of this spike derived the
"expected" hash by copying `authenticatorData[0..32]` — a tautology that would
have passed regardless of what the correct preimage was. Both sides are now
derived independently:

- `ts/src/prep.ts` hashes four candidate preimages (bare id, full origin,
  origin + `/`, `https://<id>`), records which one matches the signed bytes in
  `out/raw.json` as `rpIdHashPreimage` / `rpIdHashPreimageKind`, and **throws**
  if none matches rather than guessing.
- `onchain/tests/verify.rs::rp_id_hash_is_sha256_of_the_full_origin` recomputes
  `SHA-256(origin)` in Rust and asserts it equals the signed bytes *and* that
  `SHA-256(bare id)` does not.
- The program's expected hash in every test comes from
  `expected_rp_id_hash(origin)` — a trusted constant derived from the origin
  string — never from `authenticatorData`. Two negative tests
  (`rejects_wrong_rpid_hash`, `rejects_rpid_hash_of_bare_extension_id`) prove
  the check actually bites.

### Headline numbers

| Question | Answer |
| --- | --- |
| secp256r1 precompile available in LiteSVM? | **Yes** — but only with litesvm's non-default `precompiles` cargo feature (`litesvm = { version = "0.12", features = ["precompiles"] }`). Without it the whole tx fails with `InvalidProgramForExecution` before any log is emitted. No `solana-test-validator` fallback was needed. |
| CU consumed by our program | **5,055** of 400,000 (`Program … consumed 5055 of 400000 compute units`). Precompile signature verification is *not* charged to the CU meter — it is charged as an extra signature at the fee level. |
| Low-S normalization needed on this sample? | **Yes.** The Chrome virtual authenticator emitted a **high-S** signature; `p256.Signature.hasHighS()` was `true` and `normalizeS()` was required. Sending the signature exactly as the authenticator produced it makes the precompile reject the tx with `InstructionError(0, Custom(2))`. This is not an edge case to plan for later — it happened on the very first sample, so the extension **must** normalize S before every submission. |
| Byte layout confirmed? | **Yes**, against `solana-secp256r1-program` 3.0.0 source (`src/lib.rs`, `new_secp256r1_instruction_with_signature`): `[num_signatures u8][padding u8][14-byte offsets]` then payload `pubkey(33) ‖ signature(64) ‖ message(n)`. With one signature the concrete offsets are `public_key_offset = 16`, `signature_offset = 49`, `message_data_offset = 113`, and all three `*_instruction_index` fields are `0xFFFF` ("this instruction"). Total precompile instruction data for our sample: **182 B**. |
| `rpIdHash` preimage | **The full origin string** `chrome-extension://<id>` — *not* the bare extension id. See the correction above. |
| Exact `origin` string | `chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi` — no trailing slash, no port. |
| RP ID vs `rpIdHash` (do not conflate) | The **credential-request `rp.id` parameter** is the bare extension id `maikadpaobbjkmaomnpnhjglpabllaoi` (= `location.hostname`, what Task 3's harness passed to `navigator.credentials`). What Chrome actually **signs** into `authenticatorData[0..32]` is `SHA-256` of the **full origin** `chrome-extension://maikadpaobbjkmaomnpnhjglpabllaoi`. Both statements are true and they are about different things — the on-chain check needs the second. See the correction above. |
| `authenticatorData` flags | `0x05` = UP (0x01) | UV (0x04) both set; the program requires both. |
| `solana_program::hash::hash` | **SHA-256**, confirmed by reading the source: `solana-program` 3.0.0 `hash` module → `solana-sha256-hasher`, which uses the `sol_sha256` syscall on-chain and `sha2::Sha256` off-chain. Not keccak. |

### Transaction size (input for spike 03 — tx budget)

Measured in the passing test:

```
precompile ix data: 182 B, our ix data: 367 B, serialized tx: 788 B
```

788 B of the 1232 B packet limit is consumed by a *minimal* two-instruction
root-verify transaction with no real payload, no ALT, and only two accounts.
Phase 1 must treat this as a hard constraint: the actual wallet action
(transfer, CPI, guardian logic) has ~440 B of headroom left, which is why the
plan's session-key / delegated-signing path exists. Most of the 367 B is
`clientDataJSON` (164 B) + `authenticatorData` (37 B) + origin (51 B) +
challenge (43 B); those are unavoidable if the on-chain program must re-derive
`SHA256(clientDataJSON)` itself.

### What the tests actually prove

`cargo test` → **21 passing tests** (6 unit + 15 LiteSVM integration).

**Evidence / layout (2)**

| Test | Asserts |
| --- | --- |
| `rp_id_hash_is_sha256_of_the_full_origin` | `SHA-256(origin) == authenticatorData[0..32]` **and** `SHA-256(bare id) != authenticatorData[0..32]` (see the correction above) |
| `hand_built_precompile_ix_matches_crate` | The test's hand-rolled precompile instruction is byte-identical to `new_secp256r1_instruction_with_signature`, and `public_key_offset == 16`, `signature_offset == 49`, `message_data_offset == 113`. This is what licenses the negative tests to bend individual offset fields |

**Happy path (1)**

| Test | Asserts |
| --- | --- |
| `binds_real_assertion` | Full bind succeeds; CU < 100,000 (actual **5,055**); prints tx-size evidence |

**Our program's rejections (8)** — each asserts the **exact**
`InstructionError(1, …)` *and* the specific program log, so none can pass for
the wrong reason:

| Test | Rejects | Log |
| --- | --- | --- |
| `rejects_wrong_challenge` | challenge `AAAA` | `challenge mismatch` |
| `rejects_wrong_rpid_hash` | 1 bit flipped in the expected rpIdHash | `rpIdHash mismatch` |
| `rejects_rpid_hash_of_bare_extension_id` | `SHA-256(bare id)` — the naive-spec value | `rpIdHash mismatch` |
| `rejects_message_not_bound_to_precompile` | precompile verifies the real message, our ix is handed a different `authenticatorData` (signCount byte flipped; rpIdHash + flags untouched so checks 1–2 still pass) | `message mismatch` |
| `rejects_wrong_pubkey` | valid signature under a key ≠ the expected root key | `pubkey mismatch` |
| `rejects_multi_signature_precompile_ix` | `num_signatures = 2` (both entries verify fine — the program must refuse the shape rather than silently ignore entry #2) | `unexpected precompile instruction shape` |
| `rejects_foreign_instruction_index` | offsets with `instruction_index = 0` instead of the `0xFFFF` "this instruction" sentinel (the precompile is happy — it *is* instruction 0 — our program must not be) | `precompile references another instruction` |
| `rejects_non_precompile_instruction_index` | program pointed at instruction 1 (itself) | `not the secp256r1 precompile` |

**No-panic guarantees (2)**

| Test | Asserts |
| --- | --- |
| `truncated_instruction_data_errors_without_panic` | 8 truncation lengths (0, 10, 33, 65, 67, 80, 120, 200 B) each give exactly `InstructionError(1, InvalidInstructionData)` with no `panicked` in the logs — i.e. the bounds guards return errors instead of aborting |
| `malformed_precompile_offsets_error_without_panic` | `message_data_offset = 60000` → asserts **exactly** `InstructionError(0, Custom(3))` = `PrecompileError::InvalidDataOffsets`, that our program never ran (logs empty), and that nothing panicked. Note: a case where the precompile *verifies* but our program then reads out of range is unconstructible — both read the same offsets, so the precompile always fails first |

**Precompile controls (2)** — these prove LiteSVM is genuinely executing the
precompile rather than skipping it. Both assert exactly
`InstructionError(0, Custom(2))` = `PrecompileError::InvalidSignature` **and**
that instruction 1 never ran (empty logs, no
`webauthn root assertion bound OK`), via the shared
`assert_precompile_rejected(err, expected_code)` helper — the same helper the
malformed-offsets test uses with code 3, so no precompile-level test can pass on
a merely-nonzero error:

| Test | Asserts |
| --- | --- |
| `precompile_rejects_tampered_signature` | 1-bit signature flip kills the tx at instruction 0 |
| `precompile_rejects_high_s_signature` | the authenticator's un-normalized high-S signature is rejected |

**Known-hole documentation (6 unit tests, `src/lib.rs::substring_match_holes`)** — see the next section.

### Honest caveat — the substring-match approach to `clientDataJSON`

**This pattern is NOT production-safe and must NOT be carried into Phase 1
unchanged.** Any earlier statement that the spike's `root_verify` logic is
"reused verbatim" by Phase 1 is **withdrawn**: the precompile binding
(instruction-sysvar lookup, offsets, pubkey/message equality) is reusable, the
`clientDataJSON` handling is not.

The program checks `clientDataJSON` with three raw byte-substring searches:
`"type":"webauthn.get"`, `"challenge":"<b64url>"`, `"origin":"<origin>"`.
That is not a JSON parse. The holes are no longer asserted in prose — they are
**demonstrated by executable tests** in
`onchain/src/lib.rs::substring_match_holes`, deliberately written to assert the
current (wrong) behaviour so that Phase 1's stricter parser flips them:

| Unit test | Demonstrates |
| --- | --- |
| `documents_nested_origin_hole_passes_substring_match` | Top-level `"origin":"https://evil.example"`, `"crossOrigin":true`, and our origin only inside a nested object `{"unknownExtension":{"origin":"chrome-extension://…"}}` — **currently PASSES**. This is the headline hole |
| `documents_duplicate_origin_key_passes_substring_match` | Duplicate top-level `origin` key, first one attacker-chosen — **currently PASSES**; a real parser resolves one of the two, implementation-defined |
| `documents_cross_origin_true_passes_substring_match` | `"crossOrigin":true` — **currently PASSES**; the field is never examined |
| `documents_escaped_origin_falsely_rejected` | `"origin":"chrome-extension:\/\/…"` — legal JSON, semantically identical, **currently REJECTED** (availability bug / silent lockout) |
| `accepts_the_real_client_data_json`, `rejects_plain_wrong_origin` | Sanity anchors |

Why these are unit tests rather than LiteSVM transactions: an end-to-end version
would need a valid signature over the crafted `clientDataJSON` **under the root
passkey**, which is precisely what an attacker cannot produce. The hole lives
entirely in the string check, so that is where it is exercised. This does not
make it harmless — it makes the check unfit as a *security boundary*, and Phase 1
must not rely on it. (Quote-smuggling *inside* a string value is separately
blocked, because JSON escapes a literal `"` as `\"` so an injected
`"origin":"…"` never matches byte-wise — a happy accident of escaping, not a
designed defence.)

Additional defects with no test yet: cost is O(haystack × needle) and the
program imposes **no length cap** on `clientDataJSON`, so a caller can inflate
both CU and transaction size at will.

**Phase 1 requirement (binding):** replace the substring matcher with either
(a) a **top-level, duplicate-rejecting, escape-aware scanner** that walks the
`clientDataJSON` object at depth 0 only, rejects repeated keys, decodes JSON
escapes before comparing, and validates `type`, `challenge`, `origin` **and**
`crossOrigin`, with a hard length cap; or (b) a **canonical `clientDataJSON`
template bind** where the extension reconstructs the exact expected bytes and
the program does one full-buffer equality check (cheapest in CU, but brittle
across UA serialization changes — needs a UA-version gate). Option (a) is the
recommendation; option (b) is worth measuring as a CU optimisation. Either way
the six unit tests above must be updated to assert rejection.

### Other caveats worth carrying to Phase 1

- **UV is required by this program** (`flags & 0x05 == 0x05`). Some synced /
  cross-device passkey flows return UP-only assertions. Phase 1 must decide
  whether UV is mandatory for a root-key action (recommended: yes for root,
  configurable for lower-privilege actions) and must surface a clear error.
- **`precompile_ix_index` comes from caller-supplied instruction data.** That
  is safe here only because the program independently checks
  `ix.program_id == SECP256R1_ID`, `num_signatures == 1`, all three
  `*_instruction_index == 0xFFFF` (so the precompile cannot be made to verify
  bytes living in a *different* instruction), and then compares pubkey and
  message. Removing any one of those checks reopens a substitution attack —
  each of those four checks now has a dedicated negative test
  (`rejects_non_precompile_instruction_index`, `rejects_multi_signature_precompile_ix`,
  `rejects_foreign_instruction_index`, `rejects_wrong_pubkey` /
  `rejects_message_not_bound_to_precompile`).
- **Signature counter is not checked.** `authenticatorData[33..37]` (signCount)
  is ignored; replay protection comes entirely from the challenge, which the
  Phase 1 program must bind to on-chain state (nonce/recent blockhash), not
  just compare to a value it was handed.
- **The root pubkey and expected rpIdHash are passed in instruction data in
  this spike.** In Phase 1 both must come from the wallet account state, not
  from the caller — otherwise the caller simply supplies values matching their
  own key/origin and every check trivially passes. The spike passes them in
  only so the negative tests can bend them.
- **`authenticatorData` extension data is not examined.** The program checks
  `auth[..32]` and `auth[32]` and treats the rest as opaque message bytes. That
  is sound for binding (the whole buffer is covered by the signature) but means
  attested-credential-data or extension blobs are neither validated nor
  size-capped.

### OPEN ITEM — workspace layout (decision deferred to the Task 5/6 gate)

The repo-root `Cargo.toml` lists workspace members that do not exist yet
(`programs/*` and `spikes/03-txbudget/onchain`), so the root workspace cannot
be resolved at all — even
`cargo --manifest-path spikes/02-webauthn/onchain/Cargo.toml` fails with
`failed to load manifest for workspace member /opt/warden/programs/*`. Per the
task brief the root manifest was **not** edited. Instead the spike crate
declares its own empty `[workspace]` table so it builds and tests standalone
(its lockfile and `target/` therefore live under
`spikes/02-webauthn/onchain/`). Verified empirically: once the missing members
exist, that `[workspace]` table makes cargo fail with
`multiple workspace roots found in the same workspace`.

**Status: OPEN, deliberately deferred.** Per the coordinator, the crate keeps
its own `[workspace]` table for now; Task 5/6 will land
`spikes/03-txbudget/onchain` and root-workspace resolution will be settled at
the decision gate. The two options at that gate:

1. delete the `[workspace]` table from `spikes/02-webauthn/onchain/Cargo.toml`
   so the spike rejoins the root workspace (its `Cargo.lock` then merges into a
   root one, and `target/deploy/spike_p256.so` moves to the repo-root `target/`
   — `tests/verify.rs` already probes both locations); or
2. add the spikes to the root workspace's `exclude` list and drop them from
   `members` (spikes are throwaway evidence per `CLAUDE.md`, "never import from
   `spikes/` into `packages/`", so `exclude` is arguably the better long-term
   shape).

Whoever takes it must also note `programs/*` is still an unmatched glob and
will keep the root workspace broken on its own until Phase 1 creates a program
crate.

### Reproduce

```bash
cd /opt/warden && pnpm install
cd spikes/02-webauthn/ts && node --experimental-strip-types src/prep.ts   # → out/raw.json
cd /opt/warden/spikes/02-webauthn/onchain
cargo-build-sbf                    # ~19 s compile (+ ~1 min first-time platform-tools download)
cargo test -- --nocapture          # 6 unit + 15 integration = 21 passed
```
