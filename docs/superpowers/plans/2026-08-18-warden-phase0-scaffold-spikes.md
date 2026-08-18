# Warden Wallet — Phase 0: Scaffold, Gating Spikes, Design Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `/opt/warden` monorepo, answer the four spec §12 spikes with measured evidence, and lay the Figma design-token foundation — so Phase 1 (on-chain program) starts on facts, not assumptions.

**Architecture:** pnpm monorepo (`packages/core` TS SDK, `apps/*` extension(s), `programs/*` Rust/Anchor, `services/*`, `docs/`). Spikes are throwaway-labelled code under `spikes/` (kept for reference, never imported by product code). Each spike ends in a dated markdown result with a go/no-go line; Task 9 rolls them into `docs/spikes/DECISION.md`, which is Codex-reviewed and gates Phase 1.

**Tech Stack:** Node 22 + pnpm 11 (present) · TypeScript 5 + vitest · Solana CLI 3.1.12 / Agave (present: `cargo-build-sbf`, `solana-test-validator`) · rustup stable + Anchor via `avm` (installed in Task 1) · LiteSVM (Rust) for program tests · Playwright + Chrome (present via Playwright MCP install; CDP WebAuthn virtual authenticator) · Figma MCP (`/figma-use`, `generate_figma_design`).

**Spec:** `/opt/warden/docs/superpowers/specs/2026-08-18-warden-wallet-design.md` (rev 5, SHIP-SPEC). Read §4, §5.2, §6, §9, §12 before starting.

## Global Constraints

- Transaction size limit **1,232 bytes** for the *whole serialized transaction* (spec §6); design for it, do not assume SIMD-0296/0385 activation.
- Root passkey algorithm **ES256 (P-256) only**; on-chain verify = secp256r1 precompile (SIMD-0075) instruction in the same tx + Instructions-sysvar introspection (spec §4). Precompile requires **low-S** signatures and 33-byte compressed pubkeys.
- **Checked arithmetic everywhere** in Rust (`checked_*`/`Result`), never `+`/`-` on amounts.
- Pin versions: `rust-toolchain.toml`, `Anchor.toml` `anchor_version`, `package.json` engines; record actual installed versions in `docs/TOOLCHAIN.md` (Task 1).
- Heavy builds are **serialized** on this host (4 cores/16 GB; do not run `cargo build` concurrently with other heavy jobs — see `feedback_no_concurrent_heavy_fanouts_on_opt_host`).
- Spike code lives under `spikes/` and is labelled throwaway in its README; product packages must not import it.
- Fee constant `FEE_BPS = 85` (spec §14). Name is **Warden Wallet**.
- Copy voice: sentence case, operator verbs; drinkerlabs doctrine `/opt/drinkerlabs/DESIGN.md` (spec §9): one accent `--indigo`, Inter + JetBrains Mono, hairlines, tabular numerals.
- Every task ends with `pnpm test` (TS) and/or `cargo test` (Rust) green and a commit; the global commit hook enforces `.claude/test-gate.sh`.

---

## File structure (created by this plan)

```
/opt/warden
├── package.json  pnpm-workspace.yaml  tsconfig.base.json  .gitignore  .npmrc
├── rust-toolchain.toml  Cargo.toml (workspace)  Anchor.toml
├── .claude/settings.json (exists)  .claude/test-gate.sh
├── CLAUDE.md  README.md  docs/TOOLCHAIN.md
├── packages/core/            (TS SDK skeleton: src/index.ts, src/constants.ts, tests)
├── packages/ui-tokens/       (tokens.css + tokens.json exported from Figma)
├── programs/                 (empty in Phase 0; Phase 1 adds programs/warden)
├── spikes/
│   ├── README.md             (THROWAWAY notice)
│   ├── 01-squads/            (notes + IDL dump + result.md)
│   ├── 02-webauthn/          (ext/: manifest.json, popup.html, popup.js; test/: playwright spec;
│   │                          onchain/: Rust crate `spike-p256` + LiteSVM test; result.md)
│   ├── 03-txbudget/          (ts: measure.ts; onchain/: Rust crate `spike-conserve`; result.md)
│   └── 04-compat/            (inventory.md)
├── docs/spikes/DECISION.md
└── docs/design/figma.md      (file URL, token map, screen index)
```

---

### Task 1: Monorepo scaffold + toolchain

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `tsconfig.base.json`, `.gitignore`, `.npmrc`, `packages/core/package.json`, `packages/core/tsconfig.json`, `packages/core/src/index.ts`, `packages/core/src/constants.ts`, `packages/core/test/constants.test.ts`, `rust-toolchain.toml`, `Cargo.toml`, `.claude/test-gate.sh`, `CLAUDE.md`, `README.md`, `docs/TOOLCHAIN.md`, `spikes/README.md`

**Interfaces:**
- Produces: `packages/core` exports `FEE_BPS: number` (=85), `MAX_TX_BYTES: number` (=1232) from `src/constants.ts`; workspace scripts `pnpm test`, `pnpm -r build`.

- [ ] **Step 1: Write workspace files**

`package.json`:
```json
{
  "name": "warden",
  "private": true,
  "engines": { "node": ">=22", "pnpm": ">=11" },
  "scripts": {
    "test": "pnpm -r --if-present test",
    "build": "pnpm -r --if-present build",
    "typecheck": "pnpm -r --if-present typecheck"
  },
  "devDependencies": { "typescript": "^5.6.0", "vitest": "^3.0.0", "@types/node": "^22.0.0" }
}
```
`pnpm-workspace.yaml`:
```yaml
packages:
  - packages/*
  - apps/*
  - services/*
  - spikes/*/ts
```
`tsconfig.base.json`:
```json
{ "compilerOptions": { "target": "ES2022", "module": "ESNext", "moduleResolution": "Bundler",
  "strict": true, "noUncheckedIndexedAccess": true, "esModuleInterop": true, "skipLibCheck": true,
  "declaration": true, "sourceMap": true } }
```
`.gitignore`:
```
node_modules
dist
target
.anchor
test-ledger
*.log
.env
.env.*
!.env.example
```
`.npmrc`: `auto-install-peers=true`

- [ ] **Step 2: Write `packages/core` skeleton and its first test**

`packages/core/package.json`:
```json
{ "name": "@warden/core", "version": "0.0.1", "type": "module", "main": "dist/index.js", "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run", "typecheck": "tsc -p tsconfig.json --noEmit" } }
```
`packages/core/tsconfig.json`:
```json
{ "extends": "../../tsconfig.base.json", "compilerOptions": { "outDir": "dist", "rootDir": "src" }, "include": ["src"] }
```
`packages/core/src/constants.ts`:
```ts
/** Platform fee on in-app swaps, basis points (spec §14: Phantom parity). */
export const FEE_BPS = 85;
/** Whole serialized Solana transaction limit in bytes (spec global constraints). */
export const MAX_TX_BYTES = 1232;
```
`packages/core/src/index.ts`:
```ts
export * from "./constants.js";
```
`packages/core/test/constants.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { FEE_BPS, MAX_TX_BYTES } from "../src/index.js";
describe("constants", () => {
  it("fee is Phantom parity", () => expect(FEE_BPS).toBe(85));
  it("tx limit is 1232", () => expect(MAX_TX_BYTES).toBe(1232));
});
```

- [ ] **Step 3: Install and run tests (expect PASS)**

Run: `cd /opt/warden && pnpm install && pnpm test`
Expected: vitest reports 2 passed.

- [ ] **Step 4: Rust toolchain + Anchor (serialized; ~10–20 min)**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
rustup toolchain install stable && rustup default stable
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install latest && avm use latest
anchor --version && cargo --version && rustc --version && cargo-build-sbf --version
```
Write `rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
```
Write workspace `Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["programs/*", "spikes/02-webauthn/onchain", "spikes/03-txbudget/onchain"]
[profile.release]
overflow-checks = true
```
Record every printed version verbatim into `docs/TOOLCHAIN.md` (table: tool · version · how installed).

- [ ] **Step 5: Test gate + repo docs**

`.claude/test-gate.sh` (executable):
```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm test
if ls programs/*/Cargo.toml >/dev/null 2>&1; then cargo test --workspace --exclude spike-p256 --exclude spike-conserve; fi
```
`chmod +x .claude/test-gate.sh`.
`CLAUDE.md` (repo directives):
```markdown
# Warden Wallet — repo directives
- Spec: docs/superpowers/specs/2026-08-18-warden-wallet-design.md (rev 5). Plans: docs/superpowers/plans/.
- Never import from spikes/ into packages/ or apps/. Spikes are throwaway evidence.
- Heavy Rust builds are serialized on this host; never run two cargo builds at once.
- Amount math in Rust: checked_* only. TS: bigint for lamports/token amounts.
- Design tokens come from Figma (docs/design/figma.md) → packages/ui-tokens; do not hand-edit tokens.css.
- Codex reviews: spec, each program milestone, pre-deploy diff (see /opt/docs/CODEX-USAGE-DOCTRINE.md).
```
`README.md`: two paragraphs — what Warden is (spec §1) and how to run `pnpm install && pnpm test`.
`spikes/README.md`: "THROWAWAY. Code here answers spec §12 questions and is not product code. Results are in each `result.md` and rolled up in docs/spikes/DECISION.md."

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "chore: monorepo scaffold, core constants, toolchain record, test gate"
```

---

### Task 2: Spike 1 — Squads Smart Account API check

**Files:**
- Create: `spikes/01-squads/result.md`, `spikes/01-squads/idl/` (downloaded IDL/JSON), `spikes/01-squads/notes.md`

**Interfaces:**
- Produces: `result.md` with a filled criteria table and a one-line verdict `KEEP-OWN-PROGRAM` or `SWITCH-TO-SQUADS`; consumed by Task 9.

- [ ] **Step 1: Collect primary sources**

```bash
mkdir -p spikes/01-squads/idl && cd spikes/01-squads
git clone --depth 1 https://github.com/Squads-Protocol/smart-account-program src-smart-account 2>&1 | tail -1 || echo "clone failed — record in notes.md"
git clone --depth 1 https://github.com/Squads-Protocol/v4 src-v4 2>&1 | tail -1 || true
ls src-smart-account src-v4 | head -40
```
If the smart-account repo is private/missing, fetch docs: `curl -sL https://docs.squads.so/ | head` and record what is publicly available; the mainnet program id and IDL can be pulled with `anchor idl fetch <program_id> --provider.cluster mainnet` once the id is found in the docs (record the id you used).

- [ ] **Step 2: Answer the criteria (write `result.md`)**

Fill this table from the IDL/source, citing file:line or IDL instruction names for each row:

| # | Criterion (spec §5) | Squads answer | Evidence |
|---|---|---|---|
| 1 | Typed signers: Ed25519 + secp256r1 passkey with on-chain WebAuthn parsing | | |
| 2 | Per-member spending limits: per-mint, per-tx, per-period, **account-wide across members** | | |
| 3 | Rolling 30-day cap | | |
| 4 | Single-transaction execution of an arbitrary CPI (no propose/approve/execute) for a limited member | | |
| 5 | Program-id + discriminator allowlist for member execution | | |
| 6 | Post-state conservation checks (delegate/close-authority/owner unchanged; WSOL canonicalized) | | |
| 7 | Timelock + cancel window on large actions; guardian cancel | | |
| 8 | Guardian recovery with delay + root contest | | |
| 9 | Freeze semantics (root vs guardian bounds) | | |
| 10 | Program upgrade authority = timelocked multisig | | |
| 11 | Reserved signer kinds (future hash-based/Falcon) | | |

Verdict rule (from spec §12.1): SWITCH only if ≥ 9/11 are "yes or trivially configurable" *and* rows 4 and 6 are yes. Otherwise KEEP-OWN-PROGRAM and list which Squads patterns to borrow (account layout, member permissions bitmask, time lock implementation).

- [ ] **Step 3: Commit**

```bash
cd /opt/warden && git add spikes/01-squads && git commit -m "spike(01): Squads smart-account API check — verdict recorded"
```

---

### Task 3: Spike 2a — WebAuthn ES256 + PRF from an MV3 extension origin

**Files:**
- Create: `spikes/02-webauthn/ext/manifest.json`, `spikes/02-webauthn/ext/popup.html`, `spikes/02-webauthn/ext/popup.js`, `spikes/02-webauthn/ts/package.json`, `spikes/02-webauthn/ts/test/webauthn.spec.ts`, `spikes/02-webauthn/ts/playwright.config.ts`, `spikes/02-webauthn/result.md`

**Interfaces:**
- Produces: `spikes/02-webauthn/out/assertion.json` = `{ pubkeyDerSpki: base64, authenticatorData: base64, clientDataJSON: base64, signatureDer: base64, challenge: base64url, prfFirst: base64|null }` consumed by Task 4.

- [ ] **Step 1: Write the minimal extension**

`ext/manifest.json`:
```json
{ "manifest_version": 3, "name": "warden-spike-webauthn", "version": "0.0.1",
  "action": { "default_popup": "popup.html" }, "permissions": [] }
```
`ext/popup.html`:
```html
<!doctype html><meta charset="utf-8"><title>webauthn spike</title>
<button id="create">create</button> <button id="get">get</button>
<pre id="out"></pre><script src="popup.js"></script>
```
`ext/popup.js`:
```js
const out = document.getElementById("out");
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rpId = location.hostname; // = extension id under chrome-extension://
let credId = null, spki = null;
async function create() {
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: rpId, name: "Warden spike" },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "warden", displayName: "Warden" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],           // ES256 only
    authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
    extensions: { prf: {} },
  }});
  credId = cred.rawId; spki = cred.response.getPublicKey();
  const ext = cred.getClientExtensionResults();
  out.textContent = JSON.stringify({ step: "create", alg: cred.response.getPublicKeyAlgorithm(), prfEnabled: !!(ext.prf && ext.prf.enabled), spki: b64(spki) }, null, 2);
  window.__spike = { credId, spki };
}
async function get() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const salt = new TextEncoder().encode("WARDEN/prf/v1");
  const a = await navigator.credentials.get({ publicKey: {
    rpId, challenge, userVerification: "required",
    allowCredentials: credId ? [{ type: "public-key", id: credId }] : [],
    extensions: { prf: { eval: { first: salt } } },
  }});
  const ext = a.getClientExtensionResults();
  const result = {
    pubkeyDerSpki: b64(spki), authenticatorData: b64(a.response.authenticatorData),
    clientDataJSON: b64(a.response.clientDataJSON), signatureDer: b64(a.response.signature),
    challenge: b64url(challenge), prfFirst: ext.prf?.results?.first ? b64(ext.prf.results.first) : null,
    origin: location.origin, rpId,
  };
  out.textContent = JSON.stringify(result, null, 2);
  window.__assertion = result;
}
document.getElementById("create").onclick = () => create().catch(e => out.textContent = "create error: " + e);
document.getElementById("get").onclick = () => get().catch(e => out.textContent = "get error: " + e);
```

- [ ] **Step 2: Write the Playwright test with a CDP virtual authenticator**

`ts/package.json`:
```json
{ "name": "@warden-spike/webauthn", "private": true, "type": "module",
  "scripts": { "test": "playwright test" },
  "devDependencies": { "@playwright/test": "^1.50.0" } }
```
`ts/playwright.config.ts`:
```ts
import { defineConfig } from "@playwright/test";
export default defineConfig({ testDir: "./test", timeout: 60_000, use: { headless: true } });
```
`ts/test/webauthn.spec.ts`:
```ts
import { test, expect, chromium } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
const EXT = resolve(import.meta.dirname, "../../ext");
test("ES256 + PRF create/get from extension origin", async () => {
  const ctx = await chromium.launchPersistentContext("", {
    headless: true, channel: "chromium",
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--headless=new"],
  });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker").catch(() => null as any);
  // Extension id from any extension page URL; popups have no SW here, so open the popup directly:
  const bg = ctx.backgroundPages()[0];
  const extId = (bg?.url() ?? (await (async () => { const p = await ctx.newPage(); await p.goto("chrome://extensions"); return ""; })())).split("/")[2];
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } as any });
  await page.goto(`chrome-extension://${extId || "unknown"}/popup.html`);
  await page.click("#create");
  await page.waitForFunction(() => (window as any).__spike);
  const created = JSON.parse(await page.textContent("#out") ?? "{}");
  expect(created.alg).toBe(-7);
  await page.click("#get");
  await page.waitForFunction(() => (window as any).__assertion);
  const assertion = await page.evaluate(() => (window as any).__assertion);
  expect(assertion.origin.startsWith("chrome-extension://")).toBe(true);
  mkdirSync(resolve(import.meta.dirname, "../../out"), { recursive: true });
  writeFileSync(resolve(import.meta.dirname, "../../out/assertion.json"), JSON.stringify({ ...assertion, virtualAuthenticatorId: authenticatorId }, null, 2));
  await ctx.close();
});
```
Note for the implementer: extension id discovery under headless varies by Chromium build; if `extId` is empty, read it from `chrome://extensions` DOM (`extensions-manager` shadow root → `extensions-item[id]`) — record the exact method that worked in `result.md`.

- [ ] **Step 3: Run**

Run: `cd spikes/02-webauthn/ts && pnpm install && npx playwright install chromium && pnpm test`
Expected: PASS and `spikes/02-webauthn/out/assertion.json` exists. If `hasPrf` is rejected by CDP, rerun without it and record "PRF: not testable virtually" — PRF must then be verified manually on the owner's machine (Task 3 step 5).

- [ ] **Step 4: Write `result.md` (part a)**

Record: extension origin/RP ID used; alg −7 confirmed; PRF enabled? (virtual + note for real device); the exact `origin` string that appears in `clientDataJSON` (needed by the program in Task 4); any Chromium version caveats.

- [ ] **Step 5: Manual real-device check (owner)**

Add to `result.md` a 5-line checklist for the owner: load `spikes/02-webauthn/ext` unpacked in Chrome and Brave, create with Touch ID/Windows Hello and with a Google-Password-Manager synced passkey, click get, paste both outputs into `out/assertion-real-*.json`. This runs asynchronously; Task 9 records the result if it arrives, else marks PRF as "UNVERIFIED on real devices → Argon2id fallback stays in scope".

- [ ] **Step 6: Commit**

```bash
cd /opt/warden && git add spikes/02-webauthn && git commit -m "spike(02a): WebAuthn ES256+PRF from MV3 origin — virtual authenticator harness"
```

---

### Task 4: Spike 2b — on-chain verification of the assertion (secp256r1 precompile + Instructions-sysvar introspection)

**Files:**
- Create: `spikes/02-webauthn/onchain/Cargo.toml`, `spikes/02-webauthn/onchain/src/lib.rs`, `spikes/02-webauthn/onchain/tests/verify.rs`, `spikes/02-webauthn/ts/src/prep.ts` (converts assertion.json → raw inputs), append to `spikes/02-webauthn/result.md`

**Interfaces:**
- Consumes: `spikes/02-webauthn/out/assertion.json` (Task 3).
- Produces: proof that a native program can (1) find the secp256r1 instruction via `load_instruction_at_checked`, (2) match `(pubkey, message, sig)`, (3) parse `authenticatorData`/`clientDataJSON` fields; measured CU. Pattern reused verbatim by Phase 1's `root_verify` module.

- [ ] **Step 1: Convert the assertion to raw inputs**

`ts/src/prep.ts` (run with `node --experimental-strip-types` or `tsx`):
```ts
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";
const a = JSON.parse(readFileSync(new URL("../../out/assertion.json", import.meta.url), "utf8"));
const b = (s: string) => Buffer.from(s, "base64");
const spki = b(a.pubkeyDerSpki);                       // DER SPKI; uncompressed point is the last 65 bytes
const uncompressed = spki.subarray(spki.length - 65);
const compressed = Buffer.from(p256.ProjectivePoint.fromHex(uncompressed).toRawBytes(true)); // 33 B
let sig = p256.Signature.fromDER(b(a.signatureDer));
if (sig.hasHighS()) sig = sig.normalizeS();            // precompile requires low-S
const authData = b(a.authenticatorData), cdj = b(a.clientDataJSON);
const message = Buffer.concat([authData, createHash("sha256").update(cdj).digest()]);
writeFileSync(new URL("../../out/raw.json", import.meta.url), JSON.stringify({
  pubkey33: compressed.toString("hex"), sig64: Buffer.from(sig.toCompactRawBytes()).toString("hex"),
  message: message.toString("hex"), authenticatorData: authData.toString("hex"), clientDataJSON: cdj.toString("hex"),
  rpIdHash: authData.subarray(0, 32).toString("hex"), flags: authData[32], origin: a.origin, challenge: a.challenge }, null, 2));
console.log("ok");
```
Add `"@noble/curves": "^1.8.0"` to `ts/package.json` devDependencies; `pnpm install`; run `node --experimental-strip-types src/prep.ts` → `out/raw.json`.

- [ ] **Step 2: Write the native program**

`onchain/Cargo.toml`:
```toml
[package] name = "spike-p256" version = "0.0.1" edition = "2021"
[lib] crate-type = ["cdylib", "lib"]
[dependencies]
solana-program = "2"
[dev-dependencies]
litesvm = "0.6"
solana-sdk = "2"
solana-secp256r1-program = "2"
serde_json = "1"
hex = "0.4"
[features] no-entrypoint = []
```
(If `cargo` resolves different major versions for the installed Agave 3.x toolchain, pin to whatever `cargo-build-sbf` supports and record it in `docs/TOOLCHAIN.md`.)

`onchain/src/lib.rs`:
```rust
use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey, sysvar::instructions::{load_instruction_at_checked, ID as IX_SYSVAR}};
pub const SECP256R1_ID: Pubkey = solana_program::pubkey!("Secp256r1SigVerify1111111111111111111111111");
entrypoint!(process);
/// data = expected_pubkey(33) || rp_id_hash(32) || expected_origin_len(u16 LE) || expected_origin || challenge_b64url_len(u16 LE) || challenge_b64url
///        || precompile_ix_index(u8) || authenticator_data_len(u16 LE) || authenticator_data || client_data_json
pub fn process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let sysvar = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if *sysvar.key != IX_SYSVAR { return Err(ProgramError::InvalidArgument); }
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Result<&[u8], ProgramError> { let s = data.get(*o..*o + n).ok_or(ProgramError::InvalidInstructionData)?; *o += n; Ok(s) };
    let pk = take(&mut o, 33)?; let rp = take(&mut o, 32)?;
    let ol = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize; let origin = take(&mut o, ol)?;
    let cl = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize; let chal = take(&mut o, cl)?;
    let ix_index = take(&mut o, 1)?[0];
    let al = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize; let auth = take(&mut o, al)?;
    let cdj = &data[o..];
    // 1) authenticatorData checks: rpIdHash, flags UP(0x01) and UV(0x04)
    if &auth[..32] != rp { msg!("rpIdHash mismatch"); return Err(ProgramError::InvalidArgument); }
    if auth[32] & 0x05 != 0x05 { msg!("UP/UV not set"); return Err(ProgramError::InvalidArgument); }
    // 2) clientDataJSON checks by byte-substring (no JSON parser on-chain): type, challenge, origin
    if !contains(cdj, b"\"type\":\"webauthn.get\"") { return Err(ProgramError::InvalidArgument); }
    let mut cpat = b"\"challenge\":\"".to_vec(); cpat.extend_from_slice(chal); cpat.push(b'"');
    if !contains(cdj, &cpat) { msg!("challenge mismatch"); return Err(ProgramError::InvalidArgument); }
    let mut opat = b"\"origin\":\"".to_vec(); opat.extend_from_slice(origin); opat.push(b'"');
    if !contains(cdj, &opat) { msg!("origin mismatch"); return Err(ProgramError::InvalidArgument); }
    // 3) precompile instruction must be in this tx and bind exactly (pubkey, message)
    let ix = load_instruction_at_checked(ix_index as usize, sysvar)?;
    if ix.program_id != SECP256R1_ID { return Err(ProgramError::InvalidArgument); }
    // layout: [num_sigs u8][pad u8][offsets 14B]... then data; offsets: sig_off u16, sig_ix u16, pk_off u16, pk_ix u16, msg_off u16, msg_size u16, msg_ix u16
    let d = &ix.data; if d.len() < 16 || d[0] != 1 { return Err(ProgramError::InvalidArgument); }
    let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as usize;
    let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_sz, msg_ix) = (u(2), u(4), u(6), u(8), u(10), u(12), u(14));
    let same = u16::MAX as usize; // 0xFFFF = "this instruction"
    if sig_ix != same || pk_ix != same || msg_ix != same { return Err(ProgramError::InvalidArgument); }
    if &d[pk_off..pk_off + 33] != pk { msg!("pubkey mismatch"); return Err(ProgramError::InvalidArgument); }
    let mut expected_msg = auth.to_vec(); expected_msg.extend_from_slice(&solana_program::hash::hash(cdj).to_bytes());
    if &d[msg_off..msg_off + msg_sz] != expected_msg.as_slice() { msg!("message mismatch"); return Err(ProgramError::InvalidArgument); }
    let _sig = &d[sig_off..sig_off + 64]; // validity is enforced by the precompile itself; we only bind identity
    msg!("webauthn root assertion bound OK");
    Ok(())
}
fn contains(h: &[u8], n: &[u8]) -> bool { h.windows(n.len()).any(|w| w == n) }
```
Note: `hash::hash` is SHA-256 in solana-program (the sysvar/hash module) — confirm in docs; do **not** use keccak here.

- [ ] **Step 3: Write the LiteSVM test**

`onchain/tests/verify.rs`:
```rust
use litesvm::LiteSVM;
use solana_sdk::{instruction::{AccountMeta, Instruction}, message::Message, pubkey::Pubkey, signature::{Keypair, Signer}, transaction::Transaction, sysvar};
use std::fs;
#[test]
fn binds_real_assertion() {
    let raw: serde_json::Value = serde_json::from_str(&fs::read_to_string("../out/raw.json").expect("run Task 4 step 1 first")).unwrap();
    let hx = |k: &str| hex::decode(raw[k].as_str().unwrap()).unwrap();
    let (pk, sig, msg, auth, cdj, rp) = (hx("pubkey33"), hx("sig64"), hx("message"), hx("authenticatorData"), hx("clientDataJSON"), hx("rpIdHash"));
    let origin = raw["origin"].as_str().unwrap().as_bytes().to_vec(); let chal = raw["challenge"].as_str().unwrap().as_bytes().to_vec();
    let mut svm = LiteSVM::new();
    let pid = Pubkey::new_unique();
    svm.add_program(pid, include_bytes!("../../../../target/deploy/spike_p256.so"));
    let payer = Keypair::new(); svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    let pre = solana_secp256r1_program::new_secp256r1_instruction_with_signature(&msg, &sig.try_into().unwrap(), &pk.try_into().unwrap());
    let mut data = Vec::new();
    data.extend_from_slice(&hx("pubkey33")); data.extend_from_slice(&rp);
    data.extend_from_slice(&(origin.len() as u16).to_le_bytes()); data.extend_from_slice(&origin);
    data.extend_from_slice(&(chal.len() as u16).to_le_bytes()); data.extend_from_slice(&chal);
    data.push(0u8); // precompile ix index
    data.extend_from_slice(&(auth.len() as u16).to_le_bytes()); data.extend_from_slice(&auth); data.extend_from_slice(&cdj);
    let ours = Instruction { program_id: pid, accounts: vec![AccountMeta::new_readonly(sysvar::instructions::ID, false)], data };
    let tx = Transaction::new(&[&payer], Message::new(&[pre, ours], Some(&payer.pubkey())), svm.latest_blockhash());
    let res = svm.send_transaction(tx).expect("tx should succeed");
    println!("CU used: {}", res.compute_units_consumed);
    assert!(res.compute_units_consumed < 100_000);
}
#[test]
fn rejects_wrong_challenge() { /* same as above but with chal = b"AAAA" → expect Err */ }
```
Write `rejects_wrong_challenge` fully by copying the body and changing `chal` to `b"AAAA".to_vec()`, asserting `svm.send_transaction(tx).is_err()`.

- [ ] **Step 4: Build + run**

Run (serialized): `cd /opt/warden && cargo-build-sbf --manifest-path spikes/02-webauthn/onchain/Cargo.toml && cargo test --manifest-path spikes/02-webauthn/onchain/Cargo.toml -- --nocapture`
Expected: both tests pass; CU printed. If LiteSVM does not implement the secp256r1 precompile (tx fails with "unsupported program"), fall back: `solana-test-validator --reset -q &`, deploy `.so`, send the same two-instruction tx with `solana`/a 30-line TS script using `@solana/web3.js`, and record CU from `getTransaction` meta. Record which path worked.

- [ ] **Step 5: Append to `result.md`**

Record: precompile available in LiteSVM (y/n), CU consumed, low-S normalization needed (y/n on the sample), byte layout confirmed, the substring-match approach's caveat (JSON escaping/ordering — Phase 1 must add a stricter, still allocation-light parser or bind a canonical clientDataJSON template), and the exact `origin` string.

- [ ] **Step 6: Commit**

```bash
git add spikes/02-webauthn && git commit -m "spike(02b): secp256r1 precompile + Instructions-sysvar binding of a real WebAuthn assertion (LiteSVM)"
```

---

### Task 5: Spike 3a — wrapped-transaction byte budget

**Files:**
- Create: `spikes/03-txbudget/ts/package.json`, `spikes/03-txbudget/ts/src/measure.ts`, `spikes/03-txbudget/ts/src/wrap.ts`, `spikes/03-txbudget/ts/test/wrap.test.ts`, `spikes/03-txbudget/result.md`

**Interfaces:**
- Produces: `wrap.ts` exports `wrapForExecute(msg: VersionedMessage, wardenProgram: PublicKey, account: PublicKey, sessionKey: PublicKey): { inline: VersionedTransaction | null; stagedChunks: number; bytesInline: number; bytesOriginal: number }` — the algorithm Phase 2's SDK will productionize.

- [ ] **Step 1: Write the wrapper**

`ts/package.json`:
```json
{ "name": "@warden-spike/txbudget", "private": true, "type": "module",
  "scripts": { "test": "vitest run", "measure": "node --experimental-strip-types src/measure.ts" },
  "dependencies": { "@solana/web3.js": "^1.98.0" }, "devDependencies": { "vitest": "^3.0.0" } }
```
`ts/src/wrap.ts`:
```ts
import { PublicKey, TransactionMessage, VersionedTransaction, VersionedMessage, MessageV0, AddressLookupTableAccount, TransactionInstruction } from "@solana/web3.js";
export const MAX_TX_BYTES = 1232;
/** execute ix data: u8 op=2 | u8 n_ixs | for each: u8 program_idx | u8 n_accts | n_accts×(u8 acct_idx | u8 flags) | u16 data_len | data
 *  Indices refer to the OUTER compiled message account list, so wrapping adds only ~ (4 + 2·accts + data) bytes per instruction. */
export function wrapForExecute(msg: VersionedMessage, wardenProgram: PublicKey, account: PublicKey, sessionKey: PublicKey, luts: AddressLookupTableAccount[] = []) {
  const decompiled = TransactionMessage.decompile(msg, { addressLookupTableAccounts: luts });
  const inner: TransactionInstruction[] = decompiled.instructions;
  // Build the outer instruction: warden execute, with every inner account as a remaining account (dedup), PDA as non-signer.
  const metas = new Map<string, { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }>();
  const key = (p: PublicKey) => p.toBase58();
  for (const ix of inner) {
    metas.set(key(ix.programId), { pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const k of ix.keys) {
      const cur = metas.get(key(k.pubkey));
      const isSigner = k.pubkey.equals(account) ? false : (cur?.isSigner || k.isSigner); // PDA signs via invoke_signed
      metas.set(key(k.pubkey), { pubkey: k.pubkey, isSigner, isWritable: cur?.isWritable || k.isWritable });
    }
  }
  const order = [...metas.values()];
  const idx = (p: PublicKey) => order.findIndex(m => m.pubkey.equals(p));
  const parts: number[] = [2, inner.length];
  for (const ix of inner) {
    parts.push(idx(ix.programId), ix.keys.length);
    for (const k of ix.keys) parts.push(idx(k.pubkey), (k.isSigner ? 1 : 0) | (k.isWritable ? 2 : 0));
    parts.push(ix.data.length & 0xff, ix.data.length >> 8, ...ix.data);
  }
  const outer = new TransactionInstruction({ programId: wardenProgram, keys: [{ pubkey: account, isSigner: false, isWritable: true }, { pubkey: sessionKey, isSigner: true, isWritable: true }, ...order], data: Buffer.from(parts) });
  const compiled = new TransactionMessage({ payerKey: sessionKey, recentBlockhash: decompiled.recentBlockhash, instructions: [outer] }).compileToV0Message(luts);
  const tx = new VersionedTransaction(compiled);
  const bytesInline = tx.serialize().length + 64 * 0; // signatures already counted by serialize (1 sig placeholder)
  const bytesOriginal = new VersionedTransaction(msg).serialize().length;
  const inline = bytesInline <= MAX_TX_BYTES ? tx : null;
  const stagedChunks = inline ? 0 : Math.ceil(Buffer.from(parts).length / 900); // ~900 B payload per stage_chunk tx
  return { inline, stagedChunks, bytesInline, bytesOriginal };
}
```

- [ ] **Step 2: Unit test with a synthetic 3-instruction message**

`ts/test/wrap.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { Keypair, PublicKey, SystemProgram, TransactionMessage } from "@solana/web3.js";
import { wrapForExecute } from "../src/wrap.js";
describe("wrapForExecute", () => {
  it("wraps a small transfer inline", () => {
    const acct = Keypair.generate().publicKey, sess = Keypair.generate(), prog = Keypair.generate().publicKey;
    const ix = SystemProgram.transfer({ fromPubkey: acct, toPubkey: Keypair.generate().publicKey, lamports: 1n });
    const msg = new TransactionMessage({ payerKey: sess.publicKey, recentBlockhash: "11111111111111111111111111111111", instructions: [ix] }).compileToV0Message();
    const r = wrapForExecute(msg, prog, acct, sess.publicKey);
    expect(r.inline).not.toBeNull();
    expect(r.bytesInline).toBeLessThan(400);
    expect(r.bytesInline).toBeGreaterThan(r.bytesOriginal);
  });
});
```
Run: `cd spikes/03-txbudget/ts && pnpm install && pnpm test` → PASS.

- [ ] **Step 3: Measure three real transactions**

`ts/src/measure.ts`:
```ts
import { Connection, PublicKey, VersionedTransaction, Keypair } from "@solana/web3.js";
import { wrapForExecute } from "./wrap.js";
const RPC = process.env.RPC ?? "https://api.mainnet-beta.solana.com";
const conn = new Connection(RPC);
const user = new PublicKey("11111111111111111111111111111112"); // any funded pubkey works for quotes; swap tx build needs a real owner: use env USER_PUBKEY
const owner = new PublicKey(process.env.USER_PUBKEY ?? user.toBase58());
async function jupiter(): Promise<VersionedTransaction> {
  const q = await (await fetch(`https://lite-api.jup.ag/swap/v1/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=100000000&slippageBps=50&platformFeeBps=85`)).json();
  const s = await (await fetch("https://lite-api.jup.ag/swap/v1/swap", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ quoteResponse: q, userPublicKey: owner.toBase58(), wrapAndUnwrapSol: true }) })).json();
  return VersionedTransaction.deserialize(Buffer.from(s.swapTransaction, "base64"));
}
async function main() {
  const cases: Record<string, () => Promise<VersionedTransaction>> = { "jupiter SOL→USDC 0.1": jupiter };
  // TODO-FREE NOTE: Tensor/Marinade builders need their SDKs; add `@tensor-oss/tensorswap-sdk` and `@marinade.finance/marinade-ts-sdk` builders here in the same shape (name → () => VersionedTransaction). If an SDK needs an API key, record "not measured" for that case in result.md rather than skipping silently.
  const wardenProgram = Keypair.generate().publicKey, account = owner, session = Keypair.generate().publicKey;
  for (const [name, build] of Object.entries(cases)) {
    const tx = await build();
    const luts = await Promise.all(tx.message.addressTableLookups.map(async l => (await conn.getAddressLookupTable(l.accountKey)).value!));
    const r = wrapForExecute(tx.message, wardenProgram, account, session, luts);
    console.log(JSON.stringify({ name, bytesOriginal: r.bytesOriginal, bytesInline: r.bytesInline, fitsInline: !!r.inline, stagedChunks: r.stagedChunks, writableAccounts: tx.message.staticAccountKeys.length + tx.message.addressTableLookups.reduce((a, l) => a + l.writableIndexes.length + l.readonlyIndexes.length, 0) }));
  }
}
main().catch(e => { console.error(e); process.exit(1); });
```
Run: `USER_PUBKEY=<any mainnet pubkey holding a little SOL> pnpm measure` (read-only; nothing is signed or sent). Run it 5 times across the day (routes vary) and paste each JSON line into `result.md`.

- [ ] **Step 4: Write `result.md` (part a)**

Table: case · original bytes · wrapped bytes · fits inline? · chunks if staged · writable account count. Conclusion line: "% of Jupiter SOL→USDC routes that fit inline; typical chunk count when not".

- [ ] **Step 5: Commit**

```bash
cd /opt/warden && git add spikes/03-txbudget && git commit -m "spike(03a): wrapped-tx byte budget measured on real Jupiter routes"
```

---

### Task 6: Spike 3b — conservation-snapshot CU cost

**Files:**
- Create: `spikes/03-txbudget/onchain/Cargo.toml`, `spikes/03-txbudget/onchain/src/lib.rs`, `spikes/03-txbudget/onchain/tests/cu.rs`, append `spikes/03-txbudget/result.md`

**Interfaces:**
- Produces: measured CU for snapshotting N∈{10,20,30} writable token accounts before/after a no-op CPI, plus Token-2022 TLV byte compare; informs Phase 1's `execute` budget.

- [ ] **Step 1: Program**

`onchain/Cargo.toml`: same shape as Task 4 with `name = "spike-conserve"`, plus `spl-token = { version = "7", features = ["no-entrypoint"] }` and `spl-token-2022 = { version = "7", features = ["no-entrypoint"] }` (adjust majors to what resolves; record).
`onchain/src/lib.rs`:
```rust
use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError, pubkey::Pubkey, program_pack::Pack};
entrypoint!(process);
#[derive(Clone, PartialEq, Eq, Debug)]
struct Snap { owner: Pubkey, lamports: u64, data_len: usize, token: Option<(Pubkey, Pubkey, u64, Option<Pubkey>, Option<Pubkey>, u8)>, tlv_hash: [u8; 32] }
fn snap(a: &AccountInfo) -> Result<Snap, ProgramError> {
    let data = a.try_borrow_data()?;
    let token = if *a.owner == spl_token::ID || *a.owner == spl_token_2022::ID {
        let t = spl_token::state::Account::unpack_from_slice(&data[..spl_token::state::Account::LEN.min(data.len())]).ok();
        t.map(|t| (t.mint, t.owner, t.amount, t.delegate.into(), t.close_authority.into(), t.state as u8))
    } else { None };
    let tlv_hash = if data.len() > spl_token::state::Account::LEN { solana_program::keccak::hash(&data[spl_token::state::Account::LEN..]).to_bytes() } else { [0; 32] };
    Ok(Snap { owner: *a.owner, lamports: a.lamports(), data_len: data.len(), token, tlv_hash })
}
/// accounts[0] = vault authority pubkey (read-only marker); rest = writable accounts to snapshot. data[0] = 1 → simulate a mutation between snapshots (test negative path).
pub fn process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let vault = accounts[0].key;
    let before: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    // (a real execute would CPI here)
    let after: Vec<Snap> = accounts[1..].iter().map(snap).collect::<Result<_, _>>()?;
    let mut sol_out: u64 = 0;
    for (b, a) in before.iter().zip(after.iter()) {
        if let (Some(tb), Some(ta)) = (&b.token, &a.token) {
            if tb.1 == *vault { // vault-owned token account
                if ta.1 != tb.1 || ta.3.is_some() || ta.4.is_some() || ta.5 != 1 || a.tlv_hash != b.tlv_hash || a.data_len != b.data_len { msg!("vault token account mutated"); return Err(ProgramError::InvalidAccountData); }
                let dec = tb.2.checked_sub(ta.2).unwrap_or(0);
                if tb.0 == spl_token::native_mint::ID { sol_out = sol_out.checked_add(dec).ok_or(ProgramError::ArithmeticOverflow)?; }
            }
        }
    }
    msg!("snapshots ok, sol_out={}", sol_out);
    if data.first() == Some(&1) { return Err(ProgramError::Custom(99)); }
    Ok(())
}
```

- [ ] **Step 2: LiteSVM CU test**

`onchain/tests/cu.rs`: create a LiteSVM, add program, create N SPL token accounts owned by a `vault` pubkey (use `spl_token::state::Account` packed bytes via `svm.set_account`), invoke with N∈{10,20,30}, print `compute_units_consumed` per N; assert < 200_000 at N=30. Also one Token-2022 account with a 100-byte fake TLV tail to exercise the keccak path.

- [ ] **Step 3: Build, run, record**

Run (serialized): `cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml && cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml -- --nocapture`
Append to `result.md`: CU per N, extrapolated per-account cost, and whether `keccak` syscall or `sha256` is cheaper for the TLV compare (try both, keep the cheaper; record).

- [ ] **Step 4: Commit**

```bash
git add spikes/03-txbudget && git commit -m "spike(03b): conservation snapshot CU cost measured in LiteSVM"
```

---

### Task 7: Spike 4 — dApp compatibility inventory (top 20)

**Files:**
- Create: `spikes/04-compat/inventory.md`

**Interfaces:**
- Produces: table consumed by Task 9 and by Phase 2's adapter registry (which programs/discriminators to ship first).

- [ ] **Step 1: Pick the list**

Top 20 Solana dApps by weekly active wallets from a public source (record the source + date): e.g., Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Jito, Drift, Tensor, Magic Eden, Pump.fun, Phoenix, Sanctum, marginfi, Solend/Save, Zeta, Parcl, Helium, Realms, Squads.

- [ ] **Step 2: For each, determine from docs/SDK source (cite URLs):**

| dApp | Connect needs SIWS / signMessage? | Builds txs with extra signers / partial sigs? | Uses durable nonces? | Programs + instruction discriminators the common flows call | Requires wallet == top-level signer (any `is_signer` on the wallet key beyond fee payer)? | Verdict for Warden session path: OK / root-only / unsupported |

Use `git clone --depth 1` of each public SDK and `grep -rn "signMessage\|signIn\|nonce\|partialSign"`; for programs use the IDL instruction names. Where a dApp is closed-source, load its site with the Playwright MCP, open the connect flow, and note whether it requests `signMessage` (record "observed in UI").

- [ ] **Step 3: Summarize**

Counts: OK / root-only / unsupported; the list of `(program_id, discriminator)` pairs to seed the adapter registry; the SIWS list (dApps that will not log in with a smart account).

- [ ] **Step 4: Commit**

```bash
git add spikes/04-compat && git commit -m "spike(04): dApp compatibility inventory (top 20)"
```

---

### Task 8: Design foundation in Figma (tokens → components → two key screens)

**Files:**
- Create: `docs/design/figma.md`, `packages/ui-tokens/package.json`, `packages/ui-tokens/tokens.json`, `packages/ui-tokens/tokens.css`, `packages/ui-tokens/test/tokens.test.ts`

**Interfaces:**
- Produces: Figma file URL; `tokens.json` (name → OKLCH/px/font values) and `tokens.css` (`:root` + dark block, same names) consumed by Phase 2's extension UI. Token names are fixed here: `--w-bg`, `--w-surface`, `--w-ink`, `--w-muted`, `--w-hairline`, `--w-accent` (indigo), `--w-ok`, `--w-warn`, `--w-critical`, `--w-radius-card: 12px 12px 4px 12px`, `--w-font-ui: Inter`, `--w-font-mono: JetBrains Mono`, spacing `--w-s-4/8/12/16/24/32/48`.

- [ ] **Step 1: Read the doctrine and the Figma skill**

Read `/opt/drinkerlabs/DESIGN.md` §2 (color/type/motion) and §4; invoke `/figma-use` (mandatory before `use_figma`).

- [ ] **Step 2: Create the Figma file and variables**

With the Figma MCP: `create_new_file` "Warden Wallet — design system"; then via `use_figma` create variable collections `color` (light + dark modes) with: bg = `oklch(97% 0.008 85)` (bone) / `oklch(14% 0.02 260)` (midnight); surface = bone-1 step / midnight+4%; ink = `oklch(22% 0.008 250)` / `oklch(92% 0.006 90)`; muted at 55%; hairline = `oklch(0% 0 0 / 0.06)` / `oklch(100% 0 0 / 0.08)`; accent = `oklch(50% 0.12 270)` both modes (dark: L 62%); ok/warn/critical = `oklch(60% 0.12 150)` / `oklch(72% 0.14 75)` / `oklch(55% 0.16 25)`. `type` collection: Inter 13/15/17/22/28 (line-heights on the 4px grid), JetBrains Mono 12/13 with tabular figures. `space` collection: 4/8/12/16/24/32/48. `radius`: card `12 12 4 12`, pill 999.

- [ ] **Step 3: Components**

Create: Button (primary/secondary/destructive; ack 120ms, emphasis easing), Amount (mono, tabular, sign-colored), Address chip (mono, first4…last4, copy), Trust badge (known / first-time / dust-only), Policy verdict banner (within limits / needs passkey + delay / blocked), Balance row, Nav bar, Sheet.

- [ ] **Step 4: Two screens first**

06 Sign request / intent (popup 360×600): origin header · what changes (balance diffs, per token, mono amounts, sign colour) · authority changes (always critical) · recipient trust · policy verdict banner · primary action reads exactly what will happen ("Send 0.25 SOL to 7f3k…q9Lm") · secondary "Reject". 02 Home: balances, pending timelocks (with countdown + cancel), session status (unlocked N min, caps remaining today), one live number per doctrine (nothing fake — show `—` if RPC unavailable). Take `get_screenshot` of both; save PNGs under `docs/design/`.

- [ ] **Step 5: Export tokens and test them**

`packages/ui-tokens/tokens.json` = the variable values as authored (write by hand from Figma variables; names as in Interfaces). `tokens.css`:
```css
:root{--w-bg:oklch(97% 0.008 85);--w-surface:oklch(95% 0.008 85);--w-ink:oklch(22% 0.008 250);--w-muted:oklch(22% 0.008 250 / .55);--w-hairline:oklch(0% 0 0 / .06);--w-accent:oklch(50% 0.12 270);--w-ok:oklch(60% 0.12 150);--w-warn:oklch(72% 0.14 75);--w-critical:oklch(55% 0.16 25);--w-radius-card:12px 12px 4px 12px;--w-font-ui:Inter,system-ui,sans-serif;--w-font-mono:"JetBrains Mono",ui-monospace,monospace;--w-s-4:4px;--w-s-8:8px;--w-s-12:12px;--w-s-16:16px;--w-s-24:24px;--w-s-32:32px;--w-s-48:48px}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--w-bg:oklch(14% 0.02 260);--w-surface:oklch(18% 0.02 260);--w-ink:oklch(92% 0.006 90);--w-muted:oklch(92% 0.006 90 / .55);--w-hairline:oklch(100% 0 0 / .08);--w-accent:oklch(62% 0.12 270)}}
:root[data-theme="dark"]{--w-bg:oklch(14% 0.02 260);--w-surface:oklch(18% 0.02 260);--w-ink:oklch(92% 0.006 90);--w-muted:oklch(92% 0.006 90 / .55);--w-hairline:oklch(100% 0 0 / .08);--w-accent:oklch(62% 0.12 270)}
```
`packages/ui-tokens/package.json`: `{ "name": "@warden/ui-tokens", "version": "0.0.1", "type": "module", "scripts": { "test": "vitest run" }, "devDependencies": { "vitest": "^3.0.0" } }`.
`packages/ui-tokens/test/tokens.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
const css = readFileSync(new URL("../tokens.css", import.meta.url), "utf8");
const json = JSON.parse(readFileSync(new URL("../tokens.json", import.meta.url), "utf8"));
describe("tokens", () => {
  it("every json token exists in css :root", () => { for (const name of Object.keys(json)) expect(css.includes(`${name}:`)).toBe(true); });
  it("dark block redefines only tokens defined in :root", () => {
    const root = css.split("@media")[0]; const dark = css.split("@media")[1] ?? "";
    for (const m of dark.matchAll(/(--w-[a-z0-9-]+):/g)) expect(root.includes(`${m[1]}:`)).toBe(true);
  });
  it("exactly one accent hue family", () => expect((css.match(/--w-accent:/g) ?? []).length).toBe(3));
});
```
Run `pnpm test` → PASS.

- [ ] **Step 6: Record and commit**

`docs/design/figma.md`: file URL, node ids of the two screens, token map, what is not yet designed (screens 01,03,04,05,07–11). Commit: `git add docs/design packages/ui-tokens && git commit -m "design: Figma tokens/components + sign-request and home screens; ui-tokens package"`.

---

### Task 9: Decision gate — roll-up, Codex review, Phase 1 go/no-go

**Files:**
- Create: `docs/spikes/DECISION.md`; Modify: spec §12 (append "Result:" lines)

- [ ] **Step 1: Write `DECISION.md`**

Sections: Spike 1 verdict (KEEP-OWN-PROGRAM / SWITCH) with the 11-row table copied; Spike 2 (WebAuthn from MV3: y/n; PRF: virtual y/n, real-device status; on-chain bind: CU, LiteSVM support, low-S note); Spike 3 (inline fit %, chunk counts, snapshot CU per account, chosen hash for TLV); Spike 4 (OK/root-only/unsupported counts, adapter seed list, SIWS list). Then **Consequences for the spec** (each as a concrete edit, e.g. "§4: PRF confirmed on virtual only → Argon2id fallback remains mandatory in v1"; "§5.2: execute budget = X CU + Y per account → cap writable accounts at N"), and **Phase 1 go/no-go**.

- [ ] **Step 2: Apply the consequences to the spec** (edit §4/§5/§6/§12 in place; bump to rev 6; commit `docs(spec): rev 6 — spike results applied`).

- [ ] **Step 3: Codex review** (`mcp__codex__codex`, `gpt-5.6-terra` @ `high`, `approval-policy: on-request`, no `sandbox` param, "do not spawn subagents"): prompt = "Review /opt/warden/docs/spikes/DECISION.md against spec rev 6 §12: are the verdicts supported by the recorded evidence in spikes/*/result.md? Any spike whose evidence does not justify its consequence? ≤ 300 words, end with GO / NO-GO for Phase 1 (on-chain program plan)". Record thread id + verdict at the bottom of `DECISION.md`. If NO-GO, fix the named gap and re-run once.

- [ ] **Step 4: Commit and hand off**

```bash
git add -A && git commit -m "docs: Phase 0 decision gate — spike roll-up + Codex verdict"
```
Then write Phase 1's plan (`docs/superpowers/plans/2026-MM-DD-warden-phase1-program.md`) with the writing-plans skill, using the measured numbers as its constraints.

---

## Self-review (done at authoring)

- **Spec coverage (Phase 0 scope only):** §12.1 → Task 2; §12.2 → Tasks 3–4; §12.3 → Tasks 5–6; §12.4 → Task 7; §9 tokens/first screens → Task 8; repo/gates (§10 gates, CLAUDE.md, test-gate) → Task 1; decision → Task 9. Program/SDK/extension/services (§3–§8, §10–§11) are Phases 1–4, deliberately not here.
- **Placeholders:** none of "TBD/TODO/implement later"; Task 5 step 3 contains an explicit instruction (not a placeholder) to add two more builders and to record "not measured" if blocked. Task 4 step 3's second test body is specified by exact substitution.
- **Type consistency:** `wrapForExecute` signature identical in Task 5 Interfaces/code/test; token names identical in Task 8 Interfaces/css/test; `assertion.json` → `raw.json` field names identical between Task 3 test, Task 4 prep, and Task 4 Rust test (`pubkey33`, `sig64`, `message`, `authenticatorData`, `clientDataJSON`, `rpIdHash`, `origin`, `challenge`).
- **Known uncertainty carried into steps (not hidden):** LiteSVM secp256r1 support, CDP `hasPrf`, extension-id discovery under headless, crate major versions vs Agave 3.x — each step names the fallback and requires recording what happened.
