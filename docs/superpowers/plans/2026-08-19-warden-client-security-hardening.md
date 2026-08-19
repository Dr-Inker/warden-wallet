# Warden Wallet — Client Security Hardening and Release Assurance Plan

> **For Claude Code:** This is a security implementation plan, not evidence that
> the controls exist. Preserve the Phase 1B task order in `CLAUDE.md`. Seed every
> new claim in `docs/security/invariants.jsonl` before promoting it, and never
> report a gate green without the exact command and the SHA it passed at.

**Authored:** 2026-08-19

**Research base:** `c65d16851479eed93ec745fa27889a67dbbc77f9` (`phase1b`)

**Scope:** the production MV3 extension, client transaction boundary, key
lifecycle, approval integrity, recovery export, simulation, and extension
release channel. Program work remains governed by the existing Phase 1B plan.

## Goal and honest security property

Build the client half of Warden so that the on-chain loss limits cannot be
silently bypassed by stale approvals, forged page context, misleading intent
rendering, service-worker lifecycle errors, portable weakly encrypted vaults,
or a compromised release path.

This plan does **not** promise an “unhackable” wallet. It preserves the product
property already stated in the design spec: compromise of everything held by an
unlocked extension is bounded by on-chain caps, while larger actions are delayed
and cancellable. It also reduces the chance that the extension tricks the user
or signs something different from what it displayed.

## Scheduling contract

1. Do not interrupt the current Phase 1B sequence. At this base, conservation
   and proof-of-possession are landed; registry, staging, `execute`, `swap`, the
   TS payload builder, and close-out remain.
2. Task C0 below may land at a clean task boundary because it is ledger/test
   scaffolding only.
3. Do not implement C1–C5 against provisional SDK interfaces. Start them only
   after Phase 1B Task 8 has stabilized the payload builder, transcript mirror,
   and transaction-wrapping APIs.
4. C6 release work may start once a deterministic extension build exists.
5. One heavy build at a time on this host. Never deploy from this plan.

## Research basis: what was actually inspected

The useful comparison was source- and audit-level, pinned to commits. Repository
discovery alone is not counted as research.

| Project | Pinned source / evidence | Reusable lesson or warning |
|---|---|---|
| Brave Wallet | `brave/brave-core@f46fb7d1b2109318c9c8498df9943ce2fdb961a7` | Browser-process C++ keyring; typed Mojo requests carry `url::Origin`; lock destroys keyring/encryptor; deterministic local danger checks complement advisory simulation. Warden cannot reproduce the C++ boundary in Chrome, so it must minimize service-worker authority and rely on on-chain caps. |
| Rabby | `RabbyHub/Rabby@b00d77e486dad467aabef3e528dfa05eb968e209` plus Least Authority and SlowMist 2025 audits in `audits/2025/` | Background derives origin from the port sender, strips untrusted context, serializes approvals, and persists absolute autolock state across worker suspension. Audit warnings: password-encrypted QR vaults permit offline guessing; signing nonces must be bound exactly; unknown signature types need a hard warning; concurrent signing needs tests. |
| Backpack | `coral-xyz/backpack@5a538a41d060d2c48507007f96c766483115aecc` | PBKDF2 + NaCl secretbox vault and broad provider support, but the unlocked store retains a plaintext password and sensitive re-auth compares against that cached value. Do not copy UI-only re-auth or cached passwords. The repo labels itself unaudited/not production-ready. |
| Helium Wallet | `helium/wallet-app@1ebf21aa467686a0c4be7b0b39cd749be3b21870` | Raw mnemonic/private-key material is in platform secure storage, while the PIN/biometric lock is largely a UI boundary and reads are not configured with per-read authentication. Authentication must gate key release, not merely navigation. |
| Safe smart account | `safe-global/safe-smart-account@37a8215a8f2a10e275650cfce0059dbfb480030e` | EIP-712 binds the complete action and nonce. Modules are an alternate execution lane with their own guard. Every Warden lane—session, root, staged, queued, recovery, adapter—needs equivalent invariants. |
| Ledger Solana app | `LedgerHQ/app-solana@c855c1a0ea12e76406efbfd17203ecf419952e27` | Parses the exact message being signed; unknown messages require explicitly enabled blind signing and display “Unrecognized format” plus the message hash. The parser has a 50-file fuzz corpus across dangerous System/SPL/Token-2022/stake/vote operations. Transaction-check reports bind exact message hash, signer, and mainnet chain id; missing/mismatched reports warn rather than certify safety. |
| BlueWallet | `BlueWallet/BlueWallet@e242791752cb79f8372305472abf3623523e2465` | Useful PSBT/hardware/reproducible-build flows, but legacy backup encryption is EVP_BytesToKey-MD5 with one iteration plus AES-CBC for compatibility. Wallet export has screen protection but no fresh biometric gate in the export action. Never introduce a compatibility format like this into Warden. |
| Sparrow | `sparrowwallet/sparrow@1e660ad2301737489b98a66b86c2d11a5cd5f1bb` | Constructs a PSBT and opens that exact artifact for review; exposes UTXO, fee, change, privacy, RBF and address-reuse information; documents byte-for-byte reproducible application directories. |
| Electrum | `spesmilo/electrum@f0f652174b79dde627ab68f96cd545b5b1ece020` | Transaction view is derived from the transaction object and has reject-level sighash danger handling and fee warnings. Atomic restrictive-permission wallet writes are good; its legacy password KDF (PBKDF2-SHA512, 1,024 iterations, empty salt) is not a modern template. |
| Existing Warden prior art | `docs/security/PRIOR-ART-FINDINGS.md` | Squads v4, LazorKit, Swig, and Argent findings are already mapped into program invariants. Reuse those IDs; do not rediscover or paraphrase them into disconnected prose. |

Phantom’s current full client source was not available. Its public Lighthouse,
security, hardware-wallet, and bug-bounty documentation is useful for product
comparison, but implementation details remain **UNVERIFIED**.

## Base-state findings that drive this plan

- There is no production `apps/extension`; only the throwaway WebAuthn spike
  under `spikes/02-webauthn/ext/`. Never import from a spike.
- The invariant source of truth contains 53 rows at the research base: 34
  `test-covered`, 18 `unimplemented`, and one `llm-asserted`. These are ledger
  statuses, not a fresh test run.
- The ledger has no addressable rows for production keyring lifecycle,
  background/page trust boundaries, approval single-use semantics, intent-to-
  bytes binding, simulation-report binding, recovery export, or Chrome Web
  Store publishing controls, even though spec §17 L9 requires these lanes.
- `docs/security/RELEASE-INTEGRITY.md` honestly records no tagged release and
  only a non-reproducible development program artifact. Extension provenance
  has no implementation yet.
- Real-device WebAuthn PRF remains **UNVERIFIED**. Argon2id fallback is mandatory;
  PRF must never become a hidden availability dependency.

---

## C0 — Make client and release claims addressable before implementation

**Why first:** prose requirements are not executable gates. The ledger must make
each client property independently reviewable and prevent a polished extension
from being declared secure while testing the wrong boundary.

**Files:** `docs/security/invariants.jsonl`, generated
`docs/security/INVARIANTS.md`, `docs/security/THREATMODEL.md`, and client test
fixtures. Do not hand-edit the generated table.

- [ ] Add the following rows at honest initial status (`unimplemented` unless
  executable evidence already exists). Exact statements may be tightened, but
  do not merge distinct properties merely to reduce row count:
  - `WRD-KEY-01`: the root private key is non-exportable and never enters
    extension memory; session and recovery secrets are typed and cannot be used
    as root authority.
  - `WRD-KEY-02`: no plaintext password is retained after derivation; no password
    equality check substitutes for fresh cryptographic authentication.
  - `WRD-KEY-03`: idle and hard unlock deadlines are absolute wall-clock values,
    checked on every key use and after every service-worker wake; expiry clears
    all session unlock material.
  - `WRD-KEY-04`: encrypted keyring envelopes are versioned AEAD with random
  nonces and AAD binding account, full extension origin, key kind, and schema
  version; malformed, unknown-version, replayed-context, and tampered envelopes
    reject.
  - `WRD-EXT-01`: privileged background methods derive origin, extension id,
    tab, and frame from browser-owned sender metadata, never page-supplied data.
  - `WRD-EXT-02`: an extension UI port is privileged only when browser-owned
    sender identity proves it is the extension; content scripts cannot impersonate it.
  - `WRD-APR-01`: every approval is an immutable, expiring, single-use background
    record binding request id, origin, account, method, cluster, serialized
    message bytes and digest.
  - `WRD-APR-02`: the approval UI renders from those exact bytes and the signer
    rechecks the digest immediately before signing; caller labels, route params,
    or stale simulation objects never define the displayed intent.
  - `WRD-APR-03`: concurrent approve/reject/timeout/navigation events have one
    atomic winner and cannot sign twice or resolve the wrong request.
  - `WRD-TXI-01`: supported instructions are decoded locally from serialized
    bytes; unknown or ambiguous instructions never receive a benign verdict and
    there is no blind-sign fallback in v1.
  - `WRD-SIM-01`: every simulation/reputation result is bound to exact message
    digest, signer/account, cluster identity, and freshness; mismatch or absence
    cannot display a green/safe state.
  - `WRD-SIM-02`: simulator output is advisory and can neither authorize an
    on-chain-denied action nor bypass local/on-chain policy.
  - `WRD-EXP-01`: any recovery-secret reveal or export requires a fresh ceremony;
    root and session secrets are never exportable; portable recovery envelopes
    retain the specified 128-bit secret strength and contextual AAD.
  - `WRD-REL-01`: a clean checkout at a release tag produces a byte-identical
    extension payload in two isolated builders, with an approved SHA-256.
  - `WRD-REL-02`: the published store payload is compared with the approved
    artifact, and any unexplained file/permission/CSP difference blocks release.
  - `WRD-REL-03`: publisher authority is least-privilege, phishing-resistant,
    recoverable, and two-person controlled; no long-lived publishing secret is
    committed or printed by CI.
- [ ] Extend `THREATMODEL.md` with explicit page compromise, malicious iframe,
  service-worker suspension, approval UI race, poisoned simulator response,
  dependency/build compromise, and publisher-account takeover rows.
- [ ] Run `node scripts/gen-invariants.mjs` and commit the JSONL plus generated
  Markdown together.
- [ ] Add a test that fails if a required client/release invariant id disappears.

**C0 acceptance:** `node scripts/gen-invariants.mjs --check` passes; every new
row has a spec reference, intended code/test reference, honest status, and no
fabricated evidence SHA.

## C1 — Establish the MV3 trust boundary before wallet features

**Files:** new `apps/extension/` package, manifest, provider/content script,
background router, request store, and unit/Playwright tests. Production code
must be rewritten from the spike, never imported from it.

- [ ] Start from the smallest manifest permissions and host permissions that
  support Wallet Standard. Document every permission. Keep
  `externally_connectable` closed unless a measured requirement proves otherwise.
- [ ] Inject only the thin provider bridge. It may transport untrusted data but
  never decide origin, account authority, policy, or approval status.
- [ ] Derive page origin, tab id, frame id, and extension sender identity from
  `Port.sender`/browser APIs in the service worker. Strip any page-supplied
  `$ctx`, `origin`, `tabId`, `frameId`, `approved`, or policy verdict.
- [ ] Require extension-id equality for privileged UI ports. Separate provider,
  popup, full-page approval, and internal test message schemas.
- [ ] Validate every message with a closed schema, size limits, method allowlist,
  and rejection of unknown fields where ambiguity could matter.
- [ ] Use cryptographically random request ids. Bind a request to its originating
  port/tab/frame and cancel it on expiry, navigation, disconnect, or account change.
- [ ] Explicitly set `chrome.storage.session` access to trusted extension contexts.
  Never expose unlock state or request bodies to content scripts.

**Required red tests:** content script pretending to be UI; forged page origin;
nested/cross-origin iframe; same tab after navigation; tab-id reuse; oversized
payload; unknown method; stale port; worker restart mid-request; popup opening a
request belonging to another origin/account.

## C2 — Keyring lifecycle whose authentication controls key release

- [ ] Store only a versioned AES-256-GCM envelope in persistent extension
  storage. Nonce uniqueness is mandatory; AAD binds the envelope to its account,
  full extension origin, key kind, and schema version. Do not bind it to a
  per-release build hash: normal extension updates must not brick old envelopes.
- [ ] PRF unlock is an optimization only after a real-device compatibility
  matrix demonstrates it. Keep an Argon2id password path that can always unlock
  the same envelope.
- [ ] Benchmark Argon2id on the slowest supported desktop class and record
  memory/time/parallelism plus observed latency. Choose the floor from measured
  data and amend the spec; do not silently inherit PBKDF2 or legacy wallet values.
- [ ] Discard the password string immediately after derivation. Never retain it
  for export re-prompts, and never validate re-auth with string equality.
- [ ] While unlocked, put only the minimum unlock material needed to survive MV3
  suspension in `storage.session`, restricted to trusted contexts. Persistent
  `local`/`sync` storage must never contain an unwrapped session key, derived key,
  password, recovery key, or approval capability.
- [ ] Persist absolute `idle_expires_at` and `hard_expires_at` timestamps. Check
  them synchronously before every sign/decrypt/export operation and again after
  every `await` that could suspend or race. Alarms are a wake-up aid, not the
  authority on expiry.
- [ ] Lock clears session unlock material, in-memory key references, pending
  privileged ceremonies, hardware transports, and approval state. JS zeroing is
  best effort and must not be overstated.
- [ ] Add a Content Security Policy that forbids remote code and generic eval.
  If bundled Argon2 WASM requires `wasm-unsafe-eval`, isolate and document that
  exception and prove no network-fetched module can execute.

**Required vectors/tests:** envelope round-trip; nonce differs for identical
plaintext; one-bit ciphertext/tag/AAD corruption; wrong account/origin/key kind;
unknown version; password and PRF derive the intended unwrap keys; wrong password;
idle boundary; hard boundary; clock advance while worker is asleep; worker death
and wake; lock during pending signing; rejection after expiry even if an alarm did
not fire. Do not derive expected ciphertext from the implementation under test.

## C3 — Immutable, single-use approval-to-signature binding

- [ ] The background request record is the source of truth:
  `{id, origin, tab, frame, account, method, cluster/genesis, raw_message,
  message_digest, created_at, expires_at, state}`.
- [ ] Store raw serialized bytes and compute the digest in the trusted background.
  The approval page receives an id and reads a frozen view; it does not accept a
  transaction or origin in its URL/query payload.
- [ ] Render recipient, amounts, programs, authorities, fees, account metas and
  policy verdict by decoding `raw_message`. Display data supplied by the dApp is
  untrusted annotation only and cannot replace decoded values.
- [ ] Immediately before signing, re-read the record and recompute the digest.
  Signing uses those same bytes. Any mutation, account/cluster change, expiry,
  navigation or policy-version change invalidates the approval.
- [ ] State transition is an atomic compare-and-set from `pending` to exactly one
  terminal state. Signing and resolution are idempotent by request id; a request
  cannot consume two nonces or sign twice.
- [ ] A root ceremony binds the complete Warden action transcript. A session
  approval binds the final wrapped transaction message and recent blockhash rules
  without weakening the on-chain action/account hash.

**Required race tests:** approve twice; approve/reject concurrently; timeout while
approving; account or network switch; UI reload; two approval windows; two
requests with identical dApp payloads; request order reversal; stale root nonce;
EIP-7702-style analogue where outer transaction nonce/block context changes while
the authorization stays stale.

## C4 — Decode what is signed; simulation is corroboration, not authority

- [ ] Build a deterministic local Solana/Warden decoder over the exact serialized
  message and wrapped execute payload. The intent view must not be assembled from
  navigation parameters or the transaction-construction form.
- [ ] No blind-sign mode in v1. An unknown program, discriminator, account-role
  layout, version, address lookup, or ambiguous parse is `unsupported/blocked`,
  never “no changes detected.” The root path may offer a fully decoded staged or
  timelocked alternative; it may not bypass parsing.
- [ ] Seed a parser/fuzzer corpus modelled on Ledger’s approach. Cover System
  assign/transfer/create/nonce, SPL and Token-2022 transfer/approve/revoke/
  set-authority/close/freeze/thaw, ATA creation, Memo, ComputeBudget, stake/vote,
  durable nonce, address lookup tables, malformed compact lengths, duplicate
  accounts, trailing bytes, and every Warden instruction/payload variant.
- [ ] Use independent fixtures or differential decoders. Expected values must not
  be generated by the same function under test.
- [ ] The intent screen always shows the final account, network, recipient,
  normalized balance deltas, fees, authority/delegate/close changes, program ids,
  first-time/dust-only recipient status, and the exact policy consequence:
  within caps, root+delay, or blocked.
- [ ] Local deterministic checks retain authority even if RPC simulation is down.
  Bind every simulation/reputation response to exact message digest, signer,
  cluster identity, request id, and freshness. Missing/mismatched/error results
  display “simulation unavailable/mismatch,” never a green state.
- [ ] A simulator cannot make a denied action signable. A malicious result cannot
  hide the local parser’s System `assign`, token authority, close-account, unknown
  instruction, or Warden policy warning.

**Required adversarial tests:** benign simulation for mutated bytes; report for
another signer/cluster; stale report; RPC lies about balance; parser vs simulator
disagreement; System `assign` hidden beside a transfer; Token-2022 extensions;
address poisoning; Unicode/lookalike labels; transaction changes after preview.

## C5 — Fresh authentication for export and recovery

- [ ] Root keys remain non-exportable. Session private keys have no export API.
- [ ] Recovery reveal/export requires a fresh passkey ceremony or a full Argon2id
  unlock that cryptographically unwraps the recovery envelope; an already-unlocked
  UI, cached password comparison, PIN overlay, or recent navigation is insufficient.
- [ ] Preserve the design’s 128-bit recovery code, Argon2id envelope, versioning,
  and AAD `account || version` (extend AAD only through an explicit migration).
- [ ] Never create a password-only portable vault whose offline resistance is the
  user’s password. If device-to-device transfer is added, use recipient-bound
  public-key encryption/handshake and bind both devices and the account.
- [ ] Apply screen-capture protection where the platform supports it. Do not allow
  mnemonic/recovery copying by default; if a deliberate copy flow is retained,
  warn that clipboard clearing is not a reliable erasure guarantee.
- [ ] Backgrounding, timeout, account switch, or route change immediately closes
  and clears the reveal view.

## C6 — Reproducible extension release and publisher-account defense

- [ ] Produce a deterministic unpacked build and deterministic store ZIP: sorted
  file order, normalized timestamps/modes, pinned Node/pnpm, frozen lockfile, no
  network-fetched runtime code, and no build-time secrets embedded in output.
- [ ] Generate an SBOM/license record and run the existing supply-chain gate over
  the shipped extension workspace. Pin GitHub Actions by immutable commit SHA,
  not mutable tags, for the release lane.
- [ ] Two isolated clean builders at the same signed tag must produce byte-identical
  payload trees and ZIP SHA-256. Record command, environment, artifact hash, and
  source SHA in an extension section of `RELEASE-INTEGRITY.md`.
- [ ] Add a verifier that downloads/accepts the store-delivered package, removes
  only documented store-signature packaging, and compares every shipped file,
  permission, CSP directive, and content hash against the approved artifact.
- [ ] Publisher access uses named least-privilege identities, phishing-resistant
  hardware-backed passkeys, protected recovery, and a two-person release action.
  Document who can publish, rotate credentials, change the store listing, or alter
  update URLs. Shared accounts are forbidden.
- [ ] Prefer no unattended publishing credential. If automation is ultimately
  required, threat-model its OAuth/service credential, constrain it to the one
  extension, keep it out of forks/logs/artifacts, rotate it, and require protected
  environment approval from a second person.
- [ ] Test the release gate by tampering one JS byte, adding one permission,
  relaxing CSP, changing the update URL, and altering a dependency-produced asset;
  each mutation must fail closed.

## C7 — Compatibility and hostile-environment campaign

- [ ] Run the top-20 dApp harness from spec §12.4 against the actual production
  provider. Record supported, safely rewritten, root-only, and rejected cases;
  never claim Phantom compatibility from connect-only tests.
- [ ] Exercise cross-origin and sandboxed iframes, popup blockers, page reloads,
  rapid navigation, multiple profiles, locked worker restarts, offline RPC,
  malicious RPC, clock jumps, and concurrent dApps.
- [ ] Add property/fuzz tests for the message router, request state machine,
  transaction decoder, execute payload decoder, and key-envelope parser.
- [ ] Run browser tests against Chrome and Brave stable plus the oldest supported
  version. Real-device PRF must cover each supported OS/authenticator combination
  before its status changes from UNVERIFIED.
- [ ] Conduct a dependency-confusion/compromised-package tabletop and a publisher-
  account takeover tabletop. Each must end in an executable detection or release
  gate, not prose alone.

## C8 — Promotion and real-funds gates

No client invariant moves because a reviewer says the code “looks right.” Promote
only with named executable evidence in the same commit.

- [ ] Per task: run focused tests, update invariant evidence, regenerate the
  ledger, and obtain the required adversarial Codex review seeded with the changed
  client invariant ids.
- [ ] At the merged milestone SHA—not merely an agent worktree—run the complete
  repo gate, extension unit/integration/Playwright gates, supply-chain gate,
  deterministic dual build, and published-artifact comparison where applicable.
- [ ] Record the exact commands and SHA in the handoff/release ledger. Verification
  prose is not a substitute for those commands.
- [ ] Independent wallet/extension audit, public bug bounty, devnet soak, incident
  response drill, publisher recovery drill, and upgrade/rollback drill all precede
  real-funds mainnet.
- [ ] Any unimplemented, `llm-asserted`, UNVERIFIED, or contradicted critical
  invariant blocks a claim that the product is production-ready.

## Minimum command set at a completed milestone

Claude must replace package placeholders with the scripts introduced by this
plan and report the exact merged SHA. Do not claim these commands passed until
they actually run on that SHA.

```sh
node scripts/gen-invariants.mjs --check
pnpm typecheck
pnpm test
pnpm build
pnpm --filter <extension-package> test
pnpm --filter <extension-package> test:integration
pnpm --filter <extension-package> test:playwright
scripts/supply-chain-gate.sh
./.claude/test-gate.sh
```

Release milestones additionally require the deterministic dual-build command and
the store-payload comparison command created in C6.

## Stop conditions and owner decisions

Stop and request a decision rather than silently choosing if any of these arise:

1. Real-device PRF coverage is too narrow to support the advertised platforms.
2. Argon2id parameters that meet the security floor cause unacceptable unlock
   latency or memory failures on a supported device.
3. Chrome Web Store publishing cannot be made two-person without introducing a
   broadly scoped long-lived token.
4. A top dApp requires blind signing, partial signatures, a durable nonce, an
   unallowlisted program, or PDA top-level signing. Rejecting it is the default;
   broadening authority requires a threat-model/spec decision.
5. An external simulator requires raw sensitive data beyond the exact transaction
   already being assessed or attempts to become an authorization gate.

## Deliverable back to the owner

For every completed task return:

- merged commit SHA and clean/dirty status;
- exact commands run at that SHA and their result;
- invariant ids promoted, unchanged, or knocked down;
- red-test paths and captured browser artifacts;
- permissions/CSP/storage changes;
- remaining UNVERIFIED items and explicit owner decisions;
- confirmation that no deploy, publisher change, secret creation, or live-account
  mutation occurred unless separately authorized.
