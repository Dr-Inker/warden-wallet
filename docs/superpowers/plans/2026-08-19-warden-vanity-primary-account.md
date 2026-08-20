# Warden Wallet — Optional Vanity Primary SmartAccount Proposal and Plan

> **For Claude Code:** this document records an approved product direction and
> an implementation plan, not an implemented control or a green gate. Preserve
> the Phase 1B order in `CLAUDE.md`, do not reuse the existing vanity bot's
> cryptographic code or binaries, and do not claim any command passed without
> reporting the exact command and merged SHA.

**Authored:** 2026-08-19

**Research base:** `d56feb62164f0efcad3d7c632d24853a15ad44a1`
(`phase1b` before this plan-only handoff)

**Depends on:** Phase 1B Task 8's stable client derivation API and the production
extension trust boundary in
`2026-08-19-warden-client-security-hardening.md`. It does not supersede or
reorder either plan.

## Decision

Proceed with an optional **Custom first address** step during onboarding, with
these owner-approved constraints:

- It customizes the first/primary Warden `SmartAccount` PDA. It is not a
  "master private key" and must never be described that way. The passkey remains
  the root authority.
- The requested fragment is 1–4 Base58 characters. Four is a hard maximum in
  the UI, worker protocol, and any future acceleration service; there is no
  paid or hidden override.
- Support suffix and prefix matching. Default to suffix because its cost is
  more predictable and generally much lower for high Base58 characters.
- Matching is case-insensitive by default. Offer an explicit **Match
  capitalization exactly** toggle with a warning that it may take materially
  longer.
- The step is optional. Skipping it uses a fresh random 32-byte salt through
  the same account-creation path.
- Reject invalid characters with an explanation and suggested valid
  alternatives. Never silently delete, replace, lowercase, or otherwise mutate
  what the user typed.

This is workable with the current Warden design. The safe implementation grinds
only a public 32-byte `salt`; it never generates, imports, exports, renders, or
copies an Ed25519 private key.

## The security property

For each candidate salt, derive:

```text
owner_seed = Keccak256("WARDEN/seed/v1" || root_pubkey33 || salt32)
address    = canonical_PDA(["account", owner_seed], warden_program_id)
```

The search changes only `salt32`. It does not change the passkey, passkey
entropy, root proof-of-possession, account policy, or PDA signing semantics.
Solana PDAs are off-curve addresses with no corresponding private key; the
Warden program signs for the account through the canonical PDA seeds and bump.

The current implementation already supplies the necessary on-chain property:

| Evidence | Consequence |
|---|---|
| `packages/core/src/webauthn/transcript.ts:158-196` | The supported TypeScript mirror derives `owner_seed` from the P-256 root public key and client salt. |
| `programs/warden/src/instructions/create_account.rs:70-117` | Rust uses the same domain and derivation on-chain. |
| `programs/warden/src/instructions/create_account.rs:172-199` | Anchor derives the initialized account from `ACCOUNT_SEED`, the derived owner seed, and the canonical bump. |
| `programs/warden/src/instructions/create_account.rs:294-309` | Creation stores the canonical bump and owner seed. |
| `programs/warden/src/state/smart_account.rs:36-49` | Later authority is represented by the stored PDA material and root public key, not a vanity private key. |
| `programs/warden/src/lib.rs:16` | The program id is another address input and therefore must be final and pinned before a long search. |

No production on-chain logic change is expected. A runtime change is a stop
condition unless a parity test demonstrates a real defect that cannot be fixed
in the client.

## Feasibility evidence, not a release benchmark

Session-local read-only probes against the exact current derivation suggest the
search space is reachable:

| Probe | Observation |
|---|---|
| Exact suffix `WD` | `C7kxcNsREGN1S97CcZKyQ5YXgG8diYTHSPhh8cH2D3WD`, canonical bump 254, found at attempt 3,201 with salt ending `0c80`. |
| Exact prefix `W` | `W3ysm92QgEc3pHYf8Lh3LEDjMfuTpwVj9gQYBPu4LKU`, a valid 43-character Warden PDA, canonical bump 254, found at attempt 99 with salt ending `0062`. |
| Host-only JavaScript sample | 50,000 candidates in 11.132 seconds, about 4,492 candidates/second on this server. This is not representative of a packaged Chrome extension or supported user hardware. |
| Address-length sample | Of 100,000 Warden PDA candidates, 5,412 encoded to 43 characters and 94,588 to 44; first characters spanned the full Base58 alphabet. |

These are exploration observations and remain **UNVERIFIED** until reproduced
by a committed command in V2. No product copy may use their rates or durations.

At the observed host rate, a uniform suffix approximation gives useful scale,
not a deadline:

- Four exact-case characters: about `58^4 = 11,316,496` expected candidates,
  roughly 42 minutes at this host rate.
- `Ward` as a case-insensitive suffix: each letter has two valid Base58 cases,
  so about `29^4 = 707,281` expected candidates, roughly 2.6 minutes at this
  host rate.
- Prefixes are not uniformly distributed. The same exploration estimated
  `Ward` at roughly 45 minutes case-insensitive and roughly 12 hours exact on
  this host, but V3 must replace that estimate with range-aware math and an
  actual-device calibration.
- Five exact suffix characters would be on the order of 41 hours at this host
  rate. The hard four-character cap deliberately excludes that class.

Search duration is geometric, not a fixed work queue. After `n` independent
candidates with per-candidate success probability `p`, the chance of having
found a result is `1 - (1 - p)^n`. The UI must show attempts, measured speed,
and probabilistic 50%/95% windows. It must not subtract attempts from an
"expected total" and label the result "time remaining."

## Base58 rules: carry forward only the real rule

The Solana Base58 alphabet is:

```text
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

The only globally unavailable characters are `0` (zero), uppercase `O`,
uppercase `I`, and lowercase `l`. All other alphabet characters can appear in a
1–4 character prefix or suffix of a valid 32-byte Solana address.

Do **not** copy the existing bot's special first-character and `J` rules. They
assume every 32-byte value is rendered as a fixed 44-character Base58 string:

- `/opt/vanity-bot/web/app.js:97-163` restricts the first character to
  `123456789ABCDEFGHJ` and restricts a second character after `J`.
- `/opt/vanity-bot/web/worker.js:14-32` repeats that rejection in the worker.
- A valid Warden PDA beginning with `W` was found above. A separate enumeration
  also produced 1,704 off-curve 32-byte values beginning `Jz`, disproving the
  bot's `J` rule for PDAs.

Solana addresses are variable-length Base58 encodings. Any feasibility or cost
estimator must account for lengths 32–44, leading zero bytes encoded as `1`,
and the non-uniform distribution of prefix symbols. Add regressions for 43- and
44-character addresses and for high-character prefixes such as `W`, `z`, and
`Jz`.

Case-insensitive cost is also pattern-specific. `/opt/vanity-bot/web/app.js:167-172`
uses `33^n`, which is only a rough collapsed-alphabet shortcut. For each
requested character, the matcher must count only valid Base58 case variants:
`W/w` has two; a digit has one; `L` has one because lowercase `l` is excluded;
`i` has one because uppercase `I` is excluded. The estimator and matcher must
use the same explicit variant set.

## Existing bot: UI reference only, never a code dependency

The server bot makes ordinary Ed25519 keypairs. Warden needs candidate salts for
a root-bound PDA. Reusing the bot would create a new secret-handling path and
compute the wrong kind of address:

- `/opt/vanity-bot/web/worker.js:79-84` posts a `privateKey` out of its WASM
  worker.
- `/opt/vanity-bot/web/app.js:39-45` copies that private key to the clipboard.
- `/opt/vanity-bot/web/app.js:281-295` renders the private key and encodes it in
  a QR code.
- The deployed WASM wrapper/binary is present without its Rust source in the
  inspected deployment tree, so its supply-chain provenance is insufficient
  for Warden even if its algorithm had been suitable.
- `/opt/vanity-bot/web/app.js:270-279` presents a stochastic search as a fixed
  countdown.

Progress, cancel, prefix/suffix, and capitalization ideas may be reimplemented
from the product requirement. No source file, compiled asset, protocol, or
private-key result shape from `/opt/vanity-bot` may enter Warden.

## Target architecture

### Trusted derivation

`@warden/core` remains the client authority for `deriveOwnerSeed` and the
canonical SmartAccount address derivation. After Phase 1B Task 8 settles the
Solana client dependency, add a supported helper that accepts exactly:

```text
root_pubkey33, salt32, program_id
    -> owner_seed32, address32/base58, canonical_bump
```

Reject wrong lengths and non-canonical values. The program id must be explicit;
there is no ambient "current network" default in this function.

Create a new source-controlled `packages/vanity-pda/` package for the search
engine, estimator, worker protocol, and reproducible benchmark. It may contain a
Rust-to-WASM implementation only if the Rust source, toolchain, lockfile,
generated wrapper, and build verification are all committed or reproducibly
generated. Do not download code or WASM at runtime.

The worker implementation necessarily mirrors Keccak, canonical PDA derivation,
off-curve checking, and Base58 for speed. It is not trusted to choose the final
account. The extension main thread independently re-derives every returned
candidate through `@warden/core` and compares `salt`, owner seed, address, bump,
program id, cluster/config digest, pattern semantics, and job id.

Benchmark a pure TypeScript worker and bundled WASM before selecting the shipped
engine. Prefer the smaller CSP and supply-chain surface if TypeScript meets the
measured four-character UX. If WASM requires `wasm-unsafe-eval`, record and test
that exact CSP delta under client-plan C2; never add generic `unsafe-eval`.

### Candidate space

For each job, obtain a 192-bit nonce from `crypto.getRandomValues`. Construct
each 32-byte salt as:

```text
salt32 = job_nonce24 || counter64_le
```

For `worker_count` parallel workers, worker `i` starts at counter `i` and
increments by `worker_count`. This makes search lanes disjoint. Reject a zero or
reused job nonce, counter wrap, unsupported worker count, or CSPRNG failure.
Changing the pattern, position, capitalization mode, root public key, program
id, cluster, seed-domain version, or worker count creates a new immutable job id
and cancels all old workers.

The nonce is not a signing secret, and the final salt becomes public when the
create transaction is submitted. Fresh randomness still matters: a predictable
small counter by itself would let an observer who learns the root public key
precompute and link unfinished onboarding attempts.

### Worker protocol

Use a closed, versioned schema. A request binds:

```text
schema_version, job_id, config_digest, root_pubkey33, program_id,
seed_domain_version, pattern, position, case_mode, job_nonce24,
worker_index, worker_count, starting_counter
```

A result contains only:

```text
schema_version, job_id, config_digest, salt32, owner_seed32,
address32, address_base58, bump, attempts
```

There is no `privateKey`, `secretKey`, mnemonic, recovery material, assertion,
credential id, unlock key, session key, or RPC token field. Unknown fields and
oversized messages reject. A stale result is discarded even if its address
happens to match the current visible pattern.

### Local-only v1

Run v1 entirely in the onboarding extension page's Web Workers, not in a page
content script and not in the MV3 service worker. Limit workers and batch size so
cancel remains responsive and the browser can apply thermal/battery pressure.
Do not request WebGPU or remote compute in v1.

A server accelerator is a future, separately approved design. Even if it sees
only public material, it can link IP address, account root public key, requested
word, timing, and eventual wallet address. No root assertion, authenticator
credential, recovery material, session secret, or unlock material may ever be
sent to such a service. Any future server result must still be independently
re-derived locally.

## Onboarding state machine

1. Let the user skip or select 1–4 characters, prefix/suffix, and
   case-insensitive/exact-capitalization semantics. Validate without modifying
   the input.
2. Show a cost preview that uses the exact character variants, requested
   position, and a short derivation calibration on the current device. Label
   50% and 95% probability windows, not completion times.
3. Create the passkey and extract its compressed 33-byte P-256 public key. The
   private key stays in the authenticator.
4. Freeze the intended cluster tag, final Warden program id, account-seed
   constant, and owner-seed domain version into `config_digest` before search.
   Do not start an expensive search while any of these are provisional.
5. Start an immutable local worker job. Show attempts, measured candidates per
   second, probabilistic windows, cancel, and a warning that the page/device must
   remain available. Do not prevent cancellation to preserve a "nearly done"
   search; there is no such state.
6. On a candidate result, independently re-derive it in the extension. Reject a
   mismatch, stale job, wrong network/program/domain, invalid bump, invalid
   Base58, or non-matching capitalization.
7. Persist the selected salt, address, bump, credential reference, and
   `config_digest` as one versioned pending-onboarding record so a browser crash
   cannot mix them with another attempt. Integrity and consistency matter even
   though the salt is not secret.
8. Ask for the `create_account` WebAuthn ceremony only after the final salt and
   policy are selected. The existing signed `CreateBody` binds the salt and the
   transcript binds the derived account, program id, cluster tag, and initial
   state.
9. Submit creation. Until confirmation and readback succeed, label the address
   "pending" and do not expose a copy/fund/receive action.
10. Read the account from the intended cluster and verify program owner,
    discriminator/version, root public key, owner seed, bump, exact address,
    cluster tag, root nonce, and initial policy. Only then promote it to the
    primary receiving account.

If the user skips vanity, steps 4 and 7–10 are identical; only step 5 is replaced
with one CSPRNG salt. Existing accounts cannot be retrofitted because their
addresses are immutable. Future additional vanity accounts are out of scope for
v1.

## UX contract

- Name the feature **Custom first address (optional)**. Supporting copy should
  say "Your passkey still controls this account; Warden searches public address
  salts on this device."
- Default to suffix and case-insensitive matching. Make exact capitalization an
  unchecked toggle with: "Exact capitalization can take much longer. Search is
  random and the estimate is not a deadline."
- Explain invalid characters individually: `0`, `O`, `I`, and `l` are omitted
  from Base58 to reduce visual confusion. Offer suggestions but require the user
  to choose the replacement.
- Enforce four Unicode code points after rejecting non-ASCII input; do not count
  bytes after normalization or accept lookalike Unicode glyphs.
- Highlight the matching fragment for delight, but never show a verified badge,
  identity mark, trust score, or stronger policy because an address has a word.
- Warn before long searches using thresholds derived from the device benchmark.
  The initial proposal is a visible warning above two minutes and explicit
  confirmation above fifteen minutes. Continue to allow valid 1–4 character
  requests after confirmation; suggest suffix, case-insensitive mode, or fewer
  characters when a 95% window is very long.
- Pause or reduce concurrency on battery/thermal pressure where browser signals
  exist. Cancellation must settle within one worker batch, and changing any
  input must cancel the old job.
- Never log or send the root public key, pattern, job nonce, salt, candidate
  address, or worker result to analytics. If aggregate performance telemetry is
  proposed later, it needs a separate privacy decision and must not contain
  linkable wallet fields.

## Address-poisoning and identity implications

A recognizable fragment can make users more likely to trust partial-address
matching. Treat vanity as a cosmetic feature and ship it with the client-plan
address-poisoning controls:

- show the full address on receive and high-value confirmation surfaces;
- never auto-fill a destination from raw transaction history;
- make saved contacts the safe path for repeat recipients;
- warn when a pasted or history-derived address matches the beginning/end of a
  saved or recent address but differs in the middle;
- distinguish contacts from raw addresses without allowing a vanity fragment to
  confer identity;
- test dust/history poisoning, clipboard replacement, Unicode labels, and two
  addresses with identical displayed ends.

This feature does not replace name services, verified contacts, hardware-backed
root control, decoded intent, simulation, caps, timelocks, or recovery.

---

## V0 — Make the feature addressable before implementation

**Schedule:** after the next clean Phase 1B boundary; it may be combined with
client-plan C0, but must not reorder unfinished Phase 1B work.

**Files:** the design spec, `docs/security/invariants.jsonl`, generated
`docs/security/INVARIANTS.md`, `docs/security/THREATMODEL.md`, and ledger-presence
tests. Do not hand-edit the generated invariant table.

- [ ] Add an optional vanity-onboarding section to the design spec using the
  decisions and state machine above.
- [ ] Add `WRD-VAN-01`: vanity search varies only a 32-byte salt; it never
  generates or exports a signing secret, and the trusted client independently
  re-derives a worker result.
- [ ] Add `WRD-VAN-02`: every layer enforces 1–4 ASCII Base58 characters and
  exact prefix/suffix plus capitalization semantics; stale or mutated jobs
  cannot become the selected account.
- [ ] Add `WRD-VAN-03`: the create ceremony and post-confirmation readback bind
  the selected salt/address to root, program id, cluster/config, bump, and
  initial policy before funding or receive UI is enabled.
- [ ] Add `WRD-VAN-04`: v1 generation is local, bundled, source-auditable, and
  emits no wallet-linkable telemetry or private-key-shaped output.
- [ ] Add threat-model rows for a malicious worker/binary, stale program config,
  overlapping worker ranges, predictable salt nonce, CSPRNG failure, CPU/battery
  denial of service, server metadata linkage, and vanity-as-identity/address
  poisoning.
- [ ] Regenerate the invariant Markdown and extend the required-id test.

**V0 acceptance:** `node scripts/gen-invariants.mjs --check` passes at the merged
SHA; each row has an honest `unimplemented` status until its named executable
evidence exists.

## V1 — Pin the complete address derivation across Rust and TypeScript

**Schedule:** after Phase 1B Task 8 stabilizes the client SDK. Do not change
production program logic.

**Files:** the post-Task-8 canonical SDK address module, its tests, and a
`#[cfg(test)]` Rust vector only if needed. An edit under `programs/warden/**`
requires the full merged-SHA repo gate even when test-only.

- [ ] Extend the existing P-256 generator/`0x44` salt vector so it pins program
  id, `ACCOUNT_SEED`, owner seed, canonical PDA bytes/Base58, and bump.
- [ ] Compute expected PDA/address values with an independent implementation;
  do not generate expected values from the helper under test.
- [ ] Add root-change, salt-change, program-id-change, seed-domain-change, and
  wrong-bump negatives.
- [ ] Make the supported client helper explicit and total over byte arrays. No
  ambient RPC/network lookup is permitted.
- [ ] Pin variable-length Base58 fixtures, including valid 43- and 44-character
  addresses.

**V1 acceptance:** the Rust and TypeScript named vector tests pass at the same
merged SHA and expose identical owner seed, address, and bump.

## V2 — Build the source-controlled search engine and worker boundary

**Schedule (campaign plan 2026-08-20):** the benchmark may run after Phase 1B
Task 8; the **final TS/WASM choice, CSP delta, and shipped-build byte-comparison
wait for C2** (the CSP/WASM posture) and are re-validated by **C6** on the shipped
artifact. C6 is downstream revalidation, not a V2 start-blocker — but no vanity
artifact ships before C6 re-validates it.

**Files:** new `packages/vanity-pda/**`, its deterministic build script, worker
schemas, unit/property tests, benchmark, and supply-chain metadata.

- [ ] Implement strict request/result schemas and the disjoint nonce/counter
  search described above.
- [ ] Implement prefix/suffix and exact/case-insensitive matching over ASCII
  Base58 only. Use an explicit valid-case variant set per character.
- [ ] Return only public derivation data. Add a static and runtime test that
  rejects fields matching `privateKey`, `secretKey`, `mnemonic`, `recovery`,
  `assertion`, or `credential` in worker result schemas.
- [ ] Make cancellation bounded by a tested maximum batch duration. Discard
  stale results by job id and configuration digest.
- [ ] Add deterministic parity/property tests across the TypeScript reference
  and the shipped engine for a fixed corpus plus randomized roots/salts.
- [ ] Benchmark pure TypeScript and WASM on the same corpus. Record cold start,
  steady candidates/second, memory, bundle bytes, cancel latency, and CSP delta.
- [ ] If WASM wins the decision, add a clean rebuild that byte-compares the
  generated WASM/wrapper to the shipped asset and fails on drift.

**Required red tests:** overlapping worker lanes; reused job nonce; counter wrap;
worker-count mutation; unknown schema field; malformed byte lengths; wrong
program id; wrong bump; forged address; stale job; CSPRNG exception; cancellation
during a batch; result containing a secret-shaped field.

## V3 — Implement honest validation and probabilistic cost estimates

**Files:** `packages/vanity-pda` estimator/validator plus independent fixtures
and property tests.

- [ ] Reject only non-ASCII, length outside 1–4, and characters outside the
  Base58 alphabet. Explicitly accept `W`, `z`, `Jz`, `L`, and `i` prefixes.
- [ ] Compute exact or conservatively bounded prefix probability over the
  variable-length encoding ranges. Do not reuse the bot's fixed-44-digit math.
- [ ] Compute suffix/case probabilities from the actual variant set. Verify
  `L/l` and `i/I` edge cases rather than applying generic lowercasing.
- [ ] Calibrate actual PDA candidates/second on the current device with the
  final engine. Do not label raw Ed25519-keypair throughput as PDA throughput.
- [ ] Report 50% and 95% success windows from `p` and measured speed. After the
  search starts, report chance found so far, not "remaining candidates."
- [ ] Differentially test estimator predictions against independent exhaustive
  reduced-width fixtures and a seeded Monte Carlo corpus. Use tolerances that
  can fail; do not derive expectations from the estimator itself.

## V4 — Integrate the onboarding state machine

**Schedule (corrected, campaign plan 2026-08-20):** after **C1a + C2a + C3 + C4**,
not C1 alone. The final `create_account` ceremony consumes `assertionToCompact()`
(C2a's strict-DER + low-S output) and binds to the immutable approval record (C3);
confirmed readback gates on C4's decode contract; and no funded account may be
created before C1a settles the production origin. C1 remains the trust boundary
these build on.

**Files:** production `apps/extension/**` onboarding, background state, storage,
and Playwright tests. Never import from `spikes/**`.

- [ ] Add the optional pattern screen, device calibration, warnings, progress,
  cancel, crash-resume, and skip flow.
- [ ] Run the search in extension-owned workers. Content scripts and dApps have
  no method to start a job, choose its config, read progress, or receive a salt.
- [ ] Independently verify the worker result before storing or displaying it.
- [ ] Persist one versioned pending-onboarding record atomically and reject it
  after extension id, program id, cluster, domain version, passkey, or schema
  changes.
- [ ] Build the final `create_account` ceremony only after selection. Recheck
  after every `await` that could cross a network or worker boundary.
- [ ] Verify confirmed account data before enabling copy, receive, funding,
  sessions, or transactions.
- [ ] Ensure cancel/skip/close leaves no private material and cannot accidentally
  create with a previous job's salt.

**Required browser races:** edit pattern while a result arrives; switch network;
extension update; worker restart; two onboarding tabs; back/forward navigation;
cancel and found in the same tick; create submission timeout then restart;
confirmation on the wrong cluster; readback root or policy mismatch.

## V5 — Ship privacy and poisoning controls with the feature

**Files:** client intent/receive/contact/history surfaces, threat model, privacy
tests, and redacted log/telemetry tests.

- [ ] Add the poisoning/lookalike checks above before marketing vanity as a
  receive feature.
- [ ] Prove the worker request/result and pending record do not enter logs,
  crash reports, analytics, query strings, or dApp messages. Before confirmed
  promotion they do not enter clipboard/QR data either; after promotion, only a
  deliberate user action may copy the normal public account address, never the
  salt or worker metadata.
- [ ] Render vanity as cosmetic text only; no verification or trust semantics.
- [ ] Add a static shipped-bundle scan for private-key-shaped worker APIs and
  `/opt/vanity-bot` artifact names.
- [ ] Keep server acceleration absent. A later proposal must document metadata,
  retention, authentication, abuse controls, independent re-derivation, and an
  explicit owner decision.

## V6 — Performance, compatibility, and promotion gates

- [ ] Benchmark the packaged extension, not a Node-only harness, on Chrome and
  Brave across the slowest supported desktop class and a typical desktop.
- [ ] Measure one through four characters; suffix/prefix; exact/default case;
  cold/warm start; one/multiple workers; cancel latency; memory; CPU; browser
  responsiveness; battery impact where measurable.
- [ ] Capture the exact package version, browser, OS/CPU, worker count, config,
  source SHA, and raw result artifact. Product estimates use conservative
  measured profiles.
- [ ] Run a devnet create/readback end to end for skip and representative vanity
  cases. Include a stale-program-id negative and a worker-result mutation.
- [ ] Obtain an adversarial review seeded with `WRD-VAN-01` through `04`, the
  derivation vector, worker schema, onboarding state machine, CSP, and shipped
  bundle manifest.
- [ ] Promote an invariant only with a named test at the merged SHA. Any critical
  `unimplemented`, `llm-asserted`, UNVERIFIED, or contradicted row blocks the
  feature flag from default-on or production-ready claims.

## Acceptance matrix

The feature is not complete until all rows are executable:

| Property | Required proof |
|---|---|
| Four-character cap | UI, validator, worker, persisted job, and crafted-message tests reject five; no override path. |
| Alphabet | `0/O/I/l` reject with guidance; every other Base58 symbol is accepted in prefix and suffix tests. |
| Variable length | Independent 43- and 44-character fixtures, plus leading-`1` coverage. |
| Capitalization | Exact and case-insensitive vectors cover two-case letters, digits, `L`, and `i`. |
| Canonical address | Rust/TS/worker agree on owner seed, program id, PDA, bump, and Base58. |
| No signing secret | API/schema/bundle scan plus runtime tests show salt-only results and no secret export/copy/QR. |
| Search isolation | Fresh 192-bit nonce, disjoint counters, wrap/reuse failure, immutable job/config digest. |
| Worker distrust | Main thread rejects mutated salt/address/bump/config and stale results. |
| Crash/race safety | Pending record is atomic; two tabs, restart, cancel/found, and network switch cannot mix jobs. |
| Creation binding | Final WebAuthn body uses selected salt; confirmed readback matches root, program, cluster, address, owner seed, bump, nonce, and policy. |
| Funding safety | Copy/receive/fund controls remain unavailable until confirmed readback. |
| Honest time copy | Measured PDA speed and 50%/95% probability windows; no deterministic countdown. |
| Privacy | No wallet-linkable telemetry/log/query leak, no pre-confirmation clipboard/dApp leak, only the normal public account address is exposed after promotion, and no remote service exists in v1. |
| Poisoning | Lookalike/history/contact adversarial browser tests pass; vanity confers no identity. |
| Supply chain | Bundled engine is source-auditable; deterministic asset rebuild and shipped-manifest comparison pass. |

## Required commands at a completed milestone

These commands are the intended executable gates. V2/V4 must create the named
package scripts before claiming the milestone. Report their result and the exact
merged SHA; this list is not a claim that they currently exist or pass.

```sh
node scripts/gen-invariants.mjs --check
cargo test -p warden owner_seed_matches_pinned_vector --lib
cargo test -p warden vanity_pda_matches_pinned_vector --lib
pnpm --filter @warden/core test
pnpm --filter @warden/core typecheck
pnpm --filter @warden/vanity-pda test
pnpm --filter @warden/vanity-pda typecheck
pnpm --filter @warden/vanity-pda build:verify
pnpm --filter @warden/vanity-pda benchmark:ci
pnpm --filter @warden/extension test
pnpm --filter @warden/extension test:integration
pnpm --filter @warden/extension test:playwright
pnpm test
pnpm typecheck
pnpm build
scripts/supply-chain-gate.sh
./.claude/test-gate.sh
```

If the Rust vector uses a final name other than
`vanity_pda_matches_pinned_vector`, update this plan and CI in the same commit;
do not leave a decorative command that runs zero tests. The benchmark CI command
validates correctness, schema, and output format under a bounded sample; it does
not impose a brittle shared-runner speed floor. Human-device performance evidence
belongs in a captured artifact.

## Stop conditions and decisions Claude must not make silently

Stop and return to the owner if:

1. The program id, account seed, owner-seed domain, or supported cluster config
   is still expected to change. A search under provisional inputs is wasted and
   can create the wrong account.
2. Rust, TypeScript, the worker, and an independent implementation disagree on
   owner seed, PDA, bump, Base58, or pattern match.
3. The only performant implementation requires an unreviewable binary,
   runtime-downloaded code, generic `unsafe-eval`, WebGPU, or a third-party
   service.
4. A design sends a passkey assertion, credential material, unlock/recovery/
   session secret, or private-key-shaped value into the worker or off-device.
5. Supported hardware cannot keep four-character searches responsive enough to
   cancel safely, or the proposed UX presents probabilistic timing as a promise.
6. Product copy proposes vanity as identity, verification, phishing protection,
   or evidence that an address is safe.
7. Implementation would require changing production on-chain address or
   authorization logic. Produce the failing parity evidence and a separate
   program-change proposal first.

## Return contract for each completed task

Return the merged SHA, clean/dirty status, exact commands and results at that
SHA, invariants promoted/unchanged/knocked down, benchmark/browser artifact
paths, worker/CSP/storage/permission changes, remaining UNVERIFIED items, owner
decisions, and confirmation that no deploy, live-account mutation, secret
creation/export, remote acceleration, analytics change, or publisher action
occurred without separate authorization.
