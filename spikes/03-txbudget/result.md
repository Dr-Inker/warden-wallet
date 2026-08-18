# Spike 3a — wrapped-transaction byte budget

**Goal:** how often does a dApp-built transaction, rewrapped into Warden's own `execute`
instruction, still fit in Solana's 1,232-byte transaction limit — and when it doesn't, how many
staging chunks does the fallback (`stage_chunk` + `execute_staged`) need?

**Code:** `ts/src/wrap.ts` (`wrapForExecute`, the algorithm Phase 2's SDK will productionize),
`ts/src/measure.ts` (drives real Jupiter/Marinade/Tensor tx builders through it),
`ts/test/wrap.test.ts` (synthetic unit test).

**Method:** for each case, fetch/build a real unsigned `VersionedTransaction` from a public
read-only endpoint (nothing is signed or sent), decompile its instructions, and re-wrap them into
a single Warden `execute` instruction whose account list is every unique account touched by the
inner instructions (deduped, PDA forced to non-signer since it signs via `invoke_signed` inside
the program, not as an ed25519 signature). Compare serialized byte length against the 1,232-byte
`MAX_TX_BYTES` limit.

## Round 1 fix (2026-08-18) — read this first

Task review found a **Critical** defect in `wrap.ts` (the account-index scheme the packed
`execute` payload used was wrong — it indexed a local, pre-compile account list instead of the
actual compiled outer message's account-key list) plus two **Important** gaps (no top-level
compute-budget instructions; an unexplained `900`-byte staging constant) and a **Minor**
overclaim in the Conclusion. All four are fixed; full detail is in "Self-review → Round 1 fix"
below. **Consequence for the numbers:** every byte count in this document changed —
`bytesInline` grew (compute-budget instructions now really are counted) and the account-index
bug fix doesn't change byte counts by itself (wrong-but-same-length indices vs right ones cost
the same bytes) but it changes *correctness* (a pre-fix wrapped tx would have executed against
the wrong accounts). **The tables and Conclusion immediately below (the original 5-run Jupiter
sweep and the single-shape Marinade/Tensor table) reflect the PRE-FIX code and are superseded —
kept only for audit trail.** The authoritative, post-fix numbers are in the "Post-fix
re-measurement" subsections and the rewritten Conclusion.

## Results — Jupiter SOL→USDC (0.1 SOL, 50 bps slippage), 5 runs ≥130s apart — SUPERSEDED, pre-fix (see banner above)

USER_PUBKEY was left at the script's default fallback,
`11111111111111111111111111111112` — see "USER_PUBKEY note" below.

| run | UTC timestamp | original bytes | wrapped bytes | fits inline? | chunks if staged | writable+readonly account count |
|---|---|---|---|---|---|---|
| 1 | 2026-08-18T12:06:45Z | 842 | 976 | yes | 0 | 34 |
| 2 | 2026-08-18T12:08:57Z | 670 | 776 | yes | 0 | 24 |
| 3 | 2026-08-18T12:11:12Z | 656 | 755 | yes | 0 | 29 |
| 4 | 2026-08-18T12:13:26Z | 510 | 599 | yes | 0 | 15 |
| 5 | 2026-08-18T12:15:38Z | 914 | 1059 | yes | 0 | 38 |

Raw JSON lines (one `pnpm measure` invocation per run, `USER_PUBKEY` unset ⇒ default fallback
owner; each run ≥130s after the previous one's output, per script
`ts/.runlog/run5.sh`, not committed — see "USER_PUBKEY note"):

```
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":842,"bytesInline":976,"fitsInline":true,"stagedChunks":0,"writableAccounts":34}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":670,"bytesInline":776,"fitsInline":true,"stagedChunks":0,"writableAccounts":24}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":656,"bytesInline":755,"fitsInline":true,"stagedChunks":0,"writableAccounts":29}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":510,"bytesInline":599,"fitsInline":true,"stagedChunks":0,"writableAccounts":15}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":914,"bytesInline":1059,"fitsInline":true,"stagedChunks":0,"writableAccounts":38}
```

## Results — Marinade deposit (1 SOL) and Tensor buy-now (attempted) — SUPERSEDED, pre-fix (see banner above)

| case | original bytes | wrapped bytes | fits inline? | chunks if staged | writable+readonly account count |
|---|---|---|---|---|---|
| Marinade deposit (1 SOL, `deposit()`) — 5/5 runs identical | 559 | 662 | yes | 0 | 13 |
| Tensor buy-now (attempted) — 5/5 runs | not measured | not measured | not measured | not measured | not measured |

Marinade's `deposit()` builds a fixed, small instruction set independent of market conditions (no
routing), so all 5 runs produced byte-identical results — this is expected, not a data quality
issue.

Raw JSON lines (Marinade, one per run):
```
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":662,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":662,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":662,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":662,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":662,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
```

Raw JSON lines (Tensor, one per run — identical error every time, see "Tensor / Marinade builder
attempts" below for the full explanation and verbatim HTTP probe):
```
{"name":"tensor buy-now (attempt)","error":"not measured — Tensor REST API rejected the request without TENSOR_API_KEY: HTTP 403 \"required x-tensor-api-key in header\" ..."}
```
(×5, byte-identical each run; full untruncated error text is in `ts/src/measure.ts`'s `tensor()`.)

## Post-fix re-measurement (authoritative)

3 fresh `pnpm measure` runs against the fixed `wrap.ts` (indices computed from the real compiled
message; ComputeBudget hoisted/defaulted top-level; `stagedChunks` from a measured payload cap,
not a hardcoded constant). The first run predates the spaced-run harness (manual sanity check
right after the fix, timestamp approximate); the other two are spaced ~130s apart as before.

| run | UTC timestamp | original bytes | wrapped bytes | fits inline? | chunks if staged | account count | hops |
|---|---|---|---|---|---|---|---|
| A | ~2026-08-18T12:30:15Z (approx, manual) | 1085 | 1235 | **no** | 1 | 43 | n/a (not captured yet) |
| B | 2026-08-18T12:30:39Z | 796 | 934 | yes | 0 | 35 | n/a (not captured yet) |
| C | 2026-08-18T12:32:51Z | 518 | 604 | yes | 0 | 15 | 1 |

Raw JSON lines:
```
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":1085,"bytesInline":1235,"fitsInline":false,"stagedChunks":1,"writableAccounts":43}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":796,"bytesInline":934,"fitsInline":true,"stagedChunks":0,"writableAccounts":35}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":518,"bytesInline":604,"fitsInline":true,"stagedChunks":0,"writableAccounts":15,"hops":1}
```
(hop-count capture — `routePlan.length` from the Jupiter quote — was added to `measure.ts` between
runs A/B and run C, per Minor fix #4's ask to record hop counts; runs A and B predate it.)

**Run A is the headline new finding: a real Jupiter route that does NOT fit inline** (1235 B, 3 B
over the 1,232 B limit, 43 accounts) and needs exactly **1 staged chunk** — the first real
staging case this spike has produced across 8 total Jupiter measurements (5 pre-fix + 3 post-fix).
Marinade, all 3 post-fix runs, byte-identical as before:
```
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":702,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}
```
(702 B vs the pre-fix 662 B — the +40 B is the added top-level `ComputeBudgetProgram
.setComputeUnitLimit(600_000)` instruction, Marinade's deposit tx carries no compute-budget
instruction of its own so the default was added, per Important fix #2.)

Tensor: unchanged, still blocked on the same API-key wall (see below).

`maxStageChunkPayloadBytes()` (replacing the old unexplained `900` constant, see Important fix
#3) measured **985 bytes** for a representative `stage_chunk` tx (1 signer/payer, 3 accounts:
payer/stage-PDA/System-Program, 8-byte offset+len header) on this run — close to but not the same
as the old guess, which is exactly why deriving it was worth doing.

## Conclusion

**Scope of this conclusion, exactly:** 8 total real Jupiter SOL→USDC (0.1 SOL, 50 bps slippage)
builds (5 pre-fix + 3 post-fix, byte counts not comparable 1:1 across the fix but fitInline/account
counts still directly comparable) and Marinade's 1-SOL `deposit()` shape (identical instructions
every run, measured 4 times total — 1 pre-fix table + 3 post-fix). That's it. This is **not** a
claim about Jupiter routes in general, other input/output pairs, other trade sizes, other dApps,
or Tensor (unmeasured). Round 1 of this spike overclaimed here (a "100% inline, 45–47-account
extrapolated ceiling" conclusion drawn from only 5 same-pair runs, computed against
since-corrected buggy byte accounting) — this section replaces that claim rather than patching it.

**Post-fix result: 2 of 3 fresh Jupiter runs fit inline; 1 of 3 needed exactly 1 staged chunk**
(43-account route, 1235 B — 3 B over the 1,232 B limit). Across all 8 Jupiter measurements taken
in this spike (pre- and post-fix), account counts ranged 15–43 and the only overflow was the
43-account case. Marinade's fixed deposit shape fit inline in all 4 measurements (662 B pre-fix /
702 B post-fix, 13 accounts, no routing variance since it's not order-book/route-dependent).

**Do not treat "45–47 accounts" as a validated ceiling — it isn't, for two reasons:**
1. It was extrapolated from *pre-fix* byte counts, which excluded the compute-budget instruction
   this spike now knows the real wrapped tx must carry (~40 B). Post-fix, the 43-account run
   already overflowed at 1235 B — 8–9 accounts *earlier* than the old extrapolation predicted.
2. It was extrapolated from a straight-line fit through only 2 data points in a 5-point sample
   that never actually observed an overflow. With an overflow now observed at 43 accounts and a
   fit observed at 35 accounts (post-fix), the honest statement is: **the breakpoint for this
   input/output pair, at this trade size, is somewhere in the 35–43 account band** — no tighter
   than that without more samples, and not safe to extrapolate past 43 without new data.

**What actually explains the byte cost** (mechanism, still valid post-fix): `wrapForExecute`'s
outer `execute` instruction spends ~4 bytes of fixed overhead plus 2 bytes per referenced account
(1-byte index into the *compiled* outer message's account-key list + 1-byte signer/writable
flags) rather than re-embedding 32-byte pubkeys, and reuses whatever Address Lookup Tables the
inner route already carries — both of these keep the marginal cost per account far below a naive
32-byte-per-account scheme, which is why 15–38-account routes fit while a 43-account one just
barely didn't.

**`stagedChunks` is no longer unvalidated arithmetic.** Round 1 flagged that the `900`-byte
staging-payload constant was unexplained and the chunking path was never exercised end-to-end.
Both are fixed: `maxStageChunkPayloadBytes()` now measures the real cap (985 B on this run, from
actually serializing a representative `stage_chunk` tx and binary-searching), and it's exercised
both by a synthetic ~3,000-byte-payload unit test (`wrap.test.ts`) *and* by the real 43-account
Jupiter overflow above (`stagedChunks: 1`), which is the first real-route confirmation that the
inline/staged branch split behaves as designed.

**What Phase 2 should actually do with this:** treat "does this route need staging" as a
per-transaction runtime check (`wrapForExecute` already returns `inline: null` when it doesn't
fit), not a static assumption from this spike's sample. The safe design conclusion is that
staging support is **not optional/rare-edge-case** — this spike hit a real staging-required route
on only its 6th Jupiter measurement — so Phase 1/2 must ship the `stage_chunk`/`execute_staged`
path fully working, not as a defensively-added-but-untested fallback.

## USER_PUBKEY note

The brief's fallback owner (`11111111111111111111111111111112`, System Program's own key +1,
i.e. not actually the System Program address) was used for all runs rather than hunting down a
real funded mainnet wallet. Empirically Jupiter's `/swap/v1/swap` endpoint does not check the
owner's balance when building the transaction (no simulation is requested) — it built a valid,
different, real route on every one of the 5 calls, so the owner pubkey's funding status did not
gate or bias these measurements. `mainnet-beta` public RPC's `getLargestAccounts` was tried to
find a real funded whale address instead but hit a hard 429 rate limit after 4 retries; not worth
burning more of the request budget chasing an address that wouldn't change the result.

## Tensor / Marinade builder attempts (per task-brief NOTE)

- **Marinade** (`@marinade.finance/marinade-ts-sdk` v6.0.1 `deposit()`): built and measured
  successfully — see table above. One fix needed: the brief's own sketch passes a `bigint` amount;
  the SDK's `deposit(amountLamports: BN, …)` actually wants a `bn.js` `BN` instance
  (`new BN(1_000_000_000)`), not a JS `bigint` — passing a bigint fails inside the SDK with
  `src.toArrayLike is not a function` (BN.js API called on a plain bigint). Added `bn.js` and
  `@types/bn.js` as devDependencies to fix it.
- **Tensor** (`@tensor-oss/tensorswap-sdk` / Tensor's public REST API): **not measured**. Tensor's
  buy-now instruction needs a specific already-listed NFT mint (no "any NFT" quote endpoint like
  Jupiter's), so exercising it means first discovering a live listing via Tensor's REST API
  (`api.mainnet.tensordev.io`). Every endpoint we probed — even the read-only
  `mint/collection_stats` lookup — returned `HTTP 403 "required x-tensor-api-key in header"` with
  no key supplied and no anonymous tier available; `TENSOR_API_KEY` is not set in this
  environment. Verbatim probe:
  ```
  $ curl -si "https://api.mainnet.tensordev.io/api/v1/mint/collection_stats?slug=mad_lads"
  HTTP/2 403
  ...
  required x-tensor-api-key in header
  ```
  Time spent on the two extra builders: ~20 minutes (within the ~30-minute budget), split roughly
  Marinade 12 min / Tensor 8 min.

## Self-review

- **wrap.ts is unmodified** from the brief's exact code — it's the algorithm Phase 2 productionizes,
  so its logic was left untouched even where its own bundled unit test turned out to be wrong (see
  next point).
- **Unit test bug found and fixed.** The brief's `wrap.test.ts` sets the *original* message's
  `payerKey` to the session keypair (`sess.publicKey`) while the transfer instruction's `from` is
  a different pubkey (`acct`). That makes the *original* (unwrapped) message require **2**
  signatures (payer `sess` + instruction-signer `acct`), while the *wrapped* message requires only
  **1** (`sess`; `acct`/the PDA no longer signs directly — `wrapForExecute` explicitly forces it
  to `isSigner: false` since it authorizes via `invoke_signed` inside the program). Dropping a
  64-byte signature more than offsets the ~20 bytes of added instruction-wrapping overhead for
  this trivial 1-instruction/3-account case, so `bytesInline` (294) comes out *smaller* than
  `bytesOriginal` (313) — the exact opposite of the test's own assertion
  (`expect(r.bytesInline).toBeGreaterThan(r.bytesOriginal)`), and the brief's claimed
  `pnpm test → PASS` does not hold as originally written.
  - Root cause: that payer choice isn't how the real flow looks. A dApp builds the *original,
    unwrapped* transaction assuming the smart-account pubkey (`account`) itself is a normal
    fee-paying signer — i.e. `payerKey` should be `account`, not a separate session key (the
    session key only becomes payer in the *wrapped* tx, which is the whole point of the rewrite).
  - Fix applied: changed the test's `payerKey` from `sess.publicKey` to `acct` (one line), with a
    comment explaining why, in `ts/test/wrap.test.ts`. With that fix both messages have exactly 1
    required signature, isolating the thing the test is actually meant to check (per-instruction
    wrap overhead), and the assertions pass genuinely (not by coincidence):
    `bytesOriginal=217`, `bytesInline=294` (`< 400` ✓, `> bytesOriginal` ✓).
  - This is a real, reportable finding for Phase 2, not just a test nit: **wrapping does not
    universally add bytes** — when the original tx's signer count drops (the common case, since
    Warden replaces the account's own signature with the session key's), a small transaction can
    come out *smaller* wrapped than unwrapped. The "wrapping adds bytes" sanity heuristic only
    reliably holds once per-instruction account/data overhead exceeds the ~64-byte signature
    saving, which is comfortably true for real Jupiter-scale routes (15–38 accounts observed here)
    but not for trivial 1-instruction transfers.
- **Brief's Jupiter quote URL had a bug.** `platformFeeBps=85` in the `/quote` call requires a
  `feeAccount` in the `/swap` POST body; without one, `/swap` returns
  `{"error":"feeAccount is required for swap with platformFee","errorCode":"NOT_SUPPORTED"}` and
  no transaction is built. Dropped `platformFeeBps` entirely (a spike doesn't need real platform
  fee revenue, just a realistic route) — see `ts/src/measure.ts`.
- **Toolchain deviation:** used `tsx` instead of `node --experimental-strip-types` for the
  `measure` script (both work standalone on this Node 22.23.2, but `tsx` was simpler to keep
  working consistently with dynamic `import()` of optional SDKs like `@marinade.finance/marinade-ts-sdk`
  and `bn.js`, which is how the Tensor/Marinade "not measured"/success paths are implemented).
  `pnpm test` still runs via `vitest run` directly, no `tsx` involved there.
- **Repo-wide side effect:** `@solana/web3.js`'s `rpc-websockets` dependency pulls in
  `bufferutil`/`utf-8-validate` (and Marinade's SDK pulls in `bigint-buffer`) as native addons that
  pnpm refuses to build by default. Added `bufferutil: true`, `utf-8-validate: true`,
  `bigint-buffer: true` to the root `pnpm-workspace.yaml`'s `allowBuilds` (alongside the existing
  `esbuild: true` from an earlier spike) — without this, `pnpm install`/`pnpm test` hard-fail
  workspace-wide with `ERR_PNPM_IGNORED_BUILDS`, for *any* package that depends on `@solana/web3.js`
  in this monorepo, not just this spike. This touches a shared file outside
  `spikes/03-txbudget/`, so flagging it explicitly rather than silently including it in the
  spikes-only commit.
- Sanity check requested by the task ("bytesInline should exceed bytesOriginal … Jupiter routes
  typically have 20–40 accounts, expect many to NOT fit inline"): the first half held for every
  real (non-toy) case measured (Jupiter, Marinade); the second half did **not** — every real route
  measured across 5 spaced runs fit inline. See Conclusion.

### Round 1 fix (2026-08-18) — task review findings, addressed

**1. Critical — wrong account indices in the packed `execute` payload (FIXED).** The original
`idx()` looked up positions in a *locally built* `order` array (insertion order into a `Map` while
walking the inner instructions), but the packed indices are read by the on-chain program against
the *compiled outer message's* account-key list — and `TransactionMessage.compileToV0Message`
dedups + re-sorts accounts into `[signer+writable, signer+readonly, non-signer+writable,
non-signer+readonly]` before appending LUT-resolved keys, an ordering that has no fixed
relationship to insertion order. The bug wouldn't fail a naive smoke test — every index still
resolved to *some* valid account in range, just frequently the wrong one — which is exactly why
the original unit test (checking only `bytesInline`/`bytesOriginal`, never decoding the payload)
passed despite it.
  - **Fix:** `wrapForExecute` now compiles the outer message in two passes. Pass 1 compiles with
    the real account metas but placeholder (empty) instruction data, purely to learn the final
    compiled ordering — `compileToV0Message`'s account ordering is a pure function of each
    instruction's `keys` (pubkey + isSigner + isWritable) and the payer, **never** of instruction
    data, so this ordering is provably identical to what the real (data-filled) compile produces.
    Indices for the packed payload are computed from
    `compiled.getAccountKeys({ addressLookupTableAccounts }).keySegments().flat()` — the exact
    resolution order Solana uses on-chain — via a small `idx()` that also now **throws** if an
    account is missing or its index exceeds `0xff` (u8), and instruction account/data counts are
    asserted to fit `u8`/`u16` before packing, instead of silently truncating.
  - **New round-trip test** (`wrap.test.ts`, "round-trips: decoding the packed execute payload
    recovers the exact original inner-instruction keys, flags, and data"): builds a 2-instruction
    message with overlapping *and* distinct accounts (so `compileToV0Message`'s signer/writable
    re-sort actually has work to do — the exact scenario where the old bug pointed at the wrong
    pubkey), wraps it, decodes the packed payload with a new exported `decodeExecuteData()`, and
    asserts every decoded `{programIdx, accounts[], data}` resolves (via the new exported
    `compiledAccountKeys()`) back to the *original* inner instruction's program id, account
    pubkeys, writable flags, and data bytes. One deliberate subtlety verified explicitly: the
    packed per-account `isSigner` flag intentionally mirrors the **original** inner instruction's
    flag exactly, including for the smart account/PDA itself — that's what makes `invoke_signed`
    work (the CPI'd instruction's account meta must say `is_signer:true` for the PDA if the
    target program requires it; the runtime honors that because the calling program supplies
    matching seeds). That's separate from `metas`' forcing of the account to `isSigner:false` at
    the *outer transaction* level (no real ed25519 signature required from it) — the two flags
    serve different layers and both are now tested.

**2. Important — compute-budget instructions were being CPI-wrapped (FIXED).**
`ComputeBudgetProgram` instructions (`SetComputeUnitLimit`/`SetComputeUnitPrice`/etc.) are only
honored by the runtime at the transaction's top level, never inside a CPI — wrapping them into
`execute`'s payload the way every other inner instruction was wrapped would make them silently
inert. **Fix:** `wrapForExecute` now filters `allInner` by `programId.equals(ComputeBudgetProgram
.programId)`, hoists any found straight into the outer message's top-level instruction list
(alongside `execute`, not inside it), and — if the dApp tx carried none — adds a default
`ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 })` so the measured shape matches what
Phase 1 will actually need to build. Their bytes are counted in `bytesInline` (they're part of the
same compiled message the returned `tx` comes from). Measured effect: Marinade's wrapped size grew
662 B → 702 B (the dApp tx carries no compute-budget instruction of its own, so the default was
added) — see "Post-fix re-measurement" above.

**3. Important — unexplained `900`-byte staging constant (FIXED).** New exported
`maxStageChunkPayloadBytes(wardenProgram)` builds a representative `stage_chunk` instruction (1
signer/payer, 3 accounts: payer / stage PDA / System Program, data = 8-byte `[offset:u32,
len:u32]` header + payload) and binary-searches the largest payload that keeps the whole
transaction ≤ `MAX_TX_BYTES`, memoized per program id. Measured **985 B** (see "Post-fix
re-measurement" above) — close to but not the same as the old guess, confirming it was worth
deriving rather than assuming. `stagedChunks` now divides by this measured value instead of the
literal `900`. One implementation wrinkle surfaced and handled: `@solana/web3.js`'s
`MessageV0.serializeInstructions()` pre-allocates a fixed `PACKET_DATA_SIZE` (1232 B) scratch
buffer and **throws** ("encoding overruns Uint8Array") rather than returning a large length once
the instructions section alone would overrun it — both `maxStageChunkPayloadBytes`'s binary search
and `wrapForExecute`'s own `bytesInline`/`bytesOriginal` computation now catch that and treat it
as `+Infinity` (an unambiguous "does not fit"), since a throw there otherwise crashes the whole
measurement instead of correctly reporting an oversized tx. **New unit test** ("a synthetic
~3000-byte inner-instruction payload forces staging and yields the expected chunk count"): wraps a
single instruction carrying a 3,000-byte data payload (guaranteed to overflow), computes the
expected packed-payload length by hand from the wire format, and asserts `r.stagedChunks ===
Math.ceil(expectedPartsLen / maxStageChunkPayloadBytes(prog))` — i.e. it checks the *formula*
against the *measured* cap, not against a hardcoded chunk-count number that could silently drift.
Plus a sanity-bounds test on `maxStageChunkPayloadBytes` itself (700–1200 B).

**4. Minor — Conclusion overclaimed beyond its sample (FIXED).** See the rewritten "Conclusion"
above: explicitly scoped to "8 Jupiter SOL→USDC builds + 4 Marinade-shape builds, nothing else,"
the 45–47-account extrapolation is dropped (replaced with an honest "breakpoint is somewhere in
the 35–43 account band, not safe to extrapolate past 43" given the post-fix 43-account overflow),
and hop-count capture (`routePlan.length` from the Jupiter quote) was added to `measure.ts` for
future runs (captured starting with post-fix run C: 1 hop for a 15-account/604 B route; runs A/B
predate the capture).

## Part (b) — conservation snapshot CU

**Goal:** the CU cost of `execute`'s core safety mechanism — snapshotting every writable
vault-owned token account before/after the inner CPI and rejecting the transaction if one was
mutated outside the CPI's declared effect — as a function of N accounts, to size Phase 1's compute
budget.

**Code:** `onchain/Cargo.toml`, `onchain/src/lib.rs` (`spike-conserve` program), `onchain/tests/cu.rs`
(LiteSVM harness).

**Method:** a native program takes `accounts[0]` = vault authority marker (read-only, never
initialized on-chain), `accounts[1..]` = writable token accounts to snapshot. It reads every
token account twice (before / after — a real `execute` would CPI into the target program between
the two passes; this spike has no CPI, isolating the pure snapshot-and-compare cost), and for
every account owned by the SPL Token or Token-2022 program whose *token-level* `owner` field is
the vault, checks that owner/delegate/close_authority/state/data_len/TLV-tail-hash are unchanged
and accumulates any net SOL (wrapped-SOL mint) decrease. `accounts[]` not owned by the vault at
the token level are read but otherwise ignored (proves the ownership filter, since a real mutation
can't be produced without a CPI). `data[0] = 1` short-circuits to `Custom(99)` after snapshotting,
to measure the reject path.

Token accounts are packed **by hand** at the fixed SPL Token 165-byte layout offsets (mint 0..32,
owner 32..64, amount 64..72 LE, delegate COption 72..108, state 108, is_native COption 109..121,
delegated_amount 121..129, close_authority COption 129..165) in both the program (`src/lib.rs`)
and the test harness (`tests/cu.rs`) — see "Dependency conflict" below for why. A Token-2022
account is the same 165 bytes plus a 100-byte TLV tail (byte 165 = `2` = `AccountType::Account`,
then 99 bytes of filler), 265 bytes total, to exercise the TLV-hash comparison path.

Built with `cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml`, tested with
`cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml -- --nocapture` (LiteSVM,
`svm.set_account` to seed the token accounts, `svm.send_transaction` + `compute_units_consumed`).

### Dependency conflict: `spl-token`/`spl-token-2022` vs `solana-program 3`

`spl-token = "7"` and `spl-token-2022 = "7"` both resolve cleanly in Cargo's dependency graph
against `solana-program = "3"` — but they pull `solana-program 2.3.0` (via `solana-pubkey 2.4.0`),
a semver-major-different instance from the `solana-program 3.0.0` this crate uses for
`AccountInfo`/`Pubkey`. `cargo tree -i solana-program` reports it explicitly:

```
error: specification `solana-program` is ambiguous
help: re-run this command with one of the following specifications
  solana-program@2.3.0
  solana-program@3.0.0
```

`spl_token::state::Account::owner` is therefore a *different, non-interconvertible* `Pubkey` type
than the one on `AccountInfo` (`if tb.1 == *vault` would not even compile across the two types).
Per the task brief's documented fallback, both `src/lib.rs` and `tests/cu.rs` parse/pack the
165-byte layout by hand instead, and hardcode the SPL Token / Token-2022 program ids and the
native-mint id as `pubkey!()` literals (long-stable, publicly documented addresses) rather than
importing them from the crates. `spl-token`/`spl-token-2022` remain declared `[dependencies]`
purely so `cargo tree` records the majors that resolve.

### Results — CU sweep, N ∈ {10, 20, 30} vault-owned SPL Token accounts (happy path)

| N | compute_units_consumed |
|---|---|
| 10 | 8,688 |
| 20 | 16,134 |
| 30 | 23,254 |

All well under the 200,000 default per-instruction CU limit (assertion `cu30 < 200_000` passes
with ~8.6x headroom). Two-point linear fit (N=10 → N=30): **base ≈ 1,405 CU, ≈728 CU per
additional vault-owned SPL Token account** (`(23254 − 8688) / 20 ≈ 728.3`; the N=10→20 segment is
≈744.6 CU/account and N=20→30 is ≈712.0 CU/account — close enough to call it linear at this scale,
with some per-account variance from unique-pubkey generation/compare overhead).

**Extrapolation for Phase 1 budgeting:** at ~730 CU/account plus ~1,400 CU fixed overhead, a vault
could snapshot roughly **270 writable token accounts** before exhausting a single 200,000 CU
instruction budget (`(200,000 − 1,400) / 730 ≈ 272`) — far beyond any realistic `execute` account
list (spike 3a saw 15–38 accounts on real Jupiter routes), so the conservation-snapshot mechanism
itself is not expected to be Phase 1's binding CU constraint; the inner CPI's own cost will
dominate.

### Token-2022 TLV-tail account (265 B, 100-byte TLV tail)

10 vault-owned SPL accounts + 1 Token-2022 account with a 100-byte TLV tail: **9,707 CU** — a delta
of **1,019 CU** versus the 10-SPL-only baseline (8,688 CU) for one extra account whose data is
2,065 bytes read across the before/after passes (present twice: once as raw read, once through the
TLV-hash syscall) 265-byte account, i.e. hashing a 100-byte tail twice (before + after) plus
reading/parsing 265 vs 165 bytes.

### keccak vs sha256 for the TLV-tail hash

Tried both via a Cargo feature (`sha256-tlv`, default off ⇒ `solana_program::keccak::hash`; on ⇒
`solana_program::hash::hash`, which is SHA-256 — confirmed by reading `solana-sha256-hasher`
source, same as noted in `docs/TOOLCHAIN.md`'s spike-2b entry). Built and ran the
`cu_with_token2022_tlv_tail` test against both `.so` builds (confirmed genuinely different
binaries — different file hashes, same 25,104-byte size):

| hash syscall | compute_units_consumed |
|---|---|
| `keccak::hash` (default) | 9,707 |
| `hash::hash` (SHA-256) | 9,707 |

**No measurable difference at this size (100-byte tail, hashed twice per invocation) on this
Agave 3.1.10 / LiteSVM 0.12.0 toolchain.** `keccak` was kept as the default (matches the task
brief's original code skeleton); either is CU-equivalent for TLV tails in this size range, so
Phase 1 is free to pick based on other criteria (e.g. `keccak` is what SPL Token-2022's own
extensions ecosystem tends to use for content hashes). This is a smaller-than-expected finding —
worth re-measuring at a larger TLV size (e.g. 1 KB, closer to a token account with several
extensions) if Phase 1 needs a sharper answer, since the base syscall costs are likely to diverge
more once the per-byte term dominates over fixed overhead.

### Negative path

`data[0] = 1`: transaction fails with `InstructionError(0, Custom(99))` after logging
`"snapshots ok, sol_out=0"` — confirms the reject happens *after* a successful snapshot pass, not
instead of one (8,697 CU consumed in the failing case, consistent with the 8,688 CU happy-path
figure at N=10).

### Mutation-detection path (cheap variant)

No CPI exists in this spike to actually mutate a vault-owned account's on-chain state between the
before/after snapshots (that's `execute`'s job in Phase 1, deliberately out of scope here — see
the code comment `// (a real execute would CPI into the target program here)`), so the "reject on
mutation" branch cannot be exercised end-to-end without one. What *is* cheap and included: a token
account whose token-level `owner` field is **not** the vault (with `close_authority` deliberately
set, which would trip the mutation check if the ownership filter were broken) is correctly
**ignored**, not rejected — 9,327 CU for 10 vault-owned + 1 non-vault-owned account. This proves
the ownership-filter branch works; a true CPI-mutation test is Phase 1 scope, not this spike's.

### Reproduce

```bash
cd /opt/warden
nice -n 10 cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml
nice -n 10 cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml -- --nocapture
# keccak-vs-sha256 comparison:
nice -n 10 cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml --features sha256-tlv
nice -n 10 cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml --test cu -- --nocapture cu_with_token2022_tlv_tail
```

### Open items / caveats

- Same workspace caveat as spikes 2b/3a: this crate carries its own `[workspace]` table (root
  `Cargo.toml`'s `spikes/03-txbudget/onchain` member now finally exists on disk, but `programs/*`
  still doesn't, so the root workspace remains unresolvable on its own). Root `Cargo.toml` was not
  edited, per the task brief.
- CU numbers are LiteSVM-measured, release-profile SBF bytecode, no other instructions in the
  transaction (no compute-budget instruction, no other program) — a real `execute` transaction
  would add the inner CPI's own CU cost on top of these snapshot numbers, plus whatever priority-fee/compute-budget instructions Phase 1 chooses to include.
  - The per-account cost includes `try_borrow_data()` + a fixed-offset byte parse + two `Pubkey`
    equality checks + a `checked_sub`; no allocation beyond the two `Vec<Snap>` collects.
- Only one Token-2022 account (not a sweep) was measured for the TLV path, per the task brief's
  scope; if Phase 1 wallets are expected to hold many Token-2022 extension accounts, a small N
  sweep on the TLV path (analogous to the SPL sweep) would be worth a follow-up.
