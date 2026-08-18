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

## Round 2 fix (2026-08-18) — read this too

Re-review found round 1's index fix itself wrong in a different way, plus asked for a spec
citation. Both addressed:

1. **Critical (still open after round 1) — index space was wrong again, in the opposite
   direction.** Round 1 "fixed" the round-0 bug by switching to indices into the *compiled
   message's global* account-key list. Controller ruling: that's not this program's contract —
   on-chain, the `execute` handler only ever sees ITS OWN instruction's account slice (Anchor
   `remaining_accounts`, populated from that one instruction's own `accountKeyIndexes`, in that
   instruction's own original key order), never the message's global key list. **The correct
   contract is INSTRUCTION-LOCAL indices**: index i = position i in `outer.keys` = `[account,
   sessionKey, ...order]`. Round 0's actual bug was simpler than round 1 diagnosed: `idx()`
   searched a bare `order` array that omitted the `[account, sessionKey]` prefix, an off-by-2, not
   a wrong-index-space problem. `wrapForExecute` now indexes `outerKeys` directly (no compile step
   needed to learn indices at all — they're fixed the moment `outerKeys` is built) and, after
   compiling, decompiles the result and **asserts** the execute instruction's resolved key order
   equals `outerKeys` exactly (throws with a diagnostic otherwise) — a permanent regression guard
   for this contract. The round-trip test now decodes indices against the **instruction-local**
   key list (the decompiled execute instruction's own `.keys`), not the global message list. New
   test: builds a source tx with its own `ComputeBudgetProgram.setComputeUnitLimit` instruction
   and confirms it's hoisted to top level with its original value intact and not also referenced
   anywhere inside the packed `execute` payload. Full contract now stated in `wrap.ts`'s header
   comment. See Self-review → "Round 2 fix" for detail.
2. **Important — stage_chunk account contract now cites spec §5.1** (payer signer / Stage PDA
   writable / System Program; data = 8-byte header + payload) directly in `wrap.ts`'s code
   comment. §5.1 fixes the signer and the header shape but not the Phase 1 program's exact account
   list/order, so **the measured 985 B cap is PROVISIONAL**, not final, until that program exists
   — marked as such wherever it's cited below. No new tests needed for this one (controller
   ruling) — the existing chunk-count test already exercises the same code path.

**Byte counts are unaffected by the index-space fix** (both instruction-local and global indices
are single bytes — u8 either way — so no size difference), confirmed by 2 fresh post-round-2
measure runs below.

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
#3) measured **985 bytes** (PROVISIONAL — round 2 review: this is a spec §5.1-shaped account
layout, not the actual Phase 1 program's; re-measure once that program's stage_chunk account
list/order is fixed) for a representative `stage_chunk` tx (1 signer/payer, 3 accounts:
payer/stage-PDA/System-Program, 8-byte offset+len header) on this run — close to but not the same
as the old guess, which is exactly why deriving it was worth doing.

## Post-fix re-measurement, round 2 (authoritative — supersedes nothing byte-wise, confirms round 1)

2 fresh `pnpm measure` runs against the round-2-fixed `wrap.ts` (instruction-local indices +
compile/decompile regression assertion; §5.1-cited, PROVISIONAL stage_chunk cap — no logic
changes from round 1 that affect byte counts).

| run | UTC timestamp | original bytes | wrapped bytes | fits inline? | chunks if staged | account count | hops |
|---|---|---|---|---|---|---|---|
| D | 2026-08-18T12:43:26Z (manual, immediately post-fix) | 618 | 711 | yes | 0 | 18 | 1 |
| E | 2026-08-18T12:45:41Z | 682 | 786 | yes | 0 | 24 | 1 |

Raw JSON:
```
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":618,"bytesInline":711,"fitsInline":true,"stagedChunks":0,"writableAccounts":18,"hops":1}
{"name":"jupiter SOL→USDC 0.1","bytesOriginal":682,"bytesInline":786,"fitsInline":true,"stagedChunks":0,"writableAccounts":24,"hops":1}
{"name":"marinade deposit 1 SOL (attempt)","bytesOriginal":559,"bytesInline":702,"fitsInline":true,"stagedChunks":0,"writableAccounts":13}  (×2, byte-identical across both round-2 runs)
```

**Confirms the byte-size claim above: Marinade's wrapped size is 702 B, byte-identical to round
1's post-fix measurement** (both rounds hoist the same default `setComputeUnitLimit(600_000)` and
pack the same single deposit instruction; only the index *values* inside the packed payload
differ between rounds — same byte count, different, now-correct, meaning). Tensor: unchanged,
still blocked on the same API-key wall.

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
Both are fixed: `maxStageChunkPayloadBytes()` now measures the real cap (985 B, PROVISIONAL — see
"Round 2 fix" — on this run, from
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
transaction ≤ `MAX_TX_BYTES`, memoized per program id. Measured **985 B, PROVISIONAL** (see "Post-fix
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

### Round 2 fix (2026-08-18) — task review findings, addressed

**1. Critical (still open after round 1) — index space, corrected to instruction-local (FIXED).**
Round 1's diagnosis was wrong: it treated the round-0 bug as "indices must be computed from the
compiled MESSAGE's global account-key list" and rewrote `wrapForExecute` to do a two-pass compile
purely to learn that global ordering. Controller ruling on re-review: that is not this program's
account-resolution contract. On-chain, an instruction handler (Anchor's `remaining_accounts`
included) only ever receives the accounts belonging to *that one instruction*, resolved from that
instruction's own `accountKeyIndexes`, in that instruction's own original key order — it has no
visibility into the transaction message's global, deduped, re-sorted key list. Round 0's actual
bug, re-diagnosed correctly this time: `idx()` searched a bare `order` array (the deduped
remaining-accounts list) that omitted the 2-slot `[account, sessionKey]` prefix actually baked
into `outer.keys` — a plain off-by-2 into the wrong (too-short) array, not a "wrong index space
entirely" problem.

**Fix:** `wrapForExecute` now indexes `outerKeys = [account, sessionKey, ...order]` directly —
`idx(p) = outerKeys.findIndex(k => k.pubkey.equals(p))`, still bounds-checked against u8. No
compile step is needed to learn these indices at all (a simplification vs round 1's two-pass
approach): they're fixed the instant `outerKeys` is constructed, because `compileToV0Message`'s
per-instruction `accountKeyIndexes` preserve each instruction's own key ORDER even while
re-mapping which global message slot each position resolves to — position j of `outer.keys`
survives compilation as position j of the execute instruction's resolved key list, unconditionally.

**New regression guard:** after compiling, `wrapForExecute` decompiles the result and **asserts**
the execute instruction's resolved key list equals `outerKeys` exactly, pubkey-for-pubkey, in
order — throwing a diagnostic (listing both the expected and actual key lists) if not. This turns
"the instruction-local contract silently breaks" into a hard failure instead of a wrong-but-valid
index, the same failure mode both round-0 and round-1's bugs shared.

**Test changes:** the round-trip decode test now resolves indices against the **decompiled execute
instruction's own `.keys`** (instruction-local), not the compiled message's global account-key
list — this is what an on-chain consumer actually sees, so it's also a stronger test than round
1's version (which validated against an index space the program never uses). New test: "hoists a
ComputeBudget instruction already present in the source tx to top level, instead of CPI-wrapping
it" — builds a source tx carrying its own `setComputeUnitLimit(314_159)` (a value distinct from
the 600_000 default, so the test can't accidentally pass by observing the default instead of the
hoisted original), wraps it, and asserts: exactly one top-level ComputeBudget instruction in the
wrapped tx, decoding to the *original* 314,159 value (`ComputeBudgetInstruction
.decodeSetComputeUnitLimit`); exactly one execute instruction; and the execute instruction's
decoded packed payload contains exactly the transfer (not the ComputeBudget ix) and never
references the ComputeBudget program among its accounts. `wrap.ts`'s header comment now states the
full instruction-local contract explicitly, including the two prior wrong diagnoses (round 0's
off-by-2, round 1's wrong index space) as documented history, so a future reader doesn't
re-attempt either.

**2. Important — stage_chunk cap, spec citation + provisional marking (FIXED).**
`maxStageChunkPayloadBytes`'s doc comment now cites spec §5.1 directly for the account contract
(payer signer / Stage PDA writable / System Program; data = 8-byte offset+len header + payload) —
no logic change, the serialization this spike already built matches §5.1's shape. Per controller
ruling, §5.1 fixes the signer and header shape but not the eventual Phase 1 program's exact
account list/order, so the measured **985 B cap is marked PROVISIONAL** everywhere it's cited in
this document (banner above, "Post-fix re-measurement," and here) — it should be re-measured once
that program exists rather than treated as load-bearing for Phase 1 sizing today. No new test
added for this item (controller ruling: the existing "~3000-byte payload forces staging" test
already exercises the same `maxStageChunkPayloadBytes` code path; a spec-citation-only change
doesn't need new coverage).

**Byte-size impact of the index-space fix: none, confirmed.** Both instruction-local and
compiled-global indices are single bytes (u8) regardless of numeric value, so switching index
spaces cannot change `bytesInline`/`bytesOriginal`/`fitsInline`/`stagedChunks` for any case already
measured — only the *correctness* of what the indices point to changes. 2 fresh
`pnpm measure` runs post-round-2-fix confirm this holds (see "Post-fix re-measurement, round 2"
above): sizes for a given account count land in the same range as round 1's post-fix numbers
(e.g. Marinade: 702 B in both rounds, byte-identical).

## Part (b) — conservation snapshot CU

**Round 1 fix (2026-08-18):** task review found a **Critical** defect in the invariant check (it
only ever inspected the AFTER snapshot's booleans, so a pre-existing delegate/close_authority that
got *cleared* during the call silently passed, and an account that became too short/corrupted to
parse — `after.token = None` — was silently skipped instead of rejected) plus an **Important** gap
(COption tags decoded as `tag != 0` instead of strict `0`/`1`/error) and a **Minor** (the negative
test asserted on a string instead of the exact structured error). All fixed — see "Round 1 fix"
at the end of this section for the full detail and the before/after numbers. **The CU numbers
below are the POST-FIX, authoritative measurements** (re-run after the fix, replacing the
pre-fix numbers this section originally reported).

**Goal:** the CU cost of `execute`'s core safety mechanism — snapshotting every writable
vault-owned token account before/after the inner CPI and rejecting the transaction if one was
mutated outside the CPI's declared effect — as a function of N accounts, to size Phase 1's compute
budget.

**Code:** `onchain/Cargo.toml`, `onchain/src/lib.rs` (`spike-conserve` program), `onchain/tests/cu.rs`
(LiteSVM harness).

**Method:** a native program takes `accounts[0]` = vault authority marker (read-only, never
initialized on-chain), `accounts[1..]` = writable token accounts to snapshot. It reads every
token account twice (before / after — a real `execute` would CPI into the target program between
the two passes; this spike has no CPI, isolating the pure snapshot-and-compare cost). For every
account whose BEFORE snapshot is a token account (SPL Token or Token-2022) with token-level
`owner == vault`, `check_vault_invariants(vault, before, after)` (extracted as its own function in
round 1, directly unit tested — see below) requires the AFTER snapshot to still be a parseable
token account, requires every field except `amount` to be byte-identical before vs after (runtime
owner, token owner, mint, delegate value, delegated_amount, close_authority value, state, data_len,
TLV-tail hash), and — independently of whether anything changed — requires the AFTER state to
satisfy policy (state Initialized, delegate None, close_authority None), then returns the amount
decrease. Accounts not vault-owned at the token level are read but otherwise ignored (a real
mutation can't be produced without a CPI, so this spike proves the ownership filter rather than the
reject-on-mutation branch end-to-end — that branch is proven by direct unit tests instead, see
"Round 1 fix"). `data[0] = 1` is a SYNTHETIC control flag, unrelated to the invariant check, that
short-circuits to `Custom(99)` after snapshotting, to measure the reject-after-snapshot CU cost.

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
| 10 | 10,011 |
| 20 | 18,785 |
| 30 | 27,225 |

All well under the 200,000 default per-instruction CU limit (assertion `cu30 < 200_000` passes
with ~7.3x headroom). Two-point linear fit (N=10 → N=30): **base ≈ 1,404 CU, ≈861 CU per
additional vault-owned SPL Token account** (`(27225 − 10011) / 20 ≈ 860.7`; the N=10→20 segment is
≈877.4 CU/account and N=20→30 is ≈844.0 CU/account — close enough to call it linear at this scale).
Per-account cost rose ≈133 CU (≈18%) versus the pre-fix measurement (≈728 CU), consistent with the
extra fields now parsed and compared (`delegated_amount`, full `Option<Pubkey>` value comparisons
for delegate/close_authority instead of presence booleans, plus the stricter COption tag decode).

**Extrapolation for Phase 1 budgeting:** at ~861 CU/account plus ~1,400 CU fixed overhead, a vault
could snapshot roughly **231 writable token accounts** before exhausting a single 200,000 CU
instruction budget (`(200,000 − 1,400) / 861 ≈ 231`) — still far beyond any realistic `execute`
account list (spike 3a saw 15–38 accounts on real Jupiter routes), so the conservation-snapshot
mechanism itself is still not expected to be Phase 1's binding CU constraint; the inner CPI's own
cost will dominate.

### Token-2022 TLV-tail account (265 B, 100-byte TLV tail)

10 vault-owned SPL accounts + 1 Token-2022 account with a 100-byte TLV tail: **11,147 CU** — a
delta of **1,136 CU** versus the 10-SPL-only baseline (10,011 CU) for one extra account whose data
is read across the before/after passes (present twice: once as raw read, once through the
TLV-hash syscall) 265-byte account, i.e. hashing a 100-byte tail twice (before + after) plus
reading/parsing 265 vs 165 bytes and the fuller field comparison.

### keccak vs sha256 for the TLV-tail hash

Tried both via a Cargo feature (`sha256-tlv`, default off ⇒ `solana_program::keccak::hash`; on ⇒
`solana_program::hash::hash`, which is SHA-256 — confirmed by reading `solana-sha256-hasher`
source, same as noted in `docs/TOOLCHAIN.md`'s spike-2b entry). Re-ran after the round-1 fix,
building and running `cu_with_token2022_tlv_tail` against both `.so` builds again (confirmed
genuinely different binaries — different file hashes, same 26,160-byte size):

| hash syscall | compute_units_consumed |
|---|---|
| `keccak::hash` (default) | 11,147 |
| `hash::hash` (SHA-256) | 11,147 |

**Still no measurable difference at this size (100-byte tail, hashed twice per invocation) on this
Agave 3.1.10 / LiteSVM 0.12.0 toolchain** — the parity held across the fix, which only touched
field-comparison logic, not the hash call itself, so this was expected. `keccak` stays the default
(matches the task brief's original code skeleton); either is CU-equivalent for TLV tails in this
size range, so Phase 1 is free to pick based on other criteria (e.g. `keccak` is what SPL
Token-2022's own extensions ecosystem tends to use for content hashes). Still worth re-measuring at
a larger TLV size (e.g. 1 KB) if Phase 1 needs a sharper answer.

### Synthetic control path (renamed from "Negative path" in round 1)

`data[0] = 1`: transaction fails with the exact structured error
`TransactionError::InstructionError(0, InstructionError::Custom(99))` (asserted by equality, not
string-contains, per round 1 fix item 4) after logging `"snapshots ok, sol_out=0"` — confirms the
reject happens *after* a successful snapshot pass, not instead of one (10,019 CU consumed in the
failing case, consistent with the 10,011 CU happy-path figure at N=10). This flag has no relation
to `check_vault_invariants` — it is a caller-declared "something went wrong" control used only to
measure the reject-after-snapshot CU cost; the test is now named
`synthetic_reject_flag_returns_custom_99_after_snapshot` to make that explicit.

### Mutation-detection: unit tests on `check_vault_invariants` (round 1 — see below), plus the cheap ownership-filter LiteSVM case

No CPI exists in this spike to actually mutate a vault-owned account's on-chain state between the
before/after LiteSVM snapshots (that's `execute`'s job in Phase 1, deliberately out of scope here —
see the code comment `// (a real execute would CPI into the target program here)`), so the
reject-on-mutation branch cannot be exercised end-to-end through LiteSVM without one. Round 1 closes
that gap the right way: `check_vault_invariants` was extracted as its own pure function and is now
directly unit tested with 12 `#[cfg(test)]` cases in `src/lib.rs` (no SBF build needed, `cargo test
--lib`) covering unchanged→Ok(0), amount decrease→Ok(delta), delegate cleared→Err, delegate
set→Err, close_authority set→Err, a pre-existing-and-unchanged delegate→Err (the exact case the
Critical bug missed), data_len shrink→Err, runtime owner change→Err, TLV-hash change→Err,
after=None→Err (the other half of the Critical bug), non-vault-owner→ignored (Ok(0)), and a
malformed COption tag→parse Err. All 12 pass. What LiteSVM still covers directly: a token account
whose token-level `owner` field is **not** the vault (with `close_authority` deliberately set,
which would trip the invariant check if the ownership filter were broken) is correctly **ignored**,
not rejected — 10,750 CU for 10 vault-owned + 1 non-vault-owned account.

### Reproduce

```bash
cd /opt/warden
nice -n 10 cargo-build-sbf --manifest-path spikes/03-txbudget/onchain/Cargo.toml
nice -n 10 cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml -- --nocapture
# unit tests alone (no SBF build needed):
nice -n 10 cargo test --manifest-path spikes/03-txbudget/onchain/Cargo.toml --lib -- --nocapture
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
  - The per-account cost includes `try_borrow_data()` + a fixed-offset byte parse + strict COption
    decodes + a full field-by-field comparison + a `checked_sub`; no allocation beyond the two
    `Vec<Snap>` collects.
- Only one Token-2022 account (not a sweep) was measured for the TLV path, per the task brief's
  scope; if Phase 1 wallets are expected to hold many Token-2022 extension accounts, a small N
  sweep on the TLV path (analogous to the SPL sweep) would be worth a follow-up.
- Amount can only ever be reported as decreased (`checked_sub(..).unwrap_or(0)`) — an *increase*
  in `amount` (e.g. an inbound top-up) is silently treated as zero outflow, matching the original
  brief's design. `check_vault_invariants` does not itself flag amount increases as suspicious;
  that judgment call is unchanged from the pre-fix version and wasn't in scope for the review.

### Round 1 fix (2026-08-18) — task review findings, addressed

**1. Critical — invariant check only inspected the AFTER snapshot's booleans (FIXED).** The
pre-fix code computed `mutated` purely from the AFTER snapshot's `has_delegate`/`has_close_authority`/
`state` fields, never diffing against BEFORE. Two consequences, both closed:
  - A vault token account with a pre-existing delegate/close_authority that got **cleared** during
    the call passed silently — the AFTER booleans read "none", so nothing looked mutated, even
    though before ≠ after.
  - An account that became too short/corrupted to parse (`parse_token_fields` returning `None`)
    hit the pre-fix `if let (Some(tb), Some(ta)) = ..` pattern, which simply didn't match and fell
    through with **no error at all** — a silent skip of exactly the case that most needs rejecting.
  - **Fix:** extracted `fn check_vault_invariants(vault: &Pubkey, before: &Snap, after: &Snap) ->
    Result<u64, ProgramError>` (see `src/lib.rs`). Note the signature carries an explicit `vault:
    &Pubkey` parameter — the task review's suggested signature omitted it, but the described
    behavior ("when before.token is Some and its token-owner == vault … else ignored") requires the
    function to know `vault` to decide relevance internally, so it was added; flagging the
    deviation explicitly. The function now: returns `Ok(0)` immediately if `before.token` isn't
    vault-owned (not this account's concern); requires `after.token` to still be `Some` (hard error
    otherwise); computes an `unchanged` boolean across every field except `amount` (runtime owner,
    token owner, mint, delegate value, delegated_amount, close_authority value, state, data_len,
    tlv_hash) and errors if anything differs; THEN, independently, applies policy to the AFTER
    state (must be Initialized, delegate must be None, close_authority must be None) — this second,
    separate check is what makes a pre-existing-and-unchanged delegate/close_authority fail too,
    not just a newly-acquired one. Returns `before.amount.checked_sub(after.amount).unwrap_or(0)`.
  - **12 new unit tests** in `src/lib.rs` (`#[cfg(test)] mod tests`, `cargo test --lib`, no SBF
    build needed) exercise this function directly — see "Mutation-detection" above for the full
    list. All 12 pass.

**2. Important — COption tags decoded as `tag != 0` (FIXED).** The pre-fix `parse_token_fields`
treated any nonzero 4-byte tag as "Some" without checking it was exactly `1`, and only ever
recorded presence (`bool`), discarding the actual pubkey value — so two different delegates (or a
delegate that changed to a different delegate) would have compared as "equal" (both `true`).
**Fix:** new `read_coption_pubkey(b, tag_off) -> Result<Option<Pubkey>, ProgramError>` decodes the
4-byte LE tag strictly: `0` → `None`, `1` → `Some(pubkey)`, anything else → hard
`Err(InvalidAccountData)`. `TokenFields` now carries `delegate: Option<Pubkey>` and
`close_authority: Option<Pubkey>` (full values, compared by `PartialEq` on `Option<Pubkey>`)
instead of booleans, and a new `delegated_amount: u64` field was added to the parsed struct and the
comparison (it was parsed-but-unused pre-fix). Unit test `malformed_coption_tag_is_parse_err`
covers the strict-tag rejection.

**3. Important — negative-path test was synthetic, no real reject-on-mutation coverage (FIXED).**
Addressed by item 1's 12 unit tests. The LiteSVM `data[0]=1` test is kept (renamed
`synthetic_reject_flag_returns_custom_99_after_snapshot` with an explicit doc comment) purely as a
CU-cost control for the reject-after-snapshot path, not a mutation test — see "Synthetic control
path" above.

**4. Minor — string-contains assertion on the negative-path error (FIXED).** `tests/cu.rs`'s
`send()` helper now returns `Result<u64, solana_sdk::transaction::TransactionError>` (the exact
structured LiteSVM error) instead of a `Result<u64, String>` built with `format!("{:?}", ..)`; the
renamed test asserts `err == TransactionError::InstructionError(0, InstructionError::Custom(99))`
by equality.

**Before/after CU numbers (all re-measured post-fix, see tables above for full detail):**

| measurement | pre-fix | post-fix | delta |
|---|---|---|---|
| N=10 happy path | 8,688 | 10,011 | +1,323 (+15.2%) |
| N=20 happy path | 16,134 | 18,785 | +2,651 (+16.4%) |
| N=30 happy path | 23,254 | 27,225 | +3,971 (+17.1%) |
| N=10 + Token-2022 TLV | 9,707 | 11,147 | +1,440 (+14.8%) |
| Synthetic Custom(99) control (N=10) | 8,697 | 10,019 | +1,322 (+15.2%) |
| N=10 + 1 non-vault-owned (ignored) | 9,327 | 10,750 | +1,423 (+15.3%) |
| Fitted per-account cost | ≈728 CU | ≈861 CU | +133 (+18.3%) |
| N=30 still `< 200_000`? | yes (~8.6x headroom) | yes (~7.3x headroom) | still comfortably clear |
| `.so` size | 25,104 B | 26,160 B | +1,056 B |

Every table and figure elsewhere in this "Part (b)" section above already reflects these post-fix,
authoritative numbers; this table exists purely to make the magnitude of the fix's CU cost
explicit for whoever is sizing Phase 1's budget off the pre-fix draft of this document.
