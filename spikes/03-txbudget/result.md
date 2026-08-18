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

## Results — Jupiter SOL→USDC (0.1 SOL, 50 bps slippage), 5 runs ≥130s apart

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

## Results — Marinade deposit (1 SOL) and Tensor buy-now (attempted)

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

## Conclusion

**5/5 (100%) of real Jupiter SOL→USDC routes fit inline** in this sample (wrapped size 599–1059
bytes against the 1,232-byte limit, 15–38 accounts touched), and Marinade's 1-SOL deposit also fit
comfortably (662 bytes, 13 accounts) — **0 staged/chunked transactions were needed for any real
route measured in this spike.** This is a smaller sample than the brief anticipated (the
"expect many to NOT fit inline" sanity note assumed 20–40-account routes would commonly overflow),
so it's worth being precise about *why* the inline-fit rate came out much higher than expected,
not just reporting the headline number:

1. **The wrapper is byte-efficient.** `wrapForExecute`'s outer `execute` instruction spends only
   ~4 bytes of fixed overhead plus 2 bytes per referenced account (1-byte index + 1-byte
   signer/writable flags) — it does **not** re-embed full 32-byte pubkeys for accounts already
   present in the outer compiled message's account list, since Warden's account-index scheme
   (`u8 acct_idx` referring to the outer message's `staticAccountKeys`/LUT-resolved list) avoids
   that duplication. That's a ~16x saving per account versus naively copying pubkeys, and it's the
   main reason routes with almost 40 accounts still came in under budget.
2. **Signature-count reduction offsets instruction overhead.** As found while fixing the unit test
   (see Self-review below), wrapping *removes* the account's own ed25519 signature (64 bytes) from
   the tx, since the smart-account PDA now authorizes via the program's `invoke_signed` instead of
   signing the transaction directly. That 64-byte credit is "spent" against the added
   remaining-accounts/instruction-data overhead before the net size grows.
3. **Address Lookup Tables (LUTs) keep the *outer* message's account list short even when the
   *inner* route touches many accounts.** Jupiter routes use LUTs extensively; `wrapForExecute`
   compiles the outer message with the same LUTs (`compileToV0Message(luts)`), so accounts already
   in a lookup table cost ~1 byte (an index) in the outer message's compact-array, not 32 bytes —
   this is doing a lot of the heavy lifting for the ~30-40 account cases.

**Extrapolated headroom:** bytes grew roughly linearly with account count across the 5 runs (~20
bytes/account, from the 15-account/599-byte and 38-account/1059-byte data points). At that rate
the largest observed case (1059 bytes, 38 accounts) has ~173 bytes / ~8–9 more accounts of
headroom before hitting 1,232 — i.e. routes up to roughly **45–47 accounts** would likely still
fit inline; multi-hop Jupiter routes with heavier LUT usage or non-Jupiter dApps that don't use
LUTs at all are the more plausible source of staged/chunked cases in Phase 2, not typical 1–3-hop
Jupiter swaps. **The `stagedChunks` fallback path (`Math.ceil(instructionBytes/900)`) itself was
never exercised end-to-end by this spike** since no case measured needed it — Phase 2 should add a
synthetic large-instruction-count test (e.g. a hand-built message with 60+ dummy accounts) to
validate that arithmetic before relying on it in production, since real-world routes here never
got close enough to test it honestly.

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
