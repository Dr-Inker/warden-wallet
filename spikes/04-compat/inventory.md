# Spike 4: dApp Compatibility Inventory (Top 20 Solana dApps)

**Date:** 2026-08-18
**Author:** Task 7 (Spike 4)

## Method

For each dApp we cloned the official public SDK/program repo with `git clone --depth 1`
into `spikes/04-compat/src-<name>/` (gitignored, not committed) and grepped for
`signMessage|signIn(|SIWS|createSignInMessage|partialSign|NonceAccount|advanceNonce|durableNonce`,
then read the matched call sites for context. Program IDs and instruction names were taken
from bundled IDL JSON (Anchor) or `declare_id!()`/instruction enums in program source.
Anchor instruction discriminators not present in an IDL were computed as
`sha256("global:<instruction_name>")[0:8]` (Anchor's standard sighash scheme) — noted per row.
For closed-source dApps (no public on-chain-interaction SDK) we used WebSearch/WebFetch of docs
and, where the site was reachable, downloaded and grepped the production JS bundle for the same
patterns; Playwright was reserved for cases where JS-bundle inspection was blocked, per the task
brief's "≤5 sites, observed in UI" allowance. Pump.fun and Magic Eden were resolved via bundle
grep (no browser needed); Photon was attempted via Playwright but blocked by a Cloudflare
challenge (403 "Just a moment...") — that cell is evidence-based-but-indirect, flagged below.

**Top-20 list and source:** DappRadar's Solana dApp rankings page
(https://dappradar.com/rankings/protocol/solana) blocks automated fetch (403) and DappRadar/
DeFiLlama do not expose a scrapeable, unauthenticated "weekly active wallets" export as of
2026-08-18. We used the task brief's own reference list — which cross-checks against every
public ranking summary we *could* pull (search-engine synopses of DappRadar, Solana Compass,
CoinBureau's 2026 Solana dApp overview, and category-leader consensus: Jupiter/Raydium/Orca/
Meteora for DEX, Kamino/marginfi/Solend-Save for lending, Marinade/Jito/Sanctum for liquid
staking, Drift/Phoenix for perps/order-book, Tensor/Magic Eden for NFTs, Pump.fun for
launchpad, Helium for DePIN, Realms/Squads for governance/treasury) — as the top-20 seed list,
with **one substitution**: **Zeta Markets → Photon**. Zeta ceased Solana perpetuals operations
on 2025-05-01 to pivot to a separate L2 product ("Bullet"); it is no longer a live Solana dApp
as of 2026-08-18 (https://coincodecap.com/zeta-review, https://docs.zeta.markets/). Photon
(photon-sol.tinyastro.io) is one of the highest-volume Solana trading-terminal dApps and was
already implicitly covered by the brief's "top by weekly active wallets" intent.
**This list is a documented best-effort substitute for a live wallet-count export — treat the
ranking order as approximate, not verified per-dApp WAW figures.**

Legend: **OK** = only `signTransaction`/`signAndSendTransaction`, wallet is fee payer, no
required non-wallet co-signers, well-known program. **root-only** = same signer shape but the
program is niche enough it would need to be added to Warden's adapter registry by hand.
**unsupported** = needs SIWS/`signMessage` verified against the wallet address, real
third-party co-signers/partial sigs, durable nonces, or the wallet key as a non-fee-payer
top-level signer. Ephemeral, dApp-generated `Keypair`s that are `partialSign`'d locally before
the wallet's own signature (e.g. a fresh mint/position-NFT/token-account keypair) are **not**
treated as co-signers — they're independent of the wallet's own signature and do not require
verification against the smart-account address.

---

## Table

| # | dApp | Connect needs SIWS/signMessage? | Extra signers / partial sigs? | Durable nonces? | Programs + instructions (common flows) | Wallet = top-level signer beyond fee payer? | Verdict |
|---|------|----------------------------------|-------------------------------|------------------|------------------------------------------|----------------------------------------------|---------|
| 1 | **Jupiter** (swap aggregator) | No — not found in swap API client [1a] | No — Swap API returns one `VersionedTransaction`, wallet is sole signer per `/swap` response contract [1a] | No — not found | Jupiter Aggregator v6 `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` — `route`/`sharedAccountsRoute` (CPIs into the selected DEX programs) [1b] | No (fee payer only) | **OK** |
| 2 | **Raydium** | No — not found in raydium-sdk-V2 | Yes, but ephemeral-only — `txTool.ts` `partialSignedTxs` pattern signs local `allSigners[idx]` keypairs (ATA/setup accounts) before `signAllTransactions` [2a] | No — not found | AMM V4 `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`; CLMM `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK`; CPMM `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C` [2b] | No | **OK** |
| 3 | **Orca** (Whirlpools) | No — not found in whirlpools repo | Yes, ephemeral — `open_position` mints a position-NFT via a fresh local `Keypair`, `partialSign`'d in `transactions-processor.ts` [3a] | No — not found | Whirlpool program `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` — `swap`/`swap_v2`, `open_position`, `increase_liquidity`, `decrease_liquidity` [3b] | No | **OK** |
| 4 | **Meteora** (DLMM) | No — not found in dlmm-sdk | Yes, ephemeral — `initialize_position*` creates a position account via local keypair, same pattern as Orca | No — not found | DLMM program `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` — `swap`/`swap2`, `add_liquidity*`, `remove_liquidity*`, `initialize_position*` [4a] | No | **OK** |
| 5 | **Kamino** (klend) | No — not found in klend-sdk | Not found required (obligation accounts are PDAs, not keypairs) | No — not found | klend program `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` [5a] — `depositReserveLiquidityAndObligationCollateralV2`, `withdrawObligationCollateralAndRedeemReserveCollateralV2`, `borrowObligationLiquidityV2`, `repayObligationLiquidityV2` [5b] | No | **OK** |
| 6 | **Marinade** | No — not found in marinade-ts-sdk | No — `deposit` (SOL→mSOL) needs only the wallet; `depositStakeAccount` needs the stake account's withdraw-authority signature (commonly the wallet itself, not a 3rd party) | No — not found | `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD` [6a] — `deposit`, `depositStakeAccount`, `liquidUnstake` | No | **OK** |
| 7 | **Jito** (JitoSOL staking) | UNVERIFIED for the jito.network UI itself — the `jito-labs/jito-ts` SDK we cloned is the searcher/bundle client, not the staking front end, and has no wallet-connect code to inspect | Not found required — standard SPL Stake Pool deposit does not need extra signers | No — not found | SPL Stake Pool program `SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy`, pool `Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb` — `DepositSol`/`DepositStake`/`WithdrawStake` [7a] | No | **OK** (staking mechanism only; connect-flow SIWS unverified but SPL Stake Pool itself has no such requirement) |
| 8 | **Drift** | No at connect (not found in `wallet.ts`/`driftClient.ts` for the standard adapter path). **Caveat:** the opt-in "Swift" low-latency order flow signs the order message with `nacl.sign.detached` against the wallet key and is verified off-chain by Drift's matching engine — this *is* a signMessage-against-the-wallet-address pattern, but only for that specific opt-in flow, not core deposit/trade [8a] | Not found required for core `deposit`/`placePerpOrder` | No — not found | Program `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` [8b] — `deposit`, `withdraw`, `place_perp_order`, `place_orders` | No (core flow) | **OK** for on-chain deposit/trade; **unsupported** for the "Swift" signed-order flow specifically |
| 9 | **Tensor** | No — not found in `tensorswap-sdk` or `tensor-foundation/marketplace` | No user-side co-signer found. Legacy TensorSwap AMM pools use a protocol-owned `TSWAP_COSIGNER` (`6WQvG9Z6D1NZM76Ljz3WjgR7gGXRBJohHASdQxXyKi8q`) added server-side by Tensor itself, not a second required signature from the user [9a] | No — not found | Current marketplace `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` — `buy`, `list`, `delist`, `bid` [9b]; legacy AMM `TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN` [9c] | No | **root-only** (niche marketplace program, otherwise clean signer shape) |
| 10 | **Magic Eden** | Likely yes — Magic Eden's own `dynamic-*.js` production chunk bundles Dynamic.xyz's wallet-auth SDK (`signPersonalMessage`/`signMessage`, `signInEnabled`, `verifiedAt` fields), which implements wallet-based sign-in (SIWx-style) [10a]; could not fully confirm whether basic buy/list is gated behind it vs. optional account features | UNVERIFIED — closed-source frontend, no public on-chain SDK found for the current marketplace program | UNVERIFIED | Marketplace v2 `M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K` [10b] | UNVERIFIED | **unsupported** (evidence-weighted: Dynamic wallet-auth bundled prominently in the app shell) |
| 11 | **Pump.fun** | Yes — Pump.fun uses Privy for wallet login; Privy's "Login with Wallet" implements SIWS (request a signature, verify via `loginWithSiwe`/SIWS-equivalent for Solana) [11a]; corroborated by `signMessage`/`signIn` strings in pump.fun's own production JS bundle [11b] | UNVERIFIED | UNVERIFIED | Bonding-curve program `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` — `create`, `buy`, `sell` [11c] | UNVERIFIED | **unsupported** (SIWS required to log in) |
| 12 | **Phoenix** | No — not found in phoenix-sdk (TS or Rust) | Not found required | No — not found | Program `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY` [12a] — `Swap`, `PlaceLimitOrder`, `CancelAllOrders`, `WithdrawFunds` | No | **OK** |
| 13 | **Sanctum** | No — not found in `sanctum-lst-list` (rust/ts) | Not found required | No — not found | Sanctum Router `stkitrT1Uoy18Dk1fTrgPw8W6MVzoCfYoAFT4MLsmhq` [13a]; Infinity pool `5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx` (per Sanctum docs summary — direct fetch of learn.sanctum.so blocked/403, cited via search-engine synopsis of that page) [13b] — swap / addLiquidity / removeLiquidity | No | **root-only** |
| 14 | **marginfi** | No — not found in marginfi-v2 repo (program + tests, no frontend in this repo) | Not found required | No — not found | Program `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` [14a] — `lendingAccountDeposit`, `lendingAccountWithdraw`, `lendingAccountBorrow`, `lendingAccountRepay` | No | **OK** |
| 15 | **Solend / Save** | UNVERIFIED — no frontend in `solendprotocol/solana-program-library`; docs.save.finance not fetched | Not found required | No — not found | Program `So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo` — rebrand to Save confirmed to use the same program [15a] — Borsh enum `LendingInstruction` variants `DepositReserveLiquidity`, `DepositObligationCollateral`, `BorrowObligationLiquidity`, `RepayObligationLiquidity` (1-byte variant tag, not Anchor sighash) [15b] | No | **OK** |
| 16 | **Parcl** (v3, real-estate perps — replaces defunct Zeta) | No — not found in `v3-sdk-ts` | Yes, ephemeral — `transactionBuilder.ts` `buildSigned(signers, ...)` calls `tx.partialSign(...signers)` for locally-generated signers before the wallet signs [16a] | No — not found | Program `3parcLrT7WnXAcyPfkCz49oofuuf2guUKkjuFkAhZW8Y` [16b] — `createMarginAccount`, `depositMargin`, `modifyPosition`, `withdrawMargin` | No | **root-only** (small/niche perps program) |
| 17 | **Helium** | No — not found in helium-program-library | Yes, ephemeral — `spl-utils/transaction.ts` `partialSign(...signers)` for locally-created accounts | No — not found | Lazy Distributor `1azyuavdMyvsivtNxPoz6SucD18eDHeXzFCUPq5XU7w` [17a] — `distributeRewardsV0`/`distributeCompressionRewardsV0` (claim HNT rewards, the common consumer flow); Entity Manager `hemjuPXBpNvggtaUnN1MwT3wrdhttKEfosTcc2P9Pg8` [17b] (hotspot/entity admin flows, less common for an end user) | No | **root-only** |
| 18 | **Realms** (governance-ui + Hub) | **Mixed.** Core governance app: No — `spl-governance` voting/proposal calls found no signMessage. **Realms Hub** (forum/profile layer, same repo): **Yes** — `verify-wallet/components/sign-in-with-solana.tsx` explicitly requests a server-issued claim, calls `signMessage(claimBlob)`, and posts the signature to mint a JWT — this is SIWS by name [18a] | Not found required for voting/proposal instructions | No — not found | `@solana/spl-governance` program `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` (well-known; referenced via `DEFAULT_GOVERNANCE_PROGRAM_ID` import, not hardcoded in this repo) [18b] — `castVote`, `createProposal`, `depositGoverningTokens` | No (voting flow) | **root-only** for voting/proposals; **unsupported** for the Realms Hub SIWS profile-verification flow |
| 19 | **Squads** (v4) | No — `Squads-Protocol/v4` repo (program + SDK + CLI, no web frontend) has no signMessage/SIWS code | No same-transaction co-signing found: `proposalApprove`/`vaultTransactionExecute` are each single-signer instructions (each member submits their own approval tx) — this is *not* the brief's "co-signers/partial signatures" case (that requires N parties signing one transaction); it is N separate single-signer transactions, which is architecturally compatible with Warden's per-instruction rewrite | No — not found | Program `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` [19a] — `multisigCreate`, `proposalApprove`, `vaultTransactionCreate`, `vaultTransactionExecute` | No (per-instruction) | **root-only** |
| 20 | **Photon** (trading terminal — replaces defunct Zeta) | Likely yes, indirectly — docs describe connecting Phantom once, after which Photon *generates a separate internal trading wallet* whose exported private key is the one that actually trades; this "connect-to-link" pattern is consistent with a signature-based linking step, but photon-sol.tinyastro.io returned an HTTP 403 Cloudflare challenge to both `curl` and Playwright, so the exact signMessage call could not be directly observed [20a] | UNVERIFIED (site blocked automated access) | UNVERIFIED | UNVERIFIED — closed-source aggregator UI; underlying trades route through whichever AMM the token trades on (Raydium/pump.fun/etc.), not a fixed Photon-owned program | Effectively **irrelevant** — trades are signed by Photon's own generated keypair, not the connecting wallet | **unsupported** — the connected wallet is not the transacting key at all; Photon's model (link wallet once → generate & export a separate hot-wallet keypair that does the actual trading) is incompatible with a smart-account/session-key wallet regardless of the signer-shape questions above |

---

## Citations

- **[1a]** https://github.com/jup-ag/jupiter-quote-api-node (grep of `src/`, `generated/` — no `signMessage`/`partialSign`/`nonce` matches); Swap API contract: https://dev.jup.ag/docs/swap-api/
- **[1b]** https://solscan.io/account/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
- **[2a]** `src-raydium/src/common/txTool/txTool.ts:392-400` (from https://github.com/raydium-io/raydium-sdk-V2, depth-1 clone)
- **[2b]** `src-raydium/src/common/programId.ts:17,20,29`
- **[3a]** `src-orca/legacy-sdk/common/src/web3/transactions/transactions-processor.ts:160-172` (from https://github.com/orca-so/whirlpools)
- **[3b]** `src-orca/programs/whirlpool/src/lib.rs:3` (declare_id), `:334` (swap), `:1155` (swap_v2), `:198` (open_position)
- **[4a]** `src-meteora/idls/dlmm.json` (address field + instructions list), from https://github.com/MeteoraAg/dlmm-sdk
- **[5a]** `src-kamino/src/@codegen/klend/programId.ts:4-5`, from https://github.com/Kamino-Finance/klend-sdk
- **[5b]** `src-kamino/src/idl/klend.json` instructions list
- **[6a]** `src-marinade/src/config/marinade-config.ts:6-8`, from https://github.com/marinade-finance/marinade-ts-sdk
- **[7a]** https://www.jito.network/docs/jitosol/jitosol-liquid-staking/security/deployed-programs/ (via search-engine synopsis; direct WebFetch not attempted after search confirmed the answer)
- **[8a]** `src-drift/sdk/src/driftClient.ts:7854,7962-7966` (signMessage used only inside `signSignedMsgOrderParamsMessage`/"Swift" order flow), from https://github.com/drift-labs/protocol-v2
- **[8b]** `src-drift/programs/drift/src/ids.rs:7` — note: `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` is the well-known public Drift v2 program id (repo's own `declare_id!` for the `drift` crate is commented out in this snapshot; cross-checked against public docs)
- **[9a]** `src-tensor/src/tensorswap/constants.ts:1-23`, from https://github.com/tensor-foundation/tensorswap-sdk
- **[9b]** `src-tensor-mkt/program/idl.json` instructions list; program id per https://docs.tensor.foundation/protocols and https://github.com/tensor-foundation/marketplace (WebSearch-corroborated; IDL's `address` field was empty in the cloned snapshot)
- **[9c]** `src-tensor/src/tensorswap/constants.ts:9-10`
- **[10a]** `me_chunks/dynamic-742d17e752be8498.js` (downloaded from `https://next.cdn.magiceden.dev/_next/static/chunks/dynamic-742d17e752be8498.js`, referenced from https://magiceden.io — chunk not committed, scratch-only); mechanism described at https://www.dynamic.xyz/docs/api-reference/sdk/sign-in-with-wallet
- **[10b]** https://solscan.io/account/M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K
- **[11a]** https://privy.io/blog/token-creation-for-everyone-with-pump-fun ; https://docs.privy.io/guide/expo/authentication/siwe
- **[11b]** `pf_chunks/0.2r9n1d_ow9w.js`, `pf_chunks/01-vmtti.1liu.js` (downloaded from `https://pump.fun/_next/static/chunks/...`, referenced from https://pump.fun — not committed, scratch-only)
- **[11c]** https://docs.solanatracker.io/guides/pumpfun-program ; https://allenhark.com/solana-idl-library/pumpfun/6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P
- **[12a]** `src-phoenix/typescript/phoenix-sdk/src/index.ts:19,27`, from https://github.com/Ellipsis-Labs/phoenix-sdk
- **[13a]** `src-sanctum/rust/sanctum-lst-list/tests/tests/sanctum_router.rs:21`, from https://github.com/igneous-labs/sanctum-lst-list
- **[13b]** https://learn.sanctum.so/docs/technical-documentation/infinity (WebFetch returned 403; cited via WebSearch's synopsis of that same URL)
- **[14a]** `src-marginfi/tests/specs/basic/03_addBank.spec.ts:340`, from https://github.com/mrgnlabs/marginfi-v2; instruction names from `src-marginfi/programs/marginfi/src/lib.rs:352,362,374,386`
- **[15a]** https://docs.save.finance/ (rebrand notice) + program id cross-checked via WebSearch synopsis of https://solanacompass.com/projects/save
- **[15b]** `src-solend/token-lending/sdk/src/instruction.rs:25-53`, from https://github.com/solendprotocol/solana-program-library
- **[16a]** `src-parcl/src/transactionBuilder.ts:45-51`, from https://github.com/ParclFinance/v3-sdk-ts
- **[16b]** `src-parcl/src/constants/programIds.ts:1`
- **[17a]** `src-helium/programs/lazy-distributor/src/lib.rs:5,60,66`, from https://github.com/helium/helium-program-library
- **[17b]** `src-helium/programs/helium-entity-manager/src/lib.rs:5`
- **[18a]** `src-realms/verify-wallet/components/sign-in-with-solana.tsx:78-95`; also `src-realms/hub/components/GlobalHeader/User/Connect.tsx:92`, from https://github.com/Mythic-Project/governance-ui
- **[18b]** `src-realms/pages/dao/[symbol]/proposal/components/instructions/WithdrawFromDAO.tsx:39` (imports `DEFAULT_GOVERNANCE_PROGRAM_ID` from `@solana/governance-program-library`); program id `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` is the well-known public spl-governance deployment
- **[19a]** `src-squads/sdk/multisig/idl/squads_multisig_program.json` `address` field, from https://github.com/Squads-Protocol/v4
- **[20a]** https://solanabox.tools/guides/photon-sol-how-to-start ; https://pies-organization.gitbook.io/photon-trading/photon-on-sol/mobile-traders-sign-up ; direct access attempt: `mcp__playwright__browser_navigate` to https://photon-sol.tinyastro.io/ → HTTP 403 "Just a moment..." (Cloudflare challenge), and `curl` to the same URL returned 0 bytes

---

## Step 3: Summary

**Counts (20 dApps, one verdict per row; Drift and Realms carry a caveat noted above):**

| Verdict | Count | dApps |
|---|---|---|
| **OK** | 9 | Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Jito, Drift (core flow), Phoenix, marginfi, Solend/Save — *(11 listed; see note)* |
| **root-only** | 6 | Tensor, Sanctum, Parcl, Helium, Realms (voting/proposals), Squads |
| **unsupported** | 5 | Magic Eden, Pump.fun, Photon, Realms (Hub SIWS only — same dApp as above, different sub-flow), Drift (Swift order flow only — same dApp as above, different sub-flow) |

Note on the count table: 20 table rows map to 20 dApps, but Drift and Realms each get **two**
verdicts (a primary flow and a caveated sub-flow), so the raw tally above double-counts those
two. Counting **one verdict per dApp** (primary/most-common flow):
**OK = 11** (Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Jito, Drift, Phoenix, marginfi,
Solend/Save), **root-only = 6** (Tensor, Sanctum, Parcl, Helium, Realms, Squads),
**unsupported = 3** (Magic Eden, Pump.fun, Photon).

### `(program_id, discriminator)` seed list for the Phase-2 adapter registry

Anchor-IDL programs (8-byte sighash discriminators, `sha256("global:<name>")[0:8]`, taken from
the IDL where present, else computed):

| Program | program_id | instruction | discriminator (decimal bytes) |
|---|---|---|---|
| Jupiter Aggregator v6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | `route`/`sharedAccountsRoute` | not extracted from IDL in this spike — UNVERIFIED, needs `jup-ag/jupiter-cpi` IDL |
| Raydium AMM V4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | (non-Anchor, u8 tag enum) | not Anchor sighash — see program source |
| Raydium CLMM | `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK` | `swap`/`swapV2` | UNVERIFIED — not extracted this spike |
| Raydium CPMM | `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C` | `swap_base_input`/`swap_base_output` | UNVERIFIED — not extracted this spike |
| Orca Whirlpool | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | `swap` | `[248,198,158,145,225,117,135,200]` (computed, `sha256("global:swap")[0:8]`) |
| Orca Whirlpool | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | `open_position` | `[135,128,47,77,15,152,240,49]` (computed) |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | `swap` | `[248,198,158,145,225,117,135,200]` (computed; DLMM's IDL uses the same Anchor name) |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | `add_liquidity` | `[181,157,89,67,143,182,52,72]` (computed) |
| Kamino klend | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` | `depositReserveLiquidityAndObligationCollateralV2` | UNVERIFIED — computed value not double-checked against IDL bytes this spike |
| Marinade Finance | `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD` | `deposit` | `[242,35,198,137,82,225,242,182]` (computed) |
| SPL Stake Pool (JitoSOL) | `SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy` | `DepositSol` | non-Anchor (Borsh enum tag) — UNVERIFIED exact tag byte this spike |
| Drift v2 | `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` | `deposit` | `[242,35,198,137,82,225,242,182]` (computed) |
| Phoenix | `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY` | `Swap` | non-Anchor custom binary layout — UNVERIFIED exact tag this spike |
| marginfi v2 | `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` | `lendingAccountDeposit` | UNVERIFIED — not computed this spike |
| Solend/Save | `So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo` | `DepositReserveLiquidity` | non-Anchor, 1-byte Borsh enum variant (instruction #2 in `LendingInstruction`, i.e. tag `2` — 0-indexed from the enum in `src-solend/token-lending/sdk/src/instruction.rs:25`) |
| Parcl v3 | `3parcLrT7WnXAcyPfkCz49oofuuf2guUKkjuFkAhZW8Y` | `depositMargin` | UNVERIFIED — not computed this spike |
| Helium Lazy Distributor | `1azyuavdMyvsivtNxPoz6SucD18eDHeXzFCUPq5XU7w` | `distributeRewardsV0` | UNVERIFIED — not computed this spike |
| spl-governance (Realms) | `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` | `CastVote` | non-Anchor, custom Borsh enum — UNVERIFIED exact tag this spike |
| Squads v4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | `vaultTransactionExecute` | UNVERIFIED — not computed this spike |
| Tensor Marketplace | `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` | `buy` | UNVERIFIED — not computed this spike |
| Sanctum Infinity | `5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx` | `swap` | UNVERIFIED — not computed this spike |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `buy` | `[102,6,61,18,1,218,235,234]` (per https://docs.solanatracker.io/guides/pumpfun-program) |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `sell` | `[51,230,133,164,1,127,131,173]` (per same source) |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `create` | `[24,30,200,40,5,28,7,119]` (per same source) |

**Caveat on discriminators:** the Anchor sighash formula (`sha256("global:<snake_or_camel_name>")[0:8]`)
was applied by hand to a handful of instructions to demonstrate the seed format Phase 2 needs;
most rows above are marked UNVERIFIED because pulling every discriminator for every instruction
across 20 programs' full IDLs was out of scope for this spike's time budget. **Phase 2 should
re-derive discriminators programmatically from each program's IDL** (`anchor idl` / IDL JSON's
own `discriminator` field where Anchor ≥0.30 embeds it) rather than trust hand-computed values
in this table.

### SIWS list — dApps that will not log in with a smart account

Ordered by confidence:

1. **Pump.fun** — Privy-based "Login with Wallet" implements SIWS; confirmed via Privy's own
   docs plus signMessage/signIn strings in pump.fun's production bundle. High confidence.
2. **Magic Eden** — Dynamic.xyz wallet-auth SDK (signPersonalMessage/signMessage) bundled
   prominently in the app's own JS chunk. Medium-high confidence (could not confirm whether it
   gates *all* actions or only account features).
3. **Realms Hub** (not the core governance-ui voting app, which is unaffected) — explicit
   `sign-in-with-solana.tsx` component, high confidence, directly read the source.
4. **Photon** — indirect evidence only (site blocked automated inspection); flagged as
   effectively moot anyway since trades are signed by a Photon-generated keypair, not the
   connected wallet.
5. **Drift "Swift" orders** — not a login/connect requirement, but the opt-in low-latency order
   flow signs an order message against the wallet key and would need the smart-account's
   session key to produce a signature verifiable against the PDA address, which the PDA cannot
   do (no private key). Listed here because it's the same failure mode as SIWS even though it's
   not a "connect" step.

None of the remaining 15 dApps showed any signMessage/signIn/SIWS code path in their public
SDKs or (where closed-source) production bundles.

---

## Caveats / things a future pass should tighten

1. The top-20 *ranking* itself is not backed by a live, reproducible wallet-count export —
   DappRadar blocked automated fetch and no free alternative gave a clean scrapeable ranking.
   If Task 9 or Phase 2 need a defensible ranking (not just a defensible *list*), someone with
   DappRadar/Artemis API access should re-pull it.
2. Several "not found" signMessage/nonce/partialSign results are grep-based over a shallow
   (`--depth 1`) clone of a *library* repo, not the full production frontend — a dApp's actual
   web app (often a separate closed-source repo) could still add a signMessage step that the
   published SDK doesn't require. This affects every row marked OK/root-only with only an SDK
   citation (no UI observation) — treat as "the on-chain SDK doesn't require it" rather than
   "the live site definitely doesn't ask for it."
3. Discriminator extraction was intentionally partial (see caveat above) — do not ship Phase 2's
   adapter registry from the hand-computed values here without re-deriving from each IDL.
4. Solend/Save and Jito had no frontend code in the repos cloned (both are program+SDK-only
   repos); their "Connect needs SIWS" cells are UNVERIFIED rather than a confirmed "No".
