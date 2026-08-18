# Spike 4: dApp Compatibility Inventory (Top 20 Solana dApps)

**Date:** 2026-08-18 (round 1 fixes applied same day)
**Author:** Task 7 (Spike 4)

## Method

For each dApp we cloned the official public SDK/program repo with `git clone --depth 1`
into `spikes/04-compat/src-<name>/` (gitignored, not committed) and grepped for
`signMessage|signIn(|SIWS|createSignInMessage|partialSign|NonceAccount|advanceNonce|durableNonce`,
then read the matched call sites for context. Program IDs and instruction names were taken
from bundled IDL JSON (Anchor) or `declare_id!()`/instruction enums in program source. Where
an IDL embeds a `discriminator` field we used it directly; otherwise we computed the Anchor
sighash `sha256("global:<instruction_name>")[0:8]` by hand and cross-validated the method
against IDL-embedded values where both were available (see Seed List section — computed
`swap`→Meteora's own IDL-embedded discriminator and computed `buy`→pump.fun's published
discriminator both matched exactly, i.e. two independent instruction-name/program pairs
confirm the formula). **Since the clones are gitignored, every `path:line` citation below is
paired with that repo's commit SHA (captured via `git rev-parse HEAD` right after cloning) so
a reviewer can `git clone <url> && git checkout <sha>` and land on the exact line.**

For closed-source dApps we used WebSearch/WebFetch of docs, downloaded and grepped the live
production JS bundle where reachable (Pump.fun, Magic Eden — worked without a browser), and
used the Playwright MCP (navigate + find/click on the connect flow, no wallet extension
installed, observation only) for the 4 sites where bundle/API inspection wasn't conclusive or
possible: **Jito** (`jito.network/staking/` — blocked), **Save/Solend** (`save.finance/` —
loaded, connect modal inspected), **Magic Eden** (`magiceden.io/` — loaded, connect modal
inspected), **Photon** (`photon-sol.tinyastro.io/` — blocked). This is the full ≤4-site
Playwright allowance from the task brief.

## Round-1 fixes applied

This revision addresses four review findings: (1) the top-20 provenance section previously
mislabeled *both* Parcl and Photon as substitutes for the single defunct Zeta entry — fixed to
one substitution (Photon), and a second attempt was made at a dated, fetchable public ranking
(DefiLlama's protocols API) rather than relying solely on the brief's example list; (2) four
verdicts that rested on "likely"/indirect evidence (Jito, Solend/Save, Magic Eden, Photon) were
re-checked with direct Playwright inspection of the connect flow — two (Solend/Save, Magic
Eden) now have firm, directly-observed evidence and firm verdicts; two (Jito, Photon) remained
blocked after a second attempt and are now explicitly labeled **provisional** and excluded from
the firm tally; (3) every "No" in the top-level-signer column, plus the Meteora and Helium
ephemeral-signer claims, now cites a `path:line@sha` (IDL account-meta array, `#[derive(Accounts)]`
struct, or raw instruction builder) or is marked UNVERIFIED — no more bare assertions; (4) the
summary now publishes exactly one firm-vs-provisional tally and separates the "SIWS at
login/connect" list from the "signed-message subflow" list (Drift's Swift orders are a subflow,
not a login gate, and are no longer mixed into the SIWS list).

---

## Top-20 list and source

**DappRadar** (`https://dappradar.com/rankings/protocol/solana`) returned HTTP 403 to automated
`curl`/WebFetch on 2026-08-18 and does not expose an unauthenticated wallet-count export.

**Second attempt (this round), per the review ruling:** DefiLlama's public protocols API is
fetchable and dated. We pulled `https://api.llama.fi/protocols` (accessed 2026-08-18, HTTP 200,
8.6 MB JSON) and filtered each protocol's `chainTvls.Solana` field, and separately pulled
`https://api.llama.fi/overview/dexs/solana` (accessed 2026-08-18, HTTP 200) for 7-day Solana DEX
volume. **Both are TVL/volume rankings, not a weekly-active-wallets export** — DefiLlama does not
expose a free, unauthenticated "active users" endpoint as of 2026-08-18, so this corroborates
adoption/usage for the DeFi subset of the list but is not itself a WAW ranking either. Top Solana
protocols by `chainTvls.Solana` (2026-08-18 snapshot, non-CEX/non-RWA-issuer entries): Sanctum
Validator LSTs (#2, $1.13B), Kamino Lend (#3, $1.06B), Jupiter Lend (#5, $0.95B), Raydium AMM
(#6, $0.85B), Jito Liquid Staking (#8, $0.76B), Jupiter Perpetual Exchange (#11, $0.68B), Jupiter
Staked SOL (#16, $0.39B), PumpSwap (#22, $0.25B), Orca DEX (#23, $0.24B), Marinade Native (#25,
$0.22B), Drift Staked SOL (#26, $0.21B), Marinade Liquid Staking (#27, $0.18B), Meteora DLMM
(#29, $0.17B). By 7-day DEX volume: PumpSwap, Orca DEX, Raydium AMM, pump.fun, and Meteora DLMM
all place in the top 7 (alongside several aggregator/MEV-heavy venues — BisonFi, HumidiFi,
Manifest Trade, Axiom — that are not consumer-facing "dApps" in the sense this spike cares about
and were excluded). This directly corroborates 9 of this list's 20 entries (Sanctum, Kamino,
Jupiter, Raydium, Jito, Orca, Marinade, Meteora, Pump.fun). **DefiLlama's TVL/volume data has no
equivalent for NFT marketplaces, governance/multisig tooling, DePIN, or trading terminals**
(Tensor, Magic Eden, Squads, Realms, Helium, Photon), so those 6 entries — plus Drift and
Phoenix, whose "TVL" undercounts perps/order-book activity — remain sourced from category-leader
consensus (cross-checked search-engine synopses of DappRadar/Solana Compass/CoinBureau's 2026
Solana dApp overview) rather than a single fetchable ranking.

**Conclusion — label:** this is **an unranked example list assembled from the task brief, with
partial corroboration** (9/20 entries) **from a dated, fetchable public source (DefiLlama
protocols API, accessed 2026-08-18); DappRadar's actual weekly-active-wallets ranking was
blocked** (403, 2026-08-18) **on both attempts. Treat list membership as defensible, list order
as not verified.**

**Exactly one substitution:** **Zeta Markets → Photon.** Zeta ceased Solana perpetuals
operations on 2025-05-01 to pivot to a separate L2 product ("Bullet") and is no longer a live
Solana dApp as of 2026-08-18 (https://coincodecap.com/zeta-review, https://docs.zeta.markets/).
**Parcl was already an independent member of the brief's original 20-item list** (not a
substitute for anything) — a labeling error in the previous revision incorrectly tagged both
Parcl and Photon as "replaces Zeta"; that is fixed below, Parcl carries no substitution note.

---

## Legend

**OK** = only `signTransaction`/`signAndSendTransaction`, wallet is fee payer, no required
non-wallet co-signers, well-known program. **root-only** = same signer shape but the program is
niche enough it would need to be added to Warden's adapter registry by hand. **unsupported** =
needs SIWS/`signMessage` verified against the wallet address, real third-party co-signers/partial
sigs, durable nonces, or the wallet key as a non-fee-payer top-level signer. **provisional**
(appended to OK/root-only/unsupported) = the verdict is our best read of the evidence but at
least one required cell could not be directly confirmed (site blocked automated access, or only
indirect/bundle evidence available) — excluded from the firm tally below, listed separately.

Ephemeral, dApp-generated `Keypair`s that are `partialSign`'d locally before the wallet's own
signature (e.g. a fresh mint/position-NFT/token-account keypair) are **not** treated as
co-signers — they're independent of the wallet's own signature and do not require verification
against the smart-account address.

---

## Table

| # | dApp | Connect needs SIWS/signMessage? | Extra signers / partial sigs? | Durable nonces? | Programs + instructions (common flows) | Wallet = top-level signer beyond fee payer? | Verdict |
|---|------|----------------------------------|-------------------------------|------------------|------------------------------------------|----------------------------------------------|---------|
| 1 | **Jupiter** (swap aggregator) | No — not found in swap API client [1a] | No — Swap API returns one `VersionedTransaction`, wallet is sole signer per API contract; a `payer` field can *optionally* name a different fee payer, in which case the wallet is a non-fee-payer signer [1b] | No — not found | Jupiter Aggregator v6 `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` — `route`/`sharedAccountsRoute` (CPIs into the selected DEX programs) [1c] | No by default (fee payer); only if the caller opts into the `payer` override [1b] | **OK** |
| 2 | **Raydium** | No — not found in raydium-sdk-V2 | Yes, but ephemeral-only — `txTool.ts` `partialSignedTxs` pattern signs local `allSigners[idx]` keypairs (ATA/setup accounts) before `signAllTransactions` [2a] | No — not found | AMM V4 `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`; CLMM `CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK`; CPMM `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C` [2b] | No — `swapBaseIn` instruction meta array has exactly one `isSigner:true` entry, `userKeys.owner` [2c] | **OK** |
| 3 | **Orca** (Whirlpools) | No — not found in whirlpools repo | Yes, ephemeral — `open_position` mints a position-NFT via a fresh local `Keypair`, `partialSign`'d in `transactions-processor.ts` [3a] | No — not found | Whirlpool program `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` — `swap`/`swap_v2`, `open_position`, `increase_liquidity`, `decrease_liquidity` [3b] | No — `Swap` Accounts struct has exactly one `Signer<'info>` field, `token_authority`; every other account is `Account`/`Program`/`UncheckedAccount` [3c] | **OK** |
| 4 | **Meteora** (DLMM) | No — not found in dlmm-sdk | Yes, ephemeral — `initializeMultiplePositionAndAddLiquidityByStrategy2` takes a `positionKeypairGenerator`; doc-comment on the single-position variants states the position account "usually use `new Keypair()`" [4a] | No — not found | DLMM program `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` — `swap`/`swap2`, `add_liquidity*`, `remove_liquidity*`, `initialize_position*` [4b] | No — `swap` instruction's IDL account list has exactly one `isSigner:true` entry, `user` [4c] | **OK** |
| 5 | **Kamino** (klend) | No — not found in klend-sdk | Not found required (obligation accounts are PDAs, not keypairs) | No — not found | klend program `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` [5a] — `depositReserveLiquidityAndObligationCollateralV2`, `withdrawObligationCollateralAndRedeemReserveCollateralV2`, `borrowObligationLiquidityV2`, `repayObligationLiquidityV2` [5b] | No — `depositReserveLiquidityAndObligationCollateralV2`'s `depositAccounts` group has exactly one `isSigner:true` entry, `owner`, across 13 accounts [5c] | **OK** |
| 6 | **Marinade** | No — not found in marinade-ts-sdk | No — `deposit` (SOL→mSOL) needs only the wallet; `depositStakeAccount` needs the stake account's withdraw-authority signature (commonly the wallet itself, not a 3rd party) | No — not found | `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD` [6a] — `deposit`, `depositStakeAccount`, `liquidUnstake` | No — `deposit`'s IDL account list has exactly one `isSigner`/signer entry, `transferFrom` (the wallet's own SOL source) [6b] | **OK** |
| 7 | **Jito** (JitoSOL staking) | **UNVERIFIED, site blocked.** `jito.network/staking/` returned HTTP 403 "Just a moment..." (Cloudflare challenge) to Playwright on 2026-08-18 — same result as the `jito-labs/jito-ts` searcher/bundle-client repo we cloned, which has no wallet-connect UI code to inspect either | Not found required — standard SPL Stake Pool `DepositSol` does not need extra signers per the public interface, but we did not clone `spl-stake-pool` source this round, so the exact account-meta signer list is UNVERIFIED | No — not found (no source inspected for this claim beyond general SPL Stake Pool knowledge) | SPL Stake Pool program `SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy`, pool `Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb` — `DepositSol`/`DepositStake`/`WithdrawStake` [7a] | UNVERIFIED (no account metas cited) | **OK (provisional — UI SIWS unverified, site blocked)** |
| 8 | **Drift** | No at connect (not found in `wallet.ts`/`driftClient.ts` for the standard adapter path). **Caveat, separate subflow, not a login gate:** the opt-in "Swift" low-latency order flow signs the order message with `nacl.sign.detached` against the wallet key and is verified off-chain by Drift's matching engine [8a] | Not found required for core `deposit`/`placePerpOrder` | No — not found | Program `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` [8b] — `deposit`, `withdraw`, `place_perp_order`, `place_orders` | No — `Deposit` Accounts struct has exactly one `Signer<'info>` field, `authority` [8c] | **OK** for on-chain deposit/trade; the "Swift" signed-order subflow specifically is **unsupported** (see signed-message-subflow list below, not the SIWS list) |
| 9 | **Tensor** | No — not found in `tensorswap-sdk` or `tensor-foundation/marketplace` | No user-side co-signer found. Legacy TensorSwap AMM pools use a protocol-owned `TSWAP_COSIGNER` (`6WQvG9Z6D1NZM76Ljz3WjgR7gGXRBJohHASdQxXyKi8q`) added server-side by Tensor itself, not a second required signature from the user [9a] | No — not found | Current marketplace `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` — `buy`, `list`, `delist`, `bid` [9b]; legacy AMM `TSWAPaqyCSx2KABk68Shruf4rp7CxcNi8hAsbdwmHbN` [9c] | No — `buy`'s IDL account list has exactly one `isSigner:true` entry, `payer` [9d] | **root-only** (niche marketplace program, otherwise clean signer shape) |
| 10 | **Magic Eden** | **Yes — directly observed 2026-08-18.** `magiceden.io`'s header shows a "Log In" button (`data-test-id="wallet-connect-button"` — Magic Eden's own code treats "log in" and "connect wallet" as the same action); clicking it opens a modal with an "Enter your email" textbox, an "OR" divider, and a "Continue with a wallet" button; clicking that opens a 158-wallet picker (Phantom/Solflare/Backpack/Coinbase/etc. — far more than a plain `@solana/wallet-adapter` list, consistent with the Dynamic.xyz-branded multi-wallet connector). Magic Eden's own `dynamic-742d17e752be8498.js` production chunk bundles Dynamic's `signPersonalMessage`/`signMessage` wallet-auth code [10a]. We did not complete the flow past wallet selection (no wallet extension installed, per task constraints), so the literal signMessage prompt itself was not captured — but the email-OR-wallet unified login UI plus the bundled Dynamic auth SDK is direct, dated evidence, not inference from docs alone | Not independently confirmed — closed-source frontend, no public on-chain SDK found for the current marketplace program | UNVERIFIED | Marketplace v2 `M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K` [10b] | UNVERIFIED | **unsupported** (firm — direct 2026-08-18 UI observation + bundled Dynamic auth SDK) |
| 11 | **Pump.fun** | Yes — Pump.fun uses Privy for wallet login; Privy's "Login with Wallet" implements SIWS [11a]; corroborated by `signMessage`/`signIn` strings in pump.fun's own production JS bundle [11b] | UNVERIFIED | UNVERIFIED | Bonding-curve program `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` — `create`, `buy`, `sell` [11c] | No — the published IDL's `buy` instruction has exactly one `isSigner:true` entry, `user` [11d] | **unsupported** (SIWS required to log in) |
| 12 | **Phoenix** | No — not found in phoenix-sdk (TS or Rust) | Not found required | No — not found | Program `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY` [12a] — `Swap`, `PlaceLimitOrder`, `CancelAllOrders`, `WithdrawFunds` | UNVERIFIED — Phoenix's account-meta construction doesn't use the `isSigner: true`/`Signer<'info>` literals we grepped for elsewhere; not independently re-derived this round | **OK** (top-signer cell UNVERIFIED; nothing found that would make it unsupported) |
| 13 | **Sanctum** | No — not found in `sanctum-lst-list` (rust/ts) | Not found required | No — not found | Sanctum Router `stkitrT1Uoy18Dk1fTrgPw8W6MVzoCfYoAFT4MLsmhq` [13a]; Infinity pool `5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx` (per Sanctum docs — direct WebFetch of learn.sanctum.so returned 403; cited via WebSearch's synopsis of that same URL, not independently re-fetched this round) [13b] — swap / addLiquidity / removeLiquidity | UNVERIFIED — Infinity pool program source not cloned | **root-only** |
| 14 | **marginfi** | No — not found in marginfi-v2 repo (program + tests, no frontend in this repo) | Not found required | No — not found | Program `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` [14a] — `lendingAccountDeposit`, `lendingAccountWithdraw`, `lendingAccountBorrow`, `lendingAccountRepay` | No — `LendingAccountDeposit` Accounts struct has exactly one `Signer<'info>` field, `authority` [14b] | **OK** |
| 15 | **Solend / Save** | **No — directly observed 2026-08-18.** `save.finance` (page title "Save \| Lend and borrow crypto on Solana") loads a "Connect wallet" button; clicking it opens a plain wallet picker listing only "Phantom" and "Solflare" — no email/social option, no Dynamic/Privy branding, consistent with a standard `@solana/wallet-adapter` connect (contrast row 10/11 above) [15a] | Not found required | No — not found | Program `So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo` — rebrand to Save confirmed to use the same program [15b] — Borsh enum `LendingInstruction`, `DepositReserveLiquidity` is variant **#4** (comment-numbered in source, corrected from an earlier miscount) [15c] | No — `DepositReserveLiquidity`'s doc comment lists exactly one `[signer]` account of 10, "User transfer authority ($authority)" at index 7 [15c] | **OK** (firm) |
| 16 | **Parcl** (v3, real-estate perps) | No — not found in `v3-sdk-ts` | Yes, ephemeral — `transactionBuilder.ts` `buildSigned(signers, ...)` calls `tx.partialSign(...signers)` for locally-generated signers before the wallet signs [16a] | No — not found | Program `3parcLrT7WnXAcyPfkCz49oofuuf2guUKkjuFkAhZW8Y` [16b] — `createMarginAccount`, `depositMargin`, `modifyPosition`, `withdrawMargin` | No — `depositMargin`'s instruction builder has exactly one `isSigner: true` key, `accounts.signer`, among 8 [16c] | **root-only** (small/niche perps program) |
| 17 | **Helium** | No — not found in helium-program-library | Yes, ephemeral — `spl-utils/transaction.ts` `partialSign(...signers)` for locally-created accounts [17a] | No — not found | Lazy Distributor `1azyuavdMyvsivtNxPoz6SucD18eDHeXzFCUPq5XU7w` [17b] — `distributeRewardsV0`/`distributeCompressionRewardsV0` (claim HNT rewards, the common consumer flow); Entity Manager `hemjuPXBpNvggtaUnN1MwT3wrdhttKEfosTcc2P9Pg8` [17c] (hotspot/entity admin flows, less common for an end user) | No, and notably not even required as a signer at all — `DistributeRewardsCommonV0`'s only `Signer<'info>` field is `payer`; the reward beneficiary (`owner`) is an `UncheckedAccount`, and the source carries its own `/// TODO: Should this be permissioned? Should the owner have to sign to receive rewards?` [17d] | **root-only** |
| 18 | **Realms** (governance-ui + Hub) | **Mixed.** Core governance app: No — `spl-governance` voting/proposal calls found no signMessage (the `@solana/spl-governance` instruction-builder package itself is an external dependency, not vendored in this repo, so its exact account list is UNVERIFIED this round). **Realms Hub** (forum/profile layer, same repo, separate sub-product): **Yes** — `verify-wallet/components/sign-in-with-solana.tsx` explicitly requests a server-issued claim, calls `signMessage(claimBlob)`, and posts the signature to mint a JWT — this is SIWS by name [18a] | Not found required for voting/proposal instructions | No — not found | `@solana/spl-governance` program `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` (well-known; referenced via `DEFAULT_GOVERNANCE_PROGRAM_ID` import, not hardcoded in this repo) [18b] — `castVote`, `createProposal`, `depositGoverningTokens` | UNVERIFIED — `@solana/spl-governance`'s account-meta list not independently verified this round (external package, not vendored) | **root-only** for voting/proposals; **unsupported** for the Realms Hub SIWS profile-verification flow (see SIWS-login list) |
| 19 | **Squads** (v4) | No — `Squads-Protocol/v4` repo (program + SDK + CLI, no web frontend) has no signMessage/SIWS code | No same-transaction co-signing found: `proposalApprove`/`vaultTransactionExecute` are each single-signer instructions (each member submits their own approval tx) — this is *not* the brief's "co-signers/partial signatures" case (that requires N parties signing one transaction); it is N separate single-signer transactions | No — not found | Program `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` [19a] — `multisigCreate`, `proposalApprove`, `vaultTransactionCreate`, `vaultTransactionExecute` | No — `proposalApprove`'s IDL account list has exactly one `isSigner:true` entry, `member`, among 3 [19b] | **root-only** |
| 20 | **Photon** (trading terminal — the one substitute for defunct Zeta) | **Provisional, indirect.** `photon-sol.tinyastro.io` returned HTTP 403 "Just a moment..." to `curl` and to Playwright on two separate paths (`/` and `/en/discover`) on 2026-08-18 — three total blocked attempts. Indirect evidence: third-party how-to guides describe connecting Phantom once, after which Photon *generates a separate internal trading wallet* whose exported private key is the one that actually trades — a "connect-to-link" pattern consistent with (but not proof of) a signature-based linking step [20a] | UNVERIFIED (site blocked) | UNVERIFIED | UNVERIFIED — closed-source aggregator UI; underlying trades route through whichever AMM the token trades on (Raydium/pump.fun/etc.), not a fixed Photon-owned program | UNVERIFIED — see next column, this is moot regardless | **unsupported (provisional — evidence indirect, site blocked on 3 attempts)** — even setting the SIWS question aside, the documented behavior is that trades are signed by a Photon-generated keypair, not the connecting wallet, which is incompatible with a smart-account/session-key wallet regardless of signer-shape |

---

## Citations

Format: `[n]` `path:line` `@ commit-sha` `(clone URL)`, or a direct external URL/date where no
repo was cloned.

- **[1a]** `src-jupiter/` (no matches for `signMessage`/`signIn`/`partialSign`/`nonce` in `src/`, `generated/`) @ `6dbd33abfaa1f495f28ad122b3c06edf4ce28360`, https://github.com/jup-ag/jupiter-quote-api-node
- **[1b]** `src-jupiter/swagger.yaml:258-267` @ `6dbd33abfaa1f495f28ad122b3c06edf4ce28360` — `userPublicKey` is `required`; `payer` is an optional override described as "Allow a custom payer to pay for the transaction fees and rent of token accounts"
- **[1c]** https://solscan.io/account/JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4
- **[2a]** `src-raydium/src/common/txTool/txTool.ts:392-400` @ `8db8556024780669b8220477466e00117fc1cd77`, https://github.com/raydium-io/raydium-sdk-V2
- **[2b]** `src-raydium/src/common/programId.ts:17,20,29` @ same sha
- **[2c]** `src-raydium/src/raydium/liquidity/instruction.ts:79` @ same sha — `accountMeta({ pubkey: userKeys.owner, isWritable: false, isSigner: true })`, the only `isSigner: true` entry in the `swapBaseIn` instruction's account list
- **[3a]** `src-orca/legacy-sdk/common/src/web3/transactions/transactions-processor.ts:160-172` @ `46dc1c26bc553423f1c7bad35ba5cf9d19f6b4e7`, https://github.com/orca-so/whirlpools
- **[3b]** `src-orca/programs/whirlpool/src/lib.rs:3` (declare_id), `:334` (swap), `:1155` (swap_v2), `:198` (open_position) @ same sha
- **[3c]** `src-orca/programs/whirlpool/src/instructions/swap.rs:13-17` @ same sha — `pub struct Swap<'info> { ... pub token_authority: Signer<'info>, ... }`, the only `Signer<'info>` field among ~9 accounts
- **[4a]** `src-meteora/ts-client/src/dlmm/index.ts:3304-3348` (multi-position `positionKeypairGenerator`), `:3669` (doc comment: "`positionPubKey`: ... usually use `new Keypair()`") @ `fb02e51ae677bbd18e76543f702dae40632426db`, https://github.com/MeteoraAg/dlmm-sdk
- **[4b]** `src-meteora/idls/dlmm.json` instructions list @ same sha
- **[4c]** `src-meteora/idls/dlmm.json`, `swap` instruction accounts array, entry `{"name":"user","isSigner":true,...}` — the only signer entry @ same sha; discriminator embedded in this same IDL as `[248,198,158,145,225,117,135,200]`, matching our hand-computed `sha256("global:swap")[0:8]`
- **[5a]** `src-kamino/src/@codegen/klend/programId.ts:4-5` @ `6b0c69108e652c238e84dc2a52f7631b250dc69c`, https://github.com/Kamino-Finance/klend-sdk
- **[5b]** `src-kamino/src/idl/klend.json` instructions list @ same sha
- **[5c]** `src-kamino/src/idl/klend.json`, `depositReserveLiquidityAndObligationCollateralV2.accounts[0]` (`depositAccounts`), only `"name":"owner","isSigner":true` among 13 entries @ same sha
- **[6a]** `src-marinade/src/config/marinade-config.ts:6-8` @ `6d5b6ed3edc4eac6a5f63113d69d666e6a08274a`, https://github.com/marinade-finance/marinade-ts-sdk
- **[6b]** `src-marinade/src/programs/idl/json/marinade_finance.json`, `deposit` instruction accounts, only `transferFrom` carries a signer flag @ same sha
- **[7a]** https://www.jito.network/docs/jitosol/jitosol-liquid-staking/security/deployed-programs/ (via search-engine synopsis 2026-08-18; direct WebFetch not attempted after search confirmed the answer); staking-app connect flow: Playwright navigate to `https://www.jito.network/staking/` on 2026-08-18 → HTTP 403 "Just a moment..." (Cloudflare)
- **[8a]** `src-drift/sdk/src/driftClient.ts:7854,7962-7966` (signMessage used only inside `signSignedMsgOrderParamsMessage`/"Swift" order flow) @ `13e8e9b8d614f3b62e3a65a8c372c819e6529aeb`, https://github.com/drift-labs/protocol-v2
- **[8b]** `src-drift/programs/drift/src/ids.rs:7` @ same sha — note: `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` is the well-known public Drift v2 program id (this crate's own `declare_id!` is commented out in this snapshot; cross-checked against public docs)
- **[8c]** `src-drift/programs/drift/src/instructions/user.rs:4682-4705` @ same sha — `pub struct Deposit<'info> { ... pub authority: Signer<'info>, ... }`, the only `Signer<'info>` field among 6 accounts
- **[9a]** `src-tensor/src/tensorswap/constants.ts:1-23` @ `260d7acda8ef4eb82716a5684bed2b73e7446396`, https://github.com/tensor-foundation/tensorswap-sdk
- **[9b]** `src-tensor-mkt/program/idl.json` instructions list @ `8be7f2c3d60c18871e0913b5f837408eeb69047d`, https://github.com/tensor-foundation/marketplace; program id per https://docs.tensor.foundation/protocols (WebSearch-corroborated; IDL's `address` field was empty in the cloned snapshot)
- **[9c]** `src-tensor/src/tensorswap/constants.ts:9-10` @ `260d7acda8ef4eb82716a5684bed2b73e7446396`
- **[9d]** `src-tensor-mkt/program/idl.json`, `buy` instruction accounts, only `payer` carries `isSigner:true` @ `8be7f2c3d60c18871e0913b5f837408eeb69047d`
- **[10a]** Direct observation: Playwright navigate to `https://magiceden.io/` on 2026-08-18 → header "Log In" button, `data-test-id="wallet-connect-button"` (visible in the click-generated Playwright code `page.locator('[data-test-id="wallet-connect-button"]').click()`) → modal with "Enter your email" textbox + "OR" + "Continue with a wallet" → 158-wallet picker (Phantom/WalletConnect/Solflare/Trust/Coinbase/Backpack/Brave, search box placeholder "Search through 158 wallets..."). Bundle: `dynamic-742d17e752be8498.js` (fetched from `https://next.cdn.magiceden.dev/_next/static/chunks/dynamic-742d17e752be8498.js`, referenced from `https://magiceden.io` on 2026-08-18 — not committed, scratch-only) contains `signMessage(e){...ui:signPersonalMessage...}` and `signInEnabled`/`emailSignIn`/`socialSignIn` fields; mechanism described at https://www.dynamic.xyz/docs/api-reference/sdk/sign-in-with-wallet
- **[10b]** https://solscan.io/account/M2mx93ekt1fmXSVkTrUL9xVFHkmME8HTUi5Cyc5aF7K
- **[11a]** https://privy.io/blog/token-creation-for-everyone-with-pump-fun ; https://docs.privy.io/guide/expo/authentication/siwe
- **[11b]** `pf_chunks/0.2r9n1d_ow9w.js`, `pf_chunks/01-vmtti.1liu.js` (downloaded from `https://pump.fun/_next/static/chunks/...`, referenced from `https://pump.fun` on 2026-08-18 — not committed, scratch-only)
- **[11c]** https://docs.solanatracker.io/guides/pumpfun-program (discriminators); computed `sha256("global:buy")[0:8]` independently matches the published `buy` discriminator `[102,6,61,18,1,218,235,234]`, cross-validating the sighash formula
- **[11d]** `https://allenhark.com/idl-library/pumpfun/pump.json` (fetched 2026-08-18, HTTP 200), `buy` instruction accounts, only `user` carries `isSigner:true`
- **[12a]** `src-phoenix/typescript/phoenix-sdk/src/index.ts:19,27` @ `d722fc16c33feadec99f7d7b01c3ac4e12e44e75`, https://github.com/Ellipsis-Labs/phoenix-sdk
- **[13a]** `src-sanctum/rust/sanctum-lst-list/tests/tests/sanctum_router.rs:21` @ `0360a1af31a6c6d99ce1947029d732e2cb2d6682`, https://github.com/igneous-labs/sanctum-lst-list
- **[13b]** https://learn.sanctum.so/docs/technical-documentation/infinity (WebFetch returned 403 both this round and last; cited via WebSearch's synopsis of that same URL)
- **[14a]** `src-marginfi/tests/specs/basic/03_addBank.spec.ts:340` @ `4bd57850e689447fdd7bd300c6e2a8553cd9c25f`, https://github.com/mrgnlabs/marginfi-v2; instruction names from `src-marginfi/programs/marginfi/src/lib.rs:352,362,374,386` @ same sha
- **[14b]** `src-marginfi/programs/marginfi/src/instructions/marginfi_account/deposit.rs:147-170` @ same sha — `pub struct LendingAccountDeposit<'info> { ... pub authority: Signer<'info>, ... }`, the only `Signer<'info>` field
- **[15a]** Direct observation: Playwright navigate to `https://save.finance/` on 2026-08-18 → page title "Save | Lend and borrow crypto on Solana" → "Connect wallet" button → wallet picker listing exactly "Phantom" and "Solflare" (`img "Phantom icon"`, `text: Phantom`, `img "Solflare icon"`, `text: Solflare`), no email field, no Dynamic/Privy branding
- **[15b]** https://docs.save.finance/ (rebrand notice) + program id cross-checked via WebSearch synopsis of https://solanacompass.com/projects/save
- **[15c]** `src-solend/token-lending/sdk/src/instruction.rs:96-124` @ `d04ce00bbf4356c4fd32b3be38eb9760b696bb3e`, https://github.com/solendprotocol/solana-program-library — comment-numbered `// 4` directly precedes `DepositReserveLiquidity`; accounts list documents exactly one `[signer]` entry, "7. `[signer]` User transfer authority ($authority)" of 10 total accounts (index 0-9)
- **[16a]** `src-parcl/src/transactionBuilder.ts:45-51` @ `d00f77dd33c14b2f696bc16aedbb1e5ea0efc0e2`, https://github.com/ParclFinance/v3-sdk-ts
- **[16b]** `src-parcl/src/constants/programIds.ts:1` @ same sha
- **[16c]** `src-parcl/src/instructionBuilder.ts:183-200` @ same sha — `depositMargin`'s `TransactionInstruction.keys` array, only `{ pubkey: translateAddress(accounts.signer), isSigner: true, ... }` among 8 entries
- **[17a]** `src-helium/packages/spl-utils/src/transaction.ts:170,246` @ `145947eedf2b1dc33d8289065d63538973278aee`, https://github.com/helium/helium-program-library
- **[17b]** `src-helium/programs/lazy-distributor/src/lib.rs:5,60,66` @ same sha
- **[17c]** `src-helium/programs/helium-entity-manager/src/lib.rs:5` @ same sha
- **[17d]** `src-helium/programs/lazy-distributor/src/instructions/distribute/common.rs:13-40` @ same sha — `pub struct DistributeRewardsCommonV0<'info> { #[account(mut)] pub payer: Signer<'info>, ... }` plus, at the `owner` field: `/// TODO: Should this be permissioned? Should the owner have to sign to receive rewards? /// CHECK: Just required for ATA`
- **[18a]** `src-realms/verify-wallet/components/sign-in-with-solana.tsx:78-95`; also `src-realms/hub/components/GlobalHeader/User/Connect.tsx:92` @ `531440354a44259e038dc105f0ae6f604cc229cb`, https://github.com/Mythic-Project/governance-ui
- **[18b]** `src-realms/pages/dao/[symbol]/proposal/components/instructions/WithdrawFromDAO.tsx:39` (imports `DEFAULT_GOVERNANCE_PROGRAM_ID` from `@solana/governance-program-library`) @ same sha; program id `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` is the well-known public spl-governance deployment; `src-realms/actions/castVote.ts:1-27` shows `withCastVote` imported from the external, non-vendored `@solana/spl-governance` package, hence the account-meta list is UNVERIFIED rather than cited
- **[19a]** `src-squads/sdk/multisig/idl/squads_multisig_program.json` `address` field @ `c34015c9bf497349767c9855aeff738c9d568451`, https://github.com/Squads-Protocol/v4
- **[19b]** same file, `proposalApprove` instruction accounts, only `{"name":"member","isMut":true,"isSigner":true}` among 3 entries @ same sha
- **[20a]** https://solanabox.tools/guides/photon-sol-how-to-start ; https://pies-organization.gitbook.io/photon-trading/photon-on-sol/mobile-traders-sign-up ; direct access attempts: `curl` to `https://photon-sol.tinyastro.io/` → 0 bytes; `mcp__playwright__browser_navigate` to `https://photon-sol.tinyastro.io/` → HTTP 403 "Just a moment..."; retried to `https://photon-sol.tinyastro.io/en/discover` on 2026-08-18 → HTTP 403 again (3 total blocked attempts across two rounds)

---

## Step 3: Summary

### Firm tally (one verdict per dApp, primary/most-common flow; excludes the 2 provisional rows)

| Verdict | Count | dApps |
|---|---|---|
| **OK** | 10 | Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Drift (core deposit/trade flow), Phoenix, marginfi, Solend/Save |
| **root-only** | 6 | Tensor, Sanctum, Parcl, Helium, Realms (voting/proposals), Squads |
| **unsupported** | 2 | Magic Eden, Pump.fun |

**18 dApps, firm.** Two dApps (Drift, Realms) additionally carry a caveated secondary
verdict for a *different, non-primary* sub-flow within the same dApp — Drift's opt-in "Swift"
signed-order flow, and Realms Hub's separate SIWS-gated profile layer — both **unsupported**,
listed under "signed-message subflow" / "SIWS-login" below rather than folded into the primary
tally, since they are not what a user hits by default.

### Provisional (excluded from the firm tally above — evidence blocked or indirect)

| dApp | Verdict | Why provisional |
|---|---|---|
| Jito | OK (provisional) | `jito.network/staking/` blocked automated access (Cloudflare 403); no SDK with connect-flow code was available to substitute |
| Photon | unsupported (provisional) | `photon-sol.tinyastro.io` blocked automated access on 3 attempts; verdict rests on third-party how-to-guide description of the product's architecture, not direct inspection |

**20 dApps total = 18 firm + 2 provisional.**

### SIWS-login list — connect/login itself is gated behind a wallet signature

Ordered by confidence:

1. **Pump.fun** — Privy-based "Login with Wallet" implements SIWS; confirmed via Privy's own
   docs plus signMessage/signIn strings in pump.fun's production bundle. High confidence, firm.
2. **Magic Eden** — directly observed 2026-08-18: unified email-or-wallet login modal backed by
   Dynamic.xyz's wallet-auth SDK. High confidence, firm.
3. **Realms Hub** (a separate sub-product from the core governance-ui voting app, which is
   unaffected) — explicit `sign-in-with-solana.tsx` component, read directly from source. High
   confidence, firm.
4. **Photon** — provisional/indirect; listed here on the strength of third-party descriptions
   of a "connect Phantom once, then trade from a separately generated wallet" pattern, not a
   directly observed signMessage call.

### Signed-message subflow list — not a login gate, but a specific opt-in feature signs a message verified against the wallet address

1. **Drift "Swift" orders** — the core dApp's connect/deposit/trade flow is OK; only the
   opt-in low-latency order-signing feature would need the smart-account's session key to
   produce a signature verifiable against the PDA address, which the PDA cannot do (no private
   key). This is why Drift is not in the SIWS-login list above — it's not a login requirement.

None of the remaining dApps showed any signMessage/signIn/SIWS code path in their public SDKs
or (where closed-source) production bundles/direct UI observation.

### `(program_id, discriminator)` seed list for the Phase-2 adapter registry

Anchor-IDL programs (8-byte sighash discriminators, `sha256("global:<name>")[0:8]`, taken from
the IDL where embedded, else computed — computed values below were cross-validated where an
independent IDL-embedded value existed, see [4c]/[11c]):

| Program | program_id | instruction | discriminator (decimal bytes) | source |
|---|---|---|---|---|
| Jupiter Aggregator v6 | `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4` | `route`/`sharedAccountsRoute` | UNVERIFIED — needs `jup-ag/jupiter-cpi` IDL, not cloned this spike | — |
| Raydium AMM V4 | `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8` | (non-Anchor, u8 tag enum) | not Anchor sighash — see program source | — |
| Orca Whirlpool | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | `swap` | `[248,198,158,145,225,117,135,200]` | computed, `sha256("global:swap")[0:8]`; matches Meteora DLMM's IDL-embedded value for the same instruction name (cross-validation) |
| Orca Whirlpool | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | `open_position` | `[135,128,47,77,15,152,240,49]` | computed |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | `swap` | `[248,198,158,145,225,117,135,200]` | **IDL-embedded** (`src-meteora/idls/dlmm.json`) — ground truth, matches the computed value above |
| Meteora DLMM | `LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo` | `add_liquidity` | `[181,157,89,67,143,182,52,72]` | computed |
| Kamino klend | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` | `depositReserveLiquidityAndObligationCollateralV2` | `[205,25,185,119,225,60,144,159]` | computed this round (previously UNVERIFIED) |
| Marinade Finance | `MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD` | `deposit` | `[242,35,198,137,82,225,242,182]` | computed |
| Drift v2 | `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH` | `deposit` | `[242,35,198,137,82,225,242,182]` | computed — identical bytes to Marinade's `deposit` above, expected: Anchor discriminators hash the instruction *name*, not the program id, so any two programs both naming an instruction `deposit` collide |
| marginfi v2 | `MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA` | `lendingAccountDeposit` | `[107,148,98,153,1,126,178,57]` | computed this round (previously UNVERIFIED) |
| Squads v4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | `proposalApprove` | `[10,150,208,252,210,251,79,48]` | computed this round |
| Squads v4 | `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | `vaultTransactionExecute` | `[1,21,36,10,18,71,197,8]` | computed this round |
| Tensor Marketplace | `TCMPhJdwDryooaGtiocG1u3xcYbRpiJzb283XfCZsDp` | `buy` | `[102,6,61,18,1,218,235,234]` | computed this round — identical bytes to Pump.fun's published `buy` discriminator below (same-name collision, expected) |
| Parcl v3 | `3parcLrT7WnXAcyPfkCz49oofuuf2guUKkjuFkAhZW8Y` | `depositMargin` | `[8,65,55,223,247,167,33,10]` | computed this round |
| Helium Lazy Distributor | `1azyuavdMyvsivtNxPoz6SucD18eDHeXzFCUPq5XU7w` | `distributeRewardsV0` | `[132,146,235,96,72,213,8,221]` | computed this round |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `buy` | `[102,6,61,18,1,218,235,234]` | **published** (docs.solanatracker.io); matches our independently computed value (cross-validation) |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `sell` | `[51,230,133,164,1,127,131,173]` | published |
| Pump.fun bonding curve | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | `create` | `[24,30,200,40,5,28,7,119]` | published |
| Kamino klend | `KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD` | `borrowObligationLiquidityV2`/`repayObligationLiquidityV2` | UNVERIFIED | not computed this spike |
| SPL Stake Pool (JitoSOL) | `SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy` | `DepositSol` | UNVERIFIED — non-Anchor Borsh enum tag, program source not cloned | — |
| Phoenix | `PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY` | `Swap` | UNVERIFIED — non-Anchor custom binary layout | — |
| Solend/Save | `So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo` | `DepositReserveLiquidity` | non-Anchor, 1-byte Borsh enum variant, **tag `4`** (corrected this round — comment-numbered `// 4` directly precedes the variant in source, not the "2" estimated last round) | `src-solend/token-lending/sdk/src/instruction.rs:96-124` |
| spl-governance (Realms) | `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw` | `CastVote` | UNVERIFIED — non-Anchor custom Borsh enum, program source not cloned | — |
| Sanctum Infinity | `5ocnV1qiCgaQR8Jb8xWnVbApfaygJ8tNoZfgPwsgx9kx` | `swap` | UNVERIFIED — program source not cloned | — |

**Caveat, unchanged from round 0:** most rows above are still UNVERIFIED because pulling every
discriminator for every instruction across 20 programs' full IDLs was out of scope for this
spike's time budget. This round added computed values for 8 additional rows and validated the
computation method twice (Meteora `swap`, Pump.fun `buy`) against independent ground truth.
**Phase 2 should still re-derive discriminators programmatically from each program's IDL**
rather than trust hand-computed values in this table.

---

## Caveats / things a future pass should tighten

1. The top-20 *ranking order* is still not backed by a live, reproducible wallet-count export —
   DappRadar blocked automated fetch on both attempts (2026-08-18) and DefiLlama's fetchable
   public API is TVL/volume, not wallet counts (it corroborates *membership* for 9/20 entries,
   not *rank order* for any of them). If Task 9 or Phase 2 need a defensible ranking (not just a
   defensible list), someone with DappRadar/Artemis API-key access should re-pull it.
2. Several "not found" signMessage/nonce/partialSign results are grep-based over a shallow
   (`--depth 1`) clone of a *library* repo, not the full production frontend — a dApp's actual
   web app (often a separate closed-source repo) could still add a signMessage step that the
   published SDK doesn't require. Two of these (Solend/Save, Magic Eden) were upgraded to direct
   UI observation this round; the remaining OK/root-only rows with only an SDK citation (no UI
   observation) should be read as "the on-chain SDK doesn't require it," not "the live site
   definitely doesn't ask for it": Jupiter, Raydium, Orca, Meteora, Kamino, Marinade, Tensor,
   Sanctum, marginfi, Parcl, Helium, Squads, Phoenix.
3. Discriminator extraction remains intentionally partial (see caveat above).
4. Jito had no frontend code in the repo cloned (`jito-labs/jito-ts` is the searcher/bundle
   client, not the staking UI) and its actual staking site is Cloudflare-blocked — its
   "Connect needs SIWS" cell is UNVERIFIED/provisional rather than a confirmed "No."
5. `@solana/spl-governance`'s (Realms core voting) and SPL Stake Pool's (Jito) exact
   account-meta signer lists were not independently verified this round because neither
   program's own source was cloned (governance-ui only imports the former as an external
   package; we cloned the Jito bundle/searcher client, not `spl-stake-pool`) — flagged
   UNVERIFIED in the table rather than asserted.
