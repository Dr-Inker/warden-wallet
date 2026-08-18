# Spike 1 — Squads Smart Account API check — research notes

Date: 2026-08-18. Branch: `phase0`. Working dir: `spikes/01-squads/`.

## Sources collected

1. **`Squads-Protocol/smart-account-program`** — cloned successfully (public repo, no auth needed).
   `git clone --depth 1 https://github.com/Squads-Protocol/smart-account-program src-smart-account`
   HEAD at clone time: `80bf1f7ad28fd1176c364879776982730b8e9c80` (2026-01-27), tagged README version `v0.1.0`.
   - IDL copied to `idl/squads_smart_account_program.json` (source: `src-smart-account/idl/squads_smart_account_program.json`).
   - Mainnet + devnet program id (from `src-smart-account/README.md:33-34`): `SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG`.
   - Two audits present in-repo: `audits/certora_smart_account_audit+FV.pdf`, `audits/ottersec_smart_account_audit.pdf`.

2. **`Squads-Protocol/v4`** (Multisig v4, the older/live product) — cloned successfully.
   `git clone --depth 1 https://github.com/Squads-Protocol/v4 src-v4`
   Mainnet program id (from `src-v4/Anchor.toml:10`, `src-v4/programs/squads_multisig_program/src/lib.rs:36`): `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` — matches the id given in the task brief.
   - IDL copied to `idl/squads_multisig_program.json`.
   - v4's IDL has 36 instructions but **no** policy/allowlist/sync-CPI instructions — it is a classic propose→approve→execute multisig with `spendingLimitUse` as its only "skip full consensus" path. It does not bear on criteria 4, 5, 6 the way the smart-account-program does, so the table below is built primarily from the smart-account-program.

3. **Web/docs** (WebSearch + WebFetch, both fetched 2026-08-18):
   - `squads.xyz/blog/squads-smart-account-program-live-on-mainnet` — mainnet-launch announcement. States passkeys/session keys/alternative signature schemes are **"coming soon"** (targeted Q2 2025) at time of that post, not part of the initial mainnet launch.
   - `blog.colosseum.com/rektoff-security-bootcamp-squads-passkeys-anchor-studio/` — describes secp256r1/WebAuthn passkey + session-key support built on the SIMD-48 secp256r1 precompile, but states it is **"currently live on Devnet, will be deployed to Mainnet"** for the Smart Account API and Grid — i.e. not confirmed shipped on the mainnet program used by this spike.
   - Both are consistent with the source grep below (zero secp256r1/webauthn/passkey occurrences in the current cloned mainnet source): passkey support is roadmap/devnet, not present in the mainnet program's Rust source as of the clone.

4. **On-chain check (mainnet-beta RPC, `api.mainnet-beta.solana.com`)** for criterion 10 (program upgrade authority):
   - `getAccountInfo("SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG")` → program account, `programData: "2g3u9qgz4adKQVN1TUoh7bbBKqaSsjXtz1yX2ptagW5T"`.
   - `getAccountInfo("2g3u9qgz4adKQVN1TUoh7bbBKqaSsjXtz1yX2ptagW5T")` → `parsed.info.authority = "HT3JknwuufXdtVJggz5Z9JcnYtanPpLzTCqLWsVX1Vu2"`.
   - `getAccountInfo("HT3JknwuufXdtVJggz5Z9JcnYtanPpLzTCqLWsVX1Vu2")` → `owner: "11111111111111111111111111111111"` (System Program), `space: 0`, `executable: false`. This is consistent with either a plain Ed25519 keypair **or** an un-initialized Squads vault PDA (Squads SOL vaults are themselves System-Program-owned accounts) — could not disambiguate the two within the spike's time budget (would need to brute-force/derive candidate PDA seeds against known Squads multisig accounts, or use an indexer that labels the address, which was not accessible — `solscan.io` returned HTTP 403 to the fetch tool). Traced one historical `setAuthority` transaction on this program (`2Ks15Fac...`) showing the *previous* authority was `sqdcVVoTcKZjXU8yPUwKFbGx1Hig1rhbWJQtMRXp2E1` (a vanity "sqd"-prefixed address, itself unverified as multisig or keypair).
   - Conclusion: **unverified either way** — no repo/doc evidence found asserting this specific program's upgrade authority is a timelocked multisig, and the on-chain owner check does not prove it. Treated conservatively as NO for the verdict tally (see `result.md`).

## Method

- All 11 criteria rows were answered primarily from the `smart-account-program` Rust source (`programs/squads_smart_account_program/src/`) and its IDL, since it is the closer match to Warden's spec §5 shape (policy/allowlist/sync-execution concepts don't exist at all in v4).
- Used `grep -rn` for terms with no hits proving true absence (secp256r1, webauthn, passkey, guardian, recover, freeze, pause, falcon, hash-based, close_authority) — all returned zero matches in `programs/squads_smart_account_program/src/`.
- Read the following files in full or substantial part: `state/settings.rs`, `state/spending_limit.rs`, `state/policies/policy_core/policy.rs`, `state/policies/implementations/program_interaction.rs`, `state/policies/utils/spending_limit_v2.rs`, `state/policies/utils/account_tracking.rs`, `state/settings_transaction.rs`, `state/proposal.rs`, `instructions/use_spending_limit.rs`, `instructions/transaction_execute_sync.rs`, `instructions/transaction_execute.rs`, `instructions/settings_transaction_execute.rs`, `utils/context_validation.rs`, `interface/consensus.rs`.

## Cloned repos

`src-smart-account/` and `src-v4/` are local clones (~hundreds of MB with `.git`), excluded from git via `spikes/01-squads/.gitignore` (`src-*/`). Only `idl/`, `notes.md`, `result.md` are committed.
