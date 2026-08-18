# Backpack Wallet (coral-xyz/backpack) — Technical Research Report

## Findings

**Repo/architecture.** Monorepo (Yarn workspaces + Turbo) with packages: `app-extension`, `background`, `secure-background`, `secure-ui`, `secure-clients`, `provider-core`, `provider-injection`, `wallet-standard`, `xnft-cli`, plus mobile (`expo-devtools`) and web targets — one codebase drives Chrome extension, iOS/Android, and web. [github.com/coral-xyz/backpack](https://github.com/coral-xyz/backpack)

**Extension shell is Manifest V3.** `manifest.json`: MV3 `service_worker` background (`type: module`), a content script (`contentScript.js`) injected `run_at: document_start` into `all_frames` on `<all_urls>`, and `injected.js` exposed via `web_accessible_resources` to `<all_urls>` — the standard "inject before page scripts run" pattern. [manifest.json](https://github.com/coral-xyz/backpack/blob/master/packages/app-extension/src/manifest.json)

**Provider injection.** `packages/provider-injection/src/index.ts` sets a non-writable `_backpack_injected_provider` marker, wires a `TransportSender` (content-script or React-Native-WebView transport for mobile), and constructs `ProviderEthereumInjection`, `ProviderSolanaInjection`, and `ProviderRootXnftInjection` from `@coral-xyz/provider-core`, plus Solana `wallet-standard` `initialize()` and EIP-6963 provider discovery types — i.e., it supports both EIP-6963 multi-provider discovery and the Solana Wallet Standard, not just legacy `window.ethereum`/`window.solana` clobbering. [provider-injection/src/index.ts](https://github.com/coral-xyz/backpack/blob/master/packages/provider-injection/src/index.ts)

**Keyring.** BIP39 mnemonic (`bip39` `mnemonicToSeedSync`) with per-chain HD keyring factories — `SolanaHdKeyringFactory`, `EthereumHdKeyringFactory` — and separate `*LedgerKeyringFactory` classes, unified behind one `BlockchainKeyring` abstraction (`keyring/index.ts`, `keyring/BlockchainKeyring.ts`, `keyring/ledger.ts`). Public keys are tagged `type: "derived" | "imported" | "hardware"` and carry an `isCold: boolean` flag. [keyring/index.ts](https://github.com/coral-xyz/backpack/blob/master/packages/secure-background/src/keyring/index.ts)

**Encryption at rest.** `secure-background/src/store/KeyringStore/crypto.ts`: password → PBKDF2-HMAC-SHA256 (600,000 iterations on extension, 100,000 on mobile — cached in memory on mobile only) → NaCl `secretbox` (XSalsa20-Poly1305, via `tweetnacl`) encrypts the full keyring JSON blob; `SecretPayload` stores `ciphertext/nonce/salt/kdf/iterations/digest`. This is a conventional, sound local-vault design — no HSM/enclave binding, no on-chain component. [crypto.ts](https://github.com/coral-xyz/backpack/blob/master/packages/secure-background/src/store/KeyringStore/crypto.ts)

**Simulation/approval.** Both `SvmSignTransactionRequest` and `EvmSignTransactionRequest` (in `secure-ui/src/RequestHandlers/`) call dedicated hooks `useFetchSolanaBlowfishEvaluation.ts` / `useFetchEthereumBlowfishEvaluation.ts` that POST the unsigned tx(s) + `userAccount` + dApp `origin` to a Blowfish evaluation API (10s abort timeout, 5s poll refresh), then normalize the response into `warnings`, `errors`, and `expectedStateChanges` (per-address, human-readable diffs with colored balances and NFT image/name enrichment) rendered before the user signs. This confirms third-party (Blowfish) simulation/risk-scoring is Backpack's approval-safety layer for both EVM and SVM. [useFetchSolanaBlowfishEvaluation.ts](https://github.com/coral-xyz/backpack/blob/master/packages/secure-ui/src/RequestHandlers/SvmSignTransactionRequest/useFetchSolanaBlowfishEvaluation.ts)

**"Cold wallet" warning.** `SvmSignTransactionRequest.tsx` blocks signing with an explicit `IsColdWalletWarning` screen when the signing key is flagged `isCold` and the request originates from `"xnft"`/`"browser"` context on non-mobile — the user must actively click through ("ignore") before the normal approval UI appears. [SvmSignTransactionRequest.tsx](https://github.com/coral-xyz/backpack/blob/master/packages/secure-ui/src/RequestHandlers/SvmSignTransactionRequest/SvmSignTransactionRequest.tsx)

**Hardware wallets.** `LedgerKeyringBase` classes exist per chain (`services/ledger`, `secure-ui/.../LedgerRequests`) confirmed in code; product docs also claim Trezor and Keystone support, but no Trezor/Keystone source paths were located in this pass — UNVERIFIED at the code level. [ledger.ts](https://github.com/coral-xyz/backpack/blob/master/packages/secure-background/src/keyring/ledger.ts)

**Re-auth for export.** Exporting the mnemonic (`GetMnemonicRequest.tsx`) requires a fresh password submitted to `userClient.checkPassword()` even if the wallet is already unlocked — a separate high-risk-action gate distinct from session unlock state.

**xNFT sandboxing.** xNFTs run without direct DOM access; `react-xnft` mediates all host communication; the platform documentation describes an explicit, per-app (not per-site) permission model, reducing UI-spoofing phishing risk versus arbitrary websites. [docs.xnfts.dev](https://docs.xnfts.dev)

**Migration in progress.** `background/src/backend/core.ts` is explicitly marked `// DO NOT ADD ANYTHING NEW TO THIS FILE` — legacy background logic is being replaced by the newer `secure-background`/`secure-ui`/`secure-clients` stack; both paths coexist in the current snapshot.

**License.** Repo is currently GPL-3.0 (GitHub API `license.key: "gpl-3.0"`; `LICENSE` is stock FSF GPLv3 text). This was **not** always true: in [issue #2079](https://github.com/coral-xyz/backpack/issues/2079) (Jan 2023) maintainer armaniferrante stated Backpack was deliberately "source available," restricted to non-commercial use, not open source, pending the company proving it could survive as a business — a real relicense to plain GPL-3.0 happened later (exact commit not isolated in this pass).

**Audits/bug bounty.** Hacken lists Backpack audit engagements ([hacken.io/audits/backpack](https://hacken.io/audits/backpack/) — page returned HTTP 403 to automated fetch, scope UNVERIFIED). A public bug bounty runs via HackenProof covering business-logic fund-loss bugs, RCE, data leakage, and OWASP-class web vulns, paid in USDC.

**Incidents.** No primary-source postmortem of a Backpack wallet-extension fund-loss hack was found (absence of evidence, not proof of absence). A July 2026 KU Leuven study of 85 wallet extensions found cross-site tracking/address-linking/broken-disconnect classes of privacy bugs industry-wide; Backpack (like MetaMask, Rabby, OKX) called the cross-site-tracking finding "low-risk or out of scope" and did not fix it. [thehackernews.com/2026/07](https://thehackernews.com/2026/07/study-of-85-crypto-wallet-extensions.html)

**Worth reading for Warden:** `packages/secure-background/src/store/KeyringStore/crypto.ts` (vault crypto), `packages/secure-background/src/keyring/*` (multi-chain keyring abstraction), `packages/secure-ui/src/RequestHandlers/*` (approval UX patterns incl. Blowfish integration and cold-key warning), `packages/provider-injection/src/index.ts` + `packages/provider-core` (injection/EIP-6963/Wallet Standard), `packages/wallet-standard`.

## What Warden should adopt / change

1. **Human-readable simulation UI**: pair Warden's on-chain before/after conservation checks with a Blowfish-style (or equivalent) client-side normalized diff — colorized balance/NFT changes, plain-language warnings — not just a raw instruction dump.
2. **Fresh re-auth gate for high-risk actions**: mirror Backpack's separate password re-check before mnemonic export — require a fresh passkey ceremony (not reliance on an existing session key) before guardian changes, timelock overrides, or any key-export-equivalent action.
3. **EIP-6963 support** if/when Warden adds EVM chains, to coexist cleanly with other installed wallets.
4. **Generalize the "cold/atypical signer" warning**: Backpack's `isCold` blocking screen is a good UX primitive; Warden could add an analogous warning when a session key is used outside its normal dApp/adapter pattern, even though Warden already enforces caps on-chain.
5. **Do not benchmark against Backpack's account model** — it is a conventional password-encrypted client-side HD keypair wallet (PBKDF2+secretbox), with zero on-chain enforcement. Warden's PDA-owned funds + on-chain secp256r1 passkey + bounded session keys is categorically stronger; nothing here should lower Warden's bar.
6. **Proactively test for the KU Leuven bug classes**: address-linking across requests, disconnect/revocation not actually revoking site access, and cross-frame address exposure. Actually fixing these (where Backpack/MetaMask/Rabby/OKX shrugged them off) is a differentiator.
7. **License hygiene**: state Warden's real license up front and keep it in sync with any "open source" claims — Backpack took public credibility damage from the 2023 source-available-vs-open-source mismatch.

## Open questions
- Exact scope/dates/findings of Hacken's Backpack audit(s) (page blocked, 403).
- Whether Trezor/Keystone are implemented in this OSS repo or only server-side/closed.
- Current split between legacy `background/backend` and the new `secure-*` stack in production.
- Any actual wallet-level (non-phishing) fund-loss incident — none found via search in this pass.
- Exact commit/date of the GPL-3.0 relicense from the 2023 "source available" state.

## Confidence
**Medium-high** on repo/code facts (keyring, crypto scheme, Blowfish integration, injection, license text) — read directly from `master` on 2026-08-18. **Medium** on audit/bounty/incident claims — secondary sources only, Hacken scope unverified. **Low-medium** on "no incident" — negative result, not confirmed absence.