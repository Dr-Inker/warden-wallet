# Security

Warden is **pre-alpha and unaudited**. Nothing here is deployed with real funds, and you should not deploy it with real funds either. There is no bug bounty yet; one is planned before any mainnet use (spec §10/§11).

If you find a vulnerability, please **do not open a public issue**. Email security@drinkerlabs.info with a description and, if you can, a reproducing test (the LiteSVM harness in `programs/warden/tests` is the preferred vehicle). We will acknowledge within 7 days.

What we consider in scope right now: the on-chain program in `programs/warden` (root verification, session bounds, bucket accounting, transfer conservation), and the TypeScript transcript mirror in `packages/core`. The `spikes/` directory is throwaway evidence and is out of scope.

Known, documented limitations are listed in `docs/spikes/DECISION.md` (open items) and `docs/program/PHASE1A-MEASUREMENTS.md` (design notes).

## Release integrity

Every tagged release records a reproducible-build recipe and a per-release
`.so` SHA-256 in [`docs/security/RELEASE-INTEGRITY.md`](docs/security/RELEASE-INTEGRITY.md),
with the stated limit next to it: a matching hash proves the deployed
artifact is the one that was reviewed, not that the artifact is safe. The
pre-deploy check that enforces this — upgrade authority, Squads multisig
threshold/time-lock, and the artifact hash — is specified in
[`docs/security/DEPLOY-GATE.md`](docs/security/DEPLOY-GATE.md) and
implemented (spec + dry-run) in `scripts/deploy-gate.sh`. Dependency
provenance (`cargo deny check`, `pnpm audit`) runs in CI as a failing gate,
config in `deny.toml` and `scripts/supply-chain-gate.sh`.

## Dependency compromise

The largest single loss in the wallet-drainer corpus to date is not a
phishing site — it's a compromised **library** shipped through a normal
update: [GHSA-jcxm-7wvp-g6p5](https://github.com/solana-labs/solana-web3.js/security/advisories/GHSA-jcxm-7wvp-g6p5)
(`@solana/web3.js` 1.95.6–1.95.7, Dec 2024, a stolen npm publish token) shipped
code that exfiltrated private keys from any dependent that pulled the
compromised patch versions. Trust Wallet separately lost $7–8.5M across
~2,500 wallets (Dec 2025) to a leaked Chrome Web Store publisher key — likely
harvested by the Shai-Hulud 2.0 npm worm, per the vendor's own wording —
shipping a malicious build that exfiltrated mnemonics. Both are supply-chain
compromises of the *release channel*, not the program logic, and neither is
caught by code review of this repo's own source. This is why L9 (dependency
provenance + reproducible builds + CWS credential separation, spec §17) runs
in parallel with feature work rather than waiting for a "supply-chain phase."

**CWS release-credential separation (policy now, mechanism at Phase 2 — the
extension itself ships in Phase 2).** The Chrome Web Store publisher token
that would push a release:

- lives on a separate, human-gated path, and is **never present in any CI
  environment reachable by `npm install`/`pnpm install`** (an install-time
  script in any transitive dependency must not be able to reach it);
- is rotated on a fixed schedule (target: every 90 days, or immediately on
  any suspected exposure);
- is checked against the published listing: an alert fires if the CWS
  listing's live version ever differs from the tagged release SHA recorded
  in `docs/security/RELEASE-INTEGRITY.md`.

This is documented ahead of the extension code it will gate — see spec §17's
framing: "the gate exists before the code it guards."
