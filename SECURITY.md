# Security

Warden is **pre-alpha and unaudited**. Nothing here is deployed with real funds, and you should not deploy it with real funds either. There is no bug bounty yet; one is planned before any mainnet use (spec §10/§11).

If you find a vulnerability, please **do not open a public issue**. Email security@drinkerlabs.info with a description and, if you can, a reproducing test (the LiteSVM harness in `programs/warden/tests` is the preferred vehicle). We will acknowledge within 7 days.

Reports are in scope for the on-chain program in `programs/warden`, the TypeScript SDK and keyring in `packages/core`, and the extension in `apps/extension` (origin/Port boundaries, encrypted storage, approval UI, signing prototypes and release tooling). Please distinguish an issue reachable in the shipped bundle from one in an internal test-only composition; both are useful reports. The `spikes/` directory is throwaway evidence and is out of scope.

Current extension capabilities and known unimplemented protections are recorded in `README.md`, `docs/security/invariants.jsonl` and `docs/NEXT-SESSION.md`. A decoded transaction is not a simulation result or a policy verdict. Production signing and provider delivery remain disabled.

Known, documented limitations are listed in `docs/spikes/DECISION.md` (open items) and `docs/program/PHASE1A-MEASUREMENTS.md` (design notes).

## Release integrity

Every tagged release records a reproducible-build recipe and a per-release
`.so` SHA-256 in [`docs/security/RELEASE-INTEGRITY.md`](docs/security/RELEASE-INTEGRITY.md),
with the stated limit next to it: a matching hash proves the deployed
artifact is the one that was reviewed, not that the artifact is safe. The
pre-deploy check that enforces this — upgrade authority, Squads multisig
governance (3-of-5 exact, 7-day time-lock floor, spec §5.5), and the
artifact hash — is specified in
[`docs/security/DEPLOY-GATE.md`](docs/security/DEPLOY-GATE.md) and
implemented (spec + dry-run) in `scripts/deploy-gate.sh`. Dependency
provenance (`cargo deny --locked check`, `pnpm audit`) runs in CI as a
failing gate, config in `deny.toml` and `scripts/supply-chain-gate.sh`;
license summary in `docs/security/THIRD_PARTY_NOTICES.md`.

**Version → release tag → recorded SHA, the mapping that makes "which
build is live" answerable in one lookup.** A **version** (e.g. `v1.2.0`,
semver) names a release in changelogs, the CWS listing, and user-facing
copy. It maps 1:1 to a **git tag** of the same name (`v1.2.0`) on the
release commit — the tag is what `git checkout <release-tag>` in
`docs/security/RELEASE-INTEGRITY.md`'s build recipe resolves. That tag
maps 1:1 to a **git SHA** (`git rev-parse v1.2.0`), which is the exact key
`docs/security/RELEASE-INTEGRITY.md`'s per-release table and
`scripts/deploy-gate.sh <release-sha>` both index by. No stage of this
chain is allowed to fork: one version has exactly one tag has exactly one
SHA has exactly one recorded `.so` hash. The CWS-listing-vs-tag-SHA alert
below is what catches the chain being violated in the one place this repo
cannot directly observe (what Google's servers are actually serving).

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
