# Security

Warden is **pre-alpha and unaudited**. Nothing here is deployed with real funds, and you should not deploy it with real funds either. There is no bug bounty yet; one is planned before any mainnet use (spec §10/§11).

If you find a vulnerability, please **do not open a public issue**. Email security@drinkerlabs.info with a description and, if you can, a reproducing test (the LiteSVM harness in `programs/warden/tests` is the preferred vehicle). We will acknowledge within 7 days.

What we consider in scope right now: the on-chain program in `programs/warden` (root verification, session bounds, bucket accounting, transfer conservation), and the TypeScript transcript mirror in `packages/core`. The `spikes/` directory is throwaway evidence and is out of scope.

Known, documented limitations are listed in `docs/spikes/DECISION.md` (open items) and `docs/program/PHASE1A-MEASUREMENTS.md` (design notes).
