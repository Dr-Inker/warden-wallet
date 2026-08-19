# Next Session — Claude Security Handoff

TO: Claude Code

TASK: Resume Phase 1B in its documented order, then execute the client-security and release-assurance plan derived from the pinned wallet source/audit comparison.

CWD: `/opt/warden`

BASE: `c65d16851479eed93ec745fa27889a67dbbc77f9` (`phase1b`; verify this is still an ancestor before acting)

READ: `CLAUDE.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/security/invariants.jsonl`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease): First, only the files assigned by the next unfinished Phase 1B task. At a clean task boundary, C0 may edit `docs/security/invariants.jsonl`, generated `docs/security/INVARIANTS.md`, `docs/security/THREATMODEL.md`, and its ledger-presence tests. After Phase 1B Task 8 stabilizes client ABIs, follow the new plan’s per-task leases for `apps/extension/**`, `packages/core/**`, client tests, CI/release scripts, and security ledgers.

DO_NOT_TOUCH: `/var/www/**`; live deployments; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; `programs/warden/**` outside the active Phase 1B task lease. Never import production code from `spikes/**`.

ACCEPT: Preserve the Phase 1B order; seed client/release invariants before implementation; bind approvals and intent to exact serialized bytes; make authentication gate key release; keep simulation advisory; add deterministic dual-build and published-payload comparison gates; obtain adversarial review per task; run the full merged-SHA gate before any milestone claim; report every green gate with exact command and SHA.

SIDE_EFFECTS: Repository edits, tests, generated invariant Markdown, and local build artifacts only. No deploy, live-account mutation, store publication, credential creation/rotation, external message, or secret handling without separate authorization.

RETURN: Merged SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; captured browser/release artifacts; remaining UNVERIFIED items; owner decisions needed; confirmation of no unauthorized external side effects.

## Where to resume

At the handoff base, Phase 1B has landed the L0 harness gate, slot freshness,
conservation, proof-of-possession at account creation, the original invariant
ledger, and repo supply-chain gates. Registry, test programs, staging, `execute`,
`swap`, the TS payload builder, and close-out remain. Confirm the current branch
and plan state rather than assuming the base is still HEAD.

The new client plan is:

- [`2026-08-19-warden-client-security-hardening.md`](superpowers/plans/2026-08-19-warden-client-security-hardening.md)

Its first action, C0, fixes the largest process hole found in this review: the
current ledger has no addressable production-client invariants for key lifecycle,
browser message provenance, approval single-use semantics, exact-bytes intent,
simulator binding, recovery export, or Chrome Web Store release authority.

## Research conclusion to carry forward

Borrow the strong patterns: Brave’s process boundary and origin binding, Rabby’s
background-owned context and suspension-safe autolock, Ledger’s exact-message
parser/fuzz corpus and report binding, Safe’s coverage of alternate execution
lanes, and Sparrow/Electrum’s artifact-derived transaction review.

Do not copy the weak patterns: cached plaintext/UI-only re-auth in Backpack,
UI-only secret gating in Helium, password-portable vaults from the Rabby audit,
or legacy weak backup KDFs in BlueWallet/Electrum. Phantom’s current client
internals remain UNVERIFIED because its full source was not available.

No gate was run for this documentation-only handoff. Do not infer a green build
from the existence of the plan.
