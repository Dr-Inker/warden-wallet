# Next Session — Claude Security and Vanity Handoff

TO / Claude Code

TASK / Resume Phase 1B in its documented order; execute the client-security plan at its permitted boundaries; carry the approved optional vanity-primary-account feature through V0 and then V1–V6 only after their stated SDK/extension dependencies are stable.

CWD / `/opt/warden`

BASE / Start from the committed `phase1b` HEAD containing this handoff. Before editing, run `git rev-parse HEAD` and verify `d56feb62164f0efcad3d7c632d24853a15ad44a1` is an ancestor; record the actual starting SHA because this handoff cannot self-reference its own commit.

READ / `CLAUDE.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/plans/2026-08-19-warden-vanity-primary-account.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/security/invariants.jsonl`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease) / Only the files assigned by the next unfinished Phase 1B task. At a clean boundary, client C0 and vanity V0 may edit their named spec/security ledgers, generated invariant Markdown, and ledger-presence tests. After Phase 1B Task 8 stabilizes the client SDK, use vanity V1–V3's leases for `packages/core/**`, new `packages/vanity-pda/**`, tests, and build/security ledgers. Vanity V4–V6 additionally wait for client C1's production extension trust boundary before editing `apps/extension/**`. One active edit lease and one heavy build at a time. Do not spawn subagents unless the owner explicitly grants a number.

DO_NOT_TOUCH / `/var/www/**`; live deployments or accounts; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; production `programs/warden/**` outside the active Phase 1B lease. The existing `/opt/vanity-bot/**` is read-only evidence only: never import its source, protocol, WASM, or generated assets. Never import production code from `spikes/**`.

ACCEPT / Preserve the Phase 1B order; seed client and vanity invariants before implementation; bind approvals to exact serialized bytes; keep simulation advisory; make authentication gate key release; derive vanity addresses only by grinding a public 32-byte salt for the root-bound Warden PDA; enforce 1–4 ASCII Base58 characters at every layer; default to suffix and case-insensitive matching with an exact-capitalization warning; independently re-derive worker results; perform confirmed account readback before copy/fund/receive; ship poisoning/privacy controls; run the full merged-SHA gates; report every green gate with its exact command and SHA.

SIDE_EFFECTS / Repository documentation/code/test edits, generated invariant Markdown, and local build/benchmark/browser artifacts only. No deploy, live-account mutation, credential creation/rotation, private-key generation/export, remote vanity acceleration, analytics change, store publication, external message, or secret handling without separate authorization.

RETURN / Merged SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; worker/CSP/storage/permission changes; benchmark and browser artifacts; remaining UNVERIFIED items; owner decisions; confirmation of no unauthorized external side effects.

## Where to resume

At the implementation base, Phase 1B has landed the L0 harness gate, slot
freshness, conservation, proof-of-possession at account creation, the original
invariant ledger, and repo supply-chain gates. Registry, test programs, staging,
`execute`, `swap`, the TypeScript payload builder, and close-out remain. Confirm
the branch and plan state rather than assuming the historical base is still
HEAD.

Priority remains:

1. Continue the Phase 1B task order in `CLAUDE.md`.
2. At a clean boundary, client C0 and vanity V0 may seed their security rows and
   threat-model requirements with honest `unimplemented` status.
3. Do not implement client C1–C5 or vanity V1–V6 against provisional SDK
   interfaces. Vanity V4 additionally waits for client C1's production extension
   trust boundary.
4. Client release work and vanity reproducible worker/build work must converge
   on one shipped-artifact and CSP review; neither plan may weaken the other.

## Plans to carry forward

- [`2026-08-19-warden-client-security-hardening.md`](superpowers/plans/2026-08-19-warden-client-security-hardening.md)
- [`2026-08-19-warden-vanity-primary-account.md`](superpowers/plans/2026-08-19-warden-vanity-primary-account.md)

The client plan addresses the largest process holes found in the wallet-source
comparison: key lifecycle, browser message provenance, approval single-use
semantics, exact-bytes intent, simulator binding, recovery export, and release
authority.

The vanity plan records a **go** decision with a narrow design: an optional first
SmartAccount address, not a master private key. Warden already derives the PDA
from `Keccak256("WARDEN/seed/v1" || root_pubkey33 || salt32)`, so the feature
searches salts locally and preserves the passkey root. Four characters is a hard
cap. Suffix and case-insensitive matching are defaults; exact capitalization is
optional and explicitly warned as slower.

## Vanity corrections that must survive handoff

- Base58 excludes only `0`, `O`, `I`, and `l`. All other Base58 characters are
  admissible in 1–4 character prefix/suffix requests.
- Do not copy `/opt/vanity-bot`'s first-character whitelist or special `J` rule;
  it assumes a fixed 44-character encoding and rejects valid 43-character
  addresses. A session-local probe found a valid Warden PDA beginning with `W`.
- Do not copy its `33^n` case estimate or fixed "remaining" countdown. Prefix
  probabilities are character/length dependent and search completion is
  geometric; show calibrated 50%/95% probability windows.
- Do not reuse the bot's private-key-producing WASM or message shape. The Warden
  worker returns only salt/owner-seed/address/bump metadata and is independently
  verified through the supported core derivation.
- Freeze program id, cluster/config, account seed, and seed-domain version before
  any long search. A change to any of them changes the target address.
- Vanity is cosmetic, never identity. Full-address, saved-contact, and
  address-poisoning defenses ship with it.

No build or test gate was run merely because these proposal documents exist. Do
not infer an implemented feature or a green build from this handoff.
