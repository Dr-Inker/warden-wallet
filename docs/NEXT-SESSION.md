# Next Session — Claude Security, Vanity, and UI Handoff

TO / Claude Code

TASK / Read the dated research memo, resume Phase 1B in its documented order, execute the client-security plan at its permitted boundaries, carry the approved optional vanity-primary-account feature through V0 and then V1–V6 only after its SDK/extension dependencies are stable, and execute UI U0–U10 only at the design/client/mobile boundaries stated in its plan.

CWD / `/opt/warden`

BASE / Start from the committed `phase1b` HEAD containing this handoff. Before editing, run `git rev-parse HEAD` and verify `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a` is an ancestor; record the actual starting SHA because this handoff cannot self-reference its own commit.

READ / `docs/OVERNIGHT-HANDOFF-2026-08-19.md` first; `CLAUDE.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/plans/2026-08-19-warden-vanity-primary-account.md`; `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md`; `docs/design/figma.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/security/invariants.jsonl`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease) / Only the files assigned by the next unfinished Phase 1B task. At a clean boundary, client C0 and vanity V0 may edit their named spec/security ledgers, generated invariant Markdown, and ledger-presence tests. UI U0–U2 may edit Figma and `docs/design/figma.md` only under an explicit design lease; those frames do not authorize generated-token or extension-code edits. After Phase 1B Task 8 stabilizes the client SDK, use vanity V1–V3's leases for `packages/core/**`, new `packages/vanity-pda/**`, tests, and build/security ledgers. Client C1 must establish the production extension trust boundary before UI U7 or vanity V4–V6 edits `apps/extension/**`. Native mobile remains research/prototype-only until the owner authorizes implementation and framework selection. One active edit lease and one heavy build at a time. Do not spawn subagents unless the owner explicitly grants a number.

DO_NOT_TOUCH / `/var/www/**`; live deployments or accounts; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; production `programs/warden/**` outside the active Phase 1B lease. The existing `/opt/vanity-bot/**` is read-only evidence only: never import its source, protocol, WASM, or generated assets. Never import production code from `spikes/**`.

ACCEPT / Preserve the Phase 1B order; seed client and vanity invariants before implementation; bind approvals and rendered intent to exact serialized bytes; keep simulation advisory; make authentication gate key release; derive vanity addresses only by grinding a public 32-byte salt for the root-bound Warden PDA; enforce 1–4 ASCII Base58 characters at every layer; default to suffix and case-insensitive matching with an exact-capitalization warning; independently re-derive worker results; perform confirmed account readback before copy/fund/receive; never treat a partial-address match as recipient verification; use exact-address provenance, full-address comparison, fresh authentication, and policy/timelock for poisoning controls; keep origin/decode/simulation/policy as independent UI axes; correct meaningful light warning indicators to at least 3:1; assign work across popup/side-panel/approval-window/full-tab surfaces; treat native mobile credential/link/privacy parity as UNVERIFIED pending real-device spikes; run the full merged-SHA gates; report every green gate with its exact command and SHA.

SIDE_EFFECTS / Repository documentation/code/test edits, Figma edits made under an explicit design lease, generated invariant/token Markdown or CSS produced by their source-controlled generators, and local build/benchmark/browser/accessibility artifacts only. No deploy, live-account mutation, credential creation/rotation, private-key generation/export, remote vanity acceleration, analytics change, store publication, external message, or secret handling without separate authorization.

RETURN / Merged SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; Figma page/node ids and native-size capture paths; contrast/target/overflow measurements; state-matrix coverage; worker/CSP/storage/permission/network changes; benchmark, browser, accessibility, mobile-device, and comprehension artifacts; remaining UNVERIFIED items; owner decisions; confirmation of no unauthorized external side effects.

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
   threat-model requirements with honest `unimplemented` status. UI U0–U2 may
   correct semantics and expand the Figma system under an explicit design lease.
3. Do not implement client C1–C5 or vanity V1–V6 against provisional SDK
   interfaces. Vanity V4 additionally waits for client C1's production extension
   trust boundary.
4. Client C1's trust boundary precedes UI U7 and vanity V4. Client release work,
   generated UI tokens, and vanity reproducible worker/build work must converge
   on one shipped-artifact and CSP review; no plan may weaken another.
5. Keep native mobile at prototype/research scope until the owner authorizes an
   implementation framework and real-device spikes close credential, verified-
   link, MWA, and capture/privacy uncertainties.

## Plans to carry forward

- [`2026-08-19-warden-client-security-hardening.md`](superpowers/plans/2026-08-19-warden-client-security-hardening.md)
- [`2026-08-19-warden-vanity-primary-account.md`](superpowers/plans/2026-08-19-warden-vanity-primary-account.md)
- [`2026-08-19-wallet-ui-extension-mobile.md`](research/2026-08-19-wallet-ui-extension-mobile.md)
- [`2026-08-19-warden-s-tier-ui-mobile.md`](superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md)

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

The UI research and U0–U10 plan define “S-tier” as measurable comprehension,
state coverage, accessibility, privacy, responsive behavior, token parity, and
real-device evidence—not visual polish alone. Warden Receipt is the flagship
surface, and the popup is only one part of the extension architecture.

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
