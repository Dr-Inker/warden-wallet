# 2026-08-19 Research Memo — Claude Pickup

> **Purpose:** this is the single pickup index for the security, vanity-address,
> extension UI, and future mobile research completed on 2026-08-19. It links
> evidence and plans; it is not evidence that a proposed feature or gate exists.

TO / Claude Code

TASK / Resume Phase 1B in its documented order, then carry today's client-security, optional vanity-primary-account, and extension/mobile UI plans at their stated dependency boundaries. Apply the binding recipient-poisoning and warning-contrast corrections before implementing the current Figma approval states.

CWD / `/opt/warden`

BASE / Start from the committed `phase1b` HEAD containing this memo. Before editing, run `git rev-parse HEAD` and verify `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a` is an ancestor; record the actual starting SHA because this memo cannot self-reference its own commit.

READ / This memo first; `CLAUDE.md`; `docs/NEXT-SESSION.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/plans/2026-08-19-warden-vanity-primary-account.md`; `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md`; `docs/design/figma.md`; `docs/security/INVARIANTS.md`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease) / Only files assigned by the next unfinished Phase 1B task. At a clean boundary, client C0 and vanity V0 may edit their named spec/security ledgers, generated invariant Markdown, and ledger-presence tests. UI U0–U2 may edit Figma and its design ledger only under an explicit design lease; no generated token or extension implementation work yet. After Phase 1B Task 8 stabilizes client APIs, use the named plan leases for `packages/core/**`, `packages/vanity-pda/**`, and tests. Client C1 must establish the production extension trust boundary before UI U7 or vanity V4 edits `apps/extension/**`. One active edit lease and one heavy build at a time. Do not spawn subagents unless the owner explicitly grants a number.

DO_NOT_TOUCH / `/var/www/**`; live deployments or accounts; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; production `programs/warden/**` outside the active Phase 1B lease. Treat `/opt/vanity-bot/**` and `spikes/**` as read-only evidence; never import their source, protocol, WASM, binaries, generated assets, or private-key flow.

ACCEPT / Preserve the Phase 1B order; seed every security claim before implementation; bind approvals and rendered intent to exact serialized bytes; derive browser origin/tab/frame from browser-owned metadata; keep simulation and reputation advisory; make authentication gate key release; grind only a public salt for an optional 1–4-character Warden PDA; independently re-derive vanity results; never treat partial-address matching as recipient verification; use exact-address provenance and full-address comparison; maintain independent origin/decode/simulation/policy evidence axes; correct light-mode warning indicators to at least 3:1 non-text contrast; use popup/side-panel/approval-window/full-tab surfaces by task; design native mobile enrollment/link/privacy failures before promising parity; run full merged-SHA gates; report each green gate with its exact command and SHA.

SIDE_EFFECTS / Repository documentation/code/test edits, Figma edits made under an explicit lease, generated invariant/token Markdown or CSS produced by their source-controlled generators, and local build/benchmark/browser/accessibility artifacts only. No deploy, live-account mutation, credential creation/rotation, private-key generation/export, remote vanity acceleration, analytics change, store publication, external message, or secret handling without separate authorization.

RETURN / Resulting SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; Figma page/node ids and capture paths; measured contrast/target/overflow values; state-matrix coverage; worker/CSP/storage/permission/network changes; benchmark, browser, accessibility, mobile-device, and comprehension artifacts; remaining `UNVERIFIED` items; owner decisions; confirmation of no unauthorized external side effects.

## Today's authoritative research map

Read in this order. Each item has a different role; do not merge proposal,
observation, and executable evidence into one claim.

### 1. Current implementation and assurance context

- [Wallet design specification](superpowers/specs/2026-08-18-warden-wallet-design.md)
  is the product/security contract. Its 2026-08-19 documentation correction
  makes partial-address typing attention friction only, not identity proof.
- [Phase 1B execute/swap plan](superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md)
  owns the current program task order and remains ahead of new client work.
- [Invariant ledger](security/INVARIANTS.md),
  [prior-art findings](security/PRIOR-ART-FINDINGS.md), and
  [threat model](security/THREATMODEL.md) are the assurance indexes. Their
  status/evidence fields—not prose confidence—determine what is implemented.
- [Release integrity](security/RELEASE-INTEGRITY.md) records the current honest
  release state.
- [Security assurance and wallet landscape](research/2026-08-18-security-assurance-and-wallet-landscape.md)
  is the earlier deep research corpus reused by today's client review.

### 2. Client and release security research

- [Client Security Hardening and Release Assurance Plan](superpowers/plans/2026-08-19-warden-client-security-hardening.md)
  contains the pinned-source comparison of Brave, Rabby, Backpack, Helium,
  Safe, Ledger, BlueWallet, Sparrow, Electrum, and Warden prior art.
- The load-bearing conclusions are: browser-owned message provenance,
  immutable single-use approval records, exact-bytes rendering/recheck,
  authentication that controls key release, absolute lock deadlines across MV3
  suspension, contextual AEAD, advisory-only simulation, safe recovery export,
  reproducible artifacts, and two-person publisher authority.
- It explicitly records that there is no production `apps/extension`,
  real-device PRF remains `UNVERIFIED`, and the proposed client invariant rows
  begin honestly as unimplemented.

### 3. Optional vanity primary account research

- [Vanity Primary SmartAccount Proposal and Plan](superpowers/plans/2026-08-19-warden-vanity-primary-account.md)
  records the owner-approved direction and V0–V6 implementation sequence.
- The feature grinds only a public 32-byte salt for the root-bound Warden PDA;
  it never creates a vanity private key. The passkey remains root authority.
- Hard cap: 1–4 ASCII Base58 characters. Suffix and case-insensitive are
  defaults; exact capitalization is optional with a slower-search warning.
- Base58 excludes only `0`, `O`, `I`, and `l`. Do not copy the server
  bot's fixed-44-character first-symbol or `J` restrictions.
- Search time is geometric. Show attempts, calibrated rate, and 50%/95%
  probability windows—not a fake fixed countdown.
- `/opt/vanity-bot/**` is UI/research evidence only. Its worker returns private
  keys and is the wrong cryptographic construction for Warden.

### 4. Extension and mobile UI research

- [Extension and Mobile UI Research Record](research/2026-08-19-wallet-ui-extension-mobile.md)
  is the evidence-oriented benchmark, Figma audit, product architecture,
  security-display model, native-mobile boundary, state matrix, accessibility
  criteria, validation design, sources, and `UNVERIFIED` list.
- [S-Tier Extension and Mobile UI Plan](superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md)
  turns that record into U0–U10 with dependencies and executable acceptance
  criteria.
- [Figma design ledger](design/figma.md) records current node ids and the binding
  correction audit. The current matched-recipient and dust-override frames are
  legacy evidence until replaced; do not implement them.

## Owner decisions carried forward

### Security posture

- Warden does not claim to be unhackable.
- The honest product property is bounded wallet loss under session compromise,
  with larger actions delayed/cancellable and every approval bound to the exact
  action shown.
- Third-party simulation/reputation may inform copy but cannot authorize or
  independently block program-permitted execution.
- Audit and public bounty remain mandatory before real-funds mainnet.

### Vanity

- Proceed as an optional onboarding feature.
- Customize the first Warden SmartAccount PDA, never a “master private key.”
- Four characters is the non-negotiable cap.
- Provide optional exact capitalization with an honest time warning.

### UI

- Position Warden as **calm, comprehensible custody**, not a crypto super-app.
- Durable destinations are Home, Activity, Protect, and Settings.
- Send, Receive, and Swap are actions, not tab destinations.
- Use popup, side panel, dedicated approval window, and full tab according to
  consequence and content depth.
- Warden Receipt is the flagship approval surface:
  origin → intent → changes now → authority later → independent evidence →
  cost/timing → decision.
- Origin, decode, simulation, and policy are independent evidence axes. There
  is no universal green “safe” shield.
- Mobile is native product design, not a scaled extension popup.

## Binding corrections discovered today

### Partial-address matching is not verification

The current first/last-four confirmation can be deliberately matched by an
attacker and must not establish recipient identity. If retained, it is attention
friction with neutral copy. Exact-address contact/provenance, trusted-source
entry, full address, character-level comparison, test send, authentication,
policy, and timelock are the actual controls.

For dust-only/lookalike addresses, block by default. An expert override cannot
be released merely by typing characters copied from the suspicious address.

### Semantic indicators need their own contrast gate

Current light `warn` measures 2.33:1 on `bg` and 2.19:1 on `surface`.
Meaningful rails/dots need at least 3:1. Status prose stays in `ink`; add a
mode-specific indicator token rather than coloring text or washing the card.

### A popup is not the whole extension

The current 360 × 600 studies are a baseline, not the full surface. Persistent
work belongs in the side panel, high-consequence decisions in a request-bound
approval window, and onboarding/recovery/policy/raw complexity in a full tab.

### Mobile credentials do not silently inherit browser identity

The extension credential is scoped to its origin. Native apps require explicit
device/passkey enrollment, guardian/recovery alternatives, verified link
handling, and platform authentication/privacy evidence. Do not promise seamless
sync or Solana Mobile Wallet Adapter parity before real-device spikes.

## Resume order and dependency graph

1. Continue the exact unfinished Phase 1B task order from `CLAUDE.md`.
2. At a clean boundary, client C0 and vanity V0 may seed addressable,
   `unimplemented` invariant/spec rows.
3. UI U0–U2 may correct/design semantics in Figma under an explicit design
   lease; no production token or extension implementation follows merely from
   those frames.
4. Finish Phase 1B Task 8 and stabilize supported client derivation, payload,
   transcript, and wrapping interfaces.
5. Implement client C1 first: page/background/UI trust boundary and immutable
   request lifecycle.
6. Build UI U7 against that boundary; vanity V1–V3 may build and independently
   verify the public-salt engine.
7. Integrate vanity onboarding at V4 only after the production extension
   boundary exists.
8. Add state/accessibility/visual/privacy/comprehension gates and run them on
   the merged SHA.
9. Keep native mobile at U6 prototype/research scope until the owner authorizes
   implementation and framework selection.

## Proposed commands are not current gates

The UI plan reserves `pnpm ui:tokens:check`, `pnpm ui:state-matrix`,
`pnpm ui:a11y`, `pnpm ui:visual`, `pnpm ui:e2e:extension`,
`pnpm ui:responsive`, `pnpm ui:privacy`,
`pnpm ui:comprehension:gate`, and aggregate `pnpm ui:gate`.

At this memo's base they are specifications for future executable lanes, not
available commands and not green evidence. The same rule applies to every
unchecked item in the three dated plans.

## UNVERIFIED at handoff

- production extension trust boundary, keyring, approval store, and UI;
- real-device WebAuthn PRF;
- reproducible extension payload/store comparison;
- vanity worker, estimator, benchmark, and onboarding integration;
- revised Figma nodes/tokens/components beyond the current two screen families;
- dedicated approval-window lifecycle;
- native iOS/Android credential, links, MWA, and capture/privacy behavior;
- accessibility manual matrix, responsive captures, UI performance baselines,
  and powered comprehension study;
- every proposed UI command above.

No build or test gate was run merely because this memo and its proposal
documents exist. Do not infer an implemented feature, closed invariant, or
green build from their presence.
