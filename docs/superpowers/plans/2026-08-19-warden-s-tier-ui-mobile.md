# Warden Wallet — S-Tier Extension and Mobile UI Plan

> **For Claude Code:** this is a design and implementation plan, not evidence
> that any UI control, security state, accessibility behavior, study, or gate
> exists. Read the companion
> [research record](../../research/2026-08-19-wallet-ui-extension-mobile.md)
> first. Never report a gate green without the exact command and SHA it passed
> at.

**Authored:** 2026-08-19

**Research base:** `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a`
on `phase1b`

**Figma file:** [Warden Wallet — design system](https://www.figma.com/design/GOBwNsRgT5I36H2oGjfSbi/Warden-Wallet-%E2%80%94-design-system)
(`fileKey = GOBwNsRgT5I36H2oGjfSbi`)

**Depends on:**

- the task order in
  [Phase 1B](2026-08-18-warden-phase1b-execute-swap.md);
- the immutable request, keyring, simulation, and release boundaries in the
  [client-security plan](2026-08-19-warden-client-security-hardening.md);
- the optional onboarding flow in the
  [vanity-primary-account plan](2026-08-19-warden-vanity-primary-account.md).

## Outcome

Deliver an extension and future native-mobile design system that reaches a
premium-wallet bar while making Warden's security model more understandable
than a conventional wallet:

- users can identify the exact origin, action, recipient, continuing authority,
  cost, execution time, policy result, and cancellation path before approval;
- the UI never converts incomplete evidence into a global “safe” verdict;
- address poisoning, stale/missing simulation, partial decode, service-worker
  interruption, and authentication failures are designed as first-class states;
- the popup, side panel, approval window, full tab, iOS app, and Android app
  share semantics without pretending they share identical interaction models;
- accessibility, privacy, responsiveness, and comprehension are executable
  release criteria rather than final polish.

## Scheduling and edit contract

1. Preserve Phase 1B's current order. UI design may proceed in Figma when it has
   an explicit design lease, but production extension code waits for Phase 1B
   Task 8's stable client interfaces and client-plan C1's trust boundary.
2. Do not edit generated UI tokens by hand. Figma variables are the design
   source of truth; export tokens and generated CSS together under U7.
3. Treat the current first/last-four confirmation and light warning token as
   known design defects. Do not implement them while waiting for revised frames.
4. Use the Figma MCP to inspect variables/components, create or update frames,
   and export evidence. Record node ids and capture paths after every accepted
   tranche. A text description is not visual verification.
5. One active edit lease and one heavy build at a time on this host. Do not
   deploy, publish, create credentials, or touch live accounts.
6. Native mobile stays in research/prototype scope until the owner separately
   authorizes an app implementation and chooses its framework.

## Definition of done

“S-tier” is not a visual adjective. This plan is complete only when:

- every screen family and adversarial state has a named Figma node or a
  documented, intentional exclusion;
- Figma variables, exported tokens, and rendered components pass an automated
  parity check;
- critical flows pass deterministic state-matrix, unit, integration,
  accessibility, responsive, and visual-regression gates;
- security comprehension meets the pre-registered study thresholds;
- iOS and Android designs have real-device authentication/link/privacy evidence
  before they are described as implementable;
- the full merged SHA passes the aggregate UI gate and the repository's
  deploy-gate applicable at that phase;
- all remaining limitations are labeled `UNVERIFIED`.

---

## U0 — Correct the security semantics before expanding the system

**Purpose:** remove misleading trust signals before they propagate through
components and new screens.

**Documentation and Figma work:**

- [ ] Replace every active normative claim that first/last four verifies the
  recipient; retain historical review text only with an explicit supersession
  note. If a typed fragment remains, name it attention friction and show:
  “Displayed characters matched. Recipient identity is still unverified.”
- [ ] Remove the `ok` dot and “matches” trust copy from the
  `ConfirmField/Matched` variant. Matching must not change recipient
  provenance, policy, or risk.
- [ ] Replace the dust-only escape hatch. Default is block/report. An expert
  continuation begins a fresh trusted-source recipient entry, shows full
  address diff, requires fresh authentication, and remains timelocked or
  policy-controlled.
- [ ] Create `RecipientProvenance` and `AddressDiff` component contracts.
  Exact address, source, first seen, last genuine use, and dust-only history are
  independently represented.
- [ ] Create mode-specific warning-indicator variables whose rails/dots reach
  at least 3:1 against every allowed background. Keep semantic prose in `ink`.
- [ ] Mark existing Figma nodes `10:54` and the current `ConfirmField`
  matched state as superseded until redesigned. Do not silently mutate archived
  evidence; create a replacement and link the old node.
- [ ] Replace the current `Home / Send / Swap / Activity` navigation component
  with destination navigation `Home / Activity / Protect / Settings` and a
  separate action dock for Send/Receive/Swap.

**U0 acceptance evidence:**

- new node ids and before/after captures;
- contrast calculations for every semantic indicator/background pair;
- repository search showing no unsuperseded normative claim that a
  partial-address match verifies identity;
- a deterministic poisoning fixture with matching visible ends.

---

## U1 — Rebuild Figma as an auditable product system

**Target pages:**

1. `00 Foundations`
2. `01 Components`
3. `02 Extension`
4. `03 Mobile iOS`
5. `04 Mobile Android`
6. `05 Prototypes`
7. `06 Adversarial states`
8. `07 Research evidence`
9. `99 Archive`

**Variable collections:**

- [ ] primitive color;
- [ ] semantic role;
- [ ] security-domain status;
- [ ] type;
- [ ] spacing/size;
- [ ] radius/elevation;
- [ ] motion;
- [ ] density;
- [ ] platform;
- [ ] viewport.

**Modes and responsive rules:**

- [ ] Light, Dark, and High Contrast color modes;
- [ ] reduced-motion behavior, not merely a toggle label;
- [ ] extension popup, side panel, approval window, and full-tab breakpoints;
- [ ] iOS and Android platform modes where metrics/controls genuinely differ;
- [ ] constraints and min/max content widths documented at component level;
- [ ] long content, dynamic type, RTL, and pseudolocale examples on the
  Foundations page.

**Figma MCP procedure:**

1. Read current metadata, variables, components, and target nodes before writes.
2. Take an edit lease for one page/tranche.
3. Apply variables/components before composing screens.
4. Capture every changed top-level frame and inspect at native resolution.
5. Record page, node id, mode, viewport, content fixture, and capture path in
   [figma.md](../../design/figma.md).
6. Release the lease with a concise return: changed node ids, measurements,
   unresolved states, and no-code/no-token claims.

**U1 acceptance:** no detached production color/type/space values; all
top-level frames identify their platform, viewport, theme, and fixture; all
archived nodes are visibly marked and separated from current designs.

---

## U2 — Build the component contract before screen volume

### Foundation

- [ ] Button, IconButton, Link, TextField, AmountInput;
- [ ] Switch, Checkbox, Radio, SegmentedControl;
- [ ] Menu, Tooltip, Disclosure, Dialog, Sheet;
- [ ] focus ring, validation message, loading, destructive confirmation.

### Navigation and shell

- [ ] AppShell, AppBar, AccountSwitcher;
- [ ] ActionDock, TabBar, SideRail, Breadcrumb;
- [ ] request-bound ApprovalShell with immutable origin/account/network header.

### Financial

- [ ] AssetRow, TransactionRow, Amount, FiatValue;
- [ ] FeeBreakdown, Quote, QuoteAge, Slippage, MinimumReceived;
- [ ] Keypad, QRCode, Scanner, NetworkMark, FinalityMark.

### Security evidence

- [ ] OriginCard and origin-association state;
- [ ] IntentSummary and exact-bytes fingerprint;
- [ ] StateChange and AuthorityChange;
- [ ] RecipientProvenance and AddressDiff;
- [ ] DecodeStatus, SimulationStatus, PolicyVerdict;
- [ ] RiskEvidence and RawInstructionDisclosure.

### Ceremony and feedback

- [ ] PasskeySource, FreshAuthentication, BiometricBridge;
- [ ] HardwareStep, DevicePairing, GuardianStep, RecoveryStepper;
- [ ] TimelockCountdown;
- [ ] Skeleton, Progress, Alert, Banner, Toast, Empty, Offline, Stale, Partial,
  Error, Retry, and SuccessReceipt.

### Component contract required for every item

- visual variants and permitted semantic meaning;
- keyboard sequence, focus entry/exit, and focus restoration;
- accessible name/description/live-region behavior;
- target size and text-resize behavior;
- loading, empty, disabled, error, and interrupted states;
- content length/localization bounds;
- source/provenance of each rendered claim;
- deterministic fixture id for visual and state tests.

**U2 acceptance:** no screen-local duplicate of a component behavior; no
`Safe`/green aggregate state; no enabled action represented only by color or
elevation.

---

## U3 — Complete the extension information architecture

### Popup

- [ ] lock/unlock and interrupted unlock;
- [ ] Home security state, balances, pending countdown, session;
- [ ] Receive/copy/readback;
- [ ] recent Activity and failure/offline states;
- [ ] quick action dock;
- [ ] explicit “Open Warden” transition when content exceeds popup scope.

### Side panel

- [ ] Send;
- [ ] Swap;
- [ ] full Activity;
- [ ] Connected sites;
- [ ] Protect overview and policy inspection;
- [ ] resize behavior and dApp-context persistence.

### Full tab

- [ ] onboarding create/import/watch-only;
- [ ] optional vanity flow with honest stochastic timing;
- [ ] passkey, recovery, guardian, verification, funding;
- [ ] policy authoring and pending policy changes;
- [ ] sessions/devices and recovery;
- [ ] program id, upgrade authority/window, RPC/privacy/accessibility;
- [ ] raw and complex transaction review.

### Shared screen families

Complete IDs 01, 02, 02A, 03, 04, 05, 07, 08, 09, 10, and 11 from the
research record. Each must include happy, empty, loading, stale, offline,
partial, failure, and interruption states that apply.

**U3 acceptance:** a clickable prototype covers onboarding → fund → Send →
queued/timelocked → cancel/finalize; connect → session → revoke; and recover →
cooling → veto/complete without dead ends.

---

## U4 — Make Warden Receipt the category-leading approval surface

**Immutable header:**

- exact origin and association state;
- tab/request context;
- account and network;
- request fingerprint and expiry.

**Reading order:**

1. origin;
2. decoded intent;
3. immediate asset/fee/rent changes;
4. continuing authority changes;
5. origin/decode/simulation/policy evidence axes;
6. cost, quote age, slippage, timing, and stop path;
7. effect-specific decision.

**Required variants:**

- [ ] ordinary transfer to a saved exact address;
- [ ] first-seen manual/QR/deep-link recipient;
- [ ] matching-ends lookalike and dust-only recipient;
- [ ] swap with current, stale, changed, and expired quote;
- [ ] authority/delegate/owner/close-authority change;
- [ ] full, partial, and unknown decode;
- [ ] simulation current, stale, failed, unavailable, and digest mismatch;
- [ ] policy within, fresh passkey + hold, and blocked;
- [ ] request mutated, replayed, expired, navigated, account changed, and
  network changed;
- [ ] root, session, staged, queued, recovery, and adapter execution lanes;
- [ ] unsupported co-signer, durable nonce, top-level PDA signer, instruction-
  sysvar adjacency, SIWS/message verification, and off-allowlist program.

**Decision copy rules:**

- name asset, amount, recipient or protocol, and timing where space permits;
- never use bare “Confirm” for a consequential operation;
- keep Reject available and unambiguous;
- no preselected expert override;
- no double negative;
- no countdown that converts inaction into approval;
- after signing, show a receipt and exact lifecycle state—not “Success” before
  the appropriate evidence exists.

**U4 acceptance:** every visible consequence is derived from the same immutable
serialized request the signer will re-hash; fixtures demonstrate that changed
origin/account/network/bytes invalidate the screen and decision.

---

## U5 — Design the adversarial and accessibility matrix

Build the full matrix from the research record on `06 Adversarial states`.
Prioritize combinations, not isolated empty states:

- stale simulation + partial decode;
- trusted origin + mutated bytes;
- lookalike recipient + familiar amount;
- service-worker restart during fresh auth;
- account/network change while approval is open;
- expired quote after biometric return;
- offline while timelock cancellation is urgent;
- removed device while recovery is cooling;
- large text + long locale + critical authority change.

### Accessibility requirements

- [ ] WCAG 2.2 AA mapping at component and flow level;
- [ ] 44 × 44 CSS px internal web targets where feasible;
- [ ] 44 pt iOS and 48 dp Android native targets;
- [ ] visible focus and complete keyboard flow;
- [ ] correct names, roles, values, error association, and live regions;
- [ ] manual NVDA, desktop VoiceOver, mobile VoiceOver, and TalkBack runs;
- [ ] 400% web zoom and 200% mobile text;
- [ ] RTL, pseudolocale, reduced motion, and high contrast;
- [ ] no semantic state carried only by hue, animation, position, or sound.

**U5 acceptance:** zero serious/critical automated accessibility findings and
no unresolved manual blocker in a critical flow. Automated scans alone do not
satisfy acceptance.

---

## U6 — Prototype native mobile without faking credential parity

### Architecture spikes before high-fidelity commitment

- [ ] iOS passkey/device enrollment using the intended associated domain and
  credential-provider behavior;
- [ ] Android Credential Manager enrollment and BiometricPrompt key-use
  behavior;
- [ ] second-device/guardian/recovery route when the browser credential is
  absent or unsynced;
- [ ] Universal Link and Android App Link verification, hostile parameters,
  mutation, replay, and fallback;
- [ ] Solana Mobile Wallet Adapter on supported Android and current iOS path;
- [ ] background/foreground interruption during request and authentication;
- [ ] app-switcher snapshot, screen sharing/capture, clipboard, notification,
  crash log, and analytics privacy.

### Mobile design families

- [ ] iOS and Android Home/Activity/Protect/Settings;
- [ ] native action sheet for Send/Receive/Swap;
- [ ] Warden Receipt summary → evidence → decision;
- [ ] device enrollment and “credential not on this device” paths;
- [ ] device removal, guardian, recovery, freeze, cooling, veto, completion;
- [ ] scanner permission denied/limited/retry;
- [ ] notification → exact request → stale/mutated/expired handling;
- [ ] tablet/foldable layouts only after phone flows stabilize.

**U6 acceptance:** real-device artifact matrix with OS/device/authenticator,
credential source, link route, capture/privacy observation, command/build SHA,
and result. Simulator-only evidence remains labeled `UNVERIFIED`.

---

## U7 — Export the design contract into implementation

**Start only after (split, campaign plan 2026-08-20):** the semantic-model and
deterministic-fixture *scaffolding* may follow Phase 1B Task 8 + client C1; but
**token export additionally requires U0–U2 acceptance** — U1/U2 create the
variable collections and component contracts the export manifests reference, so
there is nothing to export before them — and **live approval rendering
additionally requires C3 + C4** (the immutable request record and exact-bytes
decode it binds to). Do not export tokens or render a live Receipt against
provisional interfaces.

- [ ] Define a source-controlled Figma export manifest: collection, variable id,
  modes, component/node ids, export timestamp, and file version.
- [ ] Generate `packages/ui-tokens` outputs from Figma; never reverse-author
  generated CSS.
- [ ] Add token schema validation, duplicate/unknown-token rejection, mode
  completeness, and contrast checks.
- [ ] Build shared semantic models independently of platform view code:
  RequestEvidence, RecipientProvenance, TransactionLifecycle, DeviceState, and
  RecoveryState.
- [ ] Render extension components from deterministic fixtures before wiring live
  provider data.
- [ ] Bind every approval view to client-plan C1/C4 immutable request records.
- [ ] Keep platform-native controls for authentication, links, scanner,
  clipboard, notifications, and secure storage.

**U7 acceptance:** Figma export and repository tokens are byte-for-byte
accounted for; a changed or missing variable fails the gate; no rendered
security label accepts untrusted caller prose as its source.

---

## U8 — Make UI quality executable

The following command names are a proposed contract. They do **not** exist at
this plan's base and must not be reported as run until implemented:

| Proposed command | Required measurement |
|---|---|
| `pnpm ui:tokens:check` | Figma/export/schema/mode parity plus contrast |
| `pnpm ui:state-matrix` | Every required fixture × surface × mode has an explicit outcome |
| `pnpm ui:a11y` | automated checks plus references to manual-run artifacts |
| `pnpm ui:visual` | deterministic native-size captures and reviewed diffs |
| `pnpm ui:e2e:extension` | popup/side-panel/approval/full-tab hostile lifecycle flows |
| `pnpm ui:responsive` | zoom, text size, viewport, platform, RTL/pseudolocale |
| `pnpm ui:privacy` | clipboard/log/storage/network/notification/capture assertions |
| `pnpm ui:comprehension:gate` | validates preregistered study dataset and thresholds |
| `pnpm ui:gate` | aggregate of all applicable lanes |

### Gate integrity rules

- Expected values come from independent fixtures/specs, never from the
  component under test.
- Screenshot count is not coverage. The state manifest defines required cells,
  and missing cells fail.
- Pixel similarity is not security comprehension. Visual, semantic, and study
  lanes remain separate.
- Density floors are prohibited; they reward clutter.
- A manual artifact records tester, date, build SHA, environment, fixture,
  expected result, observed result, and unresolved issue.
- The final gate runs on the merged SHA. A worker-branch pass does not certify
  the merge.

---

## U9 — Validate comprehension with users

### Formative rounds

- [ ] five to eight representative users on low-fidelity receipt hierarchy;
- [ ] five to eight on poisoning/provenance and timelock/cancel;
- [ ] accessibility sessions with screen-reader and large-text users;
- [ ] revise language and hierarchy before visual polish freezes components.

These rounds find failure modes; they do not satisfy the release threshold.

### Powered release study

Pre-register:

- participant population and security-experience strata;
- sample size from a power analysis;
- randomized fixture order and controls;
- exact critical questions;
- critical false-approval definition;
- exclusions and missing-data treatment;
- per-question threshold and confidence interval;
- stop/retest rules after a material design change.

Required target: at least 90% correct on each critical consequence question and
zero observed critical false approvals in the powered sample. Report raw
anonymized results, confidence intervals, and failures. Do not collapse results
into one UX score.

---

## U10 — Release evidence and handoff

- [ ] Pin current Figma node ids and capture artifacts.
- [ ] Pin token export manifest and generated outputs.
- [ ] Pin state matrix and test fixtures.
- [ ] Pin accessibility/manual-device artifacts.
- [ ] Pin comprehension protocol and results.
- [ ] Run all applicable UI gates on the merged SHA.
- [ ] Run the repository's applicable full deploy-gate on that same SHA.
- [ ] Update `docs/NEXT-SESSION.md`, create the current dated handoff that
  links back to prior memos without rewriting their historical state, and
  update security invariant evidence.
- [ ] Record remaining `UNVERIFIED` items and owner decisions.

## Stop conditions

Stop and return to the owner rather than inventing a product decision if:

- native framework selection or app implementation is required;
- a platform credential model would change the account/recovery architecture;
- Figma token correction would materially change the established brand;
- an accessibility requirement conflicts with a security ceremony;
- a third-party simulation/reputation feed would become an authorization gate;
- blind signing, analytics, a new permission, a publishing credential, or a
  live deployment is proposed;
- the current active edit lease overlaps another worker's files.

## Return contract for each tranche

Return:

- base and resulting SHA;
- exact files and Figma node ids changed;
- before/after capture paths and measured contrast/target/overflow values;
- exact gate commands and results at the resulting SHA;
- state-matrix cells added or still missing;
- security claims affected and invariant ids/evidence;
- new permissions, storage, CSP, network, analytics, or privacy behavior;
- remaining `UNVERIFIED` items and owner decisions;
- confirmation of no unauthorized external side effects.
