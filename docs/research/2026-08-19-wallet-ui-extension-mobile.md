# Warden Wallet — Extension and Mobile UI Research Record

> **Status:** research and product-direction record, not implementation evidence.
> A screen, control, or gate described here does not exist until its linked
> implementation and executable evidence land on a named commit.

**Authored:** 2026-08-19

**Repository base inspected:** `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a`
on `phase1b`

**Figma file inspected:** [Warden Wallet — design system](https://www.figma.com/design/GOBwNsRgT5I36H2oGjfSbi/Warden-Wallet-%E2%80%94-design-system)
(`fileKey = GOBwNsRgT5I36H2oGjfSbi`)

**Companion implementation plan:**
[2026-08-19-warden-s-tier-ui-mobile.md](../superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md)

## Executive decision

Warden should compete on **calm, comprehensible custody**, not on the number of
tokens, banners, feeds, quests, or trading shortcuts it can place in a popup.
Its premium differentiator is a receipt-like explanation of the exact action,
the authority it creates, the policy that will govern it, and the user's
remaining stop path.

The current Home and sign-request studies establish a promising visual voice,
but they are not yet a product system. They cover only two of eleven planned
screen families, only at 360 × 600, with several security-signalling mistakes
that must be corrected before implementation:

1. Matching the first and last four characters of a displayed recipient is
   **not recipient verification**. Address-poisoning attackers deliberately
   manufacture matching visible ends. It may be retained only as attention
   friction and must never turn the flow green, lower risk, or establish trust.
2. The light-mode warning rail/dot is 2.19:1 against `surface` and 2.33:1
   against `bg`. Because the mark itself carries status, it needs a
   mode-specific token that reaches the WCAG 3:1 non-text contrast threshold.
3. A 360 × 600 popup is unsuitable for complex or high-consequence approval.
   Warden needs a deliberate extension surface architecture: popup, side panel,
   dedicated approval window, and full tab.
4. Native mobile cannot be a scaled popup. It needs platform-native
   authentication, verified link handling, enrollment/recovery, privacy, and
   failure-state designs.

## Evidence grades

This record uses four grades so a polished proposal cannot be confused with a
measured result:

| Grade | Meaning |
|---|---|
| Observed | Read directly from the current repository, Figma nodes, or measured token values |
| Primary-source requirement | Derived from an official platform, standards, or protocol source |
| Comparative lesson | Pattern observed in a peer product or open-source design system; not automatically suitable for Warden |
| Proposal | Warden-specific direction requiring design, testing, and implementation |

## Current Figma audit

### What exists

The current file has two pages, `Components` (`9:86`) and `Screens`
(`10:2`). It contains twelve component families and nine top-level screen
variants: five light frames and four dark clones. The designed product coverage
is Home plus sign request:

- sign request, matched, authority-blocked, and dust-only variants;
- Home;
- dark variants for Home and all sign-request states except the matched state.

Every current frame is 360 × 600. Existing exports are listed in
[figma.md](../design/figma.md).

### What is missing

No complete design exists yet for:

- onboarding, import, watch-only, passkey enrollment, recovery setup, guardian
  setup, account verification, or optional vanity address creation;
- Activity, Receive, Send, Swap, Connect, Protect/Policy, Sessions/Devices,
  Guardians/Recovery, or Settings/Trust;
- expanded-tab, side-panel, dedicated approval-window, iOS, or Android layouts;
- loading, skeleton, offline, stale, partial decode, failed simulation,
  unavailable provider, interrupted authentication, or transaction lifecycle
  states;
- focus-visible, keyboard-only, hover, 200% text, 400% zoom, RTL,
  pseudolocalized, reduced-motion, or high-contrast variants;
- a component-level security evidence model, recipient provenance model, raw
  instruction disclosure, address comparison, device enrollment, or recovery
  ceremony.

### Measured color contrast

The Figma variables inspected resolve to these sRGB colors:

| Token | Light | Dark |
|---|---|---|
| `bg` | `#F8F5EF` | `#050911` |
| `surface` | `#F1EEE9` | `#0C121A` |
| `ink` | `#181B1E` | `#E6E4E0` |
| `accent` | `#495DA7` | `#6A81CE` |
| `ok` | `#439458` | `#439458` |
| `warn` | `#D79628` | `#D79628` |
| `critical` | `#BD413F` | `#BD413F` |

Contrast ratios measured from those values:

| Pair | Light `bg` | Light `surface` | Dark `bg` | Dark `surface` |
|---|---:|---:|---:|---:|
| `ink` | 15.89:1 | 14.94:1 | 15.70:1 | 14.81:1 |
| `accent` | 5.66:1 | 5.33:1 | 5.36:1 | 5.05:1 |
| `ok` | 3.44:1 | 3.23:1 | 5.33:1 | 5.03:1 |
| `warn` | **2.33:1** | **2.19:1** | 7.86:1 | 7.41:1 |
| `critical` | 4.83:1 | 4.55:1 | 3.79:1 | 3.57:1 |

The current rule that semantic prose remains in `ink` is sound. The correction
is that rails and dots are meaningful non-text graphics and therefore also
need sufficient contrast. Do not solve this by making status text colored or
by washing entire cards in semantic color. Add mode-specific semantic indicator
tokens, then measure every background on which they appear.

## Product benchmark: lessons, not imitation

| Product/source | Useful lesson for Warden | Boundary |
|---|---|---|
| [Phantom security model](https://help.phantom.com/hc/en-us/articles/49409417837843-How-wallets-are-secured) | Familiar onboarding, fraud warnings, broad ecosystem expectations | Public product material is not source-level proof of client internals |
| [Rabby source](https://github.com/RabbyHub/Rabby) | Transaction explanation and risk checks should precede signing | EVM assumptions and its visual density are not Warden defaults |
| [Rainbow design system](https://github.com/rainbow-me/rainbow/tree/develop/src/design-system) | A maintained token/component layer makes native surfaces coherent | Consumer expressiveness must not dilute security hierarchy |
| [MetaMask design system](https://github.com/MetaMask/metamask-design-system) | Shared components and documented states reduce wallet UI drift | Familiarity does not excuse generic or ambiguous approval copy |
| [Safe passkeys](https://docs.safe.global/advanced/passkeys/overview) | Passkeys need explicit signer/device semantics | Ethereum account and recovery semantics are not portable |
| [Ledger clear signing](https://developers.ledger.com/docs/clear-signing/overview) | Parsed intent must stay bound to the exact signed payload; unknown content must be obvious | Warden must not imply hardware-level isolation in an extension |
| [Backpack source](https://github.com/coral-xyz/backpack) | Solana-native account and dApp interaction patterns | Repository warns it is unaudited/not production-ready; copy no security claims |
| [Jupiter Wallet docs](https://docs.jup.ag/user-docs/manage/extension-wallet/getting-started) | Trading flows need quote, route, fee, slippage, and failure clarity | Warden is not a trading dashboard |
| [Zerion mobile](https://zerion.io/blog/track-your-defi-portfolio-on-zerions-mobile-app/) | Portfolio scanning can be legible and calm | Analytics breadth is not a v1 custody requirement |

The peer bar is useful for expected polish, but Warden's UI must expose
properties peers often collapse: exact origin, decode coverage, simulation
freshness, on-chain policy, continuing authority, timelock, and cancellation.

## Product principles

1. **Security state before portfolio decoration.** Home leads with lock,
   session, pending action, and recovery risk before market content.
2. **One consequence per primary action.** A primary button names what will
   happen: “Queue 0.25 SOL for 12 hours,” not “Confirm.”
3. **Evidence stays multidimensional.** No single green shield or “safe” score
   compresses independent facts.
4. **Unknown is a first-class state.** Decode, simulation, price, reputation,
   RPC, and policy data can each be missing without being silently treated as
   safe or dangerous.
5. **Progressive disclosure, never concealed consequence.** Advanced bytes can
   be behind a disclosure; asset loss, recipient, authority, fee, timing, and
   stop path cannot.
6. **Calm does not mean vague.** Restraint comes from hierarchy and spacing, not
   from hiding technical facts the decision depends on.
7. **Every rendered claim has provenance.** The UI knows whether a label came
   from signed bytes, local state, on-chain state, an RPC, or a third party.

## Extension surface architecture

Chrome exposes multiple extension surfaces. Warden should assign work by
consequence and dwell time:

| Surface | Purpose | Must not contain |
|---|---|---|
| Popup, 360 × 600 baseline | Lock/unlock, glanceable balances, Receive, recent activity, pending countdown, current session | Complex policy editing, long recovery, raw transaction review |
| Side panel | Persistent Send/Swap/Activity/Connected sites/Protect work alongside a dApp | A floating approval detached from the initiating request |
| Dedicated approval window | One request, bound origin/tab/account/network/digest, with immutable evidence and a single decision | Portfolio navigation, unrelated promotions, mutable quote controls |
| Full extension tab | Onboarding, recovery, devices, policy authoring, trust/upgrade details, complex or raw review | Time-sensitive approval that could become detached from its caller |
| Native mobile | Native account, activity, approval handoff, recovery and device management | A responsive copy of the browser popup |

This follows Chrome's documented [popup](https://developer.chrome.com/docs/extensions/develop/ui/add-popup)
and [side-panel](https://developer.chrome.com/docs/extensions/reference/api/sidePanel)
models. The approval window is a Warden product requirement, not a claim that
Chrome provides an automatically secure window.

### Navigation model

Use four durable destinations:

- Home
- Activity
- Protect
- Settings

Send, Receive, and Swap are actions opened from a prominent action dock, sheet,
or contextual command—not tab destinations. This keeps navigation about
places, consistent with Apple's [tab-bar guidance](https://developer.apple.com/design/human-interface-guidelines/tab-bars),
and prevents the current `Home / Send / Swap / Activity` bar from crowding out
the product's security center.

## The flagship interaction: Warden Receipt

Replace the generic “sign request” mental model with a receipt whose reading
order answers the user's real questions:

1. **Origin:** who asked, from which exact origin, tab, account, and network?
2. **Intent:** what operation did Warden decode from the exact serialized bytes?
3. **Changes now:** what assets, fees, rent, and balances change immediately?
4. **Authority later:** what delegate, owner, close authority, session,
   allowance, or ongoing permission is created or changed?
5. **Policy and evidence:** what did local decoding, simulation, and on-chain
   policy independently conclude?
6. **Cost and timing:** total fee, slippage/quote expiry where relevant, and
   whether execution is immediate, queued, or timelocked.
7. **Decision:** a verb-specific action and a clear reject/cancel path.

The receipt is derived from the immutable request record described by the
client-security plan. The display cannot accept caller-supplied labels as
truth, and signing must recheck the same digest immediately before key use.

### Four independent evidence axes

Render these independently; never derive a global “safe” verdict:

| Axis | States |
|---|---|
| Origin | associated · unverified · mismatch · reported |
| Decode | full · partial · unknown |
| Simulation | current · stale · failed · unavailable |
| Policy | within limits · passkey + hold required · blocked |

A transaction may be fully decoded yet blocked by policy, or have a current
simulation yet an unverified origin. Green on one axis must not bleed into
another.

## Recipient safety and address poisoning

### Binding correction

The first/last-four pattern currently documented in the spec and Figma is
unsafe when presented as verification. A 2025 empirical
[address-poisoning study](https://arxiv.org/abs/2508.12107) describes attackers
constructing lookalike addresses around the fragments wallets commonly show.
Four Base58 characters are a feasible vanity target—the Warden vanity research
itself demonstrates that matching short fragments is practical.

Therefore:

- an exact address saved from a trusted source/contact can establish
  provenance;
- a QR/deep-link/manual source must be recorded and displayed;
- a new recipient shows the full address with grouping and copy-safe behavior;
- Warden compares the full address to the user's last genuine recipient and
  highlights character-level differences;
- history entries originating only from unsolicited dust never become trusted;
- a high-value first send should support a small test send or timelock;
- a typed visible fragment, if retained for friction, says:
  “Displayed characters matched. Recipient identity is still unverified.”
- matching the fragment never produces an `ok` dot, a “verified” label, a
  lower risk tier, or an enabled path through a dust-only block.

For a dust/lookalike recipient, block by default. An expert override starts a
fresh trusted-source entry, shows the complete address comparison, requires
fresh authentication, and remains subject to policy/timelock. Typing the
suspicious address's own visible fragment is not an override.

### Address presentation

- Use the full Base58 string for consequential review.
- Group visually without inserting copyable whitespace.
- Offer copy plus checksum-like visual segmentation, but do not imply Solana
  addresses contain a checksum.
- Normalize neither case nor characters; Base58 is case-sensitive.
- Detect Unicode confusables in labels/domains using
  [UTS #39](https://www.unicode.org/reports/tr39/), while treating the Base58
  address itself as ASCII.

## Screen inventory

| ID | Family | Required content |
|---|---|---|
| 01 | Onboarding | Create/import/watch-only; optional vanity; passkey; recovery; guardians; verify; fund |
| 02 | Home | Security state; total; assets; pending action; session; action dock |
| 02A | Activity | Filtered lifecycle, finality, failures, replacements, queue/cancel evidence |
| 03 | Receive | Account/network; QR; full address; copy/readback; warning about unsupported assets |
| 04 | Send | Asset, amount, provenance-aware recipient, fee, timing, review |
| 05 | Swap | Pay/receive, quote source/age, slippage, route, fees, minimum received, review |
| 06 | Warden Receipt | Bound origin, intent, state changes, authority, evidence axes, policy, decision |
| 07 | Connect | Exact origin, requested accounts/scopes, expiry, privacy, approve |
| 08 | Protect | Caps, allowlists, sessions, delays, pending changes, freeze, plain-language consequences |
| 09 | Sessions and devices | Device/passkey provenance, scopes, first/last use, expiry, revoke status |
| 10 | Guardians and recovery | Recovery readiness, quorum, cooling period, drill, freeze/cancel |
| 11 | Settings and trust | Network/RPC, privacy, accessibility, program id, upgrade authority/window, exports |

### Activity lifecycle

Avoid a binary pending/complete model. The UI and fixtures need:

`prepared`, `awaiting-auth`, `queued/timelocked`, `signing`,
`broadcast`, `processed`, `confirmed`, `finalized`, `failed`,
`expired`, `dropped`, `replaced`, and `canceled-before-execution`.

Solana finality copy must align with the platform's
[confirmation guidance](https://solana.com/es/developers/guides/advanced/confirmation).
“Sent” must never ambiguously mean signed, broadcast, confirmed, or finalized.

### Connected sites

Each site record shows exact origin, associated/unverified state, exposed
accounts, scopes/methods, first and last use, expiry, session cap, and actual
revocation status. “Disconnected” appears only after the background and any
on-chain/session revocation have been verified; closing a UI is not revocation.

## Native mobile research

### Identity and enrollment boundary

The browser passkey is scoped to the extension's origin. A native app has a
different application/domain identity. Do not promise invisible credential
sync. Design explicit outcomes:

- enroll this phone as a second passkey/device;
- use an existing guardian or recovery path;
- credential not present on this device;
- credential provider did not sync;
- biometric canceled, locked out, or unavailable;
- remove a lost device and verify the revocation state.

On iOS, authentication/key storage design must be validated against
LocalAuthentication, Keychain, and Secure Enclave behavior. On Android, use
Credential Manager and BiometricPrompt semantics. Platform biometrics must gate
actual key release/use, not merely unlock a screen.

### Links and wallet handoff

Use verified [Universal Links](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
and [Android App Links](https://developer.android.com/training/app-links/about).
Treat every link parameter as untrusted, bind the resulting request to the
actual app/origin/account/network/digest, reject unknown fields, and require a
fresh review after mutation.

Solana Mobile Wallet Adapter support is an implementation spike, not an assumed
parity feature. The current [MWA specification](https://solana-mobile.github.io/mobile-wallet-adapter/spec/spec.html)
has platform and identity caveats that need real iOS and Android prototypes
before product commitments.

### Screen-capture privacy

Android `FLAG_SECURE` can reduce exposure but has documented limitations;
follow Android's [sensitive-activity guidance](https://developer.android.com/security/fraud-prevention/activities).
iOS does not offer a universal screenshot-prevention promise: detect active
capture, redact appropriate content during sharing, and protect app-switcher
snapshots using Apple's [sensitive-content guidance](https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing).
Never market either platform as screenshot-proof.

### Mobile layout

- Use native 44 pt iOS and 48 dp Android minimum interactive targets.
- Keep bottom navigation for destinations and a platform-appropriate action
  sheet for Send/Receive/Swap.
- Preserve the Warden Receipt hierarchy, but allow a summary-to-detail
  transition rather than shrinking the desktop approval.
- Place biometric/passkey ceremony in a stable, interruption-safe flow with a
  recoverable cancel state.
- Test notification, deep-link, background/foreground, device rotation, dynamic
  type, TalkBack/VoiceOver, clipboard, and app-switcher behavior.

## Figma information architecture

The target page structure is:

1. `00 Foundations`
2. `01 Components`
3. `02 Extension`
4. `03 Mobile iOS`
5. `04 Mobile Android`
6. `05 Prototypes`
7. `06 Adversarial states`
8. `07 Research evidence`
9. `99 Archive`

Recommended variable collections:

- primitive color;
- semantic role;
- security-domain status;
- type;
- spacing and size;
- radius and elevation;
- motion;
- density;
- platform;
- viewport.

Required modes are Light, Dark, and High Contrast, with reduced-motion behavior
specified alongside motion variables. Platform and viewport differences should
be variables or component properties, not detached copies with silent drift.

## Component backlog

### Foundation and navigation

Button, IconButton, Link, TextField, AmountInput, Switch, Checkbox, Radio,
SegmentedControl, Menu, Tooltip, Disclosure, AppShell, AppBar, AccountSwitcher,
ActionDock, TabBar, SideRail, Breadcrumb, Sheet, Dialog.

### Financial

AssetRow, TransactionRow, Amount, FiatValue, FeeBreakdown, Quote, QuoteAge,
Keypad, QRCode, Scanner, NetworkMark, FinalityMark.

### Security evidence

OriginCard, IntentSummary, StateChange, AuthorityChange, AddressDiff,
RecipientProvenance, RiskEvidence, DecodeStatus, SimulationStatus,
PolicyVerdict, RequestFingerprint, RawInstructionDisclosure.

### Ceremony

PasskeySource, BiometricBridge, HardwareStep, DevicePairing, GuardianStep,
RecoveryStepper, TimelockCountdown, FreshAuthentication.

### Feedback

Skeleton, Progress, Alert, Banner, Toast, EmptyState, OfflineState, StaleState,
PartialState, ErrorState, RetryState, SuccessReceipt.

Every component needs content bounds, keyboard/focus behavior, screen-reader
semantics, loading/error/disabled behavior, localization stress, and allowed
security meanings. A component variant named “Safe” is prohibited unless it
refers to one exact, independently evidenced property.

## Adversarial state matrix

Design and fixture coverage must cross at least:

- locked, unlocking, unlocked, expiring, and expired;
- initial load, skeleton, stale cache, offline, RPC mismatch, rate limit;
- full, partial, unknown, and conflicting decode;
- simulation current, stale, failed, unavailable, and digest mismatch;
- recipient saved, first seen, manual, QR, deep link, dust-only, lookalike, and
  recently changed;
- origin associated, unverified, mismatched, reported, iframe, and navigated;
- request mutation, replay, duplicate click, timeout, account change, network
  change, tab close, and service-worker restart;
- passkey canceled, unavailable, locked out, provider changed, and signature
  rejected;
- hardware connected, wrong app, wrong network, rejected, disconnected;
- every transaction lifecycle state listed above;
- zero balance, unknown token, Token-2022 extensions, spam NFT, missing price,
  extreme decimals, high fee, insufficient rent, quote expiry;
- device removed, recovery pending, guardian unavailable, freeze, veto,
  cooling, and completion;
- keyboard only, VoiceOver, NVDA, TalkBack, 200% text, 400% zoom, RTL,
  pseudolocale, reduced motion, and high contrast.

## Validation program

### Security comprehension

For high-risk fixtures, users must correctly identify:

- what leaves now;
- who receives it;
- what continuing authority is granted or changed;
- when execution occurs;
- how to stop or cancel it.

Target at least 90% correct per critical question and zero observed critical
false approvals in a sufficiently powered study. Pre-register sample size,
task order, success definitions, exclusions, and confidence intervals. A small
unpowered usability session is formative evidence, not a release gate.

Address-poisoning fixtures must be deterministic and include exact visible-end
collisions. No participant should interpret partial-character matching as
identity verification.

### Accessibility

Meet [WCAG 2.2 AA](https://www.w3.org/TR/WCAG22/) for extension/web surfaces,
plus platform guidance for [Apple accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility/)
and [Android accessibility](https://developer.android.com/design/ui/mobile/guides/foundations/accessibility).
Require:

- zero serious/critical automated violations;
- complete keyboard operation and visible focus;
- manual NVDA, VoiceOver, and TalkBack passes;
- no status encoded by color alone;
- 44 × 44 CSS px internal targets where feasible, 44 pt iOS, 48 dp Android;
- 400% browser zoom and 200% mobile text without lost decisions or overlap;
- correct names, roles, values, live regions, error association, and focus
  restoration.

### Numbers and localization

Use locale-aware decimal/grouping rules from
[Unicode TR35 numbers](https://unicode.org/reports/tr35/tr35-numbers.html),
while signing and policy math remain integer/base-unit exact. Test long asset
names, 0/2/6/9/18 decimals, huge and tiny values, negative diffs, missing fiat,
RTL labels, long translations, and non-Latin numerals without ever changing the
serialized transaction.

### Performance and privacy

Set baselines only after representative prototypes exist. Measure popup open,
first meaningful content, approval render, list scrolling, scanner startup,
authentication handoff, and memory on supported low-end devices. Record raw
artifacts rather than declaring an arbitrary animation “fast.”

Verify clipboard lifetime, notification redaction, analytics minimization,
screen/app-switcher privacy, log/crash-report redaction, browser storage, and
all external requests. No address, balance, origin, transaction, or recovery
state enters analytics by default.

## Explicit non-goals

- A universal “transaction is safe” claim.
- A feed, quest system, token discovery marketplace, or social graph in v1.
- Blind signing for unknown instructions.
- Mobile parity before native authentication and link-handoff spikes.
- Treating visual snapshots or prose review as a security gate.
- Treating automated accessibility scans as a substitute for assistive-
  technology and keyboard testing.
- Treating a beautiful Figma frame as proof that stale, hostile, or interrupted
  runtime states are handled.

## Still UNVERIFIED

- Real-device WebAuthn/passkey PRF coverage remains as recorded by the security
  plan.
- The dedicated approval-window lifecycle has not been prototyped in the
  production MV3 architecture.
- Native iOS/Android credential enrollment and Solana MWA behavior have not
  been implemented or measured.
- The current Figma file has not yet received the page/component/token changes
  proposed here.
- No comprehension study, accessibility audit, responsive capture matrix, or
  UI performance baseline has run.
- Proposed UI gate commands in the companion plan do not exist yet.

## Primary references

- [Chrome extension popup](https://developer.chrome.com/docs/extensions/develop/ui/add-popup)
- [Chrome extension side panel](https://developer.chrome.com/docs/extensions/reference/api/sidePanel)
- [Apple tab bars](https://developer.apple.com/design/human-interface-guidelines/tab-bars)
- [Apple buttons](https://developer.apple.com/design/human-interface-guidelines/buttons)
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [Figma variable modes](https://help.figma.com/hc/en-us/articles/15343816063383-Modes-for-variables)
- [Semantic interface generation research](https://arxiv.org/abs/2601.16751)
- [Cryptocurrency address-poisoning study](https://arxiv.org/abs/2508.12107)
- [Wallet privacy study, PETS 2026](https://petsymposium.org/popets/2026/popets-2026-0094.php)
- [Accessible cryptocurrency wallet research](https://arxiv.org/abs/2306.06261)
- [WalletConnect Verify](https://docs.walletconnect.network/wallet-sdk/web/verify)
- [Passkey user journeys](https://developers.google.com/identity/passkeys/ux/user-journeys)
