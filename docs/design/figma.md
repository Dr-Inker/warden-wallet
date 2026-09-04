# Warden Wallet — design foundation (Figma)

**File:** [Warden Wallet — design system](https://www.figma.com/design/GOBwNsRgT5I36H2oGjfSbi/Warden-Wallet-%E2%80%94-design-system)
`fileKey = GOBwNsRgT5I36H2oGjfSbi` · owner `Dr. Inker` (`team::1660993652229402605`) · created 2026-08-18. Figma
frames were last revised 2026-08-18 (review round 1); this ledger received a binding research audit on 2026-08-19.

Doctrine followed: `/opt/drinkerlabs/DESIGN.md`. Product context: `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`
§6 (intent view) and §9 (UI/brand).

Tokens are authored **here** and exported by hand to `packages/ui-tokens/`. Per repo `CLAUDE.md`: do not hand-edit
`tokens.css` — change the Figma variable, then re-export both files together and update the table below.

---

## Pages and node ids

| Page | node id |
|---|---|
| Components | `9:86` |
| Screens | `10:2` |

| Frame | node id | deep link |
|---|---|---|
| 06 — Sign request / intent | `10:3` | `…/design/GOBwNsRgT5I36H2oGjfSbi?node-id=10-3` |
| 06a — Sign request / confirmation matched | `10:54` | `…?node-id=10-54` |
| 06b — Sign request / blocked (authority change) | `10:106` | `…?node-id=10-106` |
| 06c — Sign request / dust-only recipient (poisoning) | `10:145` | `…?node-id=10-145` |
| 02 — Home | `10:190` | `…?node-id=10-190` |
| 06 · dark | `10:271` | `…?node-id=10-271` |
| 06b · dark | `10:307` | `…?node-id=10-307` |
| 06c · dark | `10:340` | `…?node-id=10-340` |
| 02 · dark | `10:374` | `…?node-id=10-374` |

Every frame is 360 × 600 and every frame's **content height is ≤ 600**, verified programmatically (596–600) — nothing
is clipped. Dark frames are clones carrying an explicit `color`-collection mode override: same nodes, same variables.

Screenshots in this folder: `06-sign-request.png`, `02-home.png`, `06c-dust-only.png`, `00-components.png`.

### Binding 2026-08-19 audit status

The node ids and screenshots above are historical evidence of the current file,
not approved implementation references. Research in
`docs/research/2026-08-19-wallet-ui-extension-mobile.md` found:

- `ConfirmField/Matched` and frame `10:54` incorrectly make a partial-address
  match look like recipient verification. They are **legacy / do not ship**
  until replaced with neutral attention-friction copy and exact-address
  provenance.
- Frame `10:145` and its dark clone incorrectly allow a dust/lookalike block
  to be released by typing characters from the suspicious address. They are
  **legacy / do not ship** until the override starts a fresh trusted-source
  entry, shows a full-address diff, and requires fresh authentication.
- Light-mode `warn` is 2.33:1 on `bg` and 2.19:1 on `surface`. Because its
  rails/dots carry meaningful status, a replacement light warning-indicator
  token must reach at least 3:1 on every permitted background.
- The existing `NavBar` treats Send and Swap as destinations. Replace it with
  Home / Activity / Protect / Settings plus a separate Send / Receive / Swap
  action dock.

No Figma node or exported token was changed by this documentation audit. Use an
explicit Figma edit lease and record replacement node ids, native-size captures,
and contrast measurements here.

## Components (page `9:86`)

| Component | node id | variants / notes |
|---|---|---|
| Button | `9:203` | `Primary` · `PrimaryDisabled` · `Secondary` · `SecondaryDisabled` · `Destructive`. Disabled is a **different surface**, not dimmed text: `surface` fill + hairline stroke + `muted` label + no shadow. 44 px, radius 8 |
| Amount | `9:210` | `Sign=Out` · `In` · `Muted`. Mono, tabular by construction, U+2212 minus. **No semantic colour** — see the colour rule below |
| AddressChip | `9:211` | mono `first4…last4` + copy affordance |
| TrustMark | `9:228` | `Known` · `FirstTime` · `DustOnly`. Semantic dot + **sentence-case Inter 12** label in `ink`. Not a filled badge |
| PolicyVerdict | `9:244` | `Within` · `NeedsPasskey` · `Blocked`. 2 px semantic rail + `ink` title + `muted` detail |
| ConfirmField | `9:260` | **Legacy / redesign required.** `State=Incomplete` and `State=Matched` currently imply a first-4/last-4 identity gate. A replacement may provide neutral attention friction only; matching cannot use an ok dot, establish trust, lower risk, or release a poisoning block |
| Meter | `9:261` | label left / value right, then a 4 px hairline-outlined track with an `accent` fill |
| BalanceRow | `9:267` | symbol / name / amount / fiat |
| Divider | `9:274` | 1 px hairline |
| NavBar | `9:275` | **Legacy / redesign required.** Current Home / Send / Swap / Activity conflates destinations and actions. Target: Home / Activity / Protect / Settings; separate ActionDock: Send / Receive / Swap |
| Sheet | `9:288` | bottom sheet, modal shadow tier |

## The colour rule (added in review round 1)

**Semantic hues (`ok` / `warn` / `critical`) are used for rails, dots and meter fills — never for text.**
Two reasons, in order of weight:

1. **Contrast.** Measured against `--w-surface` in light mode: `warn` = **2.19:1**, `ok` = **3.23:1**,
   `critical` = 4.55:1. Against dark `surface`, `critical` = 3.58:1. Coloured status *text* therefore fails WCAG AA
   (4.5:1) in the majority of the places it would appear. Rails/dots may carry status only when they independently
   reach WCAG's 3:1 non-text contrast threshold; current light `warn` does not and must be replaced before export.
2. **Restraint.** Doctrine §2 uses a semantic hue "as dot, not wash". A wallet that paints every outgoing amount red
   is a casino; a wallet that paints only *authority changes, blocked verdicts and poisoning* red is an instrument.

Consequences:

- Ordinary outgoing amounts (`−0.2500`) are **`ink`**; the sign is carried by the U+2212 glyph, not by hue.
- `critical` appears in exactly three places: the authority-change rail (06b), the blocked-verdict rail (06b), and the
  poison rail + dust dot + "Block and report" stroke (06c).
- A revised light warning-indicator token will appear on the pending-timelock
  rail, first-time-recipient dot, and needs-passkey rail only after measuring at
  least 3:1 on each allowed background.
- `ok` appears on independently evidenced positive state such as
  session-unlocked. It must not appear merely because displayed recipient
  characters matched.

## Variable collections

### `color` — modes `Light` / `Dark` (`VariableCollectionId:1:2`)

| Variable | Light | Dark | CSS token |
|---|---|---|---|
| `bg` | `oklch(97% 0.008 85)` (bone) | `oklch(14% 0.02 260)` (midnight) | `--w-bg` |
| `surface` | `oklch(95% 0.008 85)` | `oklch(18% 0.02 260)` | `--w-surface` |
| `ink` | `oklch(22% 0.008 250)` | `oklch(92% 0.006 90)` | `--w-ink` |
| `muted` | ink @ **68 %** alpha | ink @ **68 %** alpha | `--w-muted` |
| `hairline` | `oklch(0% 0 0 / .06)` | `oklch(100% 0 0 / .08)` | `--w-hairline` |
| `accent` | `oklch(50% 0.12 270)` | `oklch(62% 0.12 270)` | `--w-accent` |
| `ok` | `oklch(60% 0.12 150)` | same | `--w-ok` |
| `warn` | `oklch(72% 0.14 75)` | same | `--w-warn` |
| `critical` | `oklch(55% 0.16 25)` | same | `--w-critical` |

`muted` was raised from 55 % to **68 %** alpha in review round 1. Measured contrast:

| | on `bg` | on `surface` |
|---|---|---|
| light (`#5F6161` / `#5D5F5F` flattened) | 5.73:1 | 5.58:1 |
| dark (`#9E9E9E` / `#A0A1A1` flattened) | 7.45:1 | 7.26:1 |

At 55 % it measured 3.78:1 / 3.72:1 in light — below AA. 68 % clears AA with margin while still reading a full step
below `ink`.

Only `accent` is a brand chroma above 0.10; `ok`/`warn`/`critical` are semantic status hues the spec (§9) separates
from the accent, and per the rule above they never appear as chrome or as text.

**Pending Figma-first correction:** do not export the current light `warn` for
meaningful rails/dots. Add a semantic indicator role with Light/Dark/High
Contrast modes, measure it against every allowed background, and export the
Figma variables plus generated token files together.

Figma variables are sRGB, so the documented OKLCH intent was converted and the sRGB result is what Figma stores:
bg `#F8F5EF` / `#050911`, surface `#F1EEE9` / `#0C121A`, ink `#181B1E` / `#E6E4E0`, accent `#495DA7` / `#6A81CE`,
ok `#439458`, warn `#D79628`, critical `#BD413F`. **Figma variables are the design source of truth**; generated
`tokens.css` must be exported from them, never hand-authored in the reverse direction. The hex values are the actual
Figma storage values and the OKLCH notation documents authoring intent.

### `type` (`VariableCollectionId:1:12`)

`font-ui` = `Inter` · `font-mono` = `JetBrains Mono`.
UI sizes 13 / 15 / 17 / 22 / 28 with line-heights 16 / 20 / 24 / 28 / 36 (4 px baseline grid).
Mono sizes 12 / 13 with line-heights 16 / 20. Inter is tracked at −1.1 %; mono is untracked.

**Mono is reserved for amounts, addresses, hashes, tickers and timestamps.** Operational prose — fee labels, recipient
warnings, policy detail, meter labels, nav labels — is sentence-case Inter at 12–13 px. The only all-caps mono left is
the numbered chapter mark (`WHAT CHANGES`, `RECIPIENT`, `BALANCES`), at 11 px / +12 % tracking, per doctrine §3.6.

### `space` (`VariableCollectionId:1:29`)

`s-4 · s-8 · s-12 · s-16 · s-24 · s-32 · s-48` → `--w-s-*`. Rungs above 48 are skipped for a 360 px popup.

### `radius` (`VariableCollectionId:1:37`)

`card-tl` = 12 · `card-tr` = 12 · `card-br` = **4** · `card-bl` = 12 — i.e. `12px 12px 4px 12px`, **the one deliberate
imperfection**; every card in every screen carries it, and it exports as the single `--w-radius-card` token.
Also `pill` = 999 · `chip` = 4 · `control` = 8 (buttons, ConfirmField, Cancel).

### Motion (documented here, not animated in Figma)

`--ease-out: cubic-bezier(.16,1,.3,1)` · `--ease-emph: cubic-bezier(.2,0,0,1)` ·
`--dur-ack: 120ms` (button press, ConfirmField character echo) · `--dur-reveal: 240ms` (sheet, verdict expansion).

### Shadow tiers

surface = none · raised = `0 1px 2px /5 %` + `0 8px 24px /6 %` (the popup, the enabled primary button) ·
modal = `0 24px 48px /18 %` (Sheet only). Three tiers, no more. `PrimaryDisabled` deliberately has **no** shadow — the
elevation itself is part of the enabled/disabled signal.

---

## Screen notes

### 06 — sign request / intent

Target reading order is origin → decoded intent → what changes now → continuing
authority → independent origin/decode/simulation/policy evidence → cost/timing
and stop path → an effect-specific decision.

- **Origin header** — mark, host, connection age, and the key that will sign, so the user knows *which* key is acting.
- **What changes** — per-token diff from simulation in `ink` mono, with fiat, network fee and resulting balance under a
  hairline. One number is the hero; everything else is 12 px.
- **Recipient** — full Base58 address in mono plus exact-address provenance,
  source, first/last genuine use, and a full character-level diff when a
  lookalike exists.
- **Evidence** — origin, decode, simulation, and on-chain policy remain four
  independent axes; no axis turns another green.
- **Partial-address typing (legacy correction)** — current `ConfirmField` and
  `06a` (`10:54`) are not approved references. Matching first/last characters
  does not verify a recipient. If the replacement retains typing as attention
  friction, its matched copy is “Displayed characters matched. Recipient
  identity is still unverified.” It remains neutral and cannot establish
  provenance or lower risk.
- **Actions** — primary reads "Send 0.25 SOL to 7f3k…q9Lm"; secondary is "Reject".

### 06b — blocked (authority change)

Authority changes lead the screen, above the balance diff, because the balance diff is *zero* — the whole point is that
simulation shows no loss today. Critical rail, `ink` title, blocked verdict, and no approve path at all: the actions are
"Reject and block origin" and "Show raw instructions".

### 06c — dust-only recipient (address poisoning)

The poison case gets its own blocking treatment rather than a trust label alone:

- A `critical`-railed banner leads: "This address only ever sent you dust", with how it entered the history and why it
  looks like the address the user actually uses.
- The recipient card shows the poisoned address, the `DustOnly` `TrustMark`, and the **address the user actually sends
  to** for comparison — the single most useful thing the wallet can show here.
- The primary action is inverted: destructive **"Block and report this
  address"**.
- The current escape hatch that unlocks when `ConfirmField` matches is
  superseded. A replacement expert path begins a fresh recipient entry from a
  trusted source, shows the full-address comparison, requires fresh
  authentication, and remains subject to policy/timelock. Copying characters
  from the suspicious address never releases the block.

### 02 — home

Shows the account's safety state before it shows its money.

- Total held is the SOL figure the RPC actually returned; the fiat line reads `— USD unavailable — no price feed` and
  every per-row fiat is `—`. The screen is designed around the failure case so it cannot lie (doctrine §3.7).
- Session card: unlocked + minutes left, then per-mint remaining caps as **`Meter`** instances — label above, value
  right-aligned, and a 4 px hairline-outlined track with an accent fill underneath. (In round 0 these were 2 px bars
  sitting directly under their labels and read as text underlines.)
- Pending: the timelocked transfer with a mono countdown and an in-place Cancel. The cancel window is the product
  promise, so it is on the first screen, not buried in Activity.

---

## Target file structure and remaining design scope

The expansion plan is
`docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md`; research and
the complete state matrix are in
`docs/research/2026-08-19-wallet-ui-extension-mobile.md`.

Target pages:

1. `00 Foundations`
2. `01 Components`
3. `02 Extension`
4. `03 Mobile iOS`
5. `04 Mobile Android`
6. `05 Prototypes`
7. `06 Adversarial states`
8. `07 Research evidence`
9. `99 Archive`

Still undesigned: **01** onboarding, **02A** Activity, **03** Receive,
**04** Send, **05** Swap, **07** Connect, **08** Protect/Policy,
**09** Sessions & Devices, **10** Guardians & Recovery, and
**11** Settings/Trust. Also missing are popup/side-panel/dedicated-approval/
full-tab responsive variants; iOS and Android; complete security-evidence,
financial, navigation, ceremony, and feedback components; keyboard/focus;
loading/offline/stale/partial/error/interruption; top-20 dApp compatibility;
large text/zoom; RTL/pseudolocale; reduced motion; high contrast; and a `Sheet`
used in situ.

## 2026-08-20 — "Fable — Receipt Exploration" page (additive, unreviewed)

New page `Fable — Receipt Exploration` (`12:158`) explores the U4 Warden Receipt as a
"stamped instrument": four independent railed evidence seal-cells (origin / decode /
simulation / policy — separate fills, separate rails, no shared verdict), numbered
receipt chapters, and a request-fingerprint barcode band derived from the digest.
Frames are **exploration, not replacements** — the audited `Screens` frames are untouched.
Legacy `ConfirmField`/`NavBar` are deliberately not instantiated; `Button` instances are.

| Frame | light | dark |
|---|---|---|
| R-06 Receipt / transfer to known recipient (360×600) | `16:2` | `22:3` |
| R-06a Receipt / first-seen recipient — attention check typed | `17:4` | `22:103` |
| R-06b Receipt / authority change — blocked | `18:6` | `22:204` |
| R-06c Receipt / dust lookalike — blocked | `18:98` | `22:294` |
| R-06W Receipt / approval window — request-bound (720×600) | `19:10` | `22:378` |
| 02H Home v2 / protect-first + action dock | `23:22` | `24:2` |

Deep links: `…/design/GOBwNsRgT5I36H2oGjfSbi?node-id=<id with ':'→'-'>`.
Designer's note card on the page: `24:90`. All content bounds verified ≤600 (589–600),
zero horizontal text overflows, both modes (programmatic check 2026-08-20).

**New variable:** `color/warn-ind` (`VariableID:12:159`) — warning *indicator* for rails/dots.
Light `#A87005`: **3.87:1 on bg, 3.64:1 on surface** (clears the 3:1 non-text minimum with margin);
Dark `#D79628`: 7.86:1 / 7.41:1. Used for first-time-recipient dot, passkey+hold policy rail,
pending-timelock rail. `warn` itself is untouched and still must not be used as a light-mode
indicator. Not yet exported to `packages/ui-tokens` (export still gated on U0–U2 acceptance).

Security semantics in these frames follow the 2026-08-19 binding corrections: the typed
check reads "Characters matched — identity still unverified" with no ok dot and no gate
release; R-06c blocks by default, shows the full THEIRS/YOURS address comparison with the
matching ends emphasized and differing middle dimmed, and its secondary action is
"Start over from a trusted source" (fresh entry + passkey; typing never releases the block);
R-06b has no approve path. Evidence axes never merge; R-06b/R-06c deliberately show
green simulation/decode next to a blocked policy.

## Process note

The Figma MCP asks that `/figma-use` be loaded before `use_figma`. That skill is **not installed** in this environment
(`Skill` returns `Unknown skill: figma-use`) and the fallback resource `skill://figma/figma-use/SKILL.md` could not be
read (no MCP resource-reading tool is exposed to this agent). The work followed the guidance embedded in the tool
descriptions instead. Gotchas worth recording:

1. `PageNode` has `backgrounds`, not `fills`.
2. `resize()` on an auto-layout frame flips **both** sizing modes to `FIXED`. For "fixed width, hug height" you must
   re-set the modes *after* resizing — `VERTICAL` → `counterAxisSizingMode = FIXED; primaryAxisSizingMode = AUTO`;
   `HORIZONTAL` → the reverse. Getting this wrong collapses every card to the placeholder height silently.
3. `counterAxisAlignItems` has no `STRETCH`; use `layoutSizingVertical = "FILL"` on the child instead.
4. A frame fixed at 600 px with a `layoutGrow: 1` body will happily overflow and clip without any error. To check for
   overflow, set the frame back to `AUTO` (and the body to `layoutGrow: 0`), read `height`, then restore.
5. `get_screenshot` only downscales — `maxDimension` above the node's natural size returns 1×.

## Landing facelift lease — 2026-09-04 (page `26:2` "Landing — Facelift 2026-09-04")

Explicit Figma edit lease (owner request: "eyeball wardenwallet.io and give it a facelift using the figma mcp").
Additive page only — Components / Screens / Receipt Exploration untouched; no variables changed.

| Node | id | notes |
|---|---|---|
| Designer's note | `35:2` | direction, palette, honesty guard — read first |
| L-01 desktop 1440 | `27:2` | header · hero + build receipt (484 px, 1.2°) · paper "What we're building" with 01→02→03 custody flow · dark "Watch it get built" ledger rows · footer |
| L-01m mobile 390 | `34:2` | same content stacked; status strip vertical; CTAs full-width; receipt labels shortened |
| BEFORE desktop / mobile | `33:2` / `33:3` | live wardenwallet.io captures 2026-09-04 (scroll-reveal forced) |

Palette: midnight `#0B0F17` / surface `#121722` / ink `#E8E6E1` / muted `#A3A8B2` / steel `#B3B8BE` (achromatic — the mark is
brushed steel) / bone `#F8F5EF` / ivory `#EFECE5` / ink-on-paper `#1B1E24` / **one accent = design-system indigo**
`#6A81CE` dark, `#495DA7` light. Type: Newsreader (display + true italic), Inter (UI), JetBrains Mono (ledger) — all already
self-hosted on the live site. Receipt counts read from the repo at `cc19ce3` (2026-09-03): invariants 66/100 test-covered,
review runs 142, findings 286 (16 critical), Rust 697, client 729 + 704 = 1,433. Re-read `docs/security/*.jsonl` before building.
Renders: `docs/design/brand/landing-v3-desktop.png`, `landing-v3-mobile.png`.

**SHIPPED 2026-09-04** to `/var/www/wardenwallet/index.html` (backup `index.html.bak-<ts>-v2` beside it). Source copy:
`docs/design/brand/landing-v3.html`; browser proofs `landing-v3-browser-1440.png` / `-360.png`. Receipt first shipped pinned to the then-public head `6d714b2`; after the same-day push (phase1b → `0404300`) it was
bumped to `0404300` (66/100 · 142 · 286 · 16 · Rust 697 · client 1,433) and redeployed. Refresh procedure is in the HTML head comment.
