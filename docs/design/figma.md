# Warden Wallet — design foundation (Figma)

**File:** [Warden Wallet — design system](https://www.figma.com/design/GOBwNsRgT5I36H2oGjfSbi/Warden-Wallet-%E2%80%94-design-system)
`fileKey = GOBwNsRgT5I36H2oGjfSbi` · owner `Dr. Inker` (`team::1660993652229402605`) · created 2026-08-18, revised
2026-08-18 (review round 1).

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

## Components (page `9:86`)

| Component | node id | variants / notes |
|---|---|---|
| Button | `9:203` | `Primary` · `PrimaryDisabled` · `Secondary` · `SecondaryDisabled` · `Destructive`. Disabled is a **different surface**, not dimmed text: `surface` fill + hairline stroke + `muted` label + no shadow. 44 px, radius 8 |
| Amount | `9:210` | `Sign=Out` · `In` · `Muted`. Mono, tabular by construction, U+2212 minus. **No semantic colour** — see the colour rule below |
| AddressChip | `9:211` | mono `first4…last4` + copy affordance |
| TrustMark | `9:228` | `Known` · `FirstTime` · `DustOnly`. Semantic dot + **sentence-case Inter 12** label in `ink`. Not a filled badge |
| PolicyVerdict | `9:244` | `Within` · `NeedsPasskey` · `Blocked`. 2 px semantic rail + `ink` title + `muted` detail |
| ConfirmField | `9:260` | `State=Incomplete` (accent focus ring, caret, "2 characters left") · `State=Matched` (ok dot, "matches"). The typed first-4/last-4 gate required by spec §6 |
| Meter | `9:261` | label left / value right, then a 4 px hairline-outlined track with an `accent` fill |
| BalanceRow | `9:267` | symbol / name / amount / fiat |
| Divider | `9:274` | 1 px hairline |
| NavBar | `9:275` | Home / Send / Swap / Activity, sentence case, active = accent underline |
| Sheet | `9:288` | bottom sheet, modal shadow tier |

## The colour rule (added in review round 1)

**Semantic hues (`ok` / `warn` / `critical`) are used for rails, dots and meter fills — never for text.**
Two reasons, in order of weight:

1. **Contrast.** Measured against `--w-surface` in light mode: `warn` = **2.19:1**, `ok` = **3.23:1**,
   `critical` = 4.55:1. Against dark `surface`, `critical` = 3.58:1. Coloured status *text* therefore fails WCAG AA
   (4.5:1) in the majority of the places it would appear. The rail carries the same information at full legibility.
2. **Restraint.** Doctrine §2 uses a semantic hue "as dot, not wash". A wallet that paints every outgoing amount red
   is a casino; a wallet that paints only *authority changes, blocked verdicts and poisoning* red is an instrument.

Consequences:

- Ordinary outgoing amounts (`−0.2500`) are **`ink`**; the sign is carried by the U+2212 glyph, not by hue.
- `critical` appears in exactly three places: the authority-change rail (06b), the blocked-verdict rail (06b), and the
  poison rail + dust dot + "Block and report" stroke (06c).
- `warn` appears on the pending-timelock rail (02), the first-time-recipient dot (06) and the needs-passkey rail.
- `ok` appears on the session-unlocked dot (02) and the confirmation-matched dot (06a).

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

Figma variables are sRGB, so the OKLCH values were converted once and the sRGB result is what Figma stores:
bg `#F8F5EF` / `#050911`, surface `#F1EEE9` / `#0C121A`, ink `#181B1E` / `#E6E4E0`, accent `#495DA7` / `#6A81CE`,
ok `#439458`, warn `#D79628`, critical `#BD413F`. **OKLCH in `tokens.css` is the source of truth**; the hex is a lossy
render for tooling that cannot do OKLCH.

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

Reading order is origin → what changes → who receives it → what the policy will do → the gate → the button.

- **Origin header** — mark, host, connection age, and the key that will sign, so the user knows *which* key is acting.
- **What changes** — per-token diff from simulation in `ink` mono, with fiat, network fee and resulting balance under a
  hairline. One number is the hero; everything else is 12 px.
- **Recipient** — full base58 address in mono, plus a `TrustMark`.
- **Policy verdict** — the on-chain answer, not a dismissible warning: within limits / needs passkey + delay / blocked.
- **Typed confirmation (spec §6)** — a `ConfirmField` sits directly above the primary action. Until the typed value
  matches the recipient's first four and last four characters, the primary is `PrimaryDisabled`: a flat `surface`
  rectangle with a hairline and a `muted` label and no elevation — visibly not a button yet. `06a` (`10:54`) is the same
  frame with `State=Matched` and `Variant=Primary`, showing the gate released.
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
- The primary action is inverted: destructive **"Block and report this address"**. The escape hatch,
  "I understand the risk, continue", is a `SecondaryDisabled` and stays disabled until the same `ConfirmField` matches.
  You cannot proceed through a poisoning warning by muscle memory.

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

## Not yet designed

Screens **01** onboarding (incl. the one Tiempos-italic hero phrase §9), **03** receive, **04** send, **05** swap,
**07** connect, **08** policy, **09** sessions & devices, **10** guardians & recovery, **11** settings/trust.
Also missing: full-page (expanded tab) variants, hover/focus states, loading states beyond the `—` case, the top-20
dApp-compat surface (§12.4), and a `Sheet` used in situ.

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
