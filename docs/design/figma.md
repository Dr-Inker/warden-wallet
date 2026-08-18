# Warden Wallet — design foundation (Figma)

**File:** [Warden Wallet — design system](https://www.figma.com/design/GOBwNsRgT5I36H2oGjfSbi/Warden-Wallet-%E2%80%94-design-system)
`fileKey = GOBwNsRgT5I36H2oGjfSbi` · owner `Dr. Inker` (`team::1660993652229402605`) · created 2026-08-18.

Doctrine followed: `/opt/drinkerlabs/DESIGN.md` (ten principles, OKLCH-only colour, one accent, Inter + JetBrains Mono,
hairlines, tabular numerals, three shadow tiers, one deliberate imperfection, sentence-case operator voice).
Product context: `docs/superpowers/specs/2026-08-18-warden-wallet-design.md` §6 (intent view) and §9 (UI/brand).

Tokens are authored **here** and exported by hand to `packages/ui-tokens/`. Per repo `CLAUDE.md`: do not hand-edit
`tokens.css` — change the Figma variable, then re-export both files together and update the table below.

---

## Pages and node ids

| Page | node id |
|---|---|
| Components | `4:3` |
| Screens | `7:2` |

| Frame | node id | deep link |
|---|---|---|
| 06 — Sign request / intent (light) | `7:3` | `…/design/GOBwNsRgT5I36H2oGjfSbi?node-id=7-3` |
| 06b — Sign request / blocked, authority change (light) | `7:42` | `…?node-id=7-42` |
| 02 — Home (light) | `7:79` | `…?node-id=7-79` |
| 06 — Sign request / intent · dark | `7:159` | `…?node-id=7-159` |
| 02 — Home · dark | `7:190` | `…?node-id=7-190` |
| 06b — Sign request / blocked · dark | `7:242` | `…?node-id=7-242` |

Popup frame size is 360 × 600 for every screen. The dark frames are clones with an explicit `color` collection mode
override — same nodes, same variables, no duplicated colour values.

Screenshots in this folder: `06-sign-request.png`, `02-home.png`, `00-components.png` (component sheet).

## Components (page `4:3`)

| Component | node id | variants |
|---|---|---|
| Button | `4:10` | `Variant=Primary` / `Secondary` / `Destructive` — 44 px, radius 8, ack 120 ms + emphasis easing (documented, not animated in Figma) |
| Amount | `4:17` | `Sign=Positive` / `Negative` / `Neutral` — JetBrains Mono (inherently tabular), sign-coloured, U+2212 minus |
| AddressChip | `4:18` | mono `first4…last4` + copy affordance |
| TrustMark | `4:32` | `Trust=Known` / `FirstTime` / `DustOnly` — dot + mono all-caps, **not** a filled badge (doctrine §5.11) |
| PolicyVerdict | `4:48` | `Verdict=Within` / `NeedsPasskey` / `Blocked` — 2 px semantic rail + title + reason |
| BalanceRow | `4:49` | symbol / name / amount / fiat, hug height |
| Divider | `4:56` | 1 px hairline |
| NavBar | `4:57` | Home / Send / Swap / Activity, active = accent underline |
| Sheet | `4:70` | bottom sheet, modal shadow tier |

## Variable collections

### `color` — modes `Light` / `Dark` (`VariableCollectionId:1:2`)

| Variable | Light | Dark | CSS token |
|---|---|---|---|
| `bg` | `oklch(97% 0.008 85)` (bone) | `oklch(14% 0.02 260)` (midnight) | `--w-bg` |
| `surface` | `oklch(95% 0.008 85)` | `oklch(18% 0.02 260)` | `--w-surface` |
| `ink` | `oklch(22% 0.008 250)` | `oklch(92% 0.006 90)` | `--w-ink` |
| `muted` | ink @ 55 % alpha | ink @ 55 % alpha | `--w-muted` |
| `hairline` | `oklch(0% 0 0 / .06)` | `oklch(100% 0 0 / .08)` | `--w-hairline` |
| `accent` | `oklch(50% 0.12 270)` | `oklch(62% 0.12 270)` | `--w-accent` |
| `ok` | `oklch(60% 0.12 150)` | same | `--w-ok` |
| `warn` | `oklch(72% 0.14 75)` | same | `--w-warn` |
| `critical` | `oklch(55% 0.16 25)` | same | `--w-critical` |

Only `accent` carries chroma > 0.10 as *the* brand accent; `ok`/`warn`/`critical` are semantic status hues that the
spec (§9) separates from the accent, and they never appear as nav or surface chrome.

Figma variables are sRGB, so the OKLCH values above were converted once and the sRGB result is what Figma stores:
bg `#F8F5EF` / `#050911`, surface `#F1EEE9` / `#0C121A`, ink `#181B1E` / `#E6E4E0`, accent `#495DA7` / `#6A81CE`,
ok `#439458`, warn `#D79628`, critical `#BD413F`. **OKLCH in `tokens.css` is the source of truth**; the hex is a
lossy render for tooling that cannot do OKLCH.

### `type` (`VariableCollectionId:1:12`)

`font-ui` = `Inter` · `font-mono` = `JetBrains Mono`
UI sizes 13 / 15 / 17 / 22 / 28 with line-heights 16 / 20 / 24 / 28 / 36 (all on the 4 px baseline grid).
Mono sizes 12 / 13 with line-heights 16 / 20. Inter is tracked at −1.1 %; mono is untracked.
All-caps chapter marks are mono 10 px at +12 % tracking, `muted`.

### `space` (`VariableCollectionId:1:29`)

`s-4 · s-8 · s-12 · s-16 · s-24 · s-32 · s-48` → `--w-s-*`. Rungs above 48 are deliberately skipped for a 360 px popup.

### `radius` (`VariableCollectionId:1:37`)

`card-tl` = 12 · `card-tr` = 12 · `card-br` = **4** · `card-bl` = 12 — i.e. `12px 12px 4px 12px`, **the one deliberate
imperfection**; every card in both screens carries it, and it exports as the single `--w-radius-card` token.
Also `pill` = 999 · `chip` = 4 · `control` = 8 (buttons, Cancel).

### Motion (documented here, not animated in Figma)

`--ease-out: cubic-bezier(.16,1,.3,1)` · `--ease-emph: cubic-bezier(.2,0,0,1)` ·
`--dur-ack: 120ms` (button press / focus) · `--dur-reveal: 240ms` (sheet, verdict expansion).

### Shadow tiers

surface = none · raised = `0 1px 2px /5 %` + `0 8px 24px /6 %` (the popup itself, primary button) ·
modal = `0 24px 48px /18 %` (Sheet only). Three tiers, no more.

---

## Screen notes

**06 — sign request / intent** is the product. Reading order top → bottom is origin → what changes → who receives it →
what the policy will do → the button that says exactly what it does:

- **Origin header** — favicon mark, host, connection age, and the signing key, so the user knows *which* key is about to
  sign. Hairline bottom edge, no chrome.
- **What changes** — per-token balance diff from simulation, mono and sign-coloured, with the fiat value and, under a
  hairline, the fee and the resulting balance. One number is the hero; everything else is 11 px muted mono.
- **Recipient** — the full base58 address in mono plus a `TrustMark`. First-time and dust-only are the two states that
  matter; dust-only is the poisoned-address warning and is `critical`.
- **Policy verdict** — the on-chain answer, not a warning the user can click through: *within limits* /
  *needs passkey + delay* / *blocked (why)*.
- **Actions** — primary reads "Send 0.25 SOL to 7f3k…q9Lm"; secondary is "Reject". On the blocked variant the primary
  slot is destructive ("Reject and block origin") and the only other action is "Show raw instructions" — there is no
  path to approve a blocked action from this screen.

**02 — home** shows the account's safety state before it shows its money:

- Total held is the SOL number the RPC actually returned; the fiat line is `—` with `PRICE FEED UNAVAILABLE`, and the
  per-row fiat is `—` to match. This is the doctrine's "live state as ornament / never fake it" rule made literal — the
  screen is designed around the failure case so it cannot lie.
- Session card: unlocked + minutes left, then remaining caps per mint with a hairline meter.
- Pending: the timelocked transfer with a mono countdown and an in-place Cancel — the cancel window is the product
  promise, so it is on the first screen, not buried in Activity.

---

## Not yet designed

Screens **01** onboarding (incl. the one Tiempos-italic hero phrase §9), **03** receive, **04** send, **05** swap,
**07** connect, **08** policy, **09** sessions & devices, **10** guardians & recovery, **11** settings/trust.
Also missing: full-page (expanded tab) variants, empty/error/loading states beyond the `—` case, focus and hover
states, the top-20 dApp-compat surface (§12.4), and a `Sheet` used in situ.

## Process note

The Figma MCP asks that `/figma-use` be loaded before `use_figma`. That skill is **not installed** in this environment
(the `Skill` tool returns `Unknown skill: figma-use`) and the fallback resource `skill://figma/figma-use/SKILL.md`
could not be read (no MCP resource-reading tool is exposed to this agent). The work was done following the guidance
embedded in the tool descriptions instead. Two gotchas cost a rebuild each and are worth recording:

1. `PageNode` has `backgrounds`, not `fills`.
2. `resize()` on an auto-layout frame flips **both** sizing modes to `FIXED`. For "fixed width, hug height" you must
   re-set the modes *after* resizing — `VERTICAL` → `counterAxisSizingMode = FIXED; primaryAxisSizingMode = AUTO`;
   `HORIZONTAL` → the reverse. Getting this wrong collapses every card to the placeholder height silently.
3. `counterAxisAlignItems` has no `STRETCH`; use `layoutSizingVertical = "FILL"` on the child instead.
