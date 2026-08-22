# Warden landing page — independent critique (Claude), 2026-08-22

Source: drinkerlabs.info/warden/ (index.html, 798 lines). Screenshot: landing-before.png.
Standing rule: harshest critic; premium bar. This is the Claude half of the dual critique
(Codex runs its own; then we compare notes).

## Verdict in one line
**A-tier copy trapped in a C-tier visual system.** The writing is honest, sharp, and
uniquely on-brand for a "shows its work" security wallet. The design hides behind grey
minimalism to avoid the work of real visual craft — minimal is not the same as premium.

## What is genuinely good (keep, do not lose in the redesign)
- **Voice/positioning.** "A wallet that shows its work." / "A default keypair wallet is
  one signature from empty." / "Unknown is a first-class state." This is the soul of the
  page. Preserve near-verbatim.
- **The receipt thesis.** "Approvals, redesigned as a receipt" + the 01–07 evidence-axis
  grid is the product's actual differentiator, expressed in copy.
- **Radical honesty table** (In Build / Design / Research / Not Yet / None). Rare and
  trust-building for a wallet. Keep — but make it a designed centerpiece, not a footer.
- **Type pairing.** Serif display + mono labels is distinctive and correct for the brand.

## Harshest critique (what a premium bar demands we fix)
1. **Monochrome, zero brand color.** The shield logo is navy + bronze/gold; the page is
   a single flat grey. The brand identity is never expressed. Biggest miss.
2. **The hero receipt is the most important visual and it's cramped and low-fi** — tiny
   text, no depth, doesn't sell the metaphor. It should be a genuine showpiece.
3. **No visual rhythm.** Every section has identical weight (grey bg, black serif). Nothing
   draws the eye; the page reads like an academic paper. Needs alternating treatments,
   a dark hero, the shield as a recurring motif.
4. **Real logos unused.** We brought `warden-logo-mark.jpg` (shield) and
   `warden-logo-lockup.jpg` into the repo; the header still shows a tiny generic "W".
5. **No depth/motion affordance.** For a security product, restrained motion (receipt
   assembling, hover-reveal on evidence axes) would elevate trust and polish.
6. **Density.** The 01–07 grid and architecture cards are text-walls; make them scannable.
7. **Mobile unverified.** Fixed 2-col grids likely collapse awkwardly; must be checked.

## Direction for the upgrade (design-lease brief → Fable + Figma MCP)
- Build a real design system from the brand mark: **navy ground + bronze/gold accent**,
  ideally a **dark hero** (security reads well dark), light body for the honest sections.
- Make the **hero receipt a beautiful, legible, layered artifact** — the money shot.
- Deploy the **actual shield logo**; use the shield as a quiet recurring motif.
- Keep the honest **status table** but promote it to a designed section; **update content
  to true Phase 1B status** (execute + swap DONE; deploy-gate governance/hash checks in
  adversarial review; still not live / not audited / nothing to download).
- Preserve the copy. Add rhythm, color, depth, and one restrained motion beat.
- Verify mobile at 360px and 390px.

## Sequencing
Gated on product convergence (Task 11R → Task 9). Do NOT ship copy that overstates status;
the honesty table is the brand. Route creative execution to Fable under a Figma design
lease (per user doctrine), then eyeball again and run the dual Claude+Codex critique.
