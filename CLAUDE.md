# Warden Wallet — repo directives
- Spec: docs/superpowers/specs/2026-08-18-warden-wallet-design.md (rev 5). Plans: docs/superpowers/plans/.
- Never import from spikes/ into packages/ or apps/. Spikes are throwaway evidence.
- Heavy Rust builds are serialized on this host; never run two cargo builds at once.
- Amount math in Rust: checked_* only. TS: bigint for lamports/token amounts.
- Design tokens come from Figma (docs/design/figma.md) → packages/ui-tokens; do not hand-edit tokens.css.
- Codex reviews: spec, each program milestone, pre-deploy diff (see /opt/docs/CODEX-USAGE-DOCTRINE.md).
