# Warden Wallet — repo directives
- Spec: docs/superpowers/specs/2026-08-18-warden-wallet-design.md (rev 6). Plans: docs/superpowers/plans/.
- Never import from spikes/ into packages/ or apps/. Spikes are throwaway evidence.
- Heavy Rust builds are serialized on this host; never run two cargo builds at once.
- Amount math in Rust: checked_* only. TS: bigint for lamports/token amounts.
- Design tokens come from Figma (docs/design/figma.md) → packages/ui-tokens; do not hand-edit tokens.css.
- Two-model loop: every task is implemented by an isolated worker and adversarially reviewed by Codex before it counts as done; milestones get a security review; pre-deploy diff gets a recon.
- Public repo: never commit keypairs, .env, or anything under .superpowers/; program keypair policy in docs/PROGRAM-KEYS.md.
