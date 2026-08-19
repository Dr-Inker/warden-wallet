# Third-party notices

Generated 2026-08-19 from two tool runs against the workspace as it stood at
this commit — **not hand-curated**, so it is exactly as complete/stale as
`Cargo.lock`/`pnpm-lock.yaml` are. Regenerate on any dependency change with
the two commands below; this file is evidence, not a hand-maintained legal
document.

```sh
cargo deny list                 # Rust — license -> crate@version, from Cargo.lock
pnpm licenses ls                # TypeScript — package -> license, from pnpm-lock.yaml
```

Full raw output of both commands as run 2026-08-19 is kept alongside the
Task 11 fix report (`.superpowers/sdd/2026-08-18-warden-phase1b-execute-swap/task-11-report.md`,
"Fix report — round 1").

## Rust (`cargo deny list`, root workspace: `programs/warden`, `programs/test-middleman`)

Every license below is on `deny.toml`'s `[licenses] allow` list, or is one
term of a dual/multi-license crate that is satisfiable by an allowed term
(cargo-deny accepts an OR-expression if any one alternative is allowed —
e.g. `r-efi` is `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the LGPL term is
listed below only because `cargo deny list` enumerates every SPDX term of
every crate's expression, not because this repo is relying on the LGPL
term). `cargo deny check` (run 2026-08-19, see the fix report) confirms
`licenses ok` — nothing here needs the LGPL/Unlicense/BSD-1-Clause terms
to pass; MIT or Apache-2.0 alone would clear every crate in this graph.

| License | Crates (name@version) |
| --- | --- |
| Apache-2.0 | 159 crates — the full Anchor/Solana/Agave stack (`anchor-lang`, `solana-*`, `borsh`, `serde`, etc.) |
| Apache-2.0 WITH LLVM-exception | `wasi`, `wasip2`, `wit-bindgen` |
| BSD-1-Clause | `fiat-crypto` (dual-licensed; also MIT) |
| BSD-2-Clause | `zerocopy` |
| BSD-3-Clause | `curve25519-dalek@4.1.3`, `subtle` |
| LGPL-2.1-or-later | `r-efi` (dual/triple-licensed; MIT and Apache-2.0 terms also apply and are what satisfies the gate) |
| MIT | 112 crates, including `warden@0.1.0` and `test-middleman@0.1.0` themselves (both now carry `license = "MIT"`, matching the repo root `LICENSE`) |
| Unicode-3.0 | `unicode-ident` |
| Unlicense | `memchr` (dual-licensed; also MIT) |
| Zlib | `bytemuck`, `bytemuck_derive` |

**No AGPL or GPL term appears anywhere in the Rust dependency graph.** This
is the discharge of spec §16's reuse-policy constraint for the *dependency*
axis: Swig and Squads v4 (AGPL-3.0) and Backpack (GPL-3.0) are reference-only
prior art per spec §16 and are not, and must never become, Cargo
dependencies of this workspace; the standing review-prompt item in spec §16
("does this diff reproduce structure, naming or comments recognisably from
Swig/Squads/Backpack?") covers the *code-reuse* axis, which this
license-scanner file cannot check.

## TypeScript (`pnpm licenses ls`, whole pnpm workspace incl. `spikes/*/ts`)

Overwhelmingly MIT/Apache-2.0/BSD/ISC, consistent with the Rust side. Two
entries need a human note, both transitive (neither authored by, nor a
direct dependency of, this repo):

| Package | License | Where it comes from | Note |
| --- | --- | --- | --- |
| `rpc-websockets@9.3.9` | **LGPL-3.0-only** | Transitive dependency of `@solana/web3.js` (its RPC WebSocket client) | LGPL, not AGPL/GPL — the FSF's weak-copyleft license with a dynamic-linking exception. This is an npm runtime dependency loaded at module-resolution time, not statically linked C/C++, so the boundary LGPL's copyleft cares about (static linking into a derivative binary) does not obviously apply the way it would for the AGPL/GPL prior art spec §16 flags — but this is **not** a legal conclusion, only a factual note. Flag for the extension-bundle work (Phase 2, spec §17 L9's extension-side half): if the CWS bundle is built as a single statically-linked artifact rather than an npm dependency tree, re-evaluate. |
| `text-encoding-utf-8@1.0.2` | **Unknown** (no machine-readable `license` field; `pnpm licenses ls` could not classify it) | Transitive dependency of `borsh@0.7.0`, itself pulled in by `@solana/web3.js` | The published package has no SPDX `license` field for the tool to read. A manual check of the package's own repository/README is needed before this can be marked anything but "unknown" here — not done in this pass (Task 11 is a scan, not a per-package manual audit). Flag for the same Phase 2 extension-bundle review as `rpc-websockets`. |

Neither package is a *direct* dependency declared in any `package.json` in
this repo — both arrive transitively through `@solana/web3.js`, which is
itself the de facto standard Solana JS client. Swapping either out would
mean forking or patching `@solana/web3.js`'s dependency tree, which is out
of scope for Task 11 (tooling/docs) and arguably out of scope before the
extension bundle (Phase 2) actually exists to care about its final shipped
license posture.

## Open items

- `rpc-websockets` (LGPL-3.0-only) and `text-encoding-utf-8` (unknown
  license) — re-evaluate at Phase 2 when the extension bundle's actual
  build/link shape (webpack/esbuild single-file bundle vs. npm tree) is
  decided; see table above.
- This file is **generated, not hand-curated** — regenerate it (rerun both
  commands, re-paste) on every `Cargo.lock`/`pnpm-lock.yaml` change that
  Task 11's or a successor's review cares about; it will silently go stale
  otherwise.
