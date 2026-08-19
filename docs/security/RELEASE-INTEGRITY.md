# Release integrity (spec §17, L7/L9)

**Status:** UNVERIFIED beyond the one dev row below — no tagged release exists yet.

This document is the addressable record `scripts/deploy-gate.sh` checks against
(spec §17 item L7, plan Task 11 item 5): for every release SHA that is a
deploy candidate, this table's row for that SHA must carry the artifact hash
that was reviewed, and the deploy gate refuses to proceed on any mismatch.

## The limit, stated up front

A matching hash proves **the artifact deployed is the artifact that was
reviewed** — it does not prove the artifact is safe. `solana-verify` (or
`anchor build --verifiable`) is a **release gate, not assurance**: Accretion
has published a defeat of the verifiable-build pipeline (reproducible build
tooling can itself be fooled by build-environment differences that don't
change program behavior in the attacker's favor, or by a compromised build
step upstream of the hash). Treat a green row here as "we can prove what
shipped," not as "an audit says it's safe" — the audit is a separate, later
gate (§17 L7, spec §10/§11).

## Reproducible-build recipe

Toolchain versions are pinned exactly as recorded in `docs/TOOLCHAIN.md`:

| Tool | Pinned version |
| --- | --- |
| rustc / cargo | `1.97.1` (rustup `stable` channel, as resolved 2026-08-18) |
| Solana CLI (Agave) / `cargo-build-sbf` | `3.1.10` (platform-tools v1.52) |
| Anchor CLI (`avm`) | `1.1.2` |

Build command, from a clean checkout at the release tag:

```sh
git checkout <release-tag>
anchor build
sha256sum target/deploy/warden.so
```

**`anchor build --verifiable` — checked read-only, not yet adopted.**
`anchor build --help` (Anchor CLI `1.1.2`, checked 2026-08-19) advertises a
`-v, --verifiable` flag ("build artifact needs to be deterministic and
verifiable"), plus `--solana-version` and `--docker-image` flags that only
apply to `--verifiable` builds, and a `--bootstrap` flag to build the Docker
image from scratch. So Anchor 1.1.2 **does** support `--verifiable`
mechanically. It was **not run** for this task (Task 11 is tooling/docs only;
another agent owns the Rust build, and a Docker-based verifiable build is a
second build of the program, which is out of scope here and would race the
in-flight build). Adopting it is an open item for whichever task first cuts a
real release tag — see the row below for the interim, non-verifiable
`sha256sum` recipe that this repo actually exercises today.

**Fallback / cross-check tool: `solana-verify`.** Not installed on this host
(`command -v solana-verify` → not found, checked 2026-08-19). When adopted,
`solana-verify build` (mirrors `anchor build --verifiable` via a pinned
Docker image) and `solana-verify get-program-hash --url <rpc> <program-id>`
(reads the **on-chain** program's hash directly, independent of a local
build) are the two commands this table's "solana-verify output" column
records. Until then, the "solana-verify output" column reads UNVERIFIED —
no on-chain deployment exists to check yet.

## Per-release table

| Tag / label | Git SHA | `warden.so` SHA-256 | Program ID | `solana-verify get-program-hash` | Upgrade authority | Squads proposal | Toolchain (Anchor / cargo-build-sbf / rustc) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dev, unreleased | `26a8c1e45daa5ee57c76f3004294b1cbaa87a542` (working tree at Task 11, phase1b branch — **not itself a clean tag**, see caveat below) | `d1e1baf9767d9d98c7179ea3c378ce5a0463d0f506513588ea2d7e1373ba7950` | `6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2` | UNVERIFIED — not deployed on-chain, `solana-verify` not installed | UNVERIFIED — not deployed | none — no multisig configured yet (devnet or mainnet) | `1.1.2` / `3.1.10` (platform-tools v1.52) / `1.97.1` |

**Caveat on the seed row:** `target/deploy/warden.so` on disk at the time this
table was seeded (2026-08-19) was built by a **different, concurrently
running task** (another agent owns `programs/warden` in this same phase1b
branch), not by this task. Its hash is recorded here only to exercise the
table's format, per the plan's instruction ("seed it with the current build
so the format is exercised rather than described"). It is explicitly **not**
a release candidate — no git tag exists, the working tree has uncommitted
changes elsewhere in the branch, and the `.so` will change again before any
real cut. Do not point `scripts/deploy-gate.sh` at this row for anything
other than exercising the tool.

## Adding a new row

1. From a clean checkout at the release tag (`git status` clean, `git log -1`
   matches the tag), run `anchor build`.
2. `sha256sum target/deploy/warden.so` — this is the hash.
3. Once a devnet/mainnet deployment exists, run
   `solana-verify get-program-hash --url <rpc-url> <program-id>` and confirm
   it equals step 2's hash; record the verbatim command and output.
4. Confirm the on-chain `ProgramData` upgrade authority (read via RPC, or via
   `solana program show <program-id>`) and record it in the Upgrade authority
   column, plus a link/reference to the Squads proposal that authorized the
   deploy.
5. `scripts/deploy-gate.sh` reads this table's row for the release SHA it is
   asked to check — a missing row, or a hash mismatch, is a hard refuse.
