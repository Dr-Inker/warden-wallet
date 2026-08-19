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

**The reproducible recipe for a real release is `anchor build --verifiable`
(Docker-based), not plain `anchor build`.** Plain `anchor build` links
against whatever the invoking host happens to have installed beyond the
toolchain table above (system libc, linker, etc.) and is not guaranteed
byte-identical across machines; `--verifiable` builds inside a pinned Docker
image specifically so a second party can reproduce the exact bytes:

```sh
git checkout <release-tag>
anchor build --verifiable   --solana-version 3.1.10   --docker-image quay.io/ottersec/anchor:v1.1.2
sha256sum target/deploy/warden.so
```

**Where the image tag comes from — confirmed from Anchor 1.1.2's own
source, not guessed.** `anchor build --help` (checked 2026-08-19) confirms
Anchor CLI `1.1.2` supports `-v/--verifiable` plus `--solana-version` and
`--docker-image` (verifiable-only) and a `--bootstrap` flag. Reading the
Anchor 1.1.2 source directly (`cli/src/config.rs`, `Config::docker()`, from
the local `~/.cargo/git` checkout pinned by `avm`'s own `--tag v1.1.2`
install — see `.github/workflows/ci.yml`) shows the **default** image when
`--docker-image` is omitted is:

```rust
format!("quay.io/ottersec/anchor:v{version}")   // version = the Anchor CLI's own version, i.e. 1.1.2
```

i.e. `quay.io/ottersec/anchor:v1.1.2` — which is what the recipe above pins
explicitly rather than relying on the default resolving the same way on
every machine. **Still not executed in this task**: Task 11 is tooling/docs
only, another agent owns the in-flight Rust build in this branch, and a
Docker-based verifiable build is a second, heavier build of the program that
would race it. The plain, **non-reproducible** `anchor build` recipe below
is what this repo's seed row was actually produced by, and is labeled as
such in the table.

```sh
# NON-REPRODUCIBLE — host-dependent, dev/local builds only. The seed row
# below was built this way, not via --verifiable.
git checkout <release-tag>
anchor build
sha256sum target/deploy/warden.so
```

**Fallback / cross-check tool: `solana-verify`.** Not installed on this host
(`command -v solana-verify` → not found, checked 2026-08-19). When adopted,
`solana-verify build` (mirrors `anchor build --verifiable` via the same
pinned Docker image) and `solana-verify get-program-hash --url <rpc>
<program-id>` (reads the **on-chain** program's hash directly, independent
of a local build — this is what `scripts/deploy-gate.sh` check 4a is
specified to use) are the two commands this table's "solana-verify output"
column records. Until then, the "solana-verify output" column reads
UNVERIFIED — no on-chain deployment exists to check yet.

## Per-release table

| Tag / label | Git SHA | `warden.so` SHA-256 | Program ID | `solana-verify get-program-hash` | Upgrade authority | Squads proposal | Toolchain (Anchor / cargo-build-sbf / rustc) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dev, unreleased, **NON-REPRODUCIBLE** (plain `anchor build`, not `--verifiable`) | `f0f38cab713d1d9165e367f3397e11a152620eab` (working tree at Task 11 fix round 1, phase1b branch — **not itself a clean tag**, see caveat below; supersedes the round-1 seed row's `26a8c1e`, which went stale mid-task when a concurrent agent rebuilt `warden.so` — exactly the drift `scripts/deploy-gate.sh` check 4b is designed to catch, and did catch during this fix round's self-test) | `2a36f2a33b3d05cc06fc1ff03861419fb92e791bc42917cbbb15109e0dbd923d` | `6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2` | UNVERIFIED — not deployed on-chain, `solana-verify` not installed | UNVERIFIED — not deployed | none — no multisig configured yet (devnet or mainnet) | `1.1.2` / `3.1.10` (platform-tools v1.52) / `1.97.1` |

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
