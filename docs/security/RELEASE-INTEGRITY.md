# Release integrity (spec §17, L7/L9)

**Status:** UNVERIFIED beyond the one dev row below — no tagged release exists yet.

## Immutable CI action references (C6 partial)

All 11 external `uses:` call sites in `.github/workflows/**` are pinned to full
40-character upstream commits rather than mutable tags or branches. The
standalone audit is:

```sh
node --test test/github-actions-pins.test.mjs
```

It recursively scans every workflow, fails if no workflow or no external action
was measured, and rejects mutable Git refs, expressions, abbreviated or
uppercase pseudo-SHAs, and Docker actions without a SHA-256 digest. It runs as
the blocking workflow's first post-checkout command and at the start of
`.claude/test-gate.sh`. The exact action/ref/commit map and upstream resolution
method are recorded in `docs/TOOLCHAIN.md`.

This is a repository policy gate, not an upstream-source audit or GitHub runner
attestation. It has not yet run on GitHub at these pins. GitHub branch/workflow
protection still has to ensure an unreviewed workflow cannot insert executable
steps ahead of the audit; the repository test cannot enforce host-side policy.

## Extension upload artifacts (C6 partial)

`pnpm --filter @warden/extension release:gate` now produces a deterministic
unpacked payload, canonical Chrome Web Store upload ZIP, adjacent artifact
manifest, and canonical `*.sbom.json` production-dependency evidence sidecar
from a clean commit under the exact JavaScript toolchain pins in
`docs/TOOLCHAIN.md`. A read-only walk records the pnpm-installed `package.json`
production closure and package-declared license strings without host paths or
dev dependencies. It binds the clean source and ZIP hash; artifact-manifest
schema v2 in turn binds the exact sidecar byte length and SHA-256. The verifier
independently asks `unzip -t` to parse the archive and then fail-closes on
archive metadata,
path-set, file-mode, file-size, file-hash, manifest permission, CSP, update URL,
payload-tree hash, whole-ZIP hash, sidecar-byte hash, source binding, archive
binding, graph shape, or canonical JSON drift. Generated outputs are ignored;
this document does not pretend an ordinary development build is a release row.

The evidence scope deliberately says `bundleCoverage: "not-asserted"`: pnpm's
installed production closure is broader than a tree-shaken browser bundle, and
this generator does not inspect esbuild metafile inputs. `declaredLicense`
values are package metadata, not a legal conclusion; `Unknown` remains unknown.
This attachment is not a vulnerability scan, provenance signature, independent
build comparison, or proof that no other build input contributed bytes.

For a real extension release, the reviewed `*.artifact.json` bytes and ZIP hash
must be anchored in the release review/attestation system before comparing a
candidate. The JSON is unsigned and co-generated with the ZIP, so replacing
both defeats comparison if no independent reviewed anchor exists. The current
verifier accepts the canonical **upload ZIP** only. A package downloaded back
from the Web Store is a CRX/store-repackaged object and remains UNVERIFIED; a
future lane must remove only documented store-added signing/packaging and then
compare the entire payload. Two genuinely independent clean builders, exact
emitted-bundle input coverage, publisher MFA/least privilege, a provenance
signature, and an external security review also remain UNVERIFIED. Immutable CI
action syntax is now repository-gated as described above, but no off-host run or
upstream-source attestation is claimed. No Web Store upload or publisher-account
mutation is performed by this gate.

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

**The reproducible recipe for a real release — the ONLY one release rows may
use — is `anchor build --verifiable` (Docker-based), pinned by immutable
digest, never plain `anchor build` and never a bare tag.** Plain `anchor
build` links against whatever the invoking host happens to have installed
beyond the toolchain table above (system libc, linker, etc.) and is not
guaranteed byte-identical across machines. A tag like `:v1.1.2` can be
repointed by whoever controls the `ottersec` quay.io namespace — it names
"the image that was v1.1.2 last time anyone checked," not a fixed set of
bytes — so a real release recipe pins the immutable content digest instead:

```sh
git checkout <release-tag>
anchor build --verifiable   --solana-version 3.1.10   --docker-image quay.io/ottersec/anchor@sha256:4ef4cf067fb1332ddd2b997a48ed05257854f51067ade342d63ebdc1039fe72e
sha256sum target/deploy/warden.so
```

**Where the image reference comes from — resolved, not guessed, and not
merely tag-pinned.** `anchor build --help` (checked 2026-08-19) confirms
Anchor CLI `1.1.2` supports `-v/--verifiable` plus `--solana-version` and
`--docker-image` (verifiable-only) and a `--bootstrap` flag. Reading the
Anchor 1.1.2 source directly (`cli/src/config.rs`, `Config::docker()`, from
the local `~/.cargo/git` checkout pinned by `avm`'s own `--tag v1.1.2`
install — see `.github/workflows/ci.yml`) shows the **default** image when
`--docker-image` is omitted is `format!("quay.io/ottersec/anchor:v{version}")`
— i.e. the tag `quay.io/ottersec/anchor:v1.1.2`. That tag was then resolved
to its immutable manifest-list digest via a direct registry API query (no
image pull, no build — a single unauthenticated HEAD-equivalent request):

```sh
$ curl -sI     -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"     https://quay.io/v2/ottersec/anchor/manifests/v1.1.2 | grep -i docker-content-digest
docker-content-digest: sha256:4ef4cf067fb1332ddd2b997a48ed05257854f51067ade342d63ebdc1039fe72e
```

Resolved 2026-08-19; verbatim output kept in the Task 11 fix report ("Fix
report — round 2"). **This digest may need re-resolving if `ottersec`
publishes a new `v1.1.2` build** (digests are immutable per-push, but a tag
can be force-repointed to a new digest — if that ever happens, the pin above
goes stale and must be re-queried, not silently trusted). **Still not
executed as a build in this task**: Task 11 is tooling/docs only, another
agent owns the in-flight Rust build in this branch, and a Docker-based
verifiable build is a second, heavier build of the program that would race
it — the digest was resolved via a metadata-only registry query, not by
running the build.

The plain, **non-reproducible** `anchor build` command below is what this
repo's seed row was actually produced by (it predates this fix — real
release rows must not use it):

```sh
# NON-REPRODUCIBLE — host-dependent, dev/local builds only, NEVER for a real
# release row. The seed row below was built this way, not via --verifiable.
git checkout <release-tag>
anchor build
sha256sum target/deploy/warden.so
```

**Fallback / cross-check tool: `solana-verify`.** Not installed on this host
(`command -v solana-verify` → not found, checked 2026-08-19). When adopted,
`solana-verify build` (mirrors `anchor build --verifiable` via the same
digest-pinned Docker image) and `solana-verify get-program-hash --url <rpc>
<program-id>` (reads the **on-chain** program's hash directly, independent
of a local build — this is what `scripts/deploy-gate.sh` check 4a is
specified to use) are the two commands this table's "solana-verify output"
column records. Until then, the "solana-verify output" column reads
UNVERIFIED — no on-chain deployment exists to check yet.

## Per-release table

| Tag / label | Git SHA | `warden.so` SHA-256 | Program ID | `solana-verify get-program-hash` | Upgrade authority | Squads proposal | Client release statement | Toolchain (Anchor / cargo-build-sbf / rustc) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev, unreleased, **NON-REPRODUCIBLE** (plain `anchor build`, not `--verifiable`) | `f0f38cab713d1d9165e367f3397e11a152620eab` (working tree at Task 11 fix round 1, phase1b branch — **not itself a clean tag**, see caveat below; supersedes the round-1 seed row's `26a8c1e`, which went stale mid-task when a concurrent agent rebuilt `warden.so` — exactly the drift `scripts/deploy-gate.sh` check 4b is designed to catch, and did catch during this fix round's self-test) | `2a36f2a33b3d05cc06fc1ff03861419fb92e791bc42917cbbb15109e0dbd923d` | `6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2` | UNVERIFIED — not deployed on-chain, `solana-verify` not installed | UNVERIFIED — not deployed | none — no multisig configured yet (devnet or mainnet); `manifest:synthetic@1b14016c8978d3202f54185f7e7f86aaed881537b3f9544c2eb24d82a00886b3` (dev-only synthetic manifest binding — WRDF-0085; a real mainnet manifest+digest replaces this at release) | none — committed client release registry is empty | `1.1.2` / `3.1.10` (platform-tools v1.52) / `1.97.1` |

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
   matches the tag), run `anchor build --verifiable` with the pinned,
   digest-referenced Docker image from the recipe above — **never** plain
   `anchor build` for a row that is a real release candidate (that recipe is
   for dev/local builds only, see the NON-REPRODUCIBLE block above). If the
   pinned digest is stale (`ottersec` republished `v1.1.2` under a new
   digest), re-resolve it first with the `curl`/`docker-content-digest`
   query above and update the recipe block before building.
2. `sha256sum target/deploy/warden.so` — this is the hash.
3. Once a devnet/mainnet deployment exists, run
   `solana-verify get-program-hash --url <rpc-url> <program-id>` and confirm
   it equals step 2's hash; record the verbatim command and output.
4. Confirm the on-chain `ProgramData` upgrade authority (read via RPC, or via
   `solana program show <program-id>`) and record it in the Upgrade authority
   column, plus a link/reference to the Squads proposal that authorized the
   deploy.
5. Read the complete deployed ProgramData account and create the exact v1 record
   specified by `docs/security/SESSION-RELEASE-STATEMENT.md`: canonical chain and
   genesis, program/ProgramData identities, deployment slot, Squads vault upgrade
   authority, allocation, artifact/code hash, and full raw ProgramData hash.
   Add the source-owned statement and this exact row to the client release
   registry, then put its canonical digest in the Client release statement
   column as the leading backtick value
   `session-release:<name>@<64-lowercase-hex-digest>`. This committed unsigned
   record is a git-review anchor, not DSSE/Sigstore authentication; provenance
   signature and builder-identity verification remain separate release gates.
6. `scripts/deploy-gate.sh` reads this table's row for the release SHA it is
   asked to check — a missing row, or a hash mismatch, is a hard refuse.
