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
manifest, canonical `*.sbom.json` production-dependency evidence sidecar, and
canonical `*.bundle-inputs.json` JavaScript-bundle input sidecar, and canonical
`*.static-inputs.json` non-JavaScript source/output sidecar, and canonical
`*.recipe-inputs.json` release-recipe repository-input sidecar
from a clean commit under the exact JavaScript toolchain pins in
`docs/TOOLCHAIN.md`. A read-only walk records the pnpm-installed `package.json`
production closure and package-declared license strings without host paths or
dev dependencies. It binds the clean source and ZIP hash; artifact-manifest
schema v6 in turn binds each sidecar's exact byte length and SHA-256 plus the
complete reviewed manifest capability snapshot. The bundle
sidecar records every positive `bytesInOutput` input esbuild reports for the
four emitted JavaScript files, canonical repository/npm identities, actual
non-virtual input byte lengths and hashes, explicit esbuild virtual inputs and
zero-byte counts, and each output's byte length and hash. The static sidecar
records source/output byte lengths and hashes for `approval.css`,
`approval.html`, `manifest.json`, and `popup.html`, distinguishing three exact
byte copies from the manifest's JSON parse/two-space/newline serialization. The
recipe sidecar records exact byte lengths and SHA-256 hashes for the 26 reviewed
non-payload files that declare the install/release path: `.node-version`,
`.npmrc`, both root/workspace pnpm configuration files, root/extension/core
package manifests, the upload package/verification modules, the CRX3
store-package comparison modules, the signed release-source verifier, and the
reviewed-artifact detached-signature verifier plus their CLIs, the one
shared public-release-CLI argument normalizer, and the shared pinned-git
runner. The verifier
independently asks `unzip -t` to parse a private temporary copy of the same
stable-read archive bytes. It opens and verifies a same-inode `O_RDONLY` handle
after syncing the exclusive **0600** construction writer, closes the writer,
seals the inode to **0400** through that reader, verifies unchanged file type,
device, inode, size, and exact mode, removes the filesystem name, and passes only
the live read-descriptor path to Info-ZIP with the private **0700** directory as
the subprocess working directory.
The child environment contains exactly the verifier's `PATH` (falling back to
`/usr/bin:/bin` when absent), `LANG=C`, and `LC_ALL=C`; `TMPDIR` and every other
ambient verifier variable are not directly inherited.
The verifier sets `killSignal: "SIGKILL"` and derives the direct-child timeout
from the stable archive byte length as
`min(120000, 5000 + ceil(bytes / 1048576) * 1000)` milliseconds.
After Info-ZIP exits it positionally rereads that same handle in bounded chunks
and requires the exact original length and bytes. It closes/removes both handles
and the directory on success or failure and never reopens the operator-supplied
archive path. This
is least privilege for the file description and cooperative non-root inode
permissions handed to the parser and detects a completed parser-side rewrite;
it does not establish trust against root, a writer opened before the seal, or a
hostile process changing permissions/reopening procfs with greater rights or
racing the comparison. The private working directory limits accidental relative-
path effects; it does not confine a malicious same-UID executable.
The minimal child environment limits direct ambient disclosure to cooperative
tool behavior and diagnostics. It is not secret isolation: PATH still selects
the executable, and a malicious same-UID process, root, or the host may access
other permitted state. It does not attest or normalize the build environment.
The timeout bounds the direct child and verifier wait, not escaped descendants
or a process group, and its 120-second ceiling does not attest production-host
performance.
The verifier then
fail-closes on
archive metadata,
path-set, file-mode, file-size, file-hash, manifest permission, CSP, update URL,
payload-tree hash, whole-ZIP hash, sidecar-byte hash, source binding, archive
binding, dependency graph shape, JavaScript bundle/input shape, static
source/output mapping, recipe input path/byte/hash drift against the current
checkout, or canonical JSON drift. Generated outputs are ignored;
this document does not pretend an ordinary development build is a release row.

The producer's own `git` children — the clean-tree gate and the `rev-parse HEAD`
whose output becomes `source.gitCommit`, the single value binding the OpenPGP-
signed release tag to the built bytes — no longer run from the inherited PATH
and environment. Every producer git call goes through one shared helper,
`apps/extension/scripts/release-git.mjs`, which spawns the absolute
`/usr/bin/git` with a child environment built from an allow-list rather than
from `process.env`: `PATH=/usr/bin:/bin`, `LANG=C`, `LC_ALL=C`,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_OPTIONAL_LOCKS=0` — plus the call's own `cwd`, a 10-minute timeout, and
`killSignal: "SIGKILL"`. An inherited `GIT_DIR`, `GIT_WORK_TREE`,
`GIT_INDEX_FILE`, `GIT_CEILING_DIRECTORIES`, or `GIT_OBJECT_DIRECTORY`
therefore cannot make a different repository answer the clean-tree gate or
supply the recorded commit, and a `git` executable placed earlier on the
inherited PATH is never selected — which matters because `pnpm run` prepends
`node_modules/.bin`, so a compromised dependency shipping a `git` bin would
otherwise shadow the real one for the producer. The signed-source verifier's git
environment and the same-host dual-checkout rehearsal's git calls are now
defined by that same helper, so producer and verifier cannot drift apart. This
is environment pinning, not host attestation: it does not defend against a
replaced `/usr/bin/git`, a malicious same-UID process, or root, and the timeout
bounds the direct child rather than escaped descendants.

The dependency evidence scope deliberately retains
`bundleCoverage: "not-asserted"`: pnpm's installed production closure is broader
than a tree-shaken browser bundle, and no automatic package-to-input or legal
crosswalk is claimed. The separate bundle record is deliberately scoped to the
four emitted JavaScript files and esbuild's positive `bytesInOutput`
attribution, which is an estimate rather than a byte partition. The separate
static record covers the exact four non-JavaScript files in today's eight-file
payload; it does not claim absent icons or other assets. The recipe record
covers repository source/configuration bytes only; it does not attest installed
Node/pnpm/esbuild executable bytes, package-manager behavior, environment
variables, OS/runtime behavior, or which code actually executed. `declaredLicense` values
are package metadata, not a legal conclusion; `Unknown` remains unknown. No
attachment is a vulnerability scan, provenance signature, independent build
comparison, or toolchain attestation.

For a real extension release, the reviewed `*.artifact.json` bytes and ZIP hash
must be anchored in the release review/attestation system before comparing a
candidate. The JSON files are unsigned and co-generated with the ZIP, so
replacing all of them defeats comparison if no independent reviewed anchor exists. The current
upload verifier accepts the canonical **upload ZIP** only. The separate offline
CRX3 lane below handles the documented store envelope and repackaged ZIP at the
content level, but no real Web Store-returned package has passed it. Two
genuinely independent clean builders, full build-environment input coverage,
publisher MFA/least privilege, a provenance signature, and an external security
review also remain UNVERIFIED. Immutable CI action syntax is now
repository-gated as described above, but no off-host run or upstream-source
attestation is claimed. No Web Store upload or publisher-account mutation is
performed by this gate.

The deterministic upload verifier accepts either direct Node arguments or
pnpm's one literal leading `--` before its exact zero-, six-, or seven-argument
grammar. The seventh semantic argument is still the optional unpacked
directory. The shared release-CLI normalizer removes exactly one leading
separator; doubled, interior, and trailing separators remain positional input.
Its six file candidates use the shared stable release-input reader before
parsing: the upload ZIP is capped at **512 MiB**, the artifact manifest at
**8 MiB**, and each dependency, bundle-input, static-input, and recipe-input
sidecar at **256 MiB**. The reader refuses empty/non-regular, final- or parent-
symlinked, oversized, path-replaced, or metadata-changing input. The optional
unpacked directory remains a directory-tree verification input, not a bounded
file input.

### Signed release-source precondition (C6 partial; fixture-only)

`pnpm --filter @warden/extension release:source-tag-message --
<reviewed-artifact.json> <expected-artifact-manifest-sha256>` is a local,
read-only message generator. It stable-reads no more than **8 MiB**, checks the
independently recorded lowercase digest before canonical artifact parsing, and
prints exactly the C59 schema/digest message with one terminal newline. It never
invokes Git/GnuPG, accesses a key, or creates, moves, signs, or pushes a tag.
Signing authority and handling of its exact stdout remain external controls.

`pnpm --filter @warden/extension release:verify-source-tag -- <tag>
<expected-tag-object-sha> <expected-primary-fingerprint>
<expected-signing-fingerprint> <expected-artifact-manifest-sha256>` checks a
caller-selected release source against the local versioned artifact manifest.
This five-argument local/default tier requires an independent exact artifact
digest. Supplying an explicit reviewed-manifest path before that digest selects
a different artifact. All five identity arguments are independent inputs; none
is learned from the tag or artifact candidate. When the primary key signs
directly, the two fingerprint arguments are the same.

When the explicit artifact path and its digest are followed by a local dual-
report path and an independently recorded lowercase report SHA-256, the same
command composes the two preconditions. Before parsing or invoking cryptographic
tooling, the CLI opens every external candidate without following a final
symlink, requires a nonempty regular file within its ceiling, and reads through
that one file handle. It requires its canonical Linux procfs target to equal the
normalized requested path before and after reading, and refuses device, inode, size, nanosecond
modification/change-time, or returned-buffer-length drift across the read.
Artifact manifests are bounded to **8 MiB**, reports and detached signatures
to **1 MiB** each, and CRX3/reviewed-upload inputs to **512 MiB** each. It hashes
and compares the explicit artifact bytes to their independent digest before
parsing them or invoking GnuPG, then requires the canonical reviewed local-
report schema/scope, and requires exact equality among the signed tag target,
artifact source commit, and report source commit. The report and artifact
extension versions must also match. The shared source-tag verifier itself
requires this exact byte/digest pair for every call, checks it before GnuPG,
derives the trusted manifest from the canonical buffer, and refuses divergence
from any separately supplied parsed object. It returns the verified artifact
digest, which the CLI cross-checks against the buffer it opened. The exact
selected artifact bytes are read once, bounded to **8 MiB**, and parsed
canonically. Their report record must
match those bytes exactly; the
report's ZIP, four evidence-sidecar, and eight unpacked-payload records must
match every path, byte length, and SHA-256 declared by the manifest. Missing
paired inputs or exact artifact bytes, a wrong report digest,
malformed/noncanonical input, source/version mismatch, any of those fourteen
record mismatches, or disagreement between the CLI and shared-verifier digest
fails closed. The report's own
`signedTagClaim: not-asserted` and `independentBuilderClaim: not-asserted`
labels remain truthful: subsequent composition is neither proof that the
builders verified a tag nor evidence from independent builders.

Four additional trailing arguments compose the detached artifact-review lane
with that exact source/report verification: the detached-signature path, an
independently recorded lowercase signature SHA-256, and independent full review
primary/signing fingerprints. The arguments are atomic and are accepted only
with the exact artifact and dual-report inputs. The CLI reads the artifact once;
the verifier bounds the signature to **1 MiB**, checks the expected signature
digest before asking GnuPG to parse the candidate, then passes the same artifact
buffer to detached-signature verification and the fourteen-record binder. The
returned artifact digest must equal the report-bound artifact digest. A valid
signature over a different canonical manifest, wrong signature digest, missing
review field, wrong review key/subkey, or malformed signature fails closed. The
explicit `GNUPGHOME` must already contain both public keys when source and review
identities differ.

Four more trailing arguments compose the offline store-returned-package lane:
the candidate CRX3 path, its independently recorded lowercase SHA-256, an
independently reviewed expected extension id, and the exact reviewed upload ZIP
path. This tuple is atomic and requires the full report plus detached-review
binding. The candidate digest is checked before CRX parsing, and the parser's
returned package digest must equal that input. The selected artifact bytes
remain the single manifest input: the upload ZIP must equal its canonical
archive byte-for-byte, while the strict CRX3 verifier checks the independently
supplied extension id, required Chrome Web Store publisher proof, all included
signatures, bounded protobuf/header structure, embedded ZIP grammar, and every
payload byte against that same artifact. The store-repacked ZIP may differ in
archive metadata, but its file count and payload-tree digest must equal the
reviewed upload. A different exact CRX, valid store package, or reviewed upload
for a different canonical artifact therefore fails closed.

The composition reports the manifest, reviewed-upload, CRX3, embedded-archive,
extension-id, publisher-key, and payload-tree identities. It remains an offline
comparison of caller-supplied bytes: it neither downloads a package nor proves
that the candidate came from the Web Store. Tests use generated developer and
publisher keys and synthetic CRX3 files, so they do not promote `WRD-REL-02` or
replace the existing real-returned-package and owner-approved-id requirements.

The verifier accepts only an exact valid `refs/tags/<tag>` ref whose current
object id equals the supplied full lowercase SHA-1 before and after signature
verification. This explicit tag-object anchor is what makes a force-moved tag
detectable. The object must be an annotated tag, contain exactly one direct
commit target and matching tag name, and target the artifact manifest's exact
source commit. A lightweight tag, nested tag, moved ref, wrong commit, or
structurally ambiguous tag object fails closed.

The authenticated tag body has one canonical versioned message grammar before
its single terminal OpenPGP armor block: the exact first line is
`warden.extension-release-tag.v1` and the exact second line is
`artifact-manifest-sha256 <lowercase-sha256>`. No prefix, suffix, duplicate
field, additional message line, uppercase digest, second armor block, or body
after the armor is accepted. The signed digest must equal the independently
supplied and measured artifact-manifest digest. The shared verifier reports
both identities and the CLI cross-checks both before reporting success. Thus a
signature over the right source commit but a free-form message or a different
artifact no longer composes with that artifact.

Signature verification fixes `gpg.format=openpgp`, fixes `/usr/bin/git` and
`/usr/bin/gpg`, suppresses system/global Git config, and asks `git verify-tag
--raw` to verify the expected object SHA rather than the ref. Git reaches GnuPG
through an exact launcher written inside a private mode-0700 temporary
directory. The launcher forwards Git's arguments only after fixed
`--no-options`, canonical `--homedir`, `--batch`, `--no-tty`,
`--no-auto-key-import`, `--no-auto-key-retrieve`, and `--auto-key-locate clear`
arguments. Thus mutable `gpg.conf` content in the selected keyring cannot change
verification or activate a missing-key path. The launcher directory is removed
after successful and failed verification. The status parser requires exactly
one signature context, successful terminal result, and
cryptographic `VALIDSIG`; it cross-checks `GOODSIG` against the signing
fingerprint, requires `VALIDSIG`'s signing fingerprint to equal the complete
independently supplied signing-key fingerprint, and separately requires its
primary fingerprint to equal the complete independently supplied primary-key
fingerprint. A valid signature from an unexpected sibling signing subkey under
the same primary therefore fails closed. Bad, expired, revoked, unavailable-
key, failed, duplicate, or otherwise ambiguous results are refused. Unknown
future status keywords are ignored as GnuPG's machine-interface contract
requires.

The parser does not treat bare cryptographic validity as sufficient. It
requires the exact ten-field OpenPGP `VALIDSIG` record, zero reserved field,
signature version **4 or 6**, canonical decimal algorithm octets,
binary-document signature class **00**,
public-key algorithm ID **1, 19, 22, 27, or 28**, and hash algorithm ID **8, 9,
or 10**. These are respectively RSA, ECDSA, installed-GnuPG EdDSA compatibility,
Ed25519, Ed448, and SHA-256/384/512. The current
[IANA OpenPGP registries](https://www.iana.org/assignments/openpgp) and
[RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) define the identifiers
and binary-document class. ID 22 is deliberately documented as a compatibility
exception: RFC 9580 calls that encoding EdDSALegacy and deprecated, while the
installed GnuPG 2.4.4 `ed25519` fixture emits 22. The result reports signature
version, public-key algorithm, hash algorithm, and class.

The `VALIDSIG` creation date must also be a valid canonical UTC `YYYY-MM-DD`
value. Its creation and expiration timestamp fields accept the two encodings
documented by installed GnuPG: canonical decimal epoch seconds and basic ISO
`YYYYMMDDTHHMMSS`. Both normalize to integer seconds. Creation must fit RFC
9580's unsigned four-octet OpenPGP time field and its UTC date must equal the
separate creation-date field. Zero expiration normalizes to `never`; a nonzero
absolute expiration must be strictly later than creation and their difference
must fit the unsigned four-octet signature-expiration interval. Both verifier
results and CLIs report the normalized date, creation timestamp, and expiration.
This proves internal structure only: it does not choose a maximum signature
age, accepted clock skew, release window, or trustworthy present time.
Algorithm IDs alone do not attest RSA size, ECC curve, key storage, ownership,
or lifecycle.
For the accompanying `GOODSIG` key ID, the matcher uses the low 64 fingerprint
bits for v4 and high 64 bits for v6, or accepts the exact full fingerprint, as
defined by the registry's key-ID rules.

The behavior follows Git's primary
[`verify-tag`](https://git-scm.com/docs/git-verify-tag.html) and
[`tag`](https://git-scm.com/docs/git-tag.html) documentation and GnuPG's
[`--status-fd` unattended-use guidance](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-Usage-of-GPG.html),
checked 2026-09-01 alongside the installed GnuPG 2.4.4 `DETAILS` contract.
The explicitly selected, absolute caller-controlled `GNUPGHOME` must already
contain the selected public key. This lane does not create a key or tag, select
the production tag/object/primary fingerprint/signing fingerprint or reviewer
authority, attest the Git, GnuPG, shell, OS, or runtime bytes, or supply a second
independent builder. Without the optional four review-signature arguments, it
does not authenticate the external anchor for the unsigned artifact JSON.
Its ephemeral test key and repository therefore do not promote `WRD-REL-01`.

### Reviewed artifact detached signature (C6 partial; fixture-only)

`GNUPGHOME=/path/to/artifact-review-keyring pnpm --filter @warden/extension
release:verify-artifact-signature -- <reviewed-artifact.json>
<detached-signature> <expected-artifact-manifest-sha256>
<expected-detached-signature-sha256> <expected-primary-fingerprint>
<expected-signing-fingerprint>` authenticates the exact artifact-manifest and
detached-signature bytes before parsing them. The artifact path, signature path,
independently recorded lowercase artifact and signature digests, complete
primary and signing OpenPGP fingerprints, and absolute verification keyring are
all caller-controlled inputs; none is adopted from the candidate. When the
primary key signs directly, the two fingerprints are the same.

The CLI refuses non-regular/symlink inputs, caps the artifact at **8 MiB** and
signature at **1 MiB**, reads each once, and rejects size drift. It checks both
buffers against their independent digests before GnuPG or canonical parsing and
cross-checks the verifier's returned artifact and signature digests. The
verifier places those exact in-memory bytes in mode-0600 files under a private
temporary directory and invokes absolute `/usr/bin/gpg` with `--no-options`,
`--batch`, `--no-tty`, `--no-auto-key-import`, `--no-auto-key-retrieve`, an
empty automatic key-location list, `--status-fd=1`, and explicit detached-
signature and data filenames. It requires exactly one `NEWSIG`, terminal `GOODSIG`, and
cryptographic `VALIDSIG`, cross-checks signing identity, and binds the reported
signing and primary fingerprints to their separate full independent values. A
cryptographically valid signature from any other signing subkey under the same
primary fails closed. Bad, expired, revoked, missing-key, duplicate/multi-
signature, malformed, trailing, wrong-artifact, or wrong-fingerprint results
fail closed. Temporary files are removed on success and failure; GnuPG may
still maintain state inside the explicitly selected caller keyring.
The same shared allowlist requires public-key ID **1/19/22/27/28**, SHA-2 ID
**8/9/10**, exact binary-document signature class **00**, and the same
creation-date/timestamp/expiration structural contract before accepting the
reviewed bytes. The normalized time fields are returned and printed, but no
signature-age or clock-skew policy is inferred.

The contract follows GnuPG's primary
[`--verify` documentation](https://gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html),
which recommends explicitly naming both detached signature and data file,
its [`--status-fd` unattended-use guidance](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-Usage-of-GPG.html),
and documented
[`--no-auto-key-retrieve` behavior](https://gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html),
checked 2026-09-01 against installed GnuPG 2.4.4.

This is an executable review-anchor precondition, not a real review anchor or
provenance claim. A digest is independent only if its approval/recording channel
is independent of the selected file. No production artifact was signed, no
production review key or signing subkey or reviewer authority was selected, and
no key ceremony, strength/curve rule, rotation/revocation workflow, host
attestation,
transparency log, or independent build exists.
Only ephemeral fixture keys and bytes have passed, so `WRD-REL-01` remains
`unimplemented`.

### Store-returned CRX3 verifier (C6 partial; fixture-only)

`pnpm --filter @warden/extension release:verify-store -- <candidate.crx>
<expected-package-sha256> <expected-extension-id>
<expected-artifact-manifest-sha256>` accepts an offline CRX3 candidate plus
independently supplied exact-package, extension, and reviewed-artifact
identities. Both digests must be lowercase SHA-256. The package digest is
checked against the one candidate buffer; the artifact digest is checked
against the one bounded stable artifact buffer before canonical or CRX parsing;
and the strict verifier's returned package digest is cross-checked afterward.
It then verifies the reviewed canonical upload ZIP against that artifact
manifest and requires `Cr24`,
version 3, a bounded little-endian protobuf-header length, only the reviewed
CRX3 fields, exactly one developer proof matching the signed 16-byte CRX id,
exactly one current Chrome Web Store publisher proof, and valid signatures from
every included ECDSA/RSA proof. The pinned publisher public-key SHA-256 is
`61f7f2a6bfcf74cd0bc1fe2497cc9b04254c658f79f2145392867ea8366367cf`.
The candidate id must equal the independent argument; it is never adopted from
the candidate itself.

After rejecting ZIP end-record tokens in the header, the verifier removes only
the documented 12-byte fixed prefix and the exact declared protobuf header. Its
bounded embedded-ZIP reader supports STORE and DEFLATE plus optional data
descriptors and non-semantic timestamp extras, while refusing encryption,
ZIP64, unsafe/duplicate paths, semantic/unknown extras, inconsistent
local/central records, CRC/size drift, hidden bytes, comments, and trailing
ambiguity. Archive order, compression, timestamps, and mode metadata can differ
from the upload ZIP; exact path/content hashes, extension version, manifest
permissions, CSP, update URL, and payload-tree hash cannot. The command also
runs `unzip -t` over an unlinked live descriptor for the embedded ZIP. The
standalone store verifier exclusively creates and syncs a **0600** copy of the
already-verified archive bytes, opens and identity-checks a same-inode
`O_RDONLY` handle, closes the writer, seals and verifies the inode at **0400**,
unlinks the name, and passes only `/proc/<pid>/fd/<fd>` to Info-ZIP. After a
zero exit it positionally compares the same handle with every original byte.
Setup, parser, comparison, and cleanup failures fail closed, and the handle and
private directory are removed on every outcome. This prevents pathname
replacement and detects a completed parser-side rewrite. The private **0700**
directory is also the store subprocess's exact working directory, limiting
accidental relative-path effects. The child environment contains exactly the
verifier's `PATH` (or `/usr/bin:/bin` when absent), `LANG=C`, and `LC_ALL=C`; it
does not directly inherit `TMPDIR`, home-directory variables, credentials, or
unrelated parent state. This remains cooperative-host least privilege:
inherited `PATH` still selects the executable, a malicious same-UID process,
root, or the host can inspect other state, and there is no executable-
provenance proof, sandbox, or same-UID/root defense. The direct child receives
an archive-size-derived deadline of
`min(120000, 5000 + ceil(bytes / 1048576) * 1000)` milliseconds with
`killSignal: "SIGKILL"`; this is not process-group or descendant confinement.

The format contract comes from Chromium's primary
[`crx3.proto`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/crx_file/crx3.proto)
and current
[`crx_verifier.cc`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/crx_file/crx_verifier.cc),
observed 2026-09-01 as page-reported blobs
`b38dd5a77467eabca61f0d1fee461b2a6822df44` and
`522a740a4f51363b54a35b808fc2ff8680aeeaea`.

This is still fixture/parser/comparator evidence. No real Web Store package is
present; the tool does not download one, prove its acquisition route, interpret
the optional `verified_contents` field, establish who independently approved or
recorded the artifact digest, choose the unresolved production extension id, or
mutate publisher state. `WRD-REL-02` remains `unimplemented` until a real
returned package and independently anchored review inputs pass at an exact
release SHA.

### Same-host dual-checkout rehearsal (C6 partial)

`pnpm --filter @warden/extension release:dual-local` is an executable local
determinism rehearsal. From one clean source SHA it creates two sequential local
shared-object Git clones under a temporary directory. In each clone it runs
`pnpm install --frozen-lockfile --offline --frozen-store` against the host's
shared read-only pnpm store,
then runs the incumbent `release:gate`. The first checkout is removed before the
second begins. The comparator requires the exact six release files and eight
unpacked payload files, compares all 14 byte-for-byte, and writes a canonical
ignored `*.dual-local.json` report with the source SHA, observed toolchain,
orchestrator hash, commands, scope, byte lengths, and hashes. Tests fail closed
on missing, extra, duplicate, moved, one-byte-different, or noncanonical report
data; temporary checkouts are removed on both success and failure.

This rehearsal is deliberately labelled same-host and shared-store. It is not
the C6 requirement for two isolated independent builders at one signed tag, and
it does not exercise a clean remote package store, a distinct OS/runtime,
separate toolchain executable bytes, an off-host trust domain, or a provenance
signature. An independently digested report can be composed with the signed-
source verifier above, but that binds source identity rather than making either
builder independent. It cannot promote `WRD-REL-01` by itself.

### CI release-verify job (anchored pins)

Audit finding **E-4** (Fable, 2026-09-02) recorded that the only release check
CI ran was `pnpm --filter @warden/extension release:gate` — `release:package &&
release:verify` — which packages the extension and then compares the ZIP
against an `.artifact.json` the same job generated seconds earlier. That is a
self-consistency check, not verification: replacing both files defeats it, and
it is anchored to nothing an owner recorded. The three verifiers that DO take
independent expectations —
`verify-release-source-tag.mjs`, `verify-reviewed-artifact-signature.mjs`, and
`verify-store-package.mjs` — never ran in CI, and no expected primary/signing
fingerprint, tag object SHA, artifact-manifest SHA-256, or extension id was
committed anywhere in the repository. The paragraph above about co-generated
JSON stated the weakness; nothing acted on it.

`.github/workflows/release-verify.yml` is that lane. It triggers on a pushed
tag matching `v*` and on `workflow_dispatch` with an explicit `tag` input, runs
with `contents: read` only, and uses the same pinned `actions/checkout`,
`actions/setup-node`, and `pnpm/action-setup` commit SHAs as `ci.yml` (audited
by `test/github-actions-pins.test.mjs`, which globs every workflow file and now
also asserts that both `ci.yml` and `release-verify.yml` were discovered). It
checks out the tag with full history and tags, rebuilds the release package
from the tagged source, imports the ASCII-armored release public key(s) from
`apps/extension/release-pubkeys/*.asc` into a private `GNUPGHOME` under
`RUNNER_TEMP`, and then runs `pnpm --filter @warden/extension
release:verify-pins -- --tag <tag>`.

**The `v*` trigger pattern is a choice made at authoring, not a convention read
off existing code.** No release-tag naming convention is pinned anywhere in the
repository: `release-source-tag.mjs` accepts any well-formed tag name, and the
grammar it does pin is the annotated tag's *message body*
(`warden.extension-release-tag.v1` + `artifact-manifest-sha256 <digest>`), not
its name. The owner should narrow the pattern if real release tags are named
differently. A wide pattern cannot cause the wrong release to be "verified":
the runner refuses any tag that is not the one named in the pins file.

**The pins file.** `apps/extension/release-pins.json` is the owner-authored
anchor. Its schema is `warden.extension-release-pins.v1` and it carries exactly
eleven keys: `schema`, `tag`, `tagObjectSha`, `primaryFingerprint`,
`signingFingerprint`, `artifactManifestPath`, `artifactManifestSha256`,
`reviewedUploadArchivePath`, and the three optional tuples
`dualReleaseReport` (`path`, `sha256`), `artifactReviewSignature` (`path`,
`sha256`, `primaryFingerprint`, `signingFingerprint`), and `storePackage`
(`path`, `sha256`, `extensionId`). `apps/extension/scripts/release-pins.mjs`
loads it and **fails closed** before spawning anything on: a missing or
unreadable file, unparsable or non-object JSON, a wrong `schema`, any missing
key, any unknown key (top level or inside a tuple), a placeholder value
(blank, `TODO`, `REPLACE_ME`, `CHANGE_ME`, or a single-repeated-hex-character
run such as all-zeroes), a tag object SHA that is not 40 lowercase hex, an
OpenPGP fingerprint that is not 40 UPPERCASE hex, a SHA-256 that is not 64
lowercase hex, an extension id that is not 32 characters `a-p`, or a file
operand that is not a plain relative path under `apps/extension` (absolute
prefixes, `..` segments, trailing separators, and control characters are all
refused). It also refuses pins that skip a tier of the source-tag verifier's
nested grammar — `storePackage` requires `artifactReviewSignature`, which
requires `dualReleaseReport` — because such pins could never be turned into a
legal invocation.

**What is bound.** The mandatory tier always runs
`verify-release-source-tag.mjs` with six operands built from the pins: the tag
name, the expected annotated-tag object SHA, the expected primary and signing
fingerprints, the explicit reviewed artifact-manifest path, and its expected
SHA-256. Because the manifest is *regenerated* from the tagged source earlier in
the job, that digest comparison is the thing the old `release:gate` could not
do: the rebuilt bytes must hash to a value the owner recorded out of band. When
`dualReleaseReport` is pinned the call composes to eight operands; with
`artifactReviewSignature`, twelve, and `verify-reviewed-artifact-signature.mjs`
runs as well; with `storePackage`, sixteen, and `verify-store-package.mjs` runs
against the CRX3 envelope, its digest, the expected extension id, the
artifact-manifest digest, the reviewed upload ZIP, and the manifest. Optional
tuples left `null` are **skipped with a loud notice** naming exactly what is
therefore *not* bound (no reviewer signature; no store envelope), and the run
ends by restating how many verifiers were skipped. Verifier children are
spawned with `execFileSync(process.execPath, [script, ...args])` — an explicit
argv, never a shell string — under the same allow-listed environment the
release git helper uses (`apps/extension/scripts/release-git.mjs`:
`PATH=/usr/bin:/bin`, `LANG`/`LC_ALL=C`, `GIT_CONFIG_NOSYSTEM=1`,
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_OPTIONAL_LOCKS=0`) plus the one variable the
OpenPGP lane needs, `GNUPGHOME`, which must be an absolute path. Nothing is
inherited from `process.env`, so `NODE_OPTIONS`, `LD_PRELOAD`, `GIT_DIR`, and a
hostile `PATH` cannot reach the verifiers or the `git`/`gpg` children they
spawn.

**The committed pins file is a DELIBERATE PLACEHOLDER, so this job currently
FAILS on every tag.** That is the intended state, not a defect: an anchored
verifier with no anchor is worse than no verifier, because it looks green.
`apps/extension/test/release-pins.test.mjs` asserts the rejection of the
committed file specifically, so the placeholder cannot quietly become
acceptable. The owner closes this by replacing every value with the real pins
recorded out of band and committing the release public key(s) under
`apps/extension/release-pubkeys/`.

**What this does NOT establish.** It is not host attestation: it does not
defend against a compromised GitHub-hosted runner, a replaced `/usr/bin/git` or
`/usr/bin/gpg` on that runner, or a malicious action in the pinned set. It does
not make the build reproducible or independent — `release-verify.yml` is one
builder on one host, and the same-host caveat above still applies. Most
importantly, **the pins are committed to the same repository the tag comes
from**, so an attacker who can push both can move both; CI can only prove that
the tag, the signature, and the rebuilt bytes agree with the pins *as
committed*. The owner must therefore ALSO run these verifiers locally, from a
keyring and a pins record held outside this repository, before treating a
release as verified. A green run here is a necessary condition, never a
sufficient one, and it does not promote `WRD-REL-01`, `WRD-REL-02`, or
`WRD-REL-03`.

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
