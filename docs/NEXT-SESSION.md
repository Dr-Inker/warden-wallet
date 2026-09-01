# Next Session — Claude Security, Vanity, and UI Handoff

> ## 2026-09-01 CLEAN-BREAK PICKUP MEMO — C32 CLOSED; C33 NOT STARTED
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** continue C6 with one bounded C33 contract: bind the source bytes
>   and explicit build transformation for the four non-JavaScript payload files
>   (`approval.css`, `approval.html`, `manifest.json`, `popup.html`). Begin with
>   a fresh read-only map and real RED. Distinguish byte-copy from canonical JSON
>   serialization, and do not claim icons or other static assets that the exact
>   eight-file payload does not contain.
> - **CWD:** `/opt/warden`.
> - **BASE:** final C32 implementation/fix
>   `cd7f31f3ce493b9b07e2a8d032f6e91c07097621`; ledger-inclusive, fully gated
>   SHA `09619d1ec75c56eccd85e076a63ab1a7b6603f7b`. The documentation-only
>   commit containing this memo is intentionally not described as gate green.
> - **READ:** this memo and the C32/C31 entries immediately below;
>   `apps/extension/scripts/build.mjs`;
>   `apps/extension/scripts/bundle-input-evidence.mjs`;
>   `apps/extension/scripts/release-artifact.mjs`;
>   `apps/extension/scripts/package-release.mjs`;
>   `apps/extension/scripts/verify-release.mjs`; their focused tests;
>   `apps/extension/manifest.json`, HTML/CSS sources, README; and
>   `docs/security/RELEASE-INTEGRITY.md`.
> - **WRITE (edit lease):** none is currently claimed. After the read-only map,
>   lease only the smallest build/release evidence, focused-test, and
>   documentation set required for exact non-JavaScript source provenance.
> - **DO_NOT_TOUCH:** `.superpowers/**`,
>   `/root/.codex/session-graphs/**`, live `/var/www/**`, deployment/Web Store
>   publisher/account state, secrets, the empty production release registry,
>   or the C1a production extension-id/permitted-origin owner decision. Do not
>   convert source hashing into legal, independent-builder, or store-returned
>   package assurance.
> - **ACCEPT:** executable RED; canonical source/output byte lengths and hashes;
>   exact byte-copy versus canonical-JSON transformation labels; exact four-file
>   refusal on missing/extra records; source/output/ZIP/manifest attachment and
>   tamper refusal; exact-SHA focused/release evidence; a committed/full-gated
>   ledger; and explicit coverage limits. Keep the provider fixed unavailable.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs, ignored generated
>   extension artifacts, temporary test data, and git commits only; no deploy,
>   upload, publishing, live service, external message, secret creation, legal
>   ruling, or real-account/funds mutation.
> - **RETURN:** implementation/ledger SHAs, clean/dirty state, exact commands
>   and outcomes, per-file source/output/transform measurements, unchanged or
>   promoted invariants, independent-review status, explicit coverage gaps, and
>   remaining owner/counsel/external-state blockers.
>
> **C32 ledger-inclusive gate:** from a clean tree at
> `09619d1ec75c56eccd85e076a63ab1a7b6603f7b`, this exact command exited **0**
> and printed that same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|production-dependency-evidence|bundle-input-evidence|warden\.extension-artifact\.v3|warden\.extension-production-dependency-evidence\.v1|warden\.extension-js-bundle-input-evidence\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> It passed action pins **2/2**, core **700/700**, extension **494/494**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real Chromium
> **15/15**, Rust **681 passed / 0 failed / 1 ignored**, builds/typechecks, the
> measured Argon2 benchmark, canonical ZIP/two-sidecar verification, independent
> Info-ZIP parsing, emitted-bundle tooling exclusion, diff checks, and both
> clean-tree guards. Release verification measured **8 files**, **60
> production/peer components**, **4 JavaScript bundles**, and **101 positive
> bundle inputs**. At this ledger SHA the 29,047-byte bundle sidecar SHA-256 was
> `de7a8ca67c15290c8cdd09b4124bf6ce27cdefd96a10644c2f721cca04ede2bc`,
> artifact-manifest SHA-256 was
> `4fe511f6501959d879bc5d0ac3a196bf1c74b65b172cdea0471b4b767295f64e`,
> dependency-sidecar SHA-256 was
> `bc2930602b95dbae0d5c0d9f35bfddfcea15a0128a2c3bbac9736cfafe9ec93b`,
> payload-tree SHA-256 remained
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`,
> and ZIP SHA-256 remained
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`.
> Known Anchor test-middleman key mismatch, legacy macro-`cfg`, and Rust
> unused-code warnings remained non-fatal. Independent second-model review is
> still **UNVERIFIED**.
>
> **Stop state:** C32 is closed. C33 has no code, RED, edit lease, dependency
> change, release-registry edit, deployment, publisher action, or legal
> adjudication. The ignored local `apps/extension/release/` output may exist; it
> is reproducible evidence, not a tracked or reviewed release candidate.

> ## 2026-09-01 C32 DETERMINISTIC JAVASCRIPT-BUNDLE INPUT EVIDENCE — C6 PARTIAL, STATIC/LEGAL COVERAGE NOT CLAIMED
>
> Implementation commit
> `9622445bc3cbd280a07dbb9a87e249c31bd79777` adds canonical
> `warden.extension-js-bundle-input-evidence.v1`, artifact-manifest schema v3,
> strict generation/parsing/attachment verification, build-metafile plumbing,
> package/verify integration, focused tamper tests, and scoped documentation.
> The first clean release run correctly caught an integration typo after the
> focused unit lane passed; fix commit
> `cd7f31f3ce493b9b07e2a8d032f6e91c07097621` adds an explicit build-output
> shape guard and passes the returned metafiles under the correct name. The
> failed SHA is not called green. There was no dependency/lockfile change,
> deployment, registry edit, Web Store or publisher action, secret, legal
> ruling, provider-route change, or real-account/funds mutation.
>
> Real RED was captured before implementation:
>
> ```sh
> pnpm --filter @warden/extension exec vitest run test/bundle-input-evidence.test.mjs
> ```
>
> It exited **1** because the focused contract did not exist. At clean final
> implementation SHA `cd7f31f3ce493b9b07e2a8d032f6e91c07097621`, this
> exact command exited **0** and printed the same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && pnpm --filter @warden/extension exec vitest run test/bundle-input-evidence.test.mjs test/production-dependency-evidence.test.mjs test/release-artifact.test.mjs && pnpm --filter @warden/extension release:gate && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> The three focused files passed **20/20** tests, then package/verify passed for
> the canonical ZIP, dependency sidecar, new bundle-input sidecar, canonical
> unpacked tree, and independent `unzip -t` reader. Tests prove canonical
> ordering independent of metafile/result order and host paths; repository,
> registry, and explicit esbuild-virtual identities; installed source byte/hash
> capture; positive `bytesInOutput` selection with zero-byte counts retained;
> exact four-output refusal on missing/extra results; source-byte mismatch
> refusal; sidecar/manifest/archive/output binding; byte tamper refusal; and
> duplicate-key/noncanonical JSON refusal. The incumbent dependency/artifact
> tests remain **5/5** and **11/11**.
>
> From the same clean SHA, this exact command also exited **0** and printed the
> same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && pnpm --filter @warden/extension test && pnpm --filter @warden/extension typecheck && pnpm --filter @warden/extension build && if rg -n 'release-artifact|package-release|verify-release|production-dependency-evidence|bundle-input-evidence|warden\.extension-artifact\.v3|warden\.extension-js-bundle-input-evidence\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> The full extension suite passed **494/494**, typecheck/build passed, release
> tooling remained absent from `dist`, and diff/clean-tree guards passed.
>
> `pnpm --filter @warden/extension release:gate` was then rerun at the same
> clean SHA and exited **0** again. Both successful runs produced exactly **4
> JavaScript bundles** and **101 positive-byte input records** in a
> **29,047-byte** sidecar with SHA-256
> `428bd4345b02f6204ada887f40ea3ec26b12293663dbbe7b3c7c188bc20360ca`.
> The artifact-manifest SHA-256 was
> `7d04a562ce62a4f1210f32fe18e8c7e6d4f4139109f47283cfbcf345e40d40aa`,
> dependency-sidecar SHA-256 was
> `9e22737156ea826aa98d394c4a6a56bc313382e9dacef20753db787fe05c0cbe`,
> payload-tree SHA-256 remained
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`,
> and ZIP SHA-256 remained
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`.
> A scan found no `/opt/`, `/root/`, `node_modules`, `devDependencies`, or
> `unsavedDependencies` string in the new sidecar.
>
> Per-output measurements are executable data, not prose grading:
>
> - `approval.js`: **23,735 bytes**, **2** repository inputs, **23,649**
>   attributed / **86** unattributed bytes, SHA-256
>   `2bc104b2a9415e711698380b242f8f2e2f0743efcbb975a3260f28a5e254d3cd`.
> - `background.js`: **877,698 bytes**, **94** positive inputs (**58 registry,
>   35 repository, 1 esbuild virtual**) plus **2 zero-byte** inputs,
>   **868,442** attributed / **9,256** unattributed bytes, SHA-256
>   `46e9a6e034c5edfda643823e293489e293e2860ddc9813e61b2b319636e22f01`.
> - `content.js`: **8,269 bytes**, **3** repository inputs, **8,156** attributed
>   / **113** unattributed bytes, SHA-256
>   `6f3f0a595abaa108124f67d0845affafb3afdf94f5538117eeaf54a6e87777a3`.
> - `popup.js`: **3,229 bytes**, **2** repository inputs, **3,149** attributed /
>   **80** unattributed bytes, SHA-256
>   `0cccd2fded426f383ed497d316191b129c57189bf220a7c12aa9b64b2451274c`.
>
> The evidence specifically records positive contributions from
> `npm:rpc-websockets@9.3.9/dist/index.browser.mjs` and
> `npm:text-encoding-utf-8@1.0.2/lib/encoding.lib.js` to `background.js`.
> That measurement strengthens the counsel question; it does not answer it.
>
> Independent second-model review remains **UNVERIFIED**. The exact full
> repository command in the clean-break memo immediately above later exited
> **0** at ledger-inclusive SHA
> `09619d1ec75c56eccd85e076a63ab1a7b6603f7b`; that memo records the executable
> result without transferring its verdict to the later documentation-only
> commit.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> Production provider routing remains fixed unavailable. C32 changes release
> evidence only.
>
> **Harsh residual:** the sidecar covers only esbuild's positive
> `bytesInOutput` records for four JavaScript outputs. That number is esbuild's
> estimate, not a partition of final bytes; the explicitly measured
> unattributed bytes remain. Copied HTML, CSS, `manifest.json`, icons, build
> configuration/tool/environment inputs, and zero-byte/tree-shaken source
> content are not source-hashed by this record. It does not automatically
> reconcile the 60-component production closure to file inputs or decide LGPL,
> unknown-license, Jupiter-IDL, or Squads counsel items. All JSON is unsigned
> and co-generated; there is still no independent builder, provenance signature,
> store-returned-package comparison, publisher-control evidence, off-host run,
> external audit, deployment, or real-funds evidence.

> ## 2026-09-01 CLEAN-BREAK PICKUP MEMO — C31 CLOSED; C32 NOT STARTED
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** continue C6 with one bounded C32 contract: measure and bind the
>   exact source inputs that esbuild reports as contributing bytes to each of
>   the four emitted JavaScript bundles. Start with a fresh read-only map and a
>   real RED. Keep the claim narrower than the full extension artifact: esbuild
>   metafiles do not cover copied HTML, CSS, `manifest.json`, icons, legal
>   disposition, publisher control, or the store-returned package.
> - **CWD:** `/opt/warden`.
> - **BASE:** final C31 implementation/test commit
>   `80709ecde93390ee7566ccef772b7840c7e7afe2`; ledger-inclusive, fully gated
>   SHA `ad9b6a386276b56ff8c49e1ad39c28f72e4c2b32`. The documentation-only
>   commit containing this memo is intentionally not described as gate green.
> - **READ:** this memo and the C31 entry immediately below;
>   `apps/extension/scripts/build.mjs`;
>   `apps/extension/scripts/production-dependency-evidence.mjs`;
>   `apps/extension/scripts/release-artifact.mjs`;
>   `apps/extension/scripts/package-release.mjs`;
>   `apps/extension/scripts/verify-release.mjs`; their focused tests;
>   `apps/extension/package.json`; `docs/security/RELEASE-INTEGRITY.md`; and C6
>   in the client-security plan.
> - **WRITE (edit lease):** none is currently claimed. After the read-only map,
>   lease only the smallest build/release script, focused-test, and documentation
>   set required for deterministic JavaScript-bundle input evidence.
> - **DO_NOT_TOUCH:** `.superpowers/**`,
>   `/root/.codex/session-graphs/**`, live `/var/www/**`, deployment/Web Store
>   publisher/account state, secrets, the empty production release registry,
>   or the C1a production extension-id/permitted-origin owner decision. Do not
>   infer whole-artifact or legal coverage from esbuild's JavaScript metafiles.
> - **ACCEPT:** executable RED; deterministic, canonical per-output source-input
>   evidence derived from esbuild's own metafiles; exact binding to the reviewed
>   upload artifact and source SHA; missing/extra/tamper refusal; exact-SHA
>   focused and release evidence; a committed/full-gated ledger; and explicit
>   coverage limits. Keep the provider fixed unavailable.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs, ignored generated
>   extension artifacts, temporary test data, and git commits only; no deploy,
>   upload, publishing, live service, external message, secret creation, legal
>   ruling, or real-account/funds mutation.
> - **RETURN:** implementation/ledger SHAs, clean/dirty state, exact commands
>   and outcomes, per-bundle input/byte/hash measurements, unchanged or promoted
>   invariants, independent-review status, explicit coverage gaps, and remaining
>   owner/counsel/external-state blockers.
>
> **C31 ledger-inclusive gate:** from a clean tree at
> `ad9b6a386276b56ff8c49e1ad39c28f72e4c2b32`, this exact command exited **0**
> and printed that same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|production-dependency-evidence|warden\.extension-artifact\.v2|warden\.extension-production-dependency-evidence\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> It passed action pins **2/2**, core **700/700**, extension **490/490**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real Chromium
> **15/15**, Rust **681 passed / 0 failed / 1 ignored**, builds/typechecks, the
> Argon2 benchmark, canonical ZIP/sidecar verification, independent Info-ZIP
> parsing, emitted-bundle tooling exclusion, diff checks, and both clean-tree
> guards. Release verification measured **8 files**, **60 production/peer
> components**, payload-tree SHA-256
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`,
> and ZIP SHA-256
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`.
> Known Anchor test-middleman key mismatch, legacy macro-`cfg`, and Rust
> unused-code warnings remained non-fatal. Independent second-model review is
> still **UNVERIFIED**.
>
> **Stop state:** C31 is closed. C32 has no code, RED, edit lease, dependency
> change, release-registry edit, deployment, publisher action, or legal
> adjudication. The ignored local `apps/extension/release/` output may exist; it
> is reproducible evidence, not a tracked or reviewed release candidate.

> ## 2026-09-01 C31 DETERMINISTIC EXTENSION PRODUCTION-DEPENDENCY EVIDENCE — C6 PARTIAL, NO LEGAL VERDICT
>
> Implementation commit
> `327c7a85345b78e8ffd4e9e51a8c532402ef2d22` adds artifact-manifest schema
> v2, the canonical
> `warden.extension-production-dependency-evidence.v1` sidecar, strict
> parser/verifier, package/verify integration, and tamper tests. Portability fix
> `7ac2c629a364b9b8f2b175adf30341e7ac27352f` replaces child `pnpm list` and
> `pnpm licenses` calls with a read-only traversal of the pnpm-installed
> `package.json` production/peer graph after a same-SHA repeat exposed pnpm
> 11's incidental write-open of its store SQLite WAL on this read-only host.
> Final test commit `80709ecde93390ee7566ccef772b7840c7e7afe2` makes refusal of
> extraneous license metadata executable as well as missing metadata. There
> was no dependency/lockfile change, deployment, registry edit, Web Store or
> publisher action, secret, legal ruling, or provider-route change.
>
> Real RED was captured before implementation:
>
> ```sh
> pnpm --filter @warden/extension exec vitest run test/production-dependency-evidence.test.mjs
> ```
>
> It exited **1** because the new
> `scripts/production-dependency-evidence.mjs` contract did not exist. After
> implementation, the focused command below exited **0** at final implementation
> SHA `80709ecde93390ee7566ccef772b7840c7e7afe2`:
>
> ```sh
> pnpm --filter @warden/extension exec vitest run test/production-dependency-evidence.test.mjs test/release-artifact.test.mjs
> ```
>
> Both files passed **16/16** tests. The evidence tests prove canonical ordering
> independent of report order and host paths; a read-only installed-tree walk
> that includes production peers while excluding dev dependencies; missing
> package license declarations preserved as `Unknown`; missing and extraneous
> license metadata refusal; duplicate-key/noncanonical JSON refusal; sidecar
> byte tamper refusal; archive tamper refusal; and the manifest's exact sidecar
> byte-length/SHA-256 binding. Existing artifact tests remain **11/11**.
>
> From a clean tree at `80709ecde93390ee7566ccef772b7840c7e7afe2`, this
> command was run twice and exited **0** both times:
>
> ```sh
> pnpm --filter @warden/extension release:gate
> ```
>
> Both runs produced exactly **60 components**: **58 registry** plus **2
> workspace**, with a **14,737-byte** sidecar. Both runs produced sidecar
> SHA-256
> `1214c446fe93135f5a0f49e6270d76f9f0c4e2ba04917cdcbb9b4cc7ad29c084`,
> artifact-manifest SHA-256
> `65c5a0d623cd10bd0a405300890ea580857b4e9845c935de184202df71a5fb83`,
> payload-tree SHA-256
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`,
> and ZIP SHA-256
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`.
> The source SHA is inside both JSON records. A repository scan found no
> `/opt`, `/root`, `node_modules`, `devDependencies`, or
> `unsavedDependencies` string in the sidecar. The observed declared-license
> values are `0BSD`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`,
> `LGPL-3.0-only`, `MIT`, `Unknown`, and first-party `null`.
> `eyes@0.1.8` and `text-encoding-utf-8@1.0.2` have no usable string license
> declaration in their installed `package.json` and remain `Unknown`; this is
> evidence, not adjudication.
>
> The complete repository command below passed at implementation/fix SHA
> `7ac2c629a364b9b8f2b175adf30341e7ac27352f`; it is not used to pretend the
> later test-only commit was already full-gated:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|production-dependency-evidence|warden\.extension-artifact\.v2|warden\.extension-production-dependency-evidence\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> The first/last SHA matched. The gate passed the action-pin audit **2/2**,
> core **700/700**, extension **490/490**, UI tokens **11/11**,
> transaction-budget **8/8**, WebAuthn **1/1**, real Chromium **15/15**, Rust
> **681 passed / 0 failed / 1 ignored**, builds/typechecks, Argon2 benchmark,
> canonical ZIP/sidecar verification, independent Info-ZIP parse, emitted-bundle
> tooling exclusion, diff check, and clean-tree guard. Known Anchor
> test-middleman key mismatch, legacy macro-`cfg`, and Rust unused-code warnings
> remained non-fatal. The exact command above later exited **0** at
> ledger-inclusive SHA `ad9b6a386276b56ff8c49e1ad39c28f72e4c2b32`, with
> the same test counts and artifact hashes; the clean-break memo immediately
> above records that run without transferring its verdict to the later
> documentation-only commit.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> Production provider routing remains fixed unavailable. C31 changes release
> evidence only.
>
> **Harsh residual:** `bundleCoverage` is deliberately `not-asserted`. This is
> the installed production/peer closure, not proof that every component emitted
> bytes into tree-shaken JavaScript or that no other source/static input shipped.
> Declared licenses are not a vulnerability scan, legal opinion, notice bundle,
> or permission to ship. `rpc-websockets` LGPL, both unknown declarations,
> Jupiter-IDL, and Squads counsel items remain unresolved. The JSON records are
> unsigned and co-generated; an attacker who can replace the ZIP and reviewed
> anchor can replace them too. There is still no independent builder,
> provenance signature, store-returned-package comparison, publisher-control
> evidence, off-host run, external audit, deployment, or real-funds evidence.

> ## 2026-09-01 CLEAN-BREAK PICKUP MEMO — C30 CLOSED; C31 NOT STARTED
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** continue C6 from a fresh read-only map. Inventory the canonical
>   release-artifact manifest/verifier and the shipped extension's production
>   dependency/license closure, then choose one bounded deterministic
>   SBOM/license-attachment contract. Establish real RED before implementation.
>   Do not turn machine-readable dependency evidence into an unreviewed legal
>   conclusion, and do not claim whole-bundle coverage unless the generator
>   proves what production inputs the emitted bundle actually contains.
> - **CWD:** `/opt/warden`.
> - **BASE:** C30 implementation
>   `eda3d0422962f4780e5c7116dfdfcaa6c2eb82fc`; ledger-inclusive, fully gated
>   SHA `b58bd4f660a29e27059d63734587693d27a7587a`. The documentation-only
>   commit containing this memo is intentionally not described as gate green.
> - **READ:** this memo and the C30/C29 entries immediately below;
>   `apps/extension/package.json`; `apps/extension/scripts/release-artifact.mjs`;
>   `apps/extension/scripts/package-release.mjs`;
>   `apps/extension/scripts/verify-release.mjs`;
>   `apps/extension/test/release-artifact.test.mjs`; `pnpm-lock.yaml`;
>   `scripts/supply-chain-gate.sh`; `docs/security/THIRD_PARTY_NOTICES.md`;
>   `docs/security/RELEASE-INTEGRITY.md`; and C6 in the client-security plan.
> - **WRITE (edit lease):** none is currently claimed. After the read-only map,
>   lease only the smallest release script/test/docs set needed for one
>   deterministic production-dependency evidence attachment and commit it
>   in-repo.
> - **DO_NOT_TOUCH:** `.superpowers/**`,
>   `/root/.codex/session-graphs/**`, live `/var/www/**`, deployment/Web Store
>   publisher/account state, secrets, the empty production release registry,
>   or the C1a production extension-id/permitted-origin owner decision. Do not
>   resolve the open LGPL/unknown/Jupiter/Squads counsel items by assertion.
> - **ACCEPT:** one honestly scoped C6 attachment with executable RED,
>   deterministic bytes and hash binding to the reviewed upload artifact,
>   missing/extra/tamper refusal, exact-SHA focused evidence, harsh coverage
>   limits, and a committed/full-gated ledger. Keep the provider fixed
>   unavailable. A dependency inventory is not a vulnerability scan, license
>   opinion, publisher control, or store-returned-package comparison.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs, ignored generated
>   extension artifacts, temporary test data, and git commits only; no deploy,
>   upload, publishing, live service, external message, secret creation, legal
>   ruling, or real-account/funds mutation.
> - **RETURN:** implementation/ledger SHAs, clean/dirty state, exact commands
>   and outcomes, SBOM/license component and byte/hash measurements, unchanged
>   or promoted invariants, independent-review status, explicit coverage gaps,
>   and remaining owner/counsel/external-state blockers.
>
> **Stop state:** C30 is closed and fully recorded below. C31 has no code, RED,
> edit lease, dependency change, release-registry edit, deployment, publisher
> action, or legal adjudication. The ignored local `apps/extension/release/`
> output may exist; it is reproducible evidence, not a tracked or reviewed
> release candidate.

> ## 2026-09-01 C30 IMMUTABLE GITHUB ACTIONS PINS — C6 PARTIAL, NO OFF-HOST ATTESTATION
>
> Implementation commit
> `eda3d0422962f4780e5c7116dfdfcaa6c2eb82fc` replaces every external
> GitHub Actions tag/branch in `.github/workflows/**` with a full upstream
> commit and adds an executable repository-wide pin audit. It changes CI
> executable-source selection only: no extension payload, provider route,
> release registry, deployment, Web Store, publisher, account, secret, or live
> service state changed.
>
> The read-only C6 inventory found **11 mutable call sites** across six external
> actions. The incumbent supply-chain lane already runs pinned cargo-deny plus
> a fail-closed shipped-workspace pnpm audit and stores raw whole-workspace
> license reports. It still has no deterministic SBOM/license attachment bound
> to the eight-file extension upload artifact, and its existing notice carries
> unresolved `rpc-websockets` LGPL, `text-encoding-utf-8` unknown-license,
> Jupiter-IDL, and Squads clean-room/counsel items. C30 therefore chose the
> smaller no-owner-decision action-pin contract and made no legal conclusion.
>
> Executable RED was captured before changing the workflow:
>
> ```sh
> node --test test/github-actions-pins.test.mjs
> ```
>
> It exited **1** and named all 11 mutable references: two
> `actions/checkout@v4`, one `dtolnay/rust-toolchain@stable`, three
> `actions/cache@v4`, two `actions/setup-node@v4`, two
> `pnpm/action-setup@v4`, and one `actions/upload-artifact@v4`.
>
> C30 pins those call sites to six 40-character commits resolved directly from
> the named upstream refs with `git ls-remote` on 2026-09-01. The full mapping
> and resolution method live in `docs/TOOLCHAIN.md`; human-readable versions
> remain review comments only. The test recursively scans every YAML workflow,
> proves that at least one workflow and external reference were measured, and
> accepts only a repository-local `./...` action, a full lowercase Git commit,
> or a Docker SHA-256 digest. Its tamper cases reject a major tag, branch,
> abbreviated SHA, expression, Docker tag, and uppercase pseudo-SHA.
>
> The audit runs at the start of `.claude/test-gate.sh` and as the blocking CI
> job's first post-checkout command, before every other external action. Exact
> clean-SHA focused evidence belongs only to the implementation commit above.
> This command exited **0** and printed the same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && node --test test/github-actions-pins.test.mjs && python3 -c 'import pathlib,yaml; yaml.safe_load(pathlib.Path(".github/workflows/ci.yml").read_text())' && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> Both Node contracts passed and the updated workflow parsed as YAML. The first
> contract exercises the immutable/mutable grammar; the second scans the real
> repository and found zero mutable external references.
>
> Ledger-inclusive full-repository evidence belongs only to
> `b58bd4f660a29e27059d63734587693d27a7587a`. From a clean tree, this exact
> command exited **0** and the first/last SHA matched:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|warden\.extension-artifact\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> The executable gate passed the immutable-action contracts **2/2**, core
> **700/700**, extension **485/485**, UI tokens **11/11**, transaction-budget
> **8/8**, WebAuthn **1/1**, real Chromium **15/15**, Rust **681 passed / 0
> failed / 1 ignored**, builds/typechecks, and the provisional production
> Argon2 benchmark. The canonical release verifier and independent Info-ZIP
> parse passed for **8 files**; payload-tree SHA-256 remained
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`
> and ZIP SHA-256 remained
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`.
> The emitted bundle excluded all release-artifact tooling, diff/clean-tree
> guards passed, and the artifact manifest named the exact ledger source SHA.
> Known Anchor test-middleman key mismatch, legacy macro-`cfg`, and Rust
> unused-code warnings were non-fatal. The documentation-only clean-break memo
> commit does not inherit this verdict or promote an invariant.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> Production provider routing remains fixed unavailable; C30 changes only the
> repository's CI executable-source pins and their audit.
>
> **Harsh residual:** a syntactically immutable ref is not an audit of the code
> at that commit, a signature/provenance statement, or an attestation of the
> mutable `ubuntu-latest` runner image. The audit itself cannot enforce GitHub
> branch or workflow protection; host policy must stop an unreviewed workflow
> edit from inserting executable code before the audit. The pinned workflow has
> not run off-host in this campaign. There is still no extension SBOM/license
> attachment, independent builder identity, signed provenance, store-returned
> package comparison, publisher MFA/least-privilege evidence, external audit,
> deployed release, or real-funds evidence. The adjacent artifact JSON remains
> unsigned and co-generated with its ZIP.

> ## 2026-08-31 CLEAN-BREAK PICKUP MEMO — C29 CLOSED; C30 NOT STARTED
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** continue C6 from a fresh read-only map. Inventory the remaining
>   mutable GitHub Actions references and the existing license/supply-chain
>   machinery, then choose one bounded no-owner-decision slice: preferably an
>   executable immutable-action-pin audit or deterministic extension
>   SBOM/license attachment. Establish real RED before implementation. Do not
>   fabricate a store-returned-package comparison without an authorized Web
>   Store round trip.
> - **CWD:** `/opt/warden`.
> - **BASE:** C29 implementation/fix
>   `305efb34b0179c85bf097b4ef03d98ad85d0a99b`; ledger-inclusive, fully gated
>   SHA `90a9a7ea960aface4690a87d81ebfa80b81b4b12`. The documentation-only
>   commit containing this memo is intentionally not described as gate green.
> - **READ:** this memo and the C29 entry immediately below;
>   `apps/extension/README.md`; `docs/security/RELEASE-INTEGRITY.md`;
>   `docs/TOOLCHAIN.md`; C6 in
>   `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`;
>   `.github/workflows/ci.yml`; and the incumbent supply-chain/license scripts
>   and notices before adding another mechanism.
> - **WRITE (edit lease):** none is currently claimed. After the read-only map,
>   lease only the smallest C6 source/test/docs set needed for one executable
>   slice and commit it in-repo.
> - **DO_NOT_TOUCH:** `.superpowers/**`,
>   `/root/.codex/session-graphs/**`, live `/var/www/**`, deployment/Web Store
>   publisher/account state, secrets, and the empty production release
>   registry. Do not choose the C1a production extension-id/on-chain
>   permitted-origin mechanism; that remains an owner decision.
> - **ACCEPT:** one honestly scoped C6 contract with executable RED, exact-SHA
>   focused evidence, harsh residuals, and a committed/full-gated ledger. Keep
>   the provider fixed unavailable. Never call a locally generated ZIP a
>   store-returned-package comparison or treat co-generated unsigned JSON as an
>   authenticated review anchor.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs, ignored generated
>   extension artifacts, temporary test data, and git commits only; no deploy,
>   upload, publishing, live service, external message, secret creation, or
>   real-account/funds mutation.
> - **RETURN:** implementation/ledger SHAs, clean/dirty state, exact commands
>   and outcomes, artifact/SBOM/action-pin measurements, unchanged/promoted
>   invariants, independent-review status, and remaining owner/external-state
>   blockers.
>
> **Stop state:** C29 is closed and fully recorded below. C30 has no code, RED,
> edit lease, deployment action, publisher action, or release-registry change.
> The ignored local `apps/extension/release/` output may exist; it is
> reproducible evidence, not a tracked or reviewed release candidate.

> ## 2026-08-31 C29 DETERMINISTIC EXTENSION UPLOAD ARTIFACT — C6 PARTIAL, NO PUBLISH
>
> Implementation commit
> `4546fc099241745af90dd0d7de2a78f0dc69831d` adds the canonical artifact
> library, release-only clean-tree/toolchain guard, normalized unpacked tree,
> Web Store upload ZIP, adjacent artifact manifest, verifier, tamper lane,
> exact Node/pnpm pins, CI release step, and release-integrity documentation.
> Fix commit `305efb34b0179c85bf097b4ef03d98ad85d0a99b` makes the production build
> emit `manifest.json` in the canonical serialization the release parser
> requires. The first real clean-HEAD package run at `4546fc0` exposed that
> mismatch and failed closed; it was not called green.
>
> The artifact boundary follows Chrome's current primary contract:
> <https://developer.chrome.com/docs/webstore/prepare> and
> <https://developer.chrome.com/docs/webstore/publish> require an upload ZIP
> containing all extension files with `manifest.json` at the archive root.
> C29 deliberately creates that ZIP, not a CRX and not a Web-Store-returned
> package. No network, publisher API, account, or Web Store state is touched.
>
> The package command requires a clean full Git SHA and exact Node `22.23.2`,
> pnpm `11.12.0`, and esbuild `0.28.2`; it rebuilds rather than trusting stale
> `dist`. It admits only the eight reviewed payload paths, rejects symlinks and
> non-regular/unsafe/duplicate paths, pins the current `[storage]` permission,
> local-code-only CSP, and absent `update_url`, and scans emitted files for a
> bounded set of direct network primitives and high-signal secret formats. It
> writes files as `0644`, directories as `0755`, and all mtimes as
> `1980-01-01T00:00:00.000Z`.
>
> The ZIP writer uses sorted canonical UTF-8 paths, STORE/no compression,
> classic non-ZIP64 headers, fixed DOS timestamps, Unix `0644` external modes,
> and no extras/comments. The strict parser rejects any deviation, validates
> local/central agreement and CRC-32, and compares every path, size, mode, and
> SHA-256 against canonical JSON. Both extension and artifact manifests reject
> ambiguous/noncanonical JSON, including duplicate-key encodings. The verifier
> also calls independent Info-ZIP `unzip -t`.
>
> Executable RED was captured before implementation:
>
> ```sh
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec vitest run test/release-artifact.test.mjs
> ```
>
> It exited **1** because `../scripts/release-artifact.mjs` did not exist. The
> implemented lane now has **11/11** contracts. They prove byte identity under
> input reorder and source mtime/mode drift, normalized unpacked metadata,
> canonical archive parsing, unsafe-path/duplicate/symlink/mode refusal,
> canonical manifest/attestation JSON, complete payload verification, and
> fail-closed rejection after a valid canonical ZIP is recomputed with: exactly
> one JavaScript byte changed; an added manifest permission; a relaxed CSP; an
> introduced update URL; a changed dependency-produced `background.js`; or a
> missing/extra file.
>
> The release-only dirty-tree guard was separately red before the implementation
> commit: `pnpm --filter @warden/extension release:package` exited **1** and
> listed the tracked/untracked implementation paths rather than packaging them.
> The first clean package run then found the canonical-manifest integration bug
> described above. Those failures are evidence that both gates measure their
> intended boundary, not release verdicts.
>
> Exact focused evidence belongs only to clean implementation SHA
> `305efb34b0179c85bf097b4ef03d98ad85d0a99b`. This command exited **0** with
> matching first/last SHA:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|warden\.extension-artifact\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> It passed extension **485/485**, typecheck, production build, canonical
> package and verifier, Info-ZIP interoperability, artifact-tool exclusion,
> diff validation, and clean-tree guards. The measured payload has **8 files**
> and **925,564 bytes**; the STORE ZIP is **926,374 bytes**. Its payload-tree
> SHA-256 is
> `f0e7ef2c6f3d1133b5e40557a014a656ccd1fe0cb7590632973b8e33a447a879`,
> ZIP SHA-256 is
> `ce1b3a4792cd28def0b336d99a990bda3141c26f0b625b206163d505aca2c844`,
> and artifact-manifest SHA-256 is
> `2d8deac4958fc5ba873527106fa747631a221489b3702be0e912a51d3a389803`.
> `zipinfo -l apps/extension/release/warden-extension-0.0.1.zip` independently
> reported eight STORE entries, `-rw-r--r--`, and `80-Jan-01 00:00`; `unzip
> -Z1` reported the sorted paths with root `manifest.json`.
>
> A second same-tree release gate reproduced all three hashes. Two additional
> clean local clones at the exact implementation SHA installed from the pinned
> lockfile with separate copied dependency materializations:
>
> ```sh
> env npm_config_cache=/tmp/warden-npm-cache pnpm install --offline --frozen-lockfile --store-dir /tmp/warden-c29-pnpm-store --package-import-method=copy
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate
> cmp /tmp/warden-c29-builder-a.H0eOHa/apps/extension/release/warden-extension-0.0.1.zip /tmp/warden-c29-builder-b.3pMhPa/apps/extension/release/warden-extension-0.0.1.zip
> cmp /tmp/warden-c29-builder-a.H0eOHa/apps/extension/release/warden-extension-0.0.1.artifact.json /tmp/warden-c29-builder-b.3pMhPa/apps/extension/release/warden-extension-0.0.1.artifact.json
> diff -qr /tmp/warden-c29-builder-a.H0eOHa/apps/extension/release/unpacked /tmp/warden-c29-builder-b.3pMhPa/apps/extension/release/unpacked
> ```
>
> Both package gates and all three comparisons exited **0** and both ZIP hashes
> were `ce1b3a47...`. The builders had separate clean source and `node_modules`
> trees but shared this host, Node binary, and copied package cache. The first
> attempt without a writable store failed with `ERR_SQLITE_ERROR` and produced
> no artifact; it is not counted. All temporary clone/cache paths were removed
> after comparison and are recoverable by repeating the commands.
>
> Ledger-inclusive full-repository evidence belongs only to
> `90a9a7ea960aface4690a87d81ebfa80b81b4b12`. From a clean tree, this exact
> command exited **0** and the first/last SHA matched:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension release:gate && if rg -n 'release-artifact|package-release|verify-release|warden\.extension-artifact\.v1' apps/extension/dist; then exit 1; fi && git diff --check && git diff --exit-code && test -z "$(git status --porcelain)" && git rev-parse HEAD
> ```
>
> The executable gate passed core **700/700**, extension **485/485**, UI tokens
> **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real Chromium
> **15/15**, builds/typechecks, the provisional production Argon2 benchmark,
> the complete Rust workspace suite, canonical release package/verifier,
> independent Info-ZIP parse, artifact-tool exclusion, diff validation, and
> clean-tree guards. At this ledger SHA the payload-tree and ZIP hashes remain
> `f0e7ef2c...` and `ce1b3a47...`; the source-SHA-bearing artifact JSON hash is
> `5dcace34442d00124a3eeea5bf05c8d02fce67b88071a7080cef73790158c129`.
> Known Anchor test-middleman key mismatch, legacy macro-`cfg`, and Rust
> unused-code warnings were non-fatal. The documentation-only clean-break memo
> commit does not inherit this verdict or promote an invariant.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> Production provider routing remains fixed unavailable; C29 changes build and
> release evidence only.
>
> **Harsh residual:** this is a competent upload-ZIP generator, not a release
> system and emphatically not a deployable wallet. The extension still calls
> itself development/pre-alpha `0.0.1`; there is no production extension id,
> account onboarding, deployed release registry, trusted RPC/account
> composition, provider activation, send/confirm path, external audit, or
> real-funds evidence. The custom ZIP grammar has interoperability evidence
> from one Info-ZIP implementation but has never been accepted by the Chrome
> Web Store. It intentionally rejects store-repacked CRX input, so C6's
> downloaded-package normalization/comparison remains absent. The adjacent
> artifact JSON is unsigned and co-generated: if a reviewer does not anchor its
> exact bytes/hash elsewhere, replacing both JSON and ZIP defeats the verifier.
> Same-host clean clones are not independent infrastructure or builder identity.
> Direct-network and secret regexes are guardrails, not semantic no-I/O proof or
> secret provenance. GitHub Actions still use mutable major tags. There is no
> extension SBOM/license attachment, provenance signature, publisher
> MFA/least-privilege evidence, or independent review.
>
> **Next load-bearing work:** stay in C6 and keep production unavailable. The
> next autonomous slice should inventory immutable GitHub Actions SHA pins and
> deterministic extension SBOM/license attachment, then choose one bounded
> executable gate. Store-returned-package comparison cannot honestly close
> until an authorized Web Store round trip exists; do not fake it with a locally
> wrapped CRX.

> ## 2026-08-31 CLEAN-BREAK PICKUP MEMO — C28 CLOSED; C29 NOT STARTED
>
> `TO / TASK / CWD / BASE / READ / WRITE (edit lease) / DO_NOT_TOUCH / ACCEPT / SIDE_EFFECTS / RETURN`
>
> - **TO:** the next Warden implementation/review session.
> - **TASK:** begin a fresh production-enablement loop. Do not extend the
>   C23-C28 delivery micro-cut sequence. First inventory C6 deterministic
>   extension packaging/artifact comparison against the current build and
>   release-integrity contracts; select one load-bearing, no-owner-decision
>   gap and establish executable RED before implementation.
> - **CWD:** `/opt/warden`.
> - **BASE:** C28 implementation
>   `f9787ef8b592fc78a2a06b7cab2842e1fc31a707`; ledger-inclusive full-gated
>   SHA `ed3f6d50104cf8ce014e868ee741464addab60f0`. The documentation-only
>   commit containing this memo is intentionally not described as gate green.
> - **READ:** this memo and the C28 entry immediately below;
>   `docs/security/THREATMODEL.md` C28; `apps/extension/README.md`; C6 in
>   `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`;
>   and `docs/security/RELEASE-INTEGRITY.md`.
> - **WRITE (edit lease):** none is currently claimed. After a read-only map,
>   lease only the smallest C6 source/test/ledger set needed for the chosen
>   executable slice and commit it in-repo.
> - **DO_NOT_TOUCH:** `.superpowers/**`, `/root/.codex/session-graphs/**`, live
>   `/var/www/**`, deployment/publisher/account state, secrets, and the empty
>   production release registry. Do not choose the C1a production extension-id
>   or on-chain permitted-origin mechanism; that remains an owner decision.
> - **ACCEPT:** one honestly scoped deterministic packaging/comparison contract
>   with an executable RED, focused gates at an exact implementation SHA,
>   shipped-artifact measurements, harsh residuals, and committed ledgers. Keep
>   the provider fixed unavailable unless the missing deployed release, trusted
>   RPC/account composition, and owner decisions actually exist.
> - **SIDE_EFFECTS:** local `/opt/warden` source/tests/docs and git commits only;
>   no deploy, publishing, live service, external message, secret creation, or
>   real-account/funds mutation.
> - **RETURN:** exact implementation/ledger SHAs, clean/dirty state, executable
>   commands and results, artifact hashes or mismatch paths, unchanged/promoted
>   invariants, independent-review status, and remaining owner decisions.
>
> **Stop state:** C28 is closed and fully recorded below. No C29 code, RED test,
> packaging design, release-registry edit, or deployment action has begun.
>
> ## 2026-08-31 C28 PRE-SETTLEMENT-ENQUEUE RECOVERY — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `f9787ef8b592fc78a2a06b7cab2842e1fc31a707` closes the last
> deterministically controllable edge in the C23-C28 worker-cut sequence. The
> unchanged page has already accepted the exact signed terminal and emitted its
> identity-bound receipt. The production background then accepts that receipt,
> finishes delivery ownership, clears the active binding, records the delivered
> Port generation, and enters `Port.postMessage(transport-settled)`. The cut is
> immediately before the browser-only wrapper delegates that final call to
> Chrome's native Port.
>
> The wrapper still surrounds only the provider Port passed to the real
> `ProviderRuntimeTransportOwner`; production source is unchanged. It retains a
> copy of the parser-validated signed terminal only after native terminal
> enqueue succeeds. At the settlement edge it requires correlation id, receipt
> id, and immutable deadline to equal that terminal, publishes a non-secret
> marker containing the exact public signed bytes and counters, and holds before
> native settlement enqueue. A new unit post hook independently asserts that
> the production delivery lease is already inactive when the settlement send
> begins; the marker is therefore not the sole evidence for production ordering.
>
> At the cut the MAIN-world observation is one signed Promise settlement, one
> valid receipt post, one navigation, and exact marker bytes. Content retains
> one pending entry because no settlement acknowledgment has been enqueued. An
> inert extension page removes the serialized unlock session, and CDP closes
> the actual service-worker target. A different ready-but-locked boot performs
> zero selection, identity, RPC, approval create/claim/complete, signer lease,
> or signer-result work. It replays the exact durable terminal; content matches
> the retained terminal/receipt identity, resends the receipt without forwarding
> a second page response, and removes its pending entry only after the replacement
> acknowledges settlement. The page observation remains exactly unchanged, and
> the reviewed message/digest and Ed25519 signature are independently verified.
>
> Executable RED:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec playwright test -c playwright.config.ts
>   provider-sign-success.pw.ts -g "accepted page receipt recovers"`
>   first exited **1** at the intended arm boundary with
>   `unsupported signing worker checkpoint`.
>
> The current Chrome primary contracts remain:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/how-to/test/end-to-end-testing>,
> and
> <https://developer.chrome.com/docs/extensions/how-to/test/test-serviceworker-termination-with-puppeteer>.
> They support Port reconnect and forced worker-target termination tests, but
> expose no end-to-end acknowledgment for `Port.postMessage()` and no
> deterministic hook after native enqueue but before the other endpoint's
> listener. C28 therefore tests the exact pre-native edge rather than fabricating
> message loss in a content listener and calling it worker-lifecycle evidence.
>
> Exact focused evidence at clean implementation SHA
> `f9787ef8b592fc78a2a06b7cab2842e1fc31a707` used these commands:
>
> ```sh
> git rev-parse HEAD
> git status --short
> pnpm --filter @warden/extension test
> pnpm --filter @warden/extension typecheck
> pnpm --filter @warden/extension build
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts --repeat-each=5
> if rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint|during-signing-commit|warden:test:signing-commit-request-succeeded-v1|native IDBObjectStore.put is unavailable|in-flight commit checkpoint control|native signing-completion request did not reach success|after-terminal-enqueued|warden:test:terminal-enqueued-v1|terminal-enqueue checkpoint control|Warden test control|page-settled signed result|before-settlement-enqueue|warden:test:before-settlement-enqueue-v1|settlement-enqueue checkpoint control|accepted page receipt recovers' apps/extension/dist; then exit 1; fi
> git diff --check
> git diff --exit-code
> git status --short
> git rev-parse HEAD
> ```
>
> They exited **0** and the first/last SHA matched: extension **474/474**,
> typecheck, production build, all six signing/recovery/fail-closed/settlement
> browser contracts repeated five times (**30/30**), emitted-artifact
> exclusion, diff validation, and clean-tree guards passed. The
> ledger-inclusive full repository gate is deliberately not inferred from
> focused evidence; it must run on the subsequent ledger SHA.
>
> Ledger-inclusive full-repository evidence belongs only to
> `ed3f6d50104cf8ce014e868ee741464addab60f0`. From a clean tree, these exact
> commands exited **0** and the first/last SHA matched:
>
> ```sh
> git rev-parse HEAD
> git status --short
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> if rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint|during-signing-commit|warden:test:signing-commit-request-succeeded-v1|native IDBObjectStore.put is unavailable|in-flight commit checkpoint control|native signing-completion request did not reach success|after-terminal-enqueued|warden:test:terminal-enqueued-v1|terminal-enqueue checkpoint control|Warden test control|page-settled signed result|before-settlement-enqueue|warden:test:before-settlement-enqueue-v1|settlement-enqueue checkpoint control|accepted page receipt recovers' apps/extension/dist; then exit 1; fi
> git diff --check
> git diff --exit-code
> git status --short
> git rev-parse HEAD
> ```
>
> The executable gate passed core **700/700**, extension **474/474**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real
> Chromium **15/15**, builds/typechecks, the production Argon2 benchmark, the
> complete Rust workspace suite, emitted-artifact exclusion, diff validation,
> and clean-tree guards. Known Anchor test-program key, legacy macro-`cfg`, and
> Rust unused-code warnings were non-fatal. This documentation-only evidence
> commit does not inherit that verdict or promote an invariant.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`. The
> success graph, Port wrapper, checkpoint, marker, control page, counters, and
> recovery composition remain browser-only and absent from production artifacts.
>
> **Harsh residual:** C28 does **not** implement the stronger wording previously
> proposed for this cut. It does not enqueue the native settlement and then
> prove death before content receives it; Chrome exposes no deterministic
> acknowledgment or pause there. A content-side wrapper that silently drops an
> already delivered event would simulate the desired conclusion and was
> rejected. This remains a forced target close in one loaded Chromium profile,
> not idle eviction, browser/renderer/OS crash, restart, power loss, storage
> eviction/corruption, or stable-media evidence. Preparation, pending approval,
> and post-terminal-enqueue/pre-page-settlement cuts also remain unmeasured.
> Production remains fixed unavailable with an empty release registry, no
> onboarding/account registry, no production KDF decision, no Wallet Standard
> registration, no send/confirm path, no external audit, and no real-funds
> exercise.
>
> **Next load-bearing work:** stop extending the delivery micro-sequence. The
> live provider cannot honestly activate before a committed deployed release,
> trusted RPC/account selection, and the C1a production-origin owner decision.
> The next autonomous lane should map and close the highest no-owner-decision
> deployability blocker—starting with C6 deterministic extension packaging and
> artifact comparison—while preserving the fixed-unavailable provider.
>
> ## 2026-08-31 C27 POST-PAGE-RECEIPT SETTLEMENT RECOVERY — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `ae06fa2faa6e53e1dfbac3934e404449da918a78` cuts a delivery boundary that
> C24-C26 did not measure. The exact signed terminal is enqueued through the
> real Chrome Port, reaches the unchanged page, settles its Promise, and causes
> the page to emit its identity-bound receipt, but the original worker dies
> before the background transport can record exact delivery proof or accept
> that receipt.
>
> The browser-only worker wraps only the provider Port passed into the real
> `ProviderRuntimeTransportOwner`. It preserves the native sender, message and
> disconnect events, and native disconnect method. For one armed exact signed
> terminal, it calls the bound native `Port.postMessage()` first, validates the
> real transport envelope and signed response, publishes a non-secret marker,
> and synchronously holds the wrapper before returning. The production owner
> is therefore still inside `#postTerminal`: `postedGeneration` is unset and
> `finish()`/flow proof cannot run, even though the browser has delivered the
> message to the content and page owners.
>
> The MAIN-world fixture now independently counts Promise terminal settlements
> and well-formed page receipt posts and retains the last receipt identity. At
> the cut it proves one signed settlement, one receipt, one navigation, exact
> marker/page bytes, and one still-pending content entry. The test uses a
> dedicated inert extension page because the real approval popup correctly
> closes after approval completes. That independent page removes the serialized
> unlock session, then CDP closes the actual service-worker target.
>
> A different boot starts ready-but-locked and performs zero selection,
> identity, RPC, approval create/claim/complete, signer lease, or signer-result
> work. The durable operation replays the exact terminal. Because the content
> owner retained both the first terminal and the page's receipt id, it accepts
> only an exact duplicate envelope and re-sends the receipt directly without
> forwarding a second response to the page. The replacement proves delivery,
> accepts that receipt, sends settlement, and content pending falls from one to
> zero. The complete page observation remains byte-for-byte unchanged: exactly
> one Promise settlement and one page receipt. The returned message and digest
> still equal the reviewed values and the Ed25519 signature is independently
> verified.
>
> Executable RED:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec playwright test -c playwright.config.ts
>   provider-sign-success.pw.ts -g "page-settled signed result"`
>   first exited **1** at the intended arm boundary with
>   `unsupported signing worker checkpoint`.
>
> Current primary contracts rechecked:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/how-to/test/end-to-end-testing>,
> and
> <https://developer.chrome.com/docs/extensions/how-to/test/test-serviceworker-termination-with-puppeteer>.
> Chrome documents Port as a two-way long-lived channel whose messages use
> `postMessage`, `onDisconnect` as the loss signal for the other endpoint,
> extension-page execution as a valid way to inspect extension state, and
> forced worker termination as a robustness test because non-persistent worker
> state can disappear without warning. Those contracts support this bounded
> reconnect test; they do not turn `postMessage()` return into delivery
> acknowledgment or make target death equivalent to browser/OS crash.
>
> Exact focused evidence at clean implementation SHA
> `ae06fa2faa6e53e1dfbac3934e404449da918a78` used these commands:
>
> ```sh
> git rev-parse HEAD
> git status --short
> pnpm --filter @warden/extension test
> pnpm --filter @warden/extension typecheck
> pnpm --filter @warden/extension build
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts --repeat-each=5
> if rg -n "after-terminal-enqueued|terminal-enqueued-v1|Warden test control|provider-sign-success-browser" apps/extension/dist; then exit 1; fi
> git diff --check
> git diff --exit-code
> git status --short
> git rev-parse HEAD
> ```
>
> They exited **0** and the first/last SHA matched: extension **473/473**,
> typecheck, production build, all five signing/recovery/fail-closed/settlement
> browser contracts repeated five times (**25/25**), emitted-artifact
> exclusion, diff validation, and clean-tree guards passed. The
> ledger-inclusive full repository gate is deliberately not inferred from
> focused evidence; it must run on the subsequent ledger SHA.
>
> Ledger-inclusive full-repository evidence belongs only to
> `5a9dff7b2e6399ef7ff6d9558243d3d5f4b76b0b`. From a clean tree, these exact
> commands exited **0** and the first/last SHA matched:
>
> ```sh
> git rev-parse HEAD
> git status --short
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> if rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint|during-signing-commit|warden:test:signing-commit-request-succeeded-v1|native IDBObjectStore.put is unavailable|in-flight commit checkpoint control|native signing-completion request did not reach success|after-terminal-enqueued|warden:test:terminal-enqueued-v1|terminal-enqueue checkpoint control|Warden test control|page-settled signed result' apps/extension/dist; then exit 1; fi
> git diff --check
> git diff --exit-code
> git status --short
> git rev-parse HEAD
> ```
>
> The executable gate passed core **700/700**, extension **473/473**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real
> Chromium **14/14**, builds/typechecks, the production Argon2 benchmark, the
> complete Rust workspace suite, emitted-artifact exclusion, diff validation,
> and clean-tree guards. Known Anchor test-program key, legacy macro-`cfg`, and
> Rust unused-code warnings were non-fatal. This evidence-only documentation
> commit does not inherit that verdict or promote an invariant.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`. The
> success graph, terminal wrapper, control page, counters, marker, and recovery
> composition remain browser-only and absent from production artifacts.
>
> **Harsh residual:** C27 is an instrumented target-termination test inside one
> loaded Chromium profile. It is not an idle-eviction timing test, browser
> restart, renderer/browser crash, OS crash, power-loss, storage-corruption, or
> stable-media test. It cuts after the page receipt exists; it does not cut
> after terminal enqueue but before page settlement, or after background
> receipt acceptance while the settled acknowledgment is still in flight.
> Preparation and pending approval also remain uncut. Production remains fixed
> unavailable with an empty release registry, no onboarding/account registry,
> no production KDF decision, no Wallet Standard registration, no send/confirm
> path, no external audit, and no real-funds exercise.
>
> **Next load-bearing work:** C28 should isolate the final volatile boundary:
> enqueue the real background `transport-settled` acknowledgment after receipt
> acceptance, kill before the content owner receives/removes it, and prove one
> bounded locked-worker recovery clears the retained entry without a second
> page terminal, receipt, selection, RPC call, approval, key read, or signature.
> After that cut, stop extending the delivery micro-sequence and return to the
> production-enablement blockers unless executable evidence exposes a defect.
>
> ## 2026-08-31 C26 IN-FLIGHT SIGNING-COMMIT WORKER CUT — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `48cc0323ceb4a113f17fead282c569386320a606` closes the unmeasured interval
> between C25's returned signer result and C24's committed signed outcome. The
> browser-only worker now delegates the exact completed approval envelope to
> native `IDBObjectStore.put`, attaches a listener to that native request's
> `success` event, publishes a non-secret checkpoint marker through
> `chrome.storage.session`, and synchronously holds the event open. The
> production repository and its `{ durability: "strict" }` readwrite
> transaction remain real; no fake repository or simulated commit decides the
> result.
>
> The marker proves the same reviewed approval and attempt reached native write
> request success after one selection, approval create, signing claim,
> completion call, key lease, and signer result, with the exact expected RPC
> counts. At that point the page and content owner are still pending. An
> independent extension page removes the serialized unlock session, and CDP
> closes the actual service-worker target before the held request event can
> return.
>
> A different boot must start ready-but-locked and perform zero selection,
> identity, RPC, approval create/claim/complete, key lease, or signer-result
> work. The contract accepts only the native transaction's two atomic durable
> outcomes. If the signed row committed, startup invalidates zero approvals and
> the retained operation replays exactly those durable bytes; the test
> deserializes them, matches the reviewed message and digest, and independently
> verifies the Ed25519 signature. If the transaction aborted, startup converts
> exactly one unresolved attempt to `failed/worker-restarted`, the page receives
> one generic failure, and durable/page signed bytes remain null. Either branch
> retains attempt number 1, settles content pending to zero, leaves no
> non-document volatile owner, performs no retry, and keeps one navigation.
> The test deliberately validates this allowed union; it does not claim both
> outcomes were observed across repeated runs.
>
> Executable RED:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec playwright test -c playwright.config.ts
>   provider-sign-success.pw.ts -g "in-flight strict signing commit"`
>   first exited **1** at the intended arm boundary with
>   `unsupported signing worker checkpoint`.
>
> Primary contracts checked:
> <https://w3c.github.io/IndexedDB/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> and
> <https://developer.chrome.com/docs/extensions/how-to/test/test-serviceworker-termination-with-puppeteer>.
> IndexedDB defines transaction changes as atomic and defines `strict`
> durability as an attempt to verify persistence before completion, not a
> guarantee against operating-system failure or loss of the storage medium.
> C26 therefore proves an MV3 target-termination recovery contract inside one
> loaded Chromium session, not browser-crash, power-loss, eviction, corruption,
> disk-loss, or stable-media durability.
>
> Exact focused evidence at clean implementation SHA
> `48cc0323ceb4a113f17fead282c569386320a606`:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts --repeat-each=5 --workers=1
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint|during-signing-commit|warden:test:signing-commit-request-succeeded-v1|native IDBObjectStore.put is unavailable|in-flight commit checkpoint control|native signing-completion request did not reach success' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension
> **473/473**, typecheck, all four success/recovery/fail-closed/in-flight
> real-browser contracts repeated five times (**20/20**), production build,
> emitted-artifact exclusion, `git diff --check`, and clean-tree guards passed.
> The full repository gate is deliberately not inferred from focused evidence;
> it must run on the subsequent ledger-inclusive SHA.
>
> Ledger-inclusive full-repository evidence belongs only to
> `a9127d978d645a91df4cb79161ff01bcbe5789b2`. From a clean tree, this exact
> command exited **0** and printed that SHA before and after:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint|during-signing-commit|warden:test:signing-commit-request-succeeded-v1|native IDBObjectStore.put is unavailable|in-flight commit checkpoint control|native signing-completion request did not reach success' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> The executable gate passed core **700/700**, extension **473/473**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real
> Chromium **13/13**, builds/typechecks, the production Argon2 benchmark, the
> complete Rust workspace suite, emitted-artifact exclusion, diff validation,
> and clean-tree guards. Known Anchor test-program key, legacy macro-`cfg`, and
> Rust unused-code warnings were non-fatal. This evidence-only documentation
> commit does not inherit that verdict.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented` because
> the entire success composition, native checkpoint hook, marker, and recovery
> control remain excluded from production artifacts.
>
> **Harsh residual:** C26 proves only atomic recovery from an actual service-
> worker target kill while one native IndexedDB request event is held. Its
> JavaScript hook is test instrumentation; it does not reproduce an OS crash,
> power failure, browser data eviction, corruption, or storage-media loss, and
> the lane does not force or count both allowed branches. Preparation, pending
> approval, terminal enqueue, page receipt, settled acknowledgment, and whole-
> browser restart remain uncut. Production still has an empty release registry,
> fixed unavailable provider, deterministic test Connection only, no
> onboarding/account registry, no production KDF decision, no Wallet Standard
> registration, no send/confirm path, no external audit, and no real funds.
>
> **Next load-bearing work:** C27 should kill after the durable terminal result
> is available to the retained operation but before the original worker can
> finish terminal delivery, then prove a locked replacement returns exactly one
> bound outcome without signing, replay confusion, navigation, or leaked
> volatile ownership. Do not conflate terminal enqueue, page receipt, and
> settled acknowledgment; cut and measure one boundary at a time.
>
> ## 2026-08-31 C25 PRE-COMMIT SIGNATURE WORKER CUT — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `fef3860805787c1540720f78f7f53f386be45904` closes the opposite side of
> C24's signing boundary. A real MV3 worker is now killed after the contextual
> keyring callback has returned transaction bytes but before the coordinator
> receives them, reparses them, or calls `completeSigning()`. Because no signed
> outcome was committed, the only safe replacement behavior is a closed
> failure—not reconstruction or retry.
>
> The first worker's measured state at the cut is one selection, one approval
> creation, one signing claim, one signer lease, one returned signer result,
> zero signing-completion calls, and a durable `approved/signing` attempt 1
> with no transaction bytes or failure code. The page and content owners remain
> pending. The test removes the serialized unlock session and closes the actual
> service-worker CDP target.
>
> A different boot starts ready-but-locked. Startup atomically converts exactly
> one unresolved approval attempt to `failed/worker-restarted`; the already-
> bound provider operation is retained, so operation invalidation remains zero
> and that locator routes the durable failure. The replacement performs zero
> selection, identity, RPC, approval creation/claim/completion, key lease, or
> signer-result work. It emits `WARDEN_REQUEST_FAILED`, the page settles once
> as `ProviderPageTerminalError: Provider request failed`, and page/durable
> signed bytes remain absent. Attempt number remains 1, old+new signer leases
> and returned results each total exactly 1, signing completions total 0,
> navigation remains 1, and every non-document volatile owner settles.
>
> Executable RED and review correction:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec playwright test -c playwright.config.ts
>   provider-sign-success.pw.ts -g "uncommitted signature is abandoned"`
>   first exited **1** because the real worker rejected the new stage with
>   `unsupported C24 worker checkpoint`.
> - The first implementation run then exposed a test-observation mistake: the
>   page fixture snapshots `pendingCount` before `signTransaction()` registers
>   its Promise, so that historical field is zero. C25 no longer treats it as
>   live state; the independent content-owner probe measures one pending entry
>   before the cut and zero after terminal settlement.
>
> Primary contracts checked:
> <https://w3c.github.io/IndexedDB/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> and
> <https://developer.chrome.com/docs/extensions/how-to/test/test-serviceworker-termination-with-puppeteer>.
> IndexedDB defines transaction changes as atomic and distinguishes `strict`,
> `relaxed`, and user-agent-default durability. Both Warden write repositories
> already request `{ durability: "strict" }`; C25 observes the replacement read
> the committed failure transaction. Because the specification calls this a
> durability hint, C25 still makes no OS crash, power-loss, eviction,
> corruption, or stable-media guarantee.
>
> Exact focused evidence at clean implementation SHA
> `fef3860805787c1540720f78f7f53f386be45904`:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts --repeat-each=5
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension
> **473/473**, typecheck, all three success/recovery/fail-closed real-browser
> contracts repeated five times (**15/15**), production build, emitted-artifact
> exclusion, `git diff --check`, and clean-tree guards passed. The full
> repository gate is deliberately not claimed by this implementation entry; it
> must run on the subsequent ledger-inclusive SHA.
>
> Ledger-inclusive full-repository evidence belongs only to
> `e85841b54e8966e1c73367b4465b58645ee9ecb1`. From a clean tree, this exact
> command exited **0** and printed that SHA before and after:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring|after-signature-produced|signerResultsProduced|signingFailureCode|precommit checkpoint control|unsupported signing worker checkpoint|signing worker checkpoint' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> The executable gate passed core **700/700**, extension **473/473**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real
> Chromium **12/12**, builds/typechecks, the production Argon2 benchmark, the
> complete Rust workspace suite, emitted-artifact exclusion, diff validation,
> and clean-tree guards. Known Anchor test-program key, legacy macro-`cfg`, and
> Rust unused-code warnings were non-fatal. This evidence-only documentation
> commit does not inherit that verdict.
>
> Independent second-model review remains **UNVERIFIED**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented` because
> this composition and both checkpoints are still build-excluded fixtures.
>
> **Harsh residual:** C25 cuts after the keyring owner has returned bytes but
> before coordinator validation. It does not cut inside seed use, during the
> `completeSigning()` IndexedDB transaction, or between its request success and
> transaction completion. C24 and C25 bracket that commit but do not measure
> its ambiguous in-flight state. Preparation, pending approval, terminal
> enqueue, page receipt, settled acknowledgment, whole-browser restart, and
> storage loss remain uncut. Production still has an empty release registry,
> fixed unavailable provider, deterministic test Connection only, no
> onboarding/account registry, no production KDF decision, no Wallet Standard
> registration, no send/confirm path, no external audit, and no real funds.
>
> **Next load-bearing work:** C26 should force death while the strict
> `completeSigning()` transaction is in flight and accept only two durable
> outcomes: exact committed-byte replay or one `worker-restarted` failure. It
> must never retry, mix those outcomes, or deliver bytes absent from the
> replacement's durable read. If a deterministic in-transaction cut cannot be
> engineered honestly, document it as untestable and move to terminal-enqueue /
> receipt cuts rather than simulating a commit.
>
> ## 2026-08-31 C24 COMMITTED-RESULT WORKER CUT — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `f7163720fe287c19bf25368ae9c8faa4f2b53e9b` closes one precise C23
> restart gap: a real MV3 worker can now be killed after the signed transaction
> is committed to the durable approval row but before the original coordinator
> continuation or provider flow delivers it, and the unchanged page still
> receives exactly that result from a replacement worker.
>
> The browser checkpoint sits after `completeSigning()` returns the
> IndexedDB-backed `signed` outcome. At the cut, the first worker has exactly
> one selection, approval creation, signing claim, signing completion, and
> signer lease; the approval/flow/page are still pending and the page has no
> terminal bytes. The test then removes the serialized unlock session, closes
> the actual service-worker CDP target, and requires a different boot id. The
> replacement starts locked, invalidates zero signed approvals and zero bound
> operations, performs zero selection/RPC/approval/key/signing calls, follows
> the retained-operation replay branch, re-verifies the durable signed result,
> and completes the C20–C22 receipt handshake. Returned page bytes, durable
> bytes, reviewed message bytes, SHA-256 digest, and independently verified
> Ed25519 signature all match; navigation remains exactly one and every
> non-document volatile owner settles.
>
> C24 also removes a dishonest test-harness behavior. C23 resealed and unlocked
> the fixture keyring on every worker boot, which could fabricate authority
> after a restart. The test worker now calls the real authenticated
> `KeyringLifecycleOwner.restore()` first and records a test-only one-time
> initialization marker. If a prior fixture exists but its session cannot be
> restored, startup becomes ready-but-locked and never reseeds or re-unlocks.
> This lets durable terminal recovery proceed without granting a new signer
> generation, while any new selection still fails closed.
>
> Executable RED and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec playwright test -c playwright.config.ts
>   provider-sign-success.pw.ts -g "durable signed bytes replay"` first exited
>   **1** at the deliberate boundary because the restart checkpoint control did
>   not exist: `restart checkpoint control is unavailable`.
> - The finished two-contract file passed **6/6** under `--repeat-each=3`; this
>   repeats both uninterrupted C23 and committed-result C24 paths with fresh
>   temporary extensions.
> - The complete extension unit lane remains **473/473**, the production build
>   excludes every C24 checkpoint/marker string, and the complete Chromium lane
>   is now **11/11**.
>
> Primary contracts checked:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage>, and
> <https://developer.chrome.com/docs/extensions/how-to/test/test-serviceworker-termination-with-puppeteer>.
> Chrome states that service-worker globals are lost at shutdown, recommends
> persisted state and termination testing, and documents `storage.session` as
> in-memory state retained while the extension is loaded but cleared on browser
> restart, extension reload/update/disable. C24 therefore proves one forced
> worker replacement inside one browser session only; it makes no browser-
> restart claim.
>
> Exact focused evidence at clean implementation SHA
> `f7163720fe287c19bf25368ae9c8faa4f2b53e9b`:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts --repeat-each=3
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension
> **473/473**, typecheck, repeated real Chromium **6/6**, production build,
> emitted-artifact exclusion, `git diff --check`, and clean-tree guards passed.
> The full repository gate is deliberately not claimed by this implementation
> entry; it must run on the subsequent ledger-inclusive SHA.
>
> Ledger-inclusive full-repository evidence belongs only to
> `cba956c25dedb323110fcd4e983bead35181b97c`. From a clean tree, this exact
> command exited **0** and printed that SHA before and after:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> test -z "$(rg -n 'after-signing-committed|warden-provider-sign-success-keyring-initialized-v1|restart checkpoint control|C24 keyring' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> The executable gate passed core **700/700**, extension **473/473**, UI
> tokens **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, real
> Chromium **11/11**, builds/typechecks, the production Argon2 benchmark, the
> complete Rust workspace suite, emitted-artifact exclusion, diff validation,
> and clean-tree guards. Known Anchor test-program key, legacy macro-`cfg`, and
> Rust unused-code warnings were non-fatal. This evidence-only documentation
> commit does not inherit that verdict.
>
> Independent second-model review remains **UNVERIFIED**. No review verdict is
> inferred from the prior host app-server initialization failure.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented` because
> this is still a temporary, build-excluded composition.
>
> **Harsh residual:** C24 cuts only after durable signing completion. It does
> not kill during operation preparation, pending approval, signer use before
> commit, terminal enqueue, page receipt, or settled acknowledgment. It does
> not prove `storage.session` across browser restart—the official contract says
> it is cleared—or protect IndexedDB against browser crash, eviction, storage
> corruption, or disk loss. The one-time initialization marker is test fixture
> state, not an onboarding/account registry design. Production still has an
> empty release registry, fixed unavailable provider, no live RPC/KDF decision,
> no Wallet Standard injection/registration, no send/confirm, no external
> audit, and no real funds.
>
> **Next load-bearing work:** C25 should stop after the signer has produced an
> in-memory signature but before `completeSigning()` commits. The replacement
> must start locked, invalidate that exact signing attempt to
> `worker-restarted`, emit one closed failure, never retry or expose the
> uncommitted bytes, and measure old+new signer counts as exactly one. Then cut
> preparation/pending approval and the terminal/receipt phases separately.
>
> ## 2026-08-31 C23 EXACT-BYTE BROWSER SIGNING SPINE — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `5b32e1b16b76f8a229364ac404b9801791dbbad1` composes one successful
> `solana:signTransaction` request through the real, still-build-excluded
> C12–C22 owners in a temporary MV3 extension. An HTTP page uses the real
> MAIN-world request owner; the production content transport reaches one
> centrally routed background Port; the operation is durably claimed in
> IndexedDB; a password-authenticated keyring generation selects the exact
> test account/release; the pinned authority resolver and deterministic intent
> gate read a local `Connection` fixture; and the production approval page
> reviews and approves the resulting non-empty transaction before one signer
> lease completes the durable result and receipt handshake.
>
> This closes C22's “no browser exact signed bytes” evidence gap for the
> uninterrupted internal graph. The test snapshots the durable message and its
> digest before approval, then independently deserializes the page result,
> proves the returned message bytes are byte-for-byte identical, recomputes the
> SHA-256 digest, verifies the Ed25519 signature against the authenticated
> session public key with Node crypto, and proves the durable signed bytes equal
> the page bytes. It also measures one navigation, one create/claim/complete/
> signer use, two authenticated identity reads on one revocation signal, the
> exact deterministic RPC call counts, no second page settlement, and zero
> remaining actions, requests, flows, or content-pending entries after success. The document
> Port remains intentionally live until page teardown.
>
> Harsh implementation findings were load-bearing:
>
> - Independent `runtime.onConnect` listeners disconnected each other's valid
>   approval/provider Ports. The test composition now has the same architectural
>   requirement as production: one exact-name router owns the Chrome event and
>   rejects every unknown channel.
> - The first fixture signer did not match the sealed seed. The authenticated
>   keyring rejected it; the test now derives the public key independently from
>   the seed instead of weakening the equality check.
> - Real Chromium exposed two Node-only `Buffer` constructors in core
>   transaction preparation. Both are now browser-native `Uint8Array`; an
>   18-test core lane includes a regression that deletes the global `Buffer`
>   before rewriting a transaction.
> - The first temporary approval bundle used ESM despite production loading it
>   as a classic script; that masked a top-level `window.status` collision.
>   C23 now uses the production-correct ESM background and IIFE content,
>   approval, and MAIN-world formats.
> - The approval success copy previously claimed provider delivery remained
>   unavailable even when its injected capability was true. Only the true
>   branch now describes the durable return; the shipped false branch remains
>   fixed unavailable.
>
> Primary contracts checked:
> <https://github.com/wallet-standard/wallet-standard/blob/master/packages/example/wallets/src/solanaWallet.ts>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>,
> and <https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3>.
> The Wallet Standard reference returns signed transaction bytes for
> `solana:signTransaction`; Chrome documents named Port routing and that MV3
> workers terminate and reinitialize, requiring durable state and synchronous
> listener registration. Therefore uninterrupted C23 success is not evidence
> for any worker-restart cut.
>
> Exact focused evidence at clean implementation SHA
> `5b32e1b16b76f8a229364ac404b9801791dbbad1`:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest run test/session-transaction.test.ts
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec playwright test -c playwright.config.ts provider-sign-success.pw.ts
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: core rewrite
> **18/18**, extension typecheck, real Chromium exact-byte success **1/1**,
> `git diff --check`, and clean-tree guards passed. The full repository gate is
> deliberately not claimed by this implementation entry; it must run on the
> subsequent ledger-inclusive SHA.
>
> Independent second-model review remains **UNVERIFIED**. No new review is
> inferred from the prior host app-server read-only failure.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> Production still excludes the provider/coordinator/action/result/page graph
> and has an empty release registry and fixed unavailable provider.
>
> **Harsh residual:** C23 uses deterministic local RPC/account fixtures, a
> fixture seed/password/pin set, and deliberately cheap test-only Argon2id
> parameters. Artifact exclusion is required to prove none ship. It is not a
> live endpoint, production release assertion, production KDF policy, or
> published-artifact assurance. It proves only an uninterrupted worker: no
> death occurs during preparation, approval/signing, durable result recovery,
> page receipt, or settled acknowledgment. It does not inject/register Wallet
> Standard in production, onboard or migrate accounts, send/confirm a
> transaction, survive a browser crash/disk fault, undergo an external audit,
> or protect real funds.
>
> **Next load-bearing work:** C24 should compose restart-safe test authority
> instead of reseeding the keyring on every boot, then kill the real MV3 worker
> at preparation, signing, committed-result, and receipt/settlement cuts. Each
> cut must retain the initiating deadline, measure page navigation, prove at
> most one approval/signature/result, and fail closed where continuity cannot
> be proven. Never activate production by adding a parallel Port listener; any
> eventual activation must replace the fixed-unavailable branch under the one
> central router. After restart safety, commit the production RPC/release/KDF
> decision and prove single-evaluation MAIN-world Wallet Standard registration.
>
> ### C23 full-gate addendum — 53c6923 — 2026-08-31
>
> Ledger-inclusive SHA
> `53c692344c3bbc9c91f6768be70b9f3a454e3614` passed this exact command from a
> clean tree, exit **0**, and printed the same SHA before and after:
>
> ```sh
> set -euo pipefail
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh
> test -z "$(rg -n 'C23 exact-byte|C23 browser-only password|warden-provider-sign-success|warden-authority-resolver-fixture|EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG|Bow1CGKGDB9mNxeWdw85E2aCthQ1oZX4oFEe7fYT17ew' apps/extension/dist || true)"
> git diff --check
> git rev-parse HEAD
> test -z "$(git status --porcelain)"
> ```
>
> The executable gate passed core **700/700**, UI tokens **11/11**,
> transaction-budget **8/8**, WebAuthn **1/1**, extension **473/473**,
> core/extension builds and typechecks, the production Argon2 benchmark, real
> Chromium **10/10**, and the complete Rust workspace suite. The explicit
> artifact scan found no C23 database, password, memo, release, fixture-code, or
> signer markers in `apps/extension/dist`. Known Anchor test-program key and
> legacy macro-`cfg` warnings were non-fatal. This verdict belongs only to the
> exact SHA above; this documentation-only addendum commit does not inherit it.
>
> ## 2026-08-31 C22 IMMUTABLE DEADLINE + DELIVERY SETTLEMENT — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `43b6b12a8914414a9d68ab7ae97006e8541ad9eb` closes C21's
> cross-worker lifetime and enqueue-without-consumption gaps in still-unreachable
> code. C16 now mints the one absolute deadline and wraps its closed request in a
> strict transport envelope. C20 retains and replays that exact object. C21
> passes the unchanged timestamp to every `ProviderPortSession.openUntil()`;
> hashing, worker boot, Port replacement, and durable replay cannot extend it.
> At expiry C20 sends a cancellation containing the same canonical request and
> deadline, and C21 cancels only after recomputing the exact C14 operation
> identity on the current Port generation.
>
> C22 also replaces the implicit “send means delivered” assumption with a
> four-step settlement state: request → immutable terminal → page receipt →
> background settled acknowledgment. The terminal carries a deterministic
> receipt id derived from the complete operation key. C16 stores that receipt
> tombstone before settling the original Promise and re-acks an exact duplicate
> without settling twice. C20 keeps pending state after both page forwarding and
> receipt send; only the exact settled ack removes it. If the Port dies after
> page consumption, C20 resends the original request, C21 replays the same
> terminal, and C20 sends the retained receipt without forwarding a second page
> terminal.
>
> Background terminal enqueue no longer releases the live request lease.
> C14/C19 must enqueue exactly once, mark enqueue-side completion, and return the
> exact closed delivery proof. Only then can a receipt matching correlation,
> operation-derived id, original deadline, and current generation finish the
> session lease. Early, forged, expired, wrong-generation, or changed-identity
> receipts fail closed. An exact duplicate receipt after settlement is
> idempotently acknowledged.
>
> Executable RED, harsh corrections, and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run
>   test/provider-delivery-protocol.test.ts` first exited **1 before
>   collection** because `provider-delivery-protocol.js` did not exist.
> - The first complete extension compatibility run was correctly **red at
>   463/467**: three C17→C14→C16 compositions still stripped the new request
>   envelope, and one C19→C16 composition injected an old raw terminal. The
>   tests now exercise the nested transport instead of bypassing it.
> - Harsh source review found a stale-Port authority race. If operation hashing
>   began on generation 1 and generation 2 replaced it before the digest
>   completed, generation 1 could still start the flow. The new regression was
>   red with one unauthorized lease; current-Port identity is now rechecked
>   after every asynchronous identity derivation.
> - A second review found receipt settlement trusted `finish()` before the flow
>   Promise returned its delivery proof. `flowProven` now gates receipt release,
>   and a malformed or rejected dependency result closes the route even if
>   other state was cleared. Tests distinguish terminal enqueue, flow finish,
>   returned proof, page receipt, and settled ack.
> - Focused lanes cover strict/open/accessor/revoked-proxy envelopes, immutable
>   replay deadlines, exact cancellation, terminal/result substitution, early
>   and forged receipts, duplicate settlement, synchronous/re-entrant acks,
>   loss after page receipt, stale hash completion, deadline crossing, and
>   cleanup: protocol **5/5**, page **19/19**, content **17/17**, background
>   **20/20**. The complete extension lane is **473/473**.
> - Real Chromium is now **9/9**. The runtime lane proves one lease across
>   overlapping Ports through receipt settlement; real CDP worker death still
>   produces one durable fixed cancellation with one preparation; and a
>   near-deadline death proves the replacement lease carries the initiating
>   timestamp, loses ownership exactly there, leaves C20 pending count zero,
>   and emits no fabricated terminal or receipt.
>
> Primary contracts checked:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>, and
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>.
> Chrome requires state to survive unexpected MV3 worker termination and
> documents Port messaging/lifecycle behavior. It does not elevate either Port
> or Window send into an end-to-end page Promise acknowledgment. Warden's
> conservative enqueue interpretation is therefore explicit and executable.
>
> Independent second-model review remains **UNVERIFIED**. The immediately
> preceding C21 `codex review` attempt failed before model startup because the
> host app-server state path is read-only; no C22 review claim is inferred from
> that failure.
>
> Exact implementation-SHA evidence at
> `43b6b12a8914414a9d68ab7ae97006e8541ad9eb`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs'),path=require('node:path');const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk('apps/extension/dist');const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync('apps/extension/dist/background.js','utf8');const content=fs.readFileSync('apps/extension/dist/content.js','utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider delivery protocol:','warden:provider:transport-request','warden:provider:transport-terminal','warden:provider:transport-receipt','warden:provider:transport-settled','warden:provider:transport-cancel','provider runtime transport:','provider content transport:','WARDEN_USER_REJECTED','provider terminal outcome:','provider signed result flow:','provider page request:','provider approval action:','provider operation:','warden-provider-operations-v1'];const missing=required.filter(v=>!background.includes(v)||!content.includes(v));const hits=forbidden.filter(v=>all.includes(v));if(missing.length||hits.length){console.error({missing,hits});process.exit(1)}console.log('C22 delivery/settlement graph absent from shipped extension; fixed unavailable boundary remains')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension
> **473/473**, typecheck, build, Chromium **9/9**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The esbuild input graph also
> forbids `provider-delivery-protocol.ts` from both shipped background and
> content bundles. Production retains only the fixed unavailable provider.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C22 is a safety-oriented volatile protocol, not an
> exactly-once distributed transaction. Two consecutive worker/Port losses can
> still make the page time out, though they cannot extend authority or sign
> twice. The receipt exposes a document/correlation-specific operation digest
> to that same page; it is an identity token, not a secret. Navigation during
> each receipt phase is not measured. The Chromium worker delivers only a
> durable fixed failure. No browser test opens the real approval, resolves a
> reviewed non-empty release, reads trusted RPC, consumes a live signer,
> verifies one exact signed transaction end to end, registers Wallet Standard,
> or sends/confirms a transaction. The MAIN-world owner is not injected and
> production remains intentionally unavailable.
>
> **Next load-bearing work:** C23 should compose one temporary-extension,
> exact-byte `solana:signTransaction` success across the real C16→C22 transport,
> C12–C19 approval/operation/result graph, an authenticated unlock generation,
> a reviewed non-empty test release, and deterministic local RPC fixtures. It
> must prove the bytes shown for approval are the bytes returned after signing,
> kill the worker at preparation/sign/result/receipt cuts, measure navigation,
> and prove no second approval or signature. Keep production fixed-unavailable
> until that lane, a production RPC/release decision, MAIN-world registration,
> and external release assurance are green.
>
> ### C22 full-gate addendum — afb0347 — 2026-08-31
>
> Ledger-inclusive SHA
> `afb0347543820608ec3c100a07dc6073d6ede17a` passed this exact command from a
> clean tree, exit **0**, and printed the same SHA before and after:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> The executable gate passed core **699/699**, UI tokens **11/11**,
> transaction-budget **8/8**, WebAuthn **1/1**, extension **473/473**,
> typecheck/build, the Argon2 benchmark, real Chromium **9/9**, and the full
> Rust workspace suite. Known Anchor key/cfg and Rust unused-code warnings were
> non-fatal. This verdict belongs only to the exact SHA above; this
> documentation-only addendum commit does not inherit it.

> ## 2026-08-31 C21 BACKGROUND REPLACEMENT-PORT OWNERSHIP — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `cd0cc9cd1b7802fe99b78e6f7addeb8f2c0b8a21` adds the still-unreachable
> background half of C20's recovery. `ProviderRuntimeTransportOwner` accepts
> only the provider Port name and Chrome-classified web-document provenance,
> keys one route by the complete extension/origin/tab/frame/document tuple, and
> serializes the exact closed `solana:signTransaction` request language. A
> replacement that overlaps the incumbent Port becomes current before the old
> endpoint is disconnected, so retained old callbacks are generation-stale.
> The live volatile lease is retained, but a terminal value cannot cross the
> replacement until that generation has presented the same correlation and the
> same C14 SHA-256 operation identity. Same-correlation payload drift, a
> same-generation duplicate, provenance drift, expiry, or excess replay closes
> the entire document route.
>
> If background `onDisconnect` wins before the replacement arrives, the old
> session and every volatile lease are aborted permanently. The later Port gets
> a fresh random request id and signal; only C13–C19's durable operation graph
> may prove an already-committed result. No dead lease or signing capability is
> resurrected. A request may cross at most one replacement generation. The
> owner caps active documents at 256, queued/hash-blocked requests at 32,
> correlations at 1,024, and the corresponding background request-id budget at
> 2,048. Initial authority is bound to the background receive deadline before
> asynchronous hashing, and a finished same-worker replay keeps that first
> absolute deadline. The shared operation-identity code now exposes a typed
> provenance+request input so transport code does not forge a partial
> `OwnedProviderRequest` cast.
>
> Executable RED, adversarial corrections, and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run
>   test/provider-runtime-transport.test.ts` initially exited **1 before
>   collection** because `provider-runtime-transport.js` did not exist.
> - Source-level review found three load-bearing holes before freeze: 1,024
>   correlations plus one replay need 2,048 unique background ids rather than
>   the prior 1,024; requests queued behind a stalled digest needed a separate
>   32-message admission cap; and starting TTL only after hashing could mint
>   authority after the receive deadline. All three now have executable bounds
>   and regressions.
> - Delivery originally followed the newest same-provenance Port immediately.
>   It now requires that exact Port generation's completed cryptographic
>   request identity first. Tests cover replacement before verification,
>   replacement while hashing, stale callbacks, disconnect-first recovery,
>   changed payload, provenance drift, two simultaneous correlations,
>   re-entrant replacement during enqueue, one-replay exhaustion, exact
>   deadline retention, digest-deadline crossing, queue exhaustion, malformed
>   dependencies, and disposal: **15/15**.
> - The first complete extension attempt was correctly **red at 461/462**. Its
>   new multi-correlation test counted calls to `subtle.digest()` rather than
>   completed digests, so the alleged barrier could pass before route state was
>   committed. Both unit and browser barriers now measure completed digests;
>   the final complete extension lane is **462/462**.
> - Two temporary-extension Chromium contracts are real browser evidence, not
>   mocked Port prose. The first opens overlapping Ports from one HTTP content
>   document, observes Chrome disconnect the old endpoint, waits for four
>   completed identity digests, then proves one volatile flow and one response
>   on generation 2. The second composes the real C20 content owner, C21 route,
>   IndexedDB operation owner, and C19 terminal classifier; CDP kills the MV3
>   worker after one durable preparing claim, C20 resends from the unchanged
>   page, the replacement execution context invalidates exactly one row, and
>   the page receives exactly one fixed cancellation with preparation count
>   still **1**. The full Chromium lane is **8/8**.
>
> Primary contracts checked:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime/>, and
> Chromium's runtime schema at
> <https://chromium.googlesource.com/chromium/src/+/HEAD/extensions/common/api/runtime.json>.
> Chrome documents immediate Port messaging, disconnect behavior, JSON message
> serialization, and `MessageSender.documentId`; it does not document a
> cross-context ordering guarantee that old background cleanup precedes a
> content reconnect. The two safe branches above are therefore implemented and
> measured rather than inferred from event order.
>
> `codex review --commit
> cd0cc9cd1b7802fe99b78e6f7addeb8f2c0b8a21` failed **before review**:
> `failed to initialize in-process app-server client: Read-only file system`.
> Independent second-model review remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `cd0cc9cd1b7802fe99b78e6f7addeb8f2c0b8a21`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider runtime transport:','provider content transport:','WARDEN_USER_REJECTED','provider terminal outcome:','provider signed result flow:','provider page request:','provider approval action:','provider operation:','warden-provider-operations-v1'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C20-C21 and prior provider signing/terminal/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension
> **462/462**, typecheck, build, Chromium **8/8**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. Build metadata explicitly
> forbids C21 and the prior provider/signing/terminal/page owners; emitted
> background and content retain only `WARDEN_METHOD_UNAVAILABLE`.
> Ledger-inclusive full-repository evidence at
> `4ffb49c0dad6618db7eb6b13f5096d7550e3d5d7`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after. The gate ran the
> complete pnpm workspace, core **699/699**, extension **462/462**, UI tokens
> **11/11**, transaction-budget **8/8**, WebAuthn **1/1**, Chromium **8/8**,
> the pinned Argon2 worker benchmark, builds and typechecks, fixture/ledger/
> feature guards, and the complete Rust workspace. The known Anchor
> test-program key mismatch and legacy macro `cfg` notices were warnings, not
> skipped failures. This verdict belongs only to `4ffb49c…`; the evidence-only
> ledger commit that records it does not inherit the gate or promote an
> invariant.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C21 is an 884-line unshipped owner plus test-only browser
> composition. The death test deliberately reaches a durable cancellation; it
> does not open a real approval, read trusted RPC, touch a key, or prove one
> exact-byte signature. C21 binds same-worker hashing/replay to its first
> background receive deadline, but C20 does not carry the original content
> deadline across worker death. If the worker dies before the durable claim,
> the replacement can mint a fresh background lifetime even while the page
> request is near expiry. Content expiry also sends no cancellation, and
> neither background Port enqueue nor content `window.postMessage()` proves
> that C16 consumed the terminal value. A loss after enqueue can exhaust the
> one replay while the page Promise still times out. Navigation is not covered
> by the C21 Chromium lane. There is still no reviewed non-empty release,
> trusted production RPC, production coordinator/keyring graph, real-browser
> signature, Wallet Standard registration, send/confirmation, onboarding,
> production KDF policy, root ceremony, consequence review, external audit, or
> deployable wallet method. Production remains intentionally unavailable.
>
> **Next load-bearing work:** C22 should define one closed internal
> content→background transport envelope that carries the original absolute
> request deadline across every Port generation/worker, cannot be lengthened by
> replay, and is bound into cancellation handling. It should then make terminal
> receipt/settlement ownership explicit across C16→C20→C21 and browser-test
> death immediately before deadline plus loss after enqueue. Keep all of it
> build-excluded until real approval/RPC/keyring composition, exact-byte signing
> in Chromium, receipt semantics, and a reviewed non-empty release are green.

> ## 2026-08-31 C20 BOUNDED CONTENT TRANSPORT RECOVERY — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `b09f41b08736285512209935435a7d2b4c264976` adds a still-unreachable
> `ProviderContentTransportOwner` for C16's closed
> `solana:signTransaction` request only. It parses attacker-owned page input
> once, rebuilds one immutable canonical wire request, and retains that exact
> object for at most one automatic Port-loss resend. A document may retain at
> most 32 pending requests and issue at most 1,024 correlations. Each entry has
> a two-minute default / ten-minute maximum absolute TTL and an active timer;
> expiry drops only volatile transport state and deliberately does not invent a
> page error. C16's original absolute deadline remains the page-Promise
> authority when no durable terminal response arrives.
>
> Recovery is demand-bound: an idle disconnect never reopens a Port. Every
> eligible request spends its single recovery budget before a replacement Port
> is opened, preventing synchronous setup/disconnect reentrancy from becoming a
> worker-wake loop. A terminal response must have one exact reviewed unavailable,
> signed, or C19 failure shape, match a pending correlation, and arrive on that
> entry's active Port generation. The owner reconstructs/copies the response,
> removes its pending entry and timer before the re-entrant page boundary, and
> then posts it. A stale Port, unknown correlation, late response, or duplicate
> terminal cannot settle a page request. Same-page code remains the caller
> principal; this owner grants no provenance, account, approval, RPC, release,
> key, or signing authority.
>
> Executable RED and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run
>   test/provider-content-transport.test.ts` first exited **1** before
>   collection because `provider-content-transport.js` did not exist.
> - Harsh review then produced **13 pass / 1 fail**: the cache was size-bounded
>   but had no active expiry timer, so a request could remain retained for the
>   document lifetime after C16 timed out. The final absolute timer rechecks
>   early firings and never fabricates a terminal response.
> - A final side-effect audit produced **15 pass / 1 fail**: a delayed initial
>   connect could cross the exact deadline and still call `Port.postMessage()`.
>   Both initial and recovery paths now recheck absolute time immediately after
>   connection and before each send. The focused lane is **16/16**.
> - The complete extension lane at the implementation SHA is **446/446**. It
>   includes one cross-owner test that preserves C16's original Promise over
>   one lost Port, reuses the identical canonical payload, accepts a C19 fixed
>   terminal failure on the replacement generation, and proves only one page
>   request was minted. This is a fake-window/Port test, not a real-browser
>   signing or worker-restart claim.
>
> Primary lifecycle contracts checked for this boundary:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>, and
> <https://developer.chrome.com/docs/extensions/reference/api/runtime/>. Chrome
> documents that MV3 workers terminate after inactivity and that state must be
> persisted rather than kept in globals. It also documents Port disconnects,
> JSON serialization for extension messages, and `postMessage()` throwing on a
> disconnected Port. Chrome 114 changed long-lived messaging so merely opening
> a Port no longer resets worker timers. Demand-bound reconnect is therefore a
> deliberate lifecycle constraint. The conclusion that an enqueue is not page
> consumption, and that identical transport replay grants no new wallet
> authority, remains an explicit architectural inference.
>
> `codex review --commit
> b09f41b08736285512209935435a7d2b4c264976` exited **1 before review**:
> the in-process app-server client could not initialize on this host's read-only
> state path. Independent second-model review remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `b09f41b08736285512209935435a7d2b4c264976`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider content transport:','content_request_0123456789','WARDEN_USER_REJECTED','provider terminal outcome:','provider signed result flow:','provider page request:'];const missing=required.filter(s=>!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C20 and prior provider terminal/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed the same SHA before and after: extension **446/446**,
> typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The emitted content bundle
> retains `WARDEN_METHOD_UNAVAILABLE`; C20 and earlier terminal/page markers are
> absent. Ledger-inclusive full-repository evidence is not yet claimed.
>
> Ledger commit `66dd2cad0d79047ca5ca42e6a5414275ed7263b7`
> then passed this exact full-repository command, exit **0**:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **446/446**, UI tokens
> **11/11**, transaction-budget spike **8/8**, WebAuthn spike **1/1**,
> production Chromium **6/6**, the pinned Argon2 worker benchmark, core and
> extension builds/typechecks, fixture/ledger/feature guards, and the complete
> Rust workspace. The known Anchor test-program key mismatch and legacy macro
> `cfg` notices were warnings, not skipped failures. This verdict belongs only
> to `66dd2ca…`; the evidence-only follow-up does not inherit it or promote an
> invariant.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C20 is 1,401 new test/source lines for an unreachable
> transport primitive and has only fake-window/Port coverage. It does not prove
> MV3 worker death, navigation, or old/new Port ordering in Chrome. More
> importantly, its immediate reconnect can race the incumbent background
> boundary's old-Port cleanup: production currently rejects a second active
> Port for the same browser `documentId`, and Chrome does not promise the
> cross-context disconnect ordering this design would need. There is no page
> receipt acknowledgment; successful Port enqueue still does not prove page
> consumption. C16, content, and background TTLs are separately instantiated,
> and content expiry sends no per-request cancellation to the background. There
> is still no reviewed non-empty release, trusted production RPC, production
> coordinator/keyring graph, real-browser exact-byte signature, Wallet Standard
> registration, send/confirmation, onboarding, production KDF policy, root
> ceremony, consequence review, external audit, or deployable wallet method.
> Production Chromium proves only that C20 remains absent and signing disabled.
>
> **Next load-bearing work:** C21 must define a still-unreachable background
> replacement-Port/replay owner keyed by browser-owned document provenance and
> exact durable operation identity. It must make a new Port safe whether it
> arrives before or after old-Port cleanup, never let a page correlation alias a
> different canonical request, never resurrect an old volatile signing lease,
> and browser-test worker death plus old/new Port ordering. It must also bind or
> explicitly carry the request deadline/cancellation semantics across page,
> content, and background owners. Keep production fixed-unavailable until this
> composition, a reviewed non-empty release, trusted RPC, real coordinator/
> keyring composition, and real-browser exact-byte signing evidence all exist.
>
> ## 2026-08-31 C19 CLOSED PROVIDER TERMINAL OUTCOMES — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `322c28b358528f53b76cb0d636f1bcb07d57b207` replaces C18's implicit
> signed-or-throw assumption with an explicit durable outcome boundary. The new
> `ProviderTerminalOutcomeOwner` derives the exact C13 browser-request identity,
> reads its journal row, rechecks the complete operation → approval binding, and
> for an approved row also snapshots the atomic `signing` / `signed` / `failed`
> outcome. Only an exact `signed` outcome reaches C14's existing cryptographic
> replay owner. Rejected, cancelled, expired, invalidated, preparation-failed,
> worker-restarted, request-cancelled, and failed-signing states map to only four
> fixed page-safe codes: `WARDEN_USER_REJECTED`, `WARDEN_REQUEST_CANCELLED`,
> `WARDEN_REQUEST_EXPIRED`, or `WARDEN_REQUEST_FAILED`. No raw exception,
> persisted signing failure code, RPC detail, key state, or stack text crosses
> this boundary.
>
> C18 now treats C12's boolean as terminal scheduling only: both `true` and
> `false` delegate to C19, which independently decides signed versus failed from
> durable state. Harsh review caught a second replay hole before commit: C13
> deliberately throws when a retained operation is `failed`, so C15 cannot
> return its normal `replay-required` discriminator for that row. C18 now
> attempts recovery after a rejected C15 launch, but succeeds only when C19
> independently proves and enqueues an exact durable terminal outcome. If both
> launch and recovery fail, it returns an aggregate fail-closed error. A
> malformed *successful* C15 result is still a contract violation and is never
> masked by recovery. This does not translate arbitrary exceptions into page
> errors.
>
> C16 now recognizes the four exact terminal-error envelopes and rejects its
> original owner-minted Promise with `ProviderPageTerminalError` carrying only
> the closed code and fixed message. The owner still removes the pending entry
> before settlement and retains its correlation tombstone, so a later forged
> success cannot reverse a rejection. Same-page code remains the caller
> principal and can forge or suppress page traffic; these messages confer no
> origin, account, approval, or signing authority. The real content bridge still
> accepts and emits only `WARDEN_METHOD_UNAVAILABLE`.
>
> Executable RED and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run
>   test/provider-terminal-outcome.test.ts` first exited **1** before test
>   collection because `provider-terminal-outcome.js` did not exist.
> - The final focused C18/C19/C16 lane is **46/46**. It covers all operation and
>   approval terminal mappings, failed-signing redaction, refusal of `preparing`,
>   `pending`, and `signing`, exact C14 `true` proof, request/approval/signing
>   substitution, hostile-proxy cleanup, Port enqueue/release failure and replay,
>   strict protocol shapes, C18 false-terminal scheduling, retained-failure
>   recovery, and exact page-Promise rejection.
> - The full extension lane at the implementation SHA is **430/430**. A
>   cross-owner test carries C18's byte-free false terminal through real C19
>   durable classification into C16's original Promise without invoking the
>   signed deliverer. The cryptographic C14 reader remains covered separately;
>   this test does not claim a real-browser signature.
>
> Primary contracts checked for this boundary:
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>,
> and the Wallet Standard reference Solana wallet at
> <https://github.com/wallet-standard/wallet-standard/blob/master/packages/example/wallets/src/solanaWallet.ts>.
> Chrome documents long-lived Ports with `onDisconnect`, while MV3 extension
> service workers are ephemeral and must persist state rather than trust globals
> or timers. The Wallet Standard example rejects declined signing with an Error
> and returns bytes only on success; it does not define a Solana-wide public
> error-code taxonomy. Warden's four codes are therefore an internal closed
> protocol choice, not a claimed Wallet Standard requirement. The conclusion
> that enqueue is not page consumption, and that durable exact identity permits
> idempotent replay but not signing-authority resurrection, remains an explicit
> architectural inference.
>
> `codex review --commit
> 322c28b358528f53b76cb0d636f1bcb07d57b207` exited **1 before review**:
> the in-process app-server client could not initialize on this host's read-only
> state path. Independent second-model review remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `322c28b358528f53b76cb0d636f1bcb07d57b207`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider terminal outcome:','WARDEN_USER_REJECTED','provider signed result flow:','provider approval action:','provider page request:','page_validation_0000000000000000','provider approval operation:','provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C19 provider/signing/terminal/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> exited **0** and printed the same SHA before and after: extension **430/430**,
> typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The production background and
> content bundles retain `WARDEN_METHOD_UNAVAILABLE`; C12–C19 terminal,
> provider, signing, and page markers are absent. Ledger-inclusive full-repo
> evidence was then attempted at ledger SHA
> `7e196697cd3034006b5d996a2fa33b416ce26002` and correctly remained **red**:
> core reached **699/699**, but the extension stopped at **429/430** when the
> concurrent provider-operation test timed out with an unhandled
> `ProviderOperationStateError`. The test had yielded one microtask and assumed
> WebCrypto identity derivation had already reached the durable claim. Under the
> full workspace scheduler, the second call could become the claimant and wait
> on a gate that the test released only after that call rejected: a harness
> deadlock, not a runtime owner failure.
>
> Test-only repair commit
> `267163b5769cc8547b00d6417538acc784f33b50` replaces that scheduler guess with
> an explicit signal from the first preparation callback. Its focused file is
> **11/11**, and the full extension lane is **430/430**. Exact full-repository
> evidence at that clean SHA is:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It exited **0** and printed
> `267163b5769cc8547b00d6417538acc784f33b50` before and after. The gate included
> core **699/699**, extension **430/430**, UI tokens **11/11**, transaction-budget
> spike **8/8**, WebAuthn spike **1/1**, extension type/build, the KDF benchmark,
> production Chromium **6/6**, and the Rust workspace. The known Anchor
> test-program key mismatch and legacy macro `cfg` notices were warnings, not
> skipped failures. This verdict belongs only to `267163b…`; the evidence-only
> ledger follow-up does not inherit it.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C19 is still unreachable internal composition. Its
> cross-owner page test manually forwards a background result through a fake
> window. The shipped content bridge rejects both signed and C19 failure
> responses, has no bounded cache of outstanding exact requests, and does not
> resend after Port/worker loss. A disconnect can therefore leave C16 pending
> until its absolute timeout even though a durable terminal row exists. There
> is no page receipt acknowledgment; duplicate replay is safe for settlement
> only because C16 retains a tombstone. C19 classifies then C14 independently
> rereads the signed branch, so a real integration must preserve both checks and
> never add an exception-based fallback after C14 enqueue. There is still no
> non-empty reviewed release, trusted production RPC, production
> coordinator/keyring composition, real-browser exact-byte signing, Wallet
> Standard registration, send/confirmation, onboarding, production KDF policy,
> root ceremony, consequence review, or external audit. Production Chromium
> proves only that signing remains disabled. C19 closes failure ambiguity; it
> does not make Warden deployable.
>
> **Next load-bearing work:** C20 should add a still-unreachable, bounded
> content transport-recovery owner. It must snapshot one exact page request,
> reconnect only while a request is outstanding, resend the identical payload
> at most a tightly bounded number of times, preserve C16's original Promise and
> document-lifetime correlation tombstone, accept only the reviewed signed/C19
> failure protocols, and prove worker/Port/navigation races without an eager
> idle-worker wake loop or a second approval/sign attempt. Keep the production
> bridge fixed-unavailable until that owner, a non-empty reviewed release,
> trusted RPC, real coordinator/keyring composition, and real-browser
> exact-byte signing evidence all exist.
>
> ## 2026-08-31 C18 SIGNED RESULT COMPOSITION — INTERNAL ONLY, PRODUCTION PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `47f728b5769c679feaafbc51d8e4218bbac52b1f` closes the internal
> scheduling gap from C17's byte-free approval action to C14's durable signed-
> result verifier and C16's one-shot page Promise. The new bounded
> `ProviderSignedResultFlowOwner` takes one exact live provider delivery lease,
> invokes C15 once, waits for C12's boolean terminal only when C15 created a new
> approval, and then delegates the same lease to C14. A retained durable
> operation returns `replay-required` and goes directly to C14; it cannot prepare,
> open, register, or sign again. Repeated calls for the same exact in-memory
> request share one Promise, unresolved flows cap at 32, and only C14 may read,
> validate, construct, enqueue, or scrub signed transaction bytes.
>
> Harsh source review caught a load-bearing race before this commit. The core
> `SessionApprovalCoordinator` atomically changes the approval row to
> `state:"approved"` when it **claims a signing attempt**, before key use and
> before `completeSigning()` durably stores signed bytes. Therefore an approved
> row alone is not a signed-result proof. C12 now exposes a Promise that can
> resolve `true` only after its exact coordinator Promise returns a structurally
> valid id/digest/transaction/signature result and an independent read proves the
> exact bound row approved. Cancellation and settlement wait out an already-
> started coordinator Promise; if that path never wins the exact proof, the
> terminal resolves `false`. Provider/keyring lifetime loss still rejects the
> approval-page action, while a signature that already completed remains
> deliverable through C14 or replayable after reconnect. C14 independently reads
> and cryptographically validates the durable signing outcome, so the C12
> boolean is scheduling evidence, never byte authority.
>
> Executable RED and focused evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run
>   test/provider-signed-result-flow.test.ts` first exited **1** before test
>   collection because `provider-signed-result-flow.js` did not exist.
> - The final focused C12–C18/Port/page lane is **87/87**. It pins one shared
>   Promise and one delivery, retained-operation replay without another prepare,
>   false/malformed terminal refusal, malformed delivery refusal, the independent
>   32-flow cap, exact bind → register → window ordering, and cancellation/
>   settlement races.
> - Three cross-owner tests compose C12 → C15 → C17 → C18 → C14 → C16. The
>   normal test pauses C14 while C17 settles and destroys its volatile action,
>   proving delivery depends on the durable result rather than the UI route. The
>   keyring-loss test holds the page Promise pending after the row is merely
>   claimed approved, then requires delivery only after the coordinator returns.
>   The provider-loss test rejects the dead lease, constructs replacement-worker
>   owners, and replays the same operation/result without another prepare,
>   registration, or sign.
> - Harsh self-review also added explicit false-terminal assertions for malformed
>   coordinator output, absent terminal state, ordinary cancellation, and cap
>   recovery. It found no basis to enable production.
>
> This round researched the gap primarily against the repository's authoritative
> implementation rather than prose: `packages/core/src/transaction/`
> `session-approval-coordinator.ts` proves `claimForSigning()` precedes key use
> and `completeSigning()`, while `packages/core/src/approval/signing-outcome.ts`
> defines the distinct `signing`/`signed`/`failed` durable outcomes. The C17
> Chrome MV3/runtime, Solana blockhash/genesis RPC, and Wallet Standard primary
> sources remain applicable and are linked immediately below in the prior
> ledger. No external source is being used to overrule those executable local
> contracts.
>
> `codex review --commit
> 47f728b5769c679feaafbc51d8e4218bbac52b1f` exited **1 before review**:
> the in-process app-server client could not initialize on this host's read-only
> state path. Independent second-model review remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `47f728b5769c679feaafbc51d8e4218bbac52b1f`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider signed result flow:','provider approval action:','provider page request:','page_validation_0000000000000000','provider approval operation:','provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C18 provider/signing/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> exited **0** and printed the same SHA before and after: extension **403/403**,
> typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The production background and
> content bundles both retain `WARDEN_METHOD_UNAVAILABLE`; all C12–C18 markers
> are absent. Ledger-inclusive full-repository evidence is not claimed until the
> ledger SHA runs `.claude/test-gate.sh`.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C18 is a unit/integration composition of internal owners,
> not a shipped wallet method. Its page test forwards C14's exact response
> envelope through a fake window; the real content bridge still admits only
> `WARDEN_METHOD_UNAVAILABLE`. The C14 integrations use its explicit
> `readSigned` test seam, while the core cryptographic replay verifier is covered
> in its own executable lane; this is not one real-browser cryptographic-signing
> test. There is no content-script resend/reconnect owner, page receipt
> acknowledgment, provider rejection mapping, production release, trusted RPC
> endpoint, reviewed deployment pin, production coordinator/keyring composition,
> Wallet Standard registration, send/confirmation path, onboarding, production
> KDF policy, root ceremony, consequence review, or external audit. A Port
> enqueue is still not page consumption. Production Chromium proves only that
> signing is disabled. C18 removes one internal scheduling ambiguity; it does
> not make Warden deployable.
>
> **Next load-bearing work:** define the closed provider transport/recovery and
> failure protocol around C18. It must preserve C16's original page Promise over
> content/background disconnects, replay only the exact durable C14 result, map
> rejection/cancellation/expiry to strict terminal errors, and prove worker/
> Port/page races without treating `postMessage()` as acknowledgment. Keep the
> production provider fixed-unavailable until a non-empty reviewed release,
> trusted RPC, real coordinator/keyring composition, and real-browser exact-byte
> signing lane all exist.
>
> ### C18 full-gate addendum — eaeb26c — 2026-08-31
>
> Ledger-inclusive SHA
> `eaeb26c55925e9dfe01c123d8bd0431cd57ad80a` passed this exact command,
> exit **0**:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **403/403**, production
> Chromium **6/6**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust workspace.
> The known Anchor test-program key mismatch notice and legacy macro `cfg`
> notices were warnings, not skipped failures. This verdict belongs only to
> `eaeb26c…`; this evidence-only follow-up does not inherit it or promote an
> invariant.

> ## 2026-08-31 C17 EXACT APPROVAL ACTION — INTERNAL ONLY, PRODUCTION SIGNING STILL UNAVAILABLE
>
> Implementation commit
> `b36aeecd3c2b49ee18144ab1144d46dcddddd88f` adds the missing
> approval-page action boundary without making the production provider usable.
> A new volatile `ProviderApprovalActionOwner` copy-binds one background-minted
> approval id and 32-byte message digest to the exact live C12 coordinator
> capability. C15 must first prove the durable provider-operation → approval
> binding, then synchronously register that action, and only then may open the
> review window. Registration failure, capacity exhaustion, duplicate id,
> malformed capability, Port/keyring lifetime loss, or window failure keeps the
> window hidden or terminalizes the exact row.
>
> C12 now owns one Promise-idempotent `approve()` invocation. It supplies the
> coordinator's already-bound id/digest itself, structurally snapshots the
> returned id/digest/transaction/signature, scrubs every accessible byte copy,
> independently proves the exact durable approval row is `approved`, and
> returns only `true`. Signed transaction and signature bytes never enter the
> action registry, approval protocol, page, or C15 facade. A provider or keyring
> abort while signing suppresses UI success even when the signed result became
> durable; C14 remains the replay owner for that committed result.
>
> The strict approval protocol now admits `approval:approve`, but its params
> remain exactly `{requestId}`. The page cannot supply a digest, transaction,
> account, chain, release, endpoint, key, signature, or action bytes. A pending
> review carries one boolean `canApprove`; the production default is `false`.
> The background computes `true` only by matching the URL/provenance-bound
> pending row's exact digest against the live volatile registry. A successful
> action emits only `{status:"approved",requestId}`, then settles the capability;
> rejection and cancellation also settle any surviving route. A forged approve
> request when the capability is absent burns the exact pending row.
>
> The approval page enables and labels the button only when that background
> boolean is true. Its success text says that the exact request was signed and
> that provider delivery is still unavailable. The shipped runtime deliberately
> passes no action owner, and the build metafile now explicitly forbids
> `provider-approval-action.ts` together with every C12–C16 provider/signing/page
> owner. Real Chromium therefore continues to measure a disabled production
> approve button.
>
> Meaningful RED and adversarial evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/provider-approval-action.test.ts`
>   first exited **1** before collection because
>   `provider-approval-action.js` did not exist.
> - The C12 lane then exited **1**, **2 failed / 30 passed**: the prepared handle
>   exposed neither `approve()` nor its exact lifetime signal.
> - The protocol lane exited **1** before collection because the byte-free
>   approved-response constructor did not exist. The approval-Port RED was
>   **3 failed / 8 passed**: production reported `canApprove:false`, no action
>   ran, and no action settlement occurred.
> - Final focused C12/C15/action/protocol/Port is **69/69**. It proves one shared
>   action Promise, bind → action-register → window-open ordering, duplicate and
>   cap refusal, malformed/listener rollback, byte scrubbing, digest
>   substitution poison, refusal of shaped signed bytes without an approved
>   durable row, authority-loss suppression after durable signing, byte-free
>   page messages, explicit rejection/cancellation settlement, and forged-action
>   cancellation.
> - Harsh self-review found and fixed two defects after initial greens: normal
>   lifetime revocation could be falsely escalated as fatal after the registry
>   had correctly self-removed, and malformed action method binding left its
>   copied digest unscrubbed.
>
> Primary contracts reviewed:
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>,
> <https://solana.com/docs/rpc/http/getlatestblockhash>,
> <https://solana.com/docs/rpc/http/isblockhashvalid>,
> <https://solana.com/docs/rpc/http/getgenesishash>, and the Wallet Standard
> reference Solana wallet at
> <https://github.com/wallet-standard/wallet-standard/blob/master/packages/example/wallets/src/solanaWallet.ts>.
> Chrome documents that MV3 global state is ephemeral and that sender document
> lifecycle can change after Port creation; the action registry is therefore
> intentionally volatile and never reconstructs signing authority from a row.
> Solana's RPC contracts support the existing coordinator's exact
> blockhash/last-valid-height/genesis binding. Wallet Standard returns signed
> transaction bytes; C17 deliberately withholds them from the approval page.
> The conclusion that a durable row alone cannot recreate an in-memory signing
> capsule is an architectural inference, not a browser or RPC guarantee.
>
> `codex review --commit b36aeecd3c2b49ee18144ab1144d46dcddddd88f`
> exited **1** before review because the in-process app-server client could not
> initialize on this host's read-only state path. Independent second-model
> review remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `b36aeecd3c2b49ee18144ab1144d46dcddddd88f`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider approval action:','provider page request:','page_validation_0000000000000000','provider approval operation:','provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C17 provider/signing/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> exited **0** and printed the same SHA before and after: extension **395/395**,
> typecheck, build, production Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The production background
> and content bundles retain `WARDEN_METHOD_UNAVAILABLE`; all C12–C17 owner
> markers are absent. Ledger-inclusive full-gate evidence is not claimed until
> the ledger SHA runs the repository gate.
>
> Full-gate addendum: ledger-inclusive SHA
> `4fd8fc979c4ac7f1c3af6378dc047d64548d17a9` passed this exact command,
> exit **0**:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **395/395**, production
> Chromium **6/6**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust
> workspace. The known Anchor test-program key mismatch notice and legacy macro
> `cfg` notices were warnings, not skipped failures. This verdict belongs only
> to `4fd8fc9…`; this evidence-only follow-up does not inherit it or promote an
> invariant.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C17 is not a shipped signing flow. The production release
> registry is empty, no trusted production RPC endpoint or reviewed deployment
> pin exists, and the emitted runtime omits the action/coordinator graph. The
> real Chromium lane therefore measures only the disabled production page, not
> a cryptographic signature. C17 unit tests compose C12 → C15 → the real action
> registry and separately exercise the Port/UI protocol, but there is no single
> real-browser action → durable signature → C14 replay → C16 Promise flow.
> Worker restart intentionally destroys pending action authority; startup
> invalidation must terminalize pending rows, while an already-signed outcome is
> replay-only. Page `approved` means durable signature, not provider delivery,
> send, confirmation, or page consumption. C12's legacy `launch()`/`open()`
> bypasses remain internal and must not ship. Consequence review, Wallet
> Standard registration/batching, onboarding, production KDF policy, root
> ceremony, and send/confirmation remain absent. C17 narrows one signing
> authority boundary; it does not make Warden deployable.
>
> **Next load-bearing work:** compose the C17 byte-free approval terminal with
> C14 signed-result replay and C16 page-Promise settlement in one closed,
> still-unshipped lane, including provider/keyring/worker-death races. Do not add
> a non-empty production release or endpoint without a reviewed real deployment
> and explicit deployment authority; do not enable the provider merely because
> a fake/test coordinator can sign.

> ## 2026-08-31 C16 MAIN-WORLD TERMINAL IDEMPOTENCE — INTERNAL ONLY, PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `d376a885937066b3f54a661fa6ae09fc3b920d5d` adds a still-unreachable
> `solana:signTransaction` page request/promise owner. Primary-source review
> confirmed that Chrome `Port.postMessage()` is a void enqueue operation and
> `window.postMessage()` returns no recipient acknowledgment. C14 therefore
> cannot honestly persist a delivered bit, and a content-script filter alone
> cannot own Promise settlement. C16 makes the future main-world request owner
> the narrow terminal-idempotence boundary instead.
>
> One owner claims one page object for its full document lifetime, including
> after disposal. It validates and copies an exact sign-transaction input through
> the existing closed provider parser, mints a `page_` correlation from 128 bits
> of Web Crypto randomness, records that id before posting, and never accepts a
> page-supplied correlation. Every issued id remains a bounded tombstone even
> after success, unavailable error, timeout, transport failure, or disposal.
> A random collision is retried at most eight times and can never attach a
> different request to a retained id.
>
> The pending entry is installed before `window.postMessage()`. The response
> listener requires the captured same-window/same-origin event shape and one
> exact direction-tagged outer envelope, then accepts only C14's strict signed-
> transaction response or the existing fixed-unavailable response. It removes
> the exact entry and timer before the first resolve/reject. Later identical or
> conflicting deliveries, unknown correlations, wrong contexts, sparse byte
> arrays, outer-envelope accessors, and open/malformed envelopes are ignored.
> Signed bytes are copied into a new `Uint8Array` before resolving. These event
> checks are routing filters, not page authentication: every same-page script remains the same
> hostile caller principal.
>
> The in-memory registry is capped at 32 pending and 1,024 issued requests per
> document. Requests have a two-minute default and ten-minute maximum lifetime;
> timers are hints backed by absolute clock checks, reschedule if fired early,
> and cannot make a delayed response win at or after expiry. Configuration may
> lower but never raise the caps. Listener setup has rollback, disposal rejects
> all exact pending Promises, and disposed owners inspect no later hostile input.
>
> Meaningful RED and adversarial evidence:
>
> - `pnpm --filter @warden/extension exec vitest run
>   test/provider-page-request.test.ts` first exited **1** before collection
>   because `src/page/provider-request-owner.js` did not exist.
> - Harsh review found a load-bearing hole after the first **12/12** green:
>   two owners on the same document had disjoint issued-id tombstones. C16 now
>   claims the page once, rolls that claim back only when construction fails,
>   and refuses reinstallation even after disposal.
> - The review also moved the disposed check before input inspection and made a
>   partially installed listener inert/removed when registration throws.
> - The final focused lane is **14/14**. It covers pre-send registration and
>   input/result copying, out-of-order parallel responses, first-terminal wins,
>   success/error replay, random collision and exhaustion, post failure,
>   absolute timeout/early timer behavior, wrong-context and malformed traffic,
>   bounded pending/issued counts, hostile input, construction rollback,
>   disposal, and one owner per document.
>
> Official contracts reviewed:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts>,
> <https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage>,
> <https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues>, and the
> Wallet Standard reference Solana implementation at
> <https://github.com/wallet-standard/wallet-standard/blob/master/packages/example/wallets/src/solanaWallet.ts>.
> Chrome documents MAIN-world interference and Port send/disconnect behavior;
> the web-platform contracts make `postMessage` asynchronous with no receipt;
> Web Crypto supplies synchronous strong random bytes even where `subtle` is
> unavailable; Wallet Standard returns signed transaction bytes. The conclusion
> that no send call proves Promise consumption is an explicit architectural
> inference, not a delivery guarantee claimed by those APIs.
>
> `codex review --commit d376a885937066b3f54a661fa6ae09fc3b920d5d`
> exited **1** before review because the in-process app-server client could not
> initialize on this host's read-only state path. Independent second-model
> review therefore remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `d376a885937066b3f54a661fa6ae09fc3b920d5d`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const all=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider page request:','page_validation_0000000000000000','provider approval operation:','provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>all.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C16 provider/signing/page owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> exited **0** and printed the same SHA before and after: extension **380/380**,
> typecheck, build, real Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The build now explicitly
> forbids C16 from the background and the existing exact entry-point allowlists
> exclude it from content, popup, and approval bundles. Both emitted bridge
> bundles retain `WARDEN_METHOD_UNAVAILABLE`; C12–C16 markers are absent.
> Ledger-inclusive full-gate evidence is not claimed until the ledger SHA runs
> the repository gate.
>
> Full-gate addendum: ledger-inclusive SHA
> `a7a5301c9ab97aecb169f7482f100e5e46c1d58d` passed this exact command,
> exit **0**:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **380/380**, production
> Chromium **6/6**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust
> workspace. The known Anchor test-program key mismatch notice and legacy macro
> `cfg` notices were warnings, not skipped failures. This verdict belongs only
> to `a7a5301…`; this evidence-only follow-up does not inherit it or promote an
> invariant.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C16 is not injected, registered, or browser-tested as a
> main-world provider. Its one-owner guard is module-instance memory; the future
> manifest/injection lane must prove exactly one evaluation per real document
> and must not imply that a WeakSet survives a separately reinjected bundle.
> Same-page code can forge a syntactically valid terminal response, steal or
> suppress traffic, replace main-world platform methods, or deny service; Warden
> treats that whole page as the caller, not an authenticated sub-principal. The
> registry does not receive Port-disconnect notices, resend pending requests, or
> acknowledge delivery back to C14. It provides document-lifetime terminal
> deduplication, not transport recovery or durable page state. It handles only
> one sign-transaction call, not Wallet Standard batching, connect/events,
> sign-and-send, or registration. C16 unit tests compose the pure request and
> terminal schemas; no real-browser C12–C16 signature flow exists. Production
> remains fixed-unavailable, and release/RPC authority, approve/claim/sign,
> consequence review, send/confirmation, onboarding, and root ceremony remain
> absent. C16 is not deployable wallet behavior.
>
> **Next load-bearing work:** build the trusted non-empty release/RPC selection
> and the actual approval-page claim/sign action as a closed composition, while
> keeping provider success unreachable. Only after that should a separately
> gated MAIN-world Wallet Standard adapter integrate C16 and exercise real
> disconnect/replay behavior end to end.

> ## 2026-08-31 C15 BIND-BEFORE-OPEN COMPOSITION — INTERNAL ONLY, PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `a9271c979ea2707f4d0c92ddd0d03db5e2e0ce3d` closes the C12/C14
> ordering hole in still-unreachable extension code. C12 now has a distinct
> `prepare()` phase that creates and independently proves one exact durable
> pending approval without opening a window. Its prepared handle retains Port
> ownership and the authenticated keyring-generation signal, cancels on either
> revocation, and exposes an idempotent `open()` edge. The old `launch()` API is
> only a compatibility wrapper over prepare then open.
>
> New C15 `ProviderApprovalOperationOwner.launch()` is the reviewed composition
> path. It calls C14's claim-before-callback owner; that callback may call only
> C12 `prepare()` and return the exact approval id/message digest. C14 must prove
> the operation→approval binding durable before C15 calls `open()`. A retained
> bound operation returns only `replay-required`: it never prepares or opens a
> second approval. The opened result deliberately strips the raw `open`
> capability, retaining only id/account/chain/digest plus settle/cancel.
>
> Every post-preparation failure attempts exact approval cancellation. This
> includes an unproven journal bind, a disconnect after bind commit but before
> return, authority revocation during that same gap, a malformed prepared
> visibility capability, and window creation failure after a proven bind. If
> binding may have committed, C15 does not rewrite the operation as a generic
> failure: the retained locator remains the only replay identity, even when its
> approval has been cancelled. That is deliberate at-most-once safety over
> liveness.
>
> Meaningful RED and adversarial evidence:
>
> - `pnpm --filter @warden/extension exec vitest run
>   test/provider-approval-request.test.ts` first exited **1**, with **1 failed /
>   23 passed**: the new hidden-until-open case failed because
>   `installed.owner.prepare` did not exist.
> - After the split, the same command failed before collection because
>   `provider-approval-operation.js` did not exist. That RED pinned the C15
>   composition rather than merely testing C12 in isolation.
> - Harsh self-review found a real cleanup hole in the first C15 draft: a
>   malformed prepared handle could fail validation before C15 retained its
>   cancellation method. Cancellation is now bound first; the executable case
>   proves the exact row cancelled, no window call, and a durable
>   `preparation-failed` operation.
> - The final focused lane is **31/31**. It measures the order `operation claim
>   commit → approval prepare → operation bind commit → window open`, concurrent
>   and repeated open idempotence, hidden-row cancellation before open, unproven
>   bind cleanup, Port and authority races in the bind gap, malformed-handle
>   cleanup, and no reprepare/reopen after a bound operation's first window
>   failure.
>
> `codex review --commit a9271c979ea2707f4d0c92ddd0d03db5e2e0ce3d`
> exited **1** before review because the in-process app-server client could not
> initialize on this host's read-only state path. Independent second-model
> review therefore remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `a9271c979ea2707f4d0c92ddd0d03db5e2e0ce3d`, with a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> pnpm --filter @warden/extension test &&
> pnpm --filter @warden/extension typecheck &&
> pnpm --filter @warden/extension build &&
> pnpm --filter @warden/extension test:browser &&
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const text=files.map(f=>fs.readFileSync(f,'utf8')).join('\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider approval operation:','provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>text.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C15 provider/signing owners are absent')" &&
> git diff --check && git rev-parse HEAD &&
> test -z "$(git status --porcelain)"
> ```
>
> exited **0** and printed the same SHA before and after: extension **366/366**,
> typecheck, build, real Chromium **6/6**, emitted-artifact exclusion,
> `git diff --check`, and clean-tree proof passed. The build metafile now forbids
> the C15 module in addition to every C12–C14 owner/result module. Both emitted
> bundles retain `WARDEN_METHOD_UNAVAILABLE` and contain no C12–C15/coordinator
> markers. Ledger-inclusive full-gate evidence is not claimed until the ledger
> SHA runs the repository gate.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** ordering is enforced only when future production code uses
> the C15 composite. The still-exported C12 `launch()` and prepared `open()` are
> internal bypass capabilities; the production build currently makes this safe
> by forbidding both C12 and C15 entirely, but enablement must instantiate only
> the composite or remove/guard the legacy edge. A worker death after approval
> creation but before cross-database bind can strand an invisible pending row;
> death after bind but before open can leave a replay-only binding with no
> visible review. The focused composition uses an in-memory journal; native
> IndexedDB CAS/restart is separately proven by C14's Chromium lane, not by one
> end-to-end C15 browser/signature flow. Retention remains bounded. There is no
> page receipt acknowledgment or correlation-id deduplication, non-empty
> committed release, trusted endpoint, approve/sign action, simulation and
> fee/balance consequence model, send/confirmation owner, Wallet Standard
> registration/batching, onboarding, or root ceremony. C15 is not deployable
> wallet behavior.
>
> **Next load-bearing work:** make successful page delivery correlation-
> idempotent before any provider success route can ship, then add the real
> approve/claim/sign UI action behind a non-empty committed release and trusted
> RPC boundary. Production must remain fixed-unavailable until those pieces have
> executable end-to-end gates; do not infer enablement from C15.
>
> **C15 full-gate addendum:** the ledger-inclusive SHA
> `a2920004847b89e13385f4ea1689684dc4c60fbc` passed this exact command,
> exit **0**: `git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git
> diff --check && git rev-parse HEAD && test -z "$(git status --porcelain)"`.
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **366/366**, production
> Chromium **6/6**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust workspace.
> The known Anchor test-program key mismatch notice and legacy macro `cfg`
> notices were warnings, not skipped failures. This verdict belongs only to
> `a292000…`; this evidence-only addendum commit does not inherit it or promote
> an invariant.

> ## 2026-08-31 C14 DURABLE PROVIDER OPERATION / SIGNED-RESULT REPLAY — INTERNAL ONLY, PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `ad66c1633bea96e5cda14e96ab8982c3ae824985` adds a still-unreachable
> provider-operation journal, terminal signed-result owner, and success response
> language. The production build explicitly forbids every C12–C14 provider owner
> and the approval coordinator from the background graph; the content bundle
> still understands only `WARDEN_METHOD_UNAVAILABLE`. This is durability and
> replay infrastructure, not an enabled wallet method.
>
> C14 treats a live Chrome `Port` as an in-memory delivery lease, never as
> durable continuity. A stable SHA-256 operation identity joins the exact closed
> `solana:signTransaction` request—including correlation id, account selector,
> chain, options, and transaction bytes—to Chrome-owned extension, origin, tab,
> frame, and document identity. Volatile background request ids and timestamps
> are deliberately excluded so a reconnect in the same browser document can
> find the same operation. Changing one transaction byte, option, correlation
> id, or browser-document field derives a different operation.
>
> A separate IndexedDB v1 journal owns strict `preparing`, `bound`, and `failed`
> records. One serializable `readwrite` transaction claims the unique operation
> before its callback may create an approval. Only that claimant may invoke the
> callback; a concurrent connection observes `preparing` or the eventual exact
> approval id/digest binding. Startup turns every abandoned `preparing` row into
> `worker-restarted` (or `expired`) and never resumes it. Because the operation
> and approval databases are separate, there is intentionally no false cross-DB
> atomicity claim: a worker death between claim and binding loses liveness and
> may strand a non-visible pending approval, but the retained claim prevents a
> second preparation. The callback contract therefore stops immediately after
> durable approval creation; it may not open the review window or sign before
> the operation binding commits.
>
> Bound rows carry both the exact request digest and the exact approval id plus
> approved-message digest. Terminal delivery rederives the current operation,
> reads that binding, independently checks the approved row's id, digest,
> browser provenance, method, account, and requested chain, and invokes the
> core's extracted durable result reader. That reader needs only the atomic
> approval/signing-outcome read: it strictly reparses the committed transaction,
> recomputes the message digest, matches the approved raw message, requires one
> nonzero signature/required signer, and verifies Ed25519 before releasing copied
> bytes. It does not rebuild a coordinator, reopen the keyring, contact RPC, or
> create/retry a signing attempt.
>
> `Port.postMessage` is only a synchronous enqueue. C14 deliberately writes no
> delivered bit because Chrome supplies no page receipt acknowledgment; if the
> enqueue throws, a reconnect reads and releases the same committed bytes again
> without signing again. The future page boundary must deduplicate the stable
> correlation id. The journal is bounded at 32 preparing / 128 total records and
> prunes terminal rows after a ten-minute horizon anchored to resolution or
> request expiry. Accordingly, the at-most-once preparation claim is only for a
> retained row, not eternal deduplication.
>
> Meaningful RED and adversarial evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
>   vitest run test/session-approval-coordinator.test.ts` first exited **1**, **1
>   failed / 42 passed**, because the disposed-coordinator scenario had no
>   `readSignedSessionApproval` restart path even though the signed outcome was
>   durably committed.
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/provider-operation.test.ts` first
>   failed before collection because `provider-operation.js` did not exist.
> - The final C14 unit lane has **11/11** cases covering stable/reminted identity,
>   every request/provenance discriminator, copy-owned closed records, hostile
>   response proxies, concurrent claim ownership, retained interrupted claims,
>   disconnect after claim, exact terminal delivery, enqueue failure/retry,
>   unbound/wrong-digest refusal, cross-document refusal, and changed-transaction
>   refusal before signed-result access.
> - The real Chromium contract opens competing connections to native IndexedDB,
>   proves only one preparation callback runs, force-stops the exact MV3 worker,
>   proves its global marker is gone, then observes the replacement worker replay
>   the bound locator without another callback and terminalize the interrupted
>   claim as `worker-restarted`.
>
> Official contracts reviewed:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://github.com/anza-xyz/wallet-standard>, and the official Wallet
> Standard reference wallet implementation at
> <https://github.com/wallet-standard/wallet-standard/blob/master/packages/example/wallets/src/solanaWallet.ts>.
> Chrome documents disposable worker globals, `Port` disconnect/enqueue
> behavior, and browser-owned `MessageSender.documentId`; Wallet Standard's
> Solana transaction result carries signed transaction bytes. The inference that
> `postMessage` is not a page receipt acknowledgment is deliberately treated as
> an architectural constraint, not an API guarantee Chrome provides.
>
> `codex review --commit ad66c1633bea96e5cda14e96ab8982c3ae824985`
> exited **1** before review because the in-process app-server client could not
> initialize on this host's read-only state path. Independent second-model review
> therefore remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `ad66c1633bea96e5cda14e96ab8982c3ae824985`, with a clean tree:
>
> ```sh
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build
> ```
>
> exited **0**: core **699/699**, typecheck, and build passed.
>
> ```sh
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build
> ```
>
> exited **0**: extension **358/358**, typecheck, and build passed.
>
> ```sh
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test:browser
> ```
>
> exited **0**, real Chromium **6/6**, including the C14 forced-worker-death
> contract.
>
> ```sh
> node -e "const fs=require('node:fs');const path=require('node:path');const root='apps/extension/dist';const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk(root);const text=files.map(f=>fs.readFileSync(f,'utf8')).join('\\n');const background=fs.readFileSync(path.join(root,'background.js'),'utf8');const content=fs.readFileSync(path.join(root,'content.js'),'utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider operation:','warden-provider-operations-v1','provider terminal result:','provider terminal protocol:','provider approval request:','provider approval selection:','session approval coordinator:'];const missing=required.filter(s=>!background.includes(s)||!content.includes(s));const hit=forbidden.filter(s=>text.includes(s));if(missing.length||hit.length){console.error({missing,hit});process.exit(1)}console.log('extension dist remains fixed-unavailable; C12-C14 provider/signing owners are absent')"
> ```
>
> exited **0**. The build metafile also rejects all four C14 modules if they
> become reachable. `git diff --check && test -z "$(git status --porcelain)" &&
> git rev-parse HEAD` exited **0** and printed the exact implementation SHA.
> Ledger-inclusive full-gate evidence is not claimed until the ledger SHA runs
> the repository gate.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; the
> invariants JSONL is intentionally unchanged.
>
> **Harsh residual:** C12 and C14 are not yet safely composable. C12's current
> `launch()` creates the durable approval and opens the visible window before it
> returns, while C14 requires the operation→approval binding to commit before
> any visible/actionable side effect. The next slice must split C12 into a
> prepare/prove handle, bind that handle through C14, and only then open the
> window. A Port enqueue can also be delivered even if the subsequent in-memory
> `finish()` loses ownership, so future page code must deduplicate correlation
> ids; no acknowledgment protocol exists. Retention is bounded, the terminal
> owner uses a test seam in extension unit tests while the real cryptographic
> verifier is exercised in core, and the browser lane measures journal restart
> behavior rather than an end-to-end real signature. There is still no emitted
> success protocol, non-empty committed release, trusted endpoint, approve/sign
> UI action, simulation/fee/balance consequence model, send/confirmation owner,
> Wallet Standard registration/batching, onboarding, or root ceremony. C14 is
> not deployable wallet behavior.
>
> **Next load-bearing work:** split the C12 preparation and window-open phases so
> the exact durable approval locator can be bound to C14 before review becomes
> visible. Then prove disconnect/revocation races across the split and make page
> delivery correlation-idempotent. Do not import any success/result language
> into the production content/background graph until that composition, a real
> committed release/trusted RPC boundary, and the approve/sign action all have
> executable end-to-end gates.
>
> **C14 full-gate addendum:** the ledger-inclusive SHA
> `19557ff540c6e5701f619378979e9e595d0b954e` passed this exact command,
> exit **0**: `git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git
> diff --check && git rev-parse HEAD && test -z "$(git status --porcelain)"`.
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **358/358**, production
> Chromium **6/6**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust workspace.
> The known Anchor test-program key mismatch notice and legacy macro `cfg`
> notices were warnings, not skipped failures. This verdict belongs only to
> `19557ff…`; this evidence-only addendum commit does not inherit it or promote
> an invariant.
>

> ## 2026-08-31 C13 AUTHENTICATED COMMITTED-RELEASE SELECTION — INTERNAL ONLY, PROVIDER STILL UNAVAILABLE
>
> The C13 implementation set ends at
> `63521de32b7b1be425aeaaed504c1e177d689c4b`. Commit
> `2b6e667c4584e8ac918f66de0addd8d6c32c627a` adds a still-unreachable
> `CommittedProviderApprovalSelectionResolver`, an authenticated public-keyring
> identity read, and an RFC 8032 Ed25519 public-key derivation helper. Harsh
> review then found a real Promise-settlement gap between resolver return and
> C12 preparation. Commit `63521de32b7b1be425aeaaed504c1e177d689c4b`
> carries the exact unlock-generation revocation signal across selection,
> preparation, window lifetime, cancellation, and settlement.
>
> The resolver calls `resolveCommittedSessionRelease(releaseName)` before it
> inspects the Connection factory, keyring, approval repository, clock, or TTL.
> The actual committed registry is empty, so the real integration test proves
> only that this path rejects before any privileged getter. In the separately
> mocked composition test, one repository-owned release identity is joined to a
> zero-argument trusted Connection factory and two authenticated public keyring
> snapshots. Page account/chain selectors, RPC URL, release document, program
> id, and deploy pin are not read; C12 independently checks the returned account
> and chain against the page request before preparation.
>
> `readAuthenticatedSessionIdentity` opens the existing encrypted v2 bundle
> through the exact live unlock lease, strict schema and AAD checks, derives only
> the 32-byte Ed25519 public half with `@noble/curves`, checks the exact stored
> record again, and scrubs every seed/intermediate it owns. It returns copied
> account, genesis hash, program id, and public signer bytes plus the stable
> `AbortSignal` belonging to that exact unlock generation. The resolver requires
> all public bytes and the signal object itself to match across two reads. This
> catches a lock/re-unlock even when the new record produces identical public
> bytes.
>
> C12 now snapshots that authority signal before `prepare`. Provider disconnect
> or keyring revocation during preparation is recovered against the exact
> durable id/digest/browser binding and cancelled. Once active, either signal
> synchronously aborts one combined window-lifetime signal and starts exact-row
> cancellation. Normal settlement/cancellation also aborts the window lifetime
> and removes both listeners. Listener registration plus immediate state check
> is one fail-closed cleanup scope; a malformed structural signal cannot leave a
> half-installed active entry.
>
> Meaningful RED and adversarial evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
>   vitest run test/session-signer-payload.test.ts` first exited **1**, **1
>   failed / 5 passed**, because the pinned public-key helper did not exist.
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/keyring-context-ownership.test.ts`
>   first exited **1**, **2 failed / 2 passed**, because the authenticated public
>   identity method did not exist.
> - The two selection suites first failed before collection because
>   `provider-approval-selection.js` did not exist. The actual empty-registry
>   suite then proved rejection before privileged getter access; the mocked
>   suite covers stable composition, release mismatch, page-selector
>   non-access, provider abort, changed public identity, changed unlock
>   generation, and already/in-flight revoked identity.
> - After the first implementation, `env
>   npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
>   vitest run test/keyring-context-ownership.test.ts
>   test/provider-approval-selection-empty.test.ts
>   test/provider-approval-selection.test.ts
>   test/provider-approval-request.test.ts` exited **1**, **7 failed / 30
>   passed**. It exposed the absent generation signal, same-bytes re-unlock
>   blindness, resolver Promise-settlement gap, in-flight preparation race,
>   post-launch stale window, and the old provider-only window signal. Those are
>   the failures closed by `63521de…`; they are not described as green evidence.
>
> Current contracts were checked against Solana's official `getGenesisHash`
> RPC documentation, the official web3.js `Connection` API, and Chrome's
> storage/service-worker event rules:
> <https://solana.com/docs/rpc/http/getgenesishash>,
> <https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage>, and
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events>.
> A Connection is still only a trusted factory capability here; there is no
> production endpoint, release, or live genesis-hash call. Independent
> second-model review did not run; C13 remains **UNVERIFIED**.
>
> Exact implementation-SHA evidence at
> `63521de32b7b1be425aeaaed504c1e177d689c4b`: the following exact command
> exited **0**, printed the same SHA before and after, and proved a clean tree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck &&
> env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build &&
> node -e 'const fs=require("node:fs");const source=fs.readFileSync("apps/extension/dist/background.js","utf8");const required=["function deriveSessionSignerPublicKey","async readAuthenticatedSessionIdentity","function installUnavailableProviderBoundary","WARDEN_METHOD_UNAVAILABLE","Warden provider methods are not enabled"];const forbidden=["class ProviderApprovalRequestOwner","class CommittedProviderApprovalSelectionResolver","resolveCommittedSessionRelease","createCommittedSessionApprovalCoordinator"];for(const marker of required){if(!source.includes(marker))throw new Error("missing emitted marker: "+marker)}for(const marker of forbidden){if(source.includes(marker))throw new Error("forbidden emitted marker: "+marker)}console.log("C13 public identity bridge emitted; resolver absent; provider remains fixed unavailable")' &&
> git diff --check && git rev-parse HEAD && test -z "$(git status --porcelain)"
> ```
>
> Core passed **699/699**; extension passed **347/347**; both typechecks and
> builds exited **0**. The emitted worker contains the authenticated public
> identity bridge, but the build metafile rejects C12, C13, coordinator,
> authority, release, RPC, and signer-transaction reachability. The artifact
> still contains the fixed unavailable provider code/message and contains none
> of the C12/C13/release/coordinator markers. Ledger-inclusive full-gate evidence
> is not claimed until the exact ledger SHA runs it below.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`, so
> `docs/security/invariants.jsonl` is intentionally unchanged.
>
> **Harsh residual:** the happy selection path is tested with mocked release and
> coordinator factories; production proves only empty-registry refusal. The
> constructor accepts a release name and Connection factory, so “source-owned”
> remains a contract on a future reviewed composition that does not yet exist.
> The v1 encrypted payload omits a redundant public half, requiring two internal
> decryptions per selection; seed copies are scrubbed and never returned, but
> their transient exposure and cost remain. Elapsed unlock deadlines do not
> autonomously fire the generation signal; later key use and approval expiry
> remain authoritative. There is no emitted provider-to-preparation route,
> non-empty committed release, trusted endpoint, approve/claim/sign action,
> signed-result/replay protocol, send/confirmation owner, simulation or fee/
> balance consequence model, Wallet Standard registration/batching, onboarding,
> or root ceremony. This is a stronger unreachable boundary, not deployable
> wallet behavior.
>
> **Next load-bearing work:** do not emit C12/C13 merely to demonstrate wiring.
> First define a durable provider terminal-result/replay owner that binds one
> Port request to one approval outcome and cannot duplicate signing across MV3
> restart/reconnect. In parallel, a real route remains blocked on a reviewed
> non-empty committed release and source-fixed RPC endpoint with executable
> genesis/deployment attestation. The approve/sign path must recheck the exact
> row, digest, account, chain, release, registry authority, and keyring
> immediately before signing.
>
> **C13 full-gate addendum:** the ledger-inclusive SHA
> `835539457aa211a1ebfe8ac46f52b2a563b8c8ba` passed this exact command,
> exit **0**: `git rev-parse HEAD && test -z "$(git status --porcelain)" &&
> env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git
> diff --check && git rev-parse HEAD && test -z "$(git status --porcelain)"`.
> It printed the same SHA before and after, proved a clean worktree, and ran the
> complete pnpm workspace, core **699/699**, extension **347/347**, production
> Chromium **5/5**, the pinned Argon2 worker benchmark, core/extension builds
> and typechecks, fixture/ledger/feature guards, and the complete Rust workspace.
> The known Anchor test-program key mismatch notice and legacy macro `cfg`
> notices were warnings, not skipped failures. This verdict belongs only to
> `8355394…`; this evidence-only addendum commit does not inherit it or promote
> an invariant.

> ## 2026-08-31 C12 PROVIDER LEASE→PREPARATION OWNER — INTERNAL ONLY, EMITTED PROVIDER STILL UNAVAILABLE
>
> Implementation commit
> `cdaa6639edcc50fc68aca1923e198540aba9b9cf` adds the still-unreachable
> `ProviderApprovalRequestOwner`. It is the first owner that can translate one
> exact live `ProviderPortSession` lease into the existing strict approval
> coordinator and C11 window launcher. The production build explicitly rejects
> this module as a background input, and the emitted provider still returns only
> `WARDEN_METHOD_UNAVAILABLE`.
>
> The owner accepts only `solana:signTransaction`. It reserves exact object
> ownership before any await, rejects duplicate ownership, and caps preparing
> plus active requests at an independently test-pinned 32. A trusted resolver
> must return the canonical current SmartAccount bytes, chain, and a bound
> coordinator. The owner independently Base58-encodes those 32 account bytes
> and requires exact equality with the untrusted page selector; a supplied page
> chain must also equal the trusted chain. Browser-owned origin, tab, frame, and
> document provenance, the proven account/chain, and a copied transaction are
> the only values forwarded to `prepare`.
>
> A coordinator result is not enough to open a window. The owner snapshots a
> strict background-minted id and digest hint, independently reads that exact
> durable row, validates the row's id, digest, browser provenance, method,
> account, and chain, and only then attaches the provider AbortSignal and opens
> the exact C11 request id. Returned account/chain/time/digest disagreement is
> cancelled against the durable binding, not trusted as its own cleanup oracle.
> A malformed result with a valid id+digest can therefore still cancel the
> exact proven row. A malformed locator/digest, a row belonging to another
> browser request, or cancellation plus terminal-read failure is not guessed:
> it reports fatal, poisons the owner against new work, and asks the parent to
> close every privileged surface.
>
> Disconnect, window-open failure, owner disposal, and authority/preparation
> failure cannot approve or sign. Once a row exists, cleanup calls `cancel` only
> for that exact id; a losing cancel is accepted only when an exact durable read
> proves the same binding terminal or absent. Settlement likewise releases
> ownership only after an exact terminal/absent read. Harsh review found that a
> settlement and disconnect cancellation could otherwise share and zero the
> same proof buffers while either await was in flight. Each terminal operation
> now uses an isolated copy, and a concurrent settle/cancel regression proves
> both complete without weakening the binding.
>
> Meaningful RED and critique evidence:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/provider-approval-request.test.ts`
>   first exited **1** before collection because
>   `provider-approval-request.js` did not exist.
> - After the first implementation, the focused lane exited **1**, **1 failed /
>   11 passed**. A coordinator result with a wrong account caused a correctly
>   cancelled durable row to be labelled unproven because cleanup compared it
>   with the malformed return. Mandatory durable re-binding closes that flaw.
> - The final adversarial lane has 20 cases: exact browser input, unsupported
>   methods, account/chain disagreement, delayed disconnect, open failure,
>   authority change, terminal winner, unproven cleanup, malformed coordinator
>   result, missing locator, wrong durable browser owner, duplicate/cap races,
>   disposal during preparation, concurrent settle/cancel, and exact terminal
>   settlement. The 32-request cap oracle is hard-coded independently of the
>   production constant.
>
> Current platform and standard gaps were checked against Chrome's official
> messaging and runtime documentation and the Wallet Standard Solana extension:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>, and
> <https://github.com/wallet-standard/wallet-standard/blob/master/extensions/solana.md>.
> Chrome documents long-lived Port lifetime, browser-owned `MessageSender`
> metadata, disconnect semantics, and the need to treat content-script input as
> less trustworthy. Wallet Standard returns signed transaction bytes and permits
> batched feature inputs; Warden still has only a single-request, unavailable
> transport and no terminal success/replay schema. No independent second-model
> review ran for C12; it remains **UNVERIFIED**.
>
> Exact-SHA evidence at `cdaa6639edcc50fc68aca1923e198540aba9b9cf`:
> the following exact command exited **0**, printed the same SHA before and
> after, and proved a clean worktree:
>
> ```sh
> git rev-parse HEAD && test -z "$(git status --porcelain)" && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension typecheck && env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build && node -e "const fs=require('node:fs');const background=fs.readFileSync('apps/extension/dist/background.js','utf8');const required=['WARDEN_METHOD_UNAVAILABLE'];const forbidden=['provider approval request:','too many active provider approval requests','session approval coordinator:','createCommittedSessionApprovalCoordinator','resolveCommittedSessionRelease','sign approved session transaction'];const missing=required.filter(v=>!background.includes(v));const present=forbidden.filter(v=>background.includes(v));if(missing.length||present.length){console.error({missing,present});process.exit(1)}console.log('C12 owner absent from emitted worker; fixed provider-unavailable boundary remains')" && git diff --check && git rev-parse HEAD && test -z "$(git status --porcelain)"
> ```
>
> The extension passed **330/330**, typecheck and build exited **0**,
> the build graph rejected C12/coordinator/release/RPC reachability, and the
> emitted worker contained `WARDEN_METHOD_UNAVAILABLE` while containing none of
> the C12 owner, coordinator, committed-release, RPC, or signer markers. The
> ledger-inclusive full-gate evidence is recorded below; no verdict transfers
> to a different SHA.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`, so
> `docs/security/invariants.jsonl` is intentionally unchanged. C12 narrows only
> an internal request/preparation/lifetime subclaim.
>
> **Harsh residual:** none of this code is emitted. There is no source-owned
> account/cluster selection registry, authenticated account onboarding,
> committed production release, trusted endpoint, Connection factory, provider
> success/error terminal protocol, approval action, immediate-before-sign key
> use, result replay, simulation, send/confirmation owner, or Wallet Standard
> registration/batch contract. Exact source-transaction identity still rests on
> the already-tested coordinator transformation and its returned digest; this
> outer owner cannot independently rederive the transformed message without
> duplicating authority resolution. The fatal path depends on the parent runtime
> honoring `onFatal`, while local poisoning only prevents new C12 work. A tested
> but tree-shaken owner is not a deployable wallet.
>
> **Next load-bearing slice:** define a still-unshipped, source-owned selection
> resolver that can join authenticated extension account context to one
> committed release name and one explicitly trusted Connection factory. Prove
> the current empty release registry refuses before Connection, keyring, or
> window access; close in-flight selection on account/chain change. Do not
> accept a page RPC URL, release document, program id, or deployment pin, and do
> not import this path into the emitted worker until real reviewed release/RPC
> configuration exists.
>
> **C12 full-gate addendum:** the ledger-inclusive SHA
> `537f3254b72af593720f3f3d2e0dc9f8c664a7ef` passed this exact command,
> exit **0**:
> `git rev-parse HEAD && test -z "$(git status --porcelain)" && env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git diff
> --check && git rev-parse HEAD && test -z "$(git status --porcelain)"`.
> The command printed the same SHA before and after, proved a clean worktree,
> and ran the complete pnpm workspace, core **698/698**, extension **330/330**,
> production Chromium **5/5**, the pinned Argon2 worker benchmark, core and
> extension builds/typechecks, fixture/ledger/feature guards, and the complete
> Rust workspace. Anchor's test-program key mismatch notice and legacy macro
> `cfg` notices were warnings, not skipped failures. This verdict belongs only
> to `537f325…`; the follow-up evidence commit does not inherit it.

> ## 2026-08-31 C11 BACKGROUND-OWNED APPROVAL WINDOW LIFECYCLE — SHIPPED INTERNALLY, NO PROVIDER SUCCESS
>
> The C11 implementation set ends at
> `439c3995d7109f110668c82ddd893672ea679d8a`. Commit
> `1fea6ed8328721b207e2aaa17760f9ecea1b5a16` adds the production-composed
> owner, `d2d6c5b2fc8fdfc0dede6a55e5caa3d3987edbe9` fixes self-derived test
> oracles, and `439c3995d7109f110668c82ddd893672ea679d8a` adds the real-Chrome worker-
> death proof. The shipped worker now owns a readiness-gated internal launcher,
> but no browser message route receives it and every provider/popup request
> remains fixed unavailable.
>
> The launcher's only caller-controlled inputs are one strict
> `req_<32 lowercase hex>` id and an `AbortSignal`. It supplies Chrome a fixed
> `chrome-extension://<runtime-id>/approval.html?request=<id>` URL, popup type,
> focus, `720×600` requested bounds, and `setSelfAsOpener: false`. Callers
> cannot provide a URL, window id, placement, incognito flag, opener, or Chrome
> query options. The manifest remains exactly `permissions: ["storage"]`;
> there is no `tabs`, `activeTab`, `scripting`, host, external-connect, or web-
> accessible-resource expansion.
>
> One reserved request and a global hard cap of 16 exist before any await. The
> owner proves the exact durable row pending before create, validates the
> returned safe non-negative window id, detects create-to-close races with
> `chrome.windows.get`, then proves the row pending again. Duplicate request or
> window ids fail closed. Provider abort, user close, malformed/missing Chrome
> results, create/get failure, and post-create terminal races close only the
> owned window and either cancel the exact row or accept an independently
> proven non-pending winner. If cancellation fails and a read cannot prove the
> row absent/terminal, the parent fatal lifecycle removes every runtime route
> and closes the approval repository.
>
> Worker globals are deliberately not continuity. `windows.onRemoved` is
> registered synchronously during worker evaluation, but its request/window map
> is volatile. Disposal removes that listener, wakes readiness- and create-
> blocked callers, closes active or late-created windows, and starts no new
> repository transition before the parent closes IndexedDB. Mandatory startup
> invalidation cancels an abandoned pending row after worker death. This loses
> availability rather than resuming stale authority.
>
> Meaningful REDs preceded or challenged the implementation:
>
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/approval-window.test.ts` first exited
>   **1** because `approval-window.js` did not exist. The first implementation
>   run then exited **1**, **1 failed / 22 passed**, because an already-aborted
>   lifetime left its exact row pending.
> - `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
>   @warden/extension exec vitest run test/runtime.test.ts -t "ships a
>   readiness-gated internal approval-window owner"` exited **1**, **1 failed /
>   17 skipped**, because the production worker registered zero window-close
>   listeners and exposed no launcher.
> - Two new disposal cases exited **1**, **2 failed / 23 passed**, proving that
>   readiness and Chrome-create promises could outlive teardown. The fixed
>   owner races waits against disposal and removes a window returned after the
>   owner is gone.
> - The focused second-read race exited **1**, **1 failed / 24 skipped**, because
>   a row already proven rejected still triggered `cancel` plus another read.
>   Explicit non-pending proof now suppresses that unnecessary authority use.
> - The first real-Chrome window run exited **1** because headless Chrome
>   resolved requested `720×600` bounds to `1280×720`. The corrected lane
>   separately hard-codes the requested values and measures Chrome's positive
>   resolved bounds; it does not call them browser-enforced.
>
> Harsh QA also caught two harness defects. The first combined focused/typecheck
> run passed **23/23** behavior tests but TypeScript exited **2** on two
> recursive inferred test functions; explicit return types fixed the harness.
> Later audit found that unit and browser dimension expectations, and the cap,
> were imported from the code under test. Commit `d2d6c5b…` pins independent
> hard-coded `720`, `600`, and `16` oracles. No earlier adaptive green is used
> as evidence.
>
> Current platform behavior was checked against Chrome's official windows and
> service-worker lifecycle documentation:
> <https://developer.chrome.com/docs/extensions/reference/api/windows> and
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
> Chrome documents `onRemoved`, browser-session-unique window ids, Promise APIs
> at this project's Chrome floor, and that `tabs` is needed only for sensitive
> Tab fields. It also requires resilience to unexpected worker termination and
> says globals disappear. `codex review --commit
> 1fea6ed8328721b207e2aaa17760f9ecea1b5a16` could not initialize its in-
> process app-server client on this host's read-only state path. Independent
> second-model review is therefore **UNVERIFIED**; no bypass wrote outside
> `/opt`.
>
> Exact-SHA evidence at `439c3995d7109f110668c82ddd893672ea679d8a`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test` passed **310/310**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck` exited **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension build` exited **0**; and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts` passed **5/5** in real Chromium.
> The new browser case uses a temporary extension with no permissions, imports
> the real window owner plus IndexedDB owner, proves exact fixed create input,
> popup type/focus/URL, user-close cancellation, then creates a second pending
> row, force-stops the exact worker target, proves the popup outlives the old
> global map, and observes the replacement startup pass leave it `cancelled`.
>
> The same exact-SHA command rebuilt production output and recursively found no
> test-only `__wardenApprovalWindow` global, browser-contract marker,
> coordinator, authority resolver, release, RPC, signer/session-transaction,
> `chrome.tabs`, host permission, or external-connect string. `git diff
> --check` exited **0**, HEAD remained `439c399…`, and the worktree was clean.
> The C11 ledger-inclusive SHA
> `9c6f1c0be244534a9bbd99075f2a673cc2ac36e6` passed this exact executable
> command, exit **0**:
> `git rev-parse HEAD && test -z "$(git status --porcelain)" && env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh && git diff
> --check && git rev-parse HEAD && test -z "$(git status --porcelain)"`.
> It ran the complete pnpm workspace, core **698/698**, extension **310/310**,
> production Chromium **5/5**, the pinned Argon2 worker benchmark, core and
> extension builds/typechecks, fixture-drift and feature-resolution guards,
> and the complete Rust workspace. The command printed the same SHA before
> and after the gate and proved a clean worktree. Anchor's test-program key
> mismatch notice and legacy macro `cfg` notices remained warnings; they did
> not suppress or replace any failing command.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`. C11
> narrows only internal launch/lifetime/cancellation subclaims.
>
> **Harsh residual:** this still cannot open from a real provider request. There
> is no shipped authoritative account/cluster/policy resolver, production
> release entry, trusted production RPC, coordinator dispatch, approve/claim/
> sign route, simulation, fee/balance consequence model, send/confirmation
> owner, result replay, onboarding, or non-Memo verb. The launcher browser lane
> uses a test-only static approval document while the separate production lane
> tests the real review page; end-to-end provider→record→window→real review is
> absent. Current-Chromium headless evidence is not Chrome 106/store/manual,
> multi-monitor, incognito, Linux-window-manager, or focus-stealing UX
> compatibility. A briefly loaded page may display already-authenticated stale
> details during an abort/create race, but it has no approve capability; a
> future approve route must recheck durable state and all authority immediately
> before signing. An internal popup substrate is not a deployable wallet.
>
> **Next load-bearing slice:** do not expose this raw launcher to provider
> traffic. Define one background request owner that ties the provider Port's
> AbortController to the existing strict coordinator and this launcher only
> after authoritative account/cluster/release/RPC resolution succeeds. Keep
> production unavailable while the release registry is empty; do not invent a
> deployment address or trusted RPC endpoint. The first executable contract
> must prove disconnect/open-failure/authority-change resolve only the exact
> durable request before any approve/sign route is considered.

> ## 2026-08-31 C10 HONEST REVIEW LIFETIME — LIVE EXPIRY AND EXACT TECHNICAL DISCLOSURE, SIGNING STILL IMPOSSIBLE
>
> Implementation commit `7149b727c75476f4919a957c4866d21bdf0f3a1b`
> closes two honesty gaps in the C9 review-only page without adding any
> authority. The strict page protocol now refuses `createdAt` or `expiresAt`
> outside JavaScript's renderable Date range, so an authenticated but
> unrenderable timestamp cannot throw after protocol acceptance. The page
> renders the absolute ISO instant in a native `<time>` element and a live
> countdown anchored to both wall time and `performance.now()`. A backward
> wall-clock jump cannot extend the displayed lifetime; a forward jump closes
> the page on the next tick or resume check. Expiry disables both controls,
> states exactly that no signature was produced, and disconnects the Port. The
> existing clock-aware durable owner then atomically resolves the pending row
> as expired. Real Chromium observes both the visible terminal state and the
> durable `expired` record.
>
> Timers are best-effort while Chrome freezes a page, so `visibilitychange`,
> `focus`, and `pageshow` each recheck the two deadlines before the page can be
> treated as actionable again. Port loss/navigation remains fail-closed. This
> does not make the page clock an authorization clock: the durable background
> repository remains authoritative, and a future signer must recheck the
> record, digest, authority, cluster, account, registry, and release at claim
> and immediately before signing.
>
> The page now exposes every already-projected technical fact behind a native,
> initially closed `<details>/<summary>` disclosure: session signer, session
> account, registry, Warden and Memo programs, genesis hash, recent blockhash,
> compute-unit limit, heap frame, serialized message length, and Memo length.
> Values still cross the Port only as strict frozen primitives and render only
> through `textContent`. The summary retains native keyboard semantics, has a
> 48 px CSS minimum target, and was opened with the Enter key in production
> Chromium. Keeping it collapsed is load-bearing: expanded technical content
> is intentionally exhaustive and makes the narrow mobile page very long.
>
> Two behavioral REDs preceded production code. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts approval-review.pw.ts` exited **1**,
> **2/2 failed**, because `#technical-details` and `#expiry-countdown` did not
> exist. `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/approval-protocol.test.ts` exited
> **1**, **1 failed / 13 passed**, because the protocol accepted timestamp
> `8640000000000001`, which `Date#toISOString` cannot render.
>
> Harsh verification also found defects in the new QA, not in the renderer.
> The first post-build browser run passed the expiry scenario but failed the
> display case because the hard-coded session-account oracle came from a
> different fixture. The next run exposed the same mistake for registry. Both
> were replaced with constants independently decoded from static account-key
> slots 2 and 5 in `GOLDEN_MESSAGE_HEX`; only then did the lane pass **2/2**.
> The first emitted-artifact command also exited **1** with a checker
> `ReferenceError` because it forgot to read `background.js`; the corrected
> executable check below passed. These failed harness attempts are not product
> evidence and no green claim is inherited from them.
>
> Current platform/accessibility behavior was checked against the official
> WCAG 2.2 target-size understanding, WHATWG native disclosure contract, and
> Chrome page-lifecycle guidance:
> <https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum>,
> <https://html.spec.whatwg.org/dev/interactive-elements.html>, and
> <https://developer.chrome.com/docs/web-platform/page-lifecycle-api>.
> Frozen tabs suspend freezable tasks, which is why the timer is explicitly
> described as best-effort and resume events force a deadline check. No
> independent second-model review ran; it remains **UNVERIFIED**.
>
> Exact-SHA evidence at `7149b727c75476f4919a957c4866d21bdf0f3a1b`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test` passed **283/283**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck` exited **0**; and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test:browser` rebuilt the production extension and passed **4/4** in real
> Chromium. The C10 lane proves exact technical values from the serialized
> fixture, native keyboard disclosure, a disclosure target at least 44 px high,
> no horizontal overflow at 720 px and 390 px after expansion, visible expiry,
> disabled terminal controls, and a durable `expired` row. It regenerates these
> ignored visual artifacts:
> `apps/extension/test-results/approval-review.pw.ts-appr-6458e--navigation-rejection-races/approval-review-collapsed-desktop.png`,
> `approval-review-desktop.png`, `approval-review-mobile.png`, and
> `apps/extension/test-results/approval-review.pw.ts-appr-56b23-inalizes-the-durable-record/approval-review-expired-mobile.png`.
>
> After that production build, this exact emitted-artifact command exited
> **0**:
>
> ```sh
> node -e "const fs=require('node:fs');const dir='apps/extension/dist';const names=fs.readdirSync(dir).sort();const required=['approval.css','approval.html','approval.js','background.js','content.js','manifest.json','popup.html','popup.js'];const missing=required.filter(name=>!names.includes(name));const approval=fs.readFileSync(dir+'/approval.js','utf8');const background=fs.readFileSync(dir+'/background.js','utf8');const html=fs.readFileSync(dir+'/approval.html','utf8');const pageForbidden=/claimForSigning|completeSigning|signApprovedSessionMessage|indexedDB|chrome\.storage|fetch\(|XMLHttpRequest|secretKey|privateKey/;const workerForbidden=/session approval coordinator:|createPinnedSessionApprovalCoordinator|resolveCommittedSessionRelease|sign approved session transaction/;const missingC10=['expiry-countdown','technical-details','session-account-value','recent-blockhash-value'].filter(value=>!html.includes(value));if(missing.length||missingC10.length||pageForbidden.test(approval)||workerForbidden.test(background)){console.error({missing,missingC10,pageForbidden:pageForbidden.test(approval),workerForbidden:workerForbidden.test(background)});process.exit(1)}console.log('C10 dist present; review has expiry/details and no storage, keyring, RPC, coordinator, or signer surface')"
> ```
>
> Immediately after the successful exact-SHA gate, `git rev-parse HEAD`
> returned `7149b727c75476f4919a957c4866d21bdf0f3a1b`, `git status --short`
> was empty, and `git diff --check` exited **0**.
>
> The ledger-inclusive C10 SHA
> `f6fcde93d66694ed8e5b6da9cc73489ff1d39aea` then passed the exact full
> command `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh`, exit **0**. It ran the complete pnpm workspace, core
> **698/698**, extension **283/283**, production Chromium **4/4**, the pinned
> Argon2 worker benchmark, core/extension builds and typechecks, fixture-drift
> and feature-resolution guards, and the complete Rust workspace. Afterward
> HEAD remained that exact SHA, `git status --short` was empty, and `git diff
> --check` exited **0**. This verdict belongs only to `f6fcde93…`.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`.
> C10 narrows only the review-lifetime and displayed-intent portions of those
> compound claims. Review-only UI is still not authority to sign.
>
> **Harsh residual:** there is still no successful provider request, launcher,
> approve/claim/sign route, production release entry, trusted production RPC,
> simulation, fee/balance/token consequence model, account/network switch
> binding, send/confirmation owner, result delivery, or onboarding. While a
> page is frozen its visual countdown cannot tick; only the resume check and
> durable owner enforce truth. The displayed projection does not refresh live
> authority or release state. Memo remains the only decoded verb. An honest,
> accessible rejection/expiry page is not a deployable wallet.
>
> **Next load-bearing slice:** keep approval and signing closed while defining
> the background-owned request-launch lifetime. A provider request must create
> one durable record and open exactly its extension URL without giving page or
> content-script input general tabs/windows authority; open failure, duplicate
> launch, navigation, worker death, timeout, and provider disconnect must each
> have one executable terminal outcome. Do not fabricate a production release
> entry or trusted RPC endpoint.

> ## 2026-08-31 C9 CLOSED APPROVAL REVIEW — EXACT-BYTE UI SHIPPED, APPROVAL/SIGNING STILL IMPOSSIBLE
>
> Implementation commit `65df16854c1ecfbb5e288091c6dc4d76bd10b700`
> adds the first extension-owned full-page approval document at the exact URL
> `/approval.html?request=req_<128-bit lowercase hex>`. Chrome-owned sender
> metadata independently derives the same request id and must prove this
> extension id/origin, exact URL serialization, document id, tab id, frame 0,
> and active-at-connect lifecycle. The payload id can only confirm that tuple;
> it cannot select a different record. One request and one document may own one
> Port, total pages are capped at 16, and malformed, duplicate, concurrent,
> out-of-order, extra-field, accessor, custom-prototype, or wrong-id traffic
> disconnects and fails closed.
>
> The route dependency surface contains exactly `read`, `reject`, and `cancel`.
> Its closed protocol contains exactly `approval:getReview` followed optionally
> by `approval:reject`; there is no approve, claim, keyring, signer, RPC,
> provider-success, creation, enumeration, or record-selection method. Review
> snapshots one clock-aware pending record and calls a new exact-byte core
> projector. That projector authenticates the stored digest, wraps the durable
> message in the unique unsigned one-signature envelope, reuses the strict
> Solana parser, and requires the exact lookup-free v0 header, seven-key
> ordering, compute-budget pair, canonical Warden program, execute indexes,
> inline account-less Memo program, and bounded printable-ASCII payload. Only
> frozen strings/numbers cross into the page; raw bytes and authority state do
> not.
>
> The page renders the durable origin, decoded Memo, canonical network, smart
> account, message SHA-256, policy version, expiry, and request id using
> `textContent`. The reject button is enabled only after a valid response. The
> would-be approve control is permanently disabled and explicitly says signing
> is unavailable. A one-way UI state machine rejects duplicate pending or
> unrelated responses. CSP/local-asset checks reject inline handlers, inline
> script, remote assets, external runtime imports, or any page dependency beyond
> `approval/main.ts` and `approval-protocol.ts`.
>
> Port/navigation loss attempts a durable cancellation after readiness.
> Explicit rejection performs its IndexedDB transition before acknowledgement.
> If reject and disconnect race, the existing transactional single-winner CAS
> decides `rejected` or `cancelled`; neither outcome can remain pending. Clean
> parent runtime disposal is deliberately different: because the application
> closes the repository synchronously, boundary disposal does not launch a late
> unawaited transition against a closed owner. It removes/disconnects every
> route immediately and leaves any abandoned pending row for mandatory
> next-start invalidation. A cancellation already queued in that same turn also
> stops before touching the closed owner.
>
> Behavioral REDs preceded the implementation. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-approval-review.test.ts` exited **1**, **6/6 failed**, because
> `decodeSessionApprovalReview` did not exist. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/approval-protocol.test.ts test/approval-port.test.ts
> test/sender-provenance.test.ts` exited **1** with both route modules missing
> and all 12 new approval-sender cases red while 42 incumbent provenance cases
> remained green. After production UI composition, the real Chromium command
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> exec playwright test -c playwright.config.ts approval-review.pw.ts` exited
> **1** with `net::ERR_FILE_NOT_FOUND` for the exact approval URL before
> `approval.html` existed.
>
> Harsh review then found defects after the first focused greens. The page
> would accept a second valid-looking pending response after initial render; it
> now has explicit awaiting-review/review-visible/awaiting-reject/terminal
> phases. A generic base58 regex accepted strings that did not decode to 32
> bytes; the protocol now checks exact decoded length. Proxy introspection could
> leak native exceptions instead of the closed protocol error. Re-awaiting the
> already-crossed readiness promise before rejection needlessly widened the
> reject/disconnect race. Finally, synchronous runtime disposal could schedule
> cancellation after owner close and report a false fatal. Each has a focused
> regression or an executable browser consequence.
>
> Current Chrome contracts were checked against the official Port messaging,
> MessageSender/runtime, and extension-worker lifecycle documentation:
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>, and
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
> Port disconnect is the browser-owned navigation/frame teardown signal;
> `documentLifecycle` is only a creation-time snapshot and is used only to
> reject, never to claim continued liveness. Worker globals are not continuity,
> so next-start durable invalidation remains mandatory. No independent
> second-model review ran; it remains **UNVERIFIED**.
>
> Exact-SHA evidence at `65df16854c1ecfbb5e288091c6dc4d76bd10b700`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-approval-review.test.ts test/session-intent.test.ts`
> passed **98/98**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/approval-protocol.test.ts
> test/approval-port.test.ts test/sender-provenance.test.ts
> test/manifest-storage.test.ts test/runtime.test.ts` passed **98/98**. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core typecheck`,
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build`,
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck`, and `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension build` each exited **0**.
>
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test:browser` rebuilt the production extension and passed **3/3** in real
> Chromium: durable IndexedDB single winners/worker death, the new review page,
> and provider frame/provenance/wake behavior. The review lane asserted
> `scrollWidth === clientWidth` at both 720×900 and 390×844, a card contained by
> the viewport, controls at least 44 px high, and stacked mobile actions without
> overlap. It captured
> `apps/extension/test-results/approval-review.pw.ts-appr-6458e--navigation-rejection-races/approval-review-desktop.png`
> and `approval-review-mobile.png`; these ignored artifacts are regenerated by
> the command. The same browser lane executes approval-channel forgery from the
> real isolated content-script world and observes a causal disconnect.
>
> After build, this exact emitted-artifact command exited **0**:
>
> ```sh
> node -e "const fs=require('node:fs');const dir='apps/extension/dist';const names=fs.readdirSync(dir).sort();const required=['approval.css','approval.html','approval.js','background.js','content.js','manifest.json','popup.html','popup.js'];const missing=required.filter(name=>!names.includes(name));const approval=fs.readFileSync(dir+'/approval.js','utf8');const background=fs.readFileSync(dir+'/background.js','utf8');const pageForbidden=/claimForSigning|completeSigning|signApprovedSessionMessage|indexedDB|chrome\.storage|fetch\(|XMLHttpRequest|secretKey|privateKey/;const workerForbidden=/session approval coordinator:|createPinnedSessionApprovalCoordinator|resolveCommittedSessionRelease|sign approved session transaction/;if(missing.length||pageForbidden.test(approval)||workerForbidden.test(background)){console.error({missing,pageForbidden:pageForbidden.test(approval),workerForbidden:workerForbidden.test(background)});process.exit(1)}console.log('C9 dist present; approval page has no storage, keyring, RPC, coordinator, or signer surface')"
> ```
>
> The build itself also enforces the stronger esbuild input graph: the worker
> must include the review projector/route and must exclude the coordinator,
> authority resolver, release registry, RPC owner, and signer. `git rev-parse
> HEAD` returned the exact implementation SHA, `git status --short` was empty,
> and `git diff --check` exited **0**. The ledger-inclusive C9 SHA
> `04c810a649a537d46e38e0898548c06287cb6ec7` then passed the exact full command
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit
> **0**. Afterward `git rev-parse HEAD` still returned that exact SHA, `git
> status --short` was empty, and `git diff --check` exited **0**.
>
> **No invariant status changes.** `WRD-EXT-01`, `WRD-EXT-02`, `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, and `WRD-TXI-01` remain `unimplemented`; their
> notes record the narrower partial boundary. Review-only UI is not authority
> to sign.
>
> **Harsh residual:** this page is not reachable from any successful provider
> request because the coordinator and provider success route remain excluded.
> The production release registry is empty. The UI displays only a subset of
> the projected technical fields, has no live expiry countdown, and does not
> refresh authority/registry/account/cluster state; the future signer must do
> that again. It has no simulation, fees, balance/consequence model, account or
> network switch binding, approve action, key use, send, confirmation, event,
> retry/replay delivery, or onboarding. Clean runtime disposal may leave an
> unreachable pending row until the next startup invalidates it. Memo is the
> only decoded verb. A polished rejection screen is not a deployable wallet.
>
> **Next load-bearing slice:** keep approval/signing closed and make the review
> lifetime honest while release/RPC authority is unresolved. Add live expiry
> terminalization and expose the already-projected program/session/compute facts
> behind an accessible technical-details section, with real Chromium clock,
> navigation, mobile, and screenshot measurements. Then define the background
> launcher/request-lifetime contract that can eventually open this exact page
> without giving an untrusted page a tabs/windows capability. Do not fabricate a
> production release entry or trusted RPC endpoint.

> ## 2026-08-31 C8 DURABLE SIGNING OUTCOME — ATOMIC RESULT OWNER SHIPPED, SIGNING ROUTE STILL CLOSED
>
> Implementation commit `0dc769aaf43554c69b59ff04b11b534d0b022fd6`
> replaces the ambiguous post-claim `approved` tombstone with a versioned
> durable signing outcome. One strict atomic IndexedDB envelope owns the exact
> approval plus one of `signing`, `signed`, or `failed`. Each attempt has a
> background-minted 128-bit CAS token, bounded u32 attempt number, start and
> resolution times, the approval digest, and either exact signed transaction
> bytes plus SHA-256 or one closed machine-readable failure code. Missing,
> extra, symbolic, accessor, custom-prototype, malformed, digest-tampered,
> impossible-state, stale-token, empty/oversized-transaction, unknown-failure,
> clock-regressed, and exhausted-counter inputs fail closed.
>
> Approval resolution and the first signing claim are one IndexedDB readwrite
> transaction. A failed attempt may retry with a fresh token before approval
> expiry. Completion/failure are CAS operations and idempotent only for the
> exact existing token/result. Pre-C8 pending and non-approved terminal records
> migrate on their next write; a legacy raw `approved` record is rejected and
> deleted because it cannot prove whether any signed bytes existed. Tombstone
> retention follows the latest signing resolution rather than the earlier
> human decision.
>
> The still-opt-in coordinator persists completion before releasing a
> signature, rereads after lost claim/completion/failure acknowledgements, and
> reparses plus Ed25519-verifies every durable replay against the exact approved
> message. A committed signed result replays without keyring, authority RPC, or
> the volatile capsule. Post-claim errors persist a closed failure and retain
> the capsule for a same-worker retry. Disposal during the completion await may
> leave a valid replayable result but returns only `DISPOSED` to the old worker.
> Transient approval/outcome reads no longer discard the sole capsule.
>
> Shipped MV3 startup now cancels pending approvals and changes unresolved
> `signing` attempts to `failed/worker-restarted`; completed signed bytes survive
> an actual forced worker stop/wake. A regressed startup clock preserves the CAS
> record and keeps readiness failed instead of deleting evidence. The emitted
> worker owns only this persistence boundary. Recursive artifact scanning proves
> that the coordinator, session signer, C6 composition, C7 resolver, and success
> state remain absent; every provider request is still unavailable.
>
> Behavioral REDs preceded and sharpened C8. The new outcome suite first exited
> **1** before collection because the module did not exist. The extension-owner
> unit suite then had **2 passed / 2 failed** before completion/failure methods
> existed, and the coordinator had **24 passed / 13 failed** before attempt
> ownership was wired through. The full browser lane later failed **1/2**
> because its provider-restart assertion still measured the pre-C8 top-level
> record shape; the corrected lane reads the atomic envelope while retaining
> legacy compatibility. This was a QA measurement defect, not a product pass.
>
> Harsh review found further load-bearing bugs. Disposal could release bytes
> after durable completion; transient reads could erase retry authority; invalid
> transaction/failure inputs and time regressions could reach a broad malformed-
> record catch and delete valid CAS state; startup rollback could delete an
> unresolved attempt; and legacy approved records had no executable browser
> measurement. Each now has a regression. Two final genuine REDs were captured:
> the focused coordinator suite was **41 passed / 1 failed** because a committed
> failure whose acknowledgement was lost discarded its capsule; recovery reread
> now makes it **43/43**, including lost claim/completion/failure acknowledgements.
> The real Chromium lane received `ApprovalRecordFormatError` instead of the
> expected `ApprovalStateConflictError` for an expired wrong-digest claim and
> deleted the record; expiry/clock ordering now preserves `expired` and the lane
> is green.
>
> Research used the current IndexedDB 3.0 transaction/durability contract,
> Chrome extension service-worker lifecycle guidance, and RFC 8032:
> <https://www.w3.org/TR/IndexedDB/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> and <https://www.rfc-editor.org/info/rfc8032/>. IndexedDB readwrite completion
> is the atomic logical commit and overlapping scopes serialize, but `strict`
> durability is only a hint: it does not prove survival across browser/OS/device
> rollback. Chrome explicitly discards worker globals, motivating durable result
> ownership. Ed25519 deterministically signs one key/message, so exact retry does
> not require fresh signature randomness. Independent second-model review is
> **UNVERIFIED**: `codex review --uncommitted` exited **1** because its in-process
> app-server client could not initialize on this host's read-only path.
>
> Exact-SHA evidence at `0dc769aaf43554c69b59ff04b11b534d0b022fd6`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/approval-signing-outcome.test.ts
> test/session-approval-coordinator.test.ts
> test/session-authority-resolver.test.ts test/session-rpc.test.ts
> test/session-release.test.ts` passed **120/120**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test`
> passed **686/686**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core typecheck` and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core build` exited **0**. From `packages/core`, `node
> --input-type=module -e "const m=await import('@warden/core/approval');for(const
> name of ['createApprovalSigningAttempt','completeApprovalSigningAttempt','failApprovalSigningAttempt','retryApprovalSigningAttempt','snapshotApprovalSigningRecord'])if(typeof
> m[name]!=='function')process.exit(1);console.log('approval subpath resolves
> durable signing outcomes')"` exited **0**.
>
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test` passed **247/247**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension typecheck` and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
> exited **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test:browser` passed the real Chromium lane **2/2**. After
> build, this exact shipped-artifact command exited **0**:
>
> ```sh
> node -e "const fs=require('node:fs'),path=require('node:path');const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const files=walk('apps/extension/dist');const background=fs.readFileSync('apps/extension/dist/background.js','utf8');const required=['approval signing outcome:','worker-restarted','transactionDigest does not authenticate transactionBytes'];const missing=required.filter(s=>!background.includes(s));const forbidden=/SessionApprovalCoordinator|session approval coordinator:|sign approved session transaction|signApprovedSessionMessage|createPinnedSessionApprovalCoordinator|resolveCommittedSessionRelease|APPROVAL_SIGNING_IN_PROGRESS/;const hit=files.find(f=>forbidden.test(fs.readFileSync(f,'utf8')));if(missing.length||hit){console.error({missing,hit});process.exit(1)}console.log('extension dist owns C8 outcomes; coordinator/release routes remain isolated')"
> ```
>
> `git rev-parse HEAD` still returned the exact implementation SHA, `git status
> --short` was empty, and `git diff --check` exited **0**. The ledger-inclusive
> C8 SHA `47718d7fca3e2d41e18a3d59d4cc35f1e02bb1e5` then passed the exact full command
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit
> **0**. Afterward, `git rev-parse HEAD` returned that exact SHA, `git status
> --short` was empty, and `git diff --check` exited **0**.
>
> **No invariant status changes.** `WRD-APR-01`, `WRD-APR-02`, and
> `WRD-APR-03` remain `unimplemented`; their notes are refreshed with this
> partial boundary. `WRD-TXI-01` and `WRD-KEY-04` also remain `unimplemented`.
>
> **Harsh residual:** atomic commit is not physical durability. Profile
> corruption, storage eviction, OS/device rollback, and a compromised extension
> origin remain out of scope. Signed bytes survive normal worker death; failed
> and orphaned attempts lose their volatile authority capsule across death and
> therefore report a closed failure rather than retrying. The production release
> registry is empty, the coordinator/signer remain unshipped, and no provider
> method succeeds. There is no extension-owned approval page, exact-byte intent
> render, navigation/Port teardown composition, account/network-change binding,
> success/event protocol, simulation/fee display, sender, confirmation owner, or
> replay delivery route. Memo remains the only decoded verb. C8 removes the
> tombstone ambiguity but is not a deployable wallet.
>
> **Next load-bearing slice:** build the extension-owned full-page approval
> surface and its browser-proven UI route around the durable record. It must
> render only locally decoded intent derived from the exact stored bytes, bind
> one request to exact UI provenance and Port/navigation/account/cluster
> lifetime, and make cancellation races executable in real Chromium. Keep the
> provider success path and coordinator import closed while the committed
> release registry is empty; UI presence is not authority to sign.

> ## 2026-08-31 C7 COMMITTED RELEASE STATEMENT — PROVENANCE SHAPE CLOSED, PRODUCTION REGISTRY EMPTY
>
> Implementation commit `54bc05dc5adbbbd9b9a37f08cdf405b5fd66c4fa`
> adds the still-opt-in `@warden/core/transaction/session-release` boundary.
> It parses one exact in-toto Statement v1-shaped record with exactly two
> ordered immutable subjects: the release `target/deploy/warden.so` SHA-256 and
> the full raw canonical ProgramData-account SHA-256. Its v1 predicate pins the
> full release commit, committed deploy-manifest name and digest, chain,
> canonical genesis, literal shipped Warden program, canonical loader-v3
> ProgramData PDA, deployment slot, governed upgrade authority, and exact
> allocation. Missing, extra, inherited/custom-prototype, symbolic, sparse,
> future-versioned, noncanonical, zero, reordered, public-genesis-aliased
> localnet, or out-of-range data fails closed. Every hostile field is read once
> into immutable primitive state before later getters can mutate earlier input.
>
> `sessionReleaseStatementDigest` reconstructs one fixed-order canonical JSON
> form and hashes it with SHA-256. Independent hard-coded goldens pin the shipped
> ProgramData PDA, Squads vault PDA, fixture deploy-manifest digest, and complete
> statement digest. The canonical `RELEASE-INTEGRITY.md` parser now carries the
> exact release SHA plus an optional leading-value-only dedicated token
> `session-release:<name>@<digest>`; duplicate tokens reject. The real dev seed
> row has no token and parses as unbound. `bindSessionReleaseStatement` then
> requires exact agreement among the statement, unique release row, complete
> copy-owned deploy pin, row artifact/code hash, deploy-manifest content digest,
> public genesis, literal program, and Squads-vault-derived upgrade authority
> before it creates the C6 pin object.
>
> The only runtime selection map is a private frozen null-prototype registry.
> It is deliberately **empty**: `COMMITTED_SESSION_RELEASE_NAMES` is `[]`, and
> `mainnet-r1`, `__proto__`, `constructor`, and `toString` all refuse as unknown.
> A future entry must source-own both its exact statement and canonical release
> table row. Runtime callers may supply only the committed release name; an
> earlier design that accepted caller-provided release Markdown was rejected in
> review because it could falsely make an omitted repository row look present.
> `assertCommittedSessionReleaseDocumentBinding` is a separate release-gate
> drift assertion and cannot inject runtime pins. With today's empty registry,
> `createCommittedSessionApprovalCoordinator` refuses after one release-name
> read and before integrity text, Connection, signer, approval-owner, or keyring
> access. The incumbent deploy manifest map and synthetic pin/member arrays are
> now frozen and null-prototype/own-key resolved, closing prototype-name lookup
> aliases without adding a production manifest. The extension imports none of
> C7 and remains unable to sign.
>
> Behavioral REDs preceded and hardened this boundary. First, `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-release.test.ts` exited **1** before collection because the
> module did not exist. Harsh schema review then made `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-release.test.ts test/deploy-cli.test.ts` exit **1**, **44
> passed / 2 failed**: an array with a hidden own `reviewed` property was
> accepted and a dedicated release cell with two valid tokens silently selected
> the first. Exact array shapes and duplicate refusal close both. Removing
> caller-chosen release Markdown made the focused session-release command exit
> **1**, **31 passed / 1 failed** on its two-argument resolver; source-embedded
> rows reduced the runtime resolver to one argument. A final identity pass made
> the same command exit **1**, **32 passed / 2 failed**: custom-prototype
> statements and `solana:localnet` carrying devnet genesis were accepted. Plain
> prototype enforcement and public-genesis alias refusal close them. Review
> also found that the authority-drift test was actually dying earlier on stale
> statement digest; it now recomputes the row and asserts the specific upgrade-
> authority refusal. The deploy-source attestation correctly went red **19
> passed / 1 failed** after the three verifier-closure edits; `node
> scripts/gen-verifier-attestation.mjs` rediscovered and re-pinned all seven
> files, after which the attestation suite passed **20/20**.
>
> The format and its limits were researched against the current approved SLSA
> v1.2 provenance specification, in-toto Statement v1 and envelope/DSSE
> specifications, Sigstore verification guidance, and GitHub artifact-
> attestation guidance:
> <https://slsa.dev/spec/v1.2/provenance>,
> <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>,
> <https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md>,
> <https://docs.sigstore.dev/cosign/verifying/verify/>, and
> <https://docs.github.com/en/actions/concepts/security/artifact-attestations>.
> The committed record is explicitly **unsigned**. Git review authenticates the
> source entry today; it is not DSSE/Sigstore authentication, builder identity,
> SLSA provenance, an audit, or evidence that the bytes are safe. Independent
> second-model review remains **UNVERIFIED**: `codex review --uncommitted`
> exited **1** because its in-process app-server client could not initialize on
> this host's read-only path.
>
> Exact-SHA evidence at `54bc05dc5adbbbd9b9a37f08cdf405b5fd66c4fa`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-release.test.ts test/deploy-cli.test.ts
> test/deploy-attestation.test.ts test/session-rpc.test.ts
> test/session-authority-resolver.test.ts` passed **106/106**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test`
> passed **675/675**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core typecheck` and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core build` exited **0**. From `packages/core`, `node
> --input-type=module -e "const
> m=await import('@warden/core/transaction/session-release');if(typeof
> m.parseSessionReleaseStatement!=='function'||typeof
> m.resolveCommittedSessionRelease!=='function'||typeof
> m.createCommittedSessionApprovalCoordinator!=='function'||m.COMMITTED_SESSION_RELEASE_NAMES.length!==0)process.exit(1);console.log('session-release
> subpath resolves; committed releases: 0')"` exited **0**. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
> passed **246/246**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension typecheck` and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
> exited **0**. After build, the following exact command exited **0** with no
> match:
>
> ```sh
> node -e "const fs=require('node:fs'),path=require('node:path');const re=/session-release|SessionReleaseError|parseSessionReleaseStatement|resolveCommittedSessionRelease|createCommittedSessionApprovalCoordinator|SESSION_RELEASE_PREDICATE_TYPE|session release:/;const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const hit=walk('apps/extension/dist').find(f=>re.test(fs.readFileSync(f,'utf8')));if(hit){console.error(hit);process.exit(1)}console.log('extension dist release-boundary isolation: no matches')"
> ```
>
> `git rev-parse HEAD` still returned the
> exact implementation SHA, `git status --short` was empty, and `git diff
> --check` exited **0**. The ledger-inclusive C7 SHA
> `7431865ae749aa04c81c5e58928d60f8f2b5254c` then passed the exact full command
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit
> **0**. Afterward, `git rev-parse HEAD` returned that exact SHA, `git status
> --short` was empty, and `git diff --check` exited **0**.
>
> **No invariant status changes.** `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
> `WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`, so
> `docs/security/invariants.jsonl` is intentionally unchanged.
>
> **Harsh residual:** the production release registry and production deploy
> manifest are empty/absent by design, so C7 enables no chain. No DSSE/Sigstore
> signature, certificate identity policy, transparency-log proof, SLSA builder
> provenance, independently reproduced artifact, real ProgramData readback, or
> audited release exists. Git review can bind a future source record but cannot
> prove the builder or deployment RPC was honest. The trusted Connection remains
> unspecified and non-atomic; one malicious endpoint can lie consistently, and
> a governed upgrade can land after the last observation. There is still no
> approval render, successful provider route, simulation/fee surface, sender,
> confirmation owner, durable signed-result/replay recovery, or token
> consequence model. Memo remains the only decoded verb. This closes the
> release-pin injection seam without making the wallet deployable.
>
> **Next load-bearing slice:** replace the coordinator's post-claim `approved`
> tombstone with a durable signed-result/failure ownership boundary that can
> safely replay a completed result or recover a failed signing attempt. Keep it
> still unreachable from the provider until an approval surface and a real
> committed release exist; do not weaken the empty-registry refusal.

> ## 2026-08-31 C6 CHAIN-BOUND BLOCKHASH RPC — REAL COMPOSITION CLOSED, RELEASE PROVENANCE ABSENT
>
> Implementation commit `933245dac0c95c2deb6bdfda72666aeb56528cc5`
> adds the still-opt-in `@warden/core/transaction/session-rpc` boundary. The
> `ConnectionSessionApprovalBlockhashClient` is permanently bound to one
> supported chain and exact genesis pin, accepts only `confirmed` commitment,
> copy-owns every byte input, and uses only contextual
> `getLatestBlockhashAndContext` and `isBlockhashValid` calls with the exact
> non-regressing `minContextSlot`. It rechecks `getGenesisHash` immediately
> before every blockhash operation. Public chains require the canonical
> mainnet/devnet/testnet genesis; localnet requires an explicit nonzero pin.
> Malformed, zero, noncanonical, cross-chain, cross-genesis, unsafe-height, and
> regressed-context inputs or responses fail closed. There is no retry,
> endpoint selection, approved-hash refresh, send, or confirmation behavior.
>
> `createPinnedSessionApprovalCoordinator` is the smallest real composition
> seam: it requires one explicit trusted Connection, an exact release pin set,
> the current session signer, approval owner, and contextual keyring. It
> installs the real six-account authority resolver, contextual blockhash
> client, deterministic Memo-only intent gate, approval coordinator, and
> exact-byte signer. Connection, approval-owner, keyring, resolver, blockhash,
> and intent capabilities are captured and exposed internally only through
> frozen bound facades. Mutable release arrays and PublicKeys are copied before
> use. A full integration signs the exact 394-byte transaction while later
> mutations of every supplied capability, release array, and the exported
> blockhash/intent class prototypes are made hostile. The six authority reads
> remain `[0, 52, 52, 52, 62, 62]`; the latest request is exactly
> `{commitment: "confirmed", minContextSlot: 42}`, validity is exactly the
> approved blockhash at slot 52, and the Connection sees eight genesis checks.
>
> Three behavioral REDs preceded the final boundary. First, `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-rpc.test.ts` exited **1** before collection because
> `session-rpc.js` did not exist. Harsh getter review then made the same command
> exit **1**, **17 passed / 2 failed**: later config/request getters could replace
> earlier Connection references, and a response value getter could mutate the
> context object before its slot was copied. Finally, after adding prototype
> mutation to the real integration, `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-rpc.test.ts test/session-authority-resolver.test.ts` exited
> **1**, **37 passed / 1 failed**, because the coordinator dynamically followed
> the replaced internal latest-blockhash method. Sequential snapshots and
> immutable bound capability facades close all three failures.
>
> Primary contracts were checked against Solana's latest-blockhash,
> blockhash-validity, and genesis RPC documentation and the pinned web3.js v1
> Connection API/source:
> <https://solana.com/docs/rpc/http/getlatestblockhash>,
> <https://solana.com/docs/rpc/http/isblockhashvalid>,
> <https://solana.com/docs/rpc/http/getgenesishash>, and
> <https://solana-foundation.github.io/solana-web3.js/v1.x/classes/Connection.html>.
> The lockfile resolves `@solana/web3.js` to `1.98.4`; its local implementation
> confirms that `getLatestBlockhash()` drops `context`, while
> `getLatestBlockhashAndContext()` and `isBlockhashValid()` preserve and forward
> the contextual config. Independent second-model review remains
> **UNVERIFIED**: `codex review --uncommitted` exited **1** because its
> in-process app-server client could not initialize on this read-only host.
>
> Exact-SHA evidence at `933245dac0c95c2deb6bdfda72666aeb56528cc5`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-rpc.test.ts test/session-authority-resolver.test.ts
> test/session-intent.test.ts test/session-approval-coordinator.test.ts` passed
> **161/161**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core test` passed **640/640**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core typecheck`
> and `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core
> build` exited **0**. From `packages/core`, `node --input-type=module -e
> "const module = await import('@warden/core/transaction/session-rpc'); if
> (typeof module.ConnectionSessionApprovalBlockhashClient !== 'function' ||
> typeof module.createPinnedSessionApprovalCoordinator !== 'function')
> process.exit(1); console.log('session-rpc subpath resolves')"` exited **0**.
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test` passed **246/246**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension typecheck` and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
> exited **0**. After build, `node -e "const fs=require('node:fs');const
> path=require('node:path');const
> pattern=/ConnectionSessionApprovalBlockhashClient|createPinnedSessionApprovalCoordinator|SessionApprovalRpcError|session-rpc|session
> approval RPC|endpoint genesis
> changed|PinnedSessionAuthorityResolver|ConnectionSessionAuthorityRpc|SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES/;const
> walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const
> hit=walk('apps/extension/dist').find(f=>pattern.test(fs.readFileSync(f,'utf8')));if(hit){console.error(hit);process.exit(1)}console.log('extension
> dist session substrate isolation: no matches')"` exited **0** with no match.
> `git
> rev-parse HEAD` still returned the exact implementation SHA, `git status
> --short` was empty, and `git diff --check` exited **0**. The preceding
> ledger-inclusive C5 SHA `7ce245336f5ed1e7d89a927c0872a37adc8d716d`
> passed `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh`, exit **0**. The full gate for this new
> ledger-inclusive boundary is pending; do not transfer the preceding verdict.
>
> **No invariant status changes.** `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
> `WRD-TXI-01`, and `WRD-KEY-04` remain `unimplemented`, so
> `docs/security/invariants.jsonl` is intentionally unchanged.
>
> **Harsh residual:** this factory validates the shape and exact equality of
> pins; it cannot prove that a human reviewed their provenance. No committed
> production release pin set or trusted-RPC owner supplies it. Genesis and
> contextual data are separate calls, so even an honest load-balanced endpoint
> is not atomically bound; a malicious trusted endpoint can lie consistently.
> Six full ProgramData reads and eight genesis calls per successful approval are
> an availability cost. A governed upgrade, authority change, or blockhash
> expiry can still occur after the last observation. Post-claim failure still
> leaves the existing `approved` tombstone without a durable signed result.
> There is no approval page, successful provider route, sender, simulation,
> fee presentation, confirmation owner, replay, or recovery. Memo remains the
> only decoded verb. The shipped extension imports none of this substrate and
> remains intentionally unable to sign.
>
> **Next load-bearing slice:** research and build a repository-owned,
> schema-validated release-pin registry/loader that can supply C6 only from an
> exact reviewed manifest binding chain, genesis, Warden program/ProgramData,
> upgrade authority, deployment slot, allocation, raw hash, and code hash.
> Do not invent production pins: make their absence executable and preserve
> provider closure until a real release candidate has independently reviewed
> provenance.

> ## 2026-08-31 C5 PINNED AUTHORITY SNAPSHOT — RPC/PROGRAM/TIME RESOLUTION CLOSED, RUNTIME COMPOSITION ABSENT
>
> Implementation commit `5edb932503fdeebb72c029eba49c5f79653599fc`
> adds the still-opt-in `@warden/core/transaction/session-authority` boundary
> and composes it through the real intent gate and approval coordinator. One
> authority observation is exactly one ordered six-account
> `getMultipleAccountsInfoAndContext` request at `confirmed` commitment and a
> caller-supplied non-regressing `minContextSlot`: SmartAccount, SessionKey,
> Registry, the literal shipped Warden Program, its canonical ProgramData PDA,
> and the Clock sysvar. Missing, extra, malformed, wrong-owner, wrong-size, or
> wrong-executable accounts fail closed before an authority packet is emitted.
>
> The resolver binds an explicitly trusted RPC capability at construction,
> checks the RPC genesis hash against a pinned mainnet/devnet/testnet/localnet
> mapping, and copy-owns bounded hostile responses. It pins the Warden program
> id, upgradeable-loader Program state, canonical ProgramData address, governed
> upgrade authority, deployment slot, exact ProgramData allocation, full raw
> ProgramData SHA-256, and executable-code SHA-256. It independently validates
> the three Warden state accounts and encodes their exact bytes into the
> authorization packet. The Clock account must be canonical, 40 bytes,
> sysvar-owned, non-executable, and from the same response context; its slot
> must equal the response context and its Unix time must be safe. Session
> validity is evaluated at observed Clock time plus 30 seconds, never browser
> wall time.
>
> Every resolver, configuration, response, account, and byte-array boundary is
> single-read/copy-owned. The coordinator now binds ProgramData address, slot,
> authority, code hash, raw hash, allocation, and observed Clock in every
> capsule comparison. Clock observations are compared between each immediately
> consecutive authority read: forward time is allowed and any regression is
> rejected. The approval render exposes the same program identity and
> cluster-observed time. A production integration contract drives the real
> resolver, Memo-only decoder, coordinator, and exact-byte signer; the six
> authority reads use exact minimum contexts `[0, 52, 52, 52, 62, 62]`.
>
> The initial focused test was genuinely red: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-authority-resolver.test.ts` exited **1** before collection
> because the resolver module did not exist. Harsh review then produced a
> second real red at the implementation boundary: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-authority-resolver.test.ts
> test/session-approval-coordinator.test.ts` exited **1**, **53 passed / 2
> failed**. The adapter followed a post-construction mutation of the supplied
> Connection method, and the coordinator accepted Clock regression from a
> newer intermediate observation when the value remained above the original
> capsule. Both defects are now regression-tested and closed. Review also
> replaced a guessed ProgramData PDA with an official derivation/literal pin,
> replaced circular fixture hash expectations with independent Node/OpenSSL
> goldens, made extension isolation recursive and executable, asserted exact
> request counts, corrected the signed-transaction byte count, and bounded
> account data before copying. Independent second-model review remains
> **UNVERIFIED** because `codex review --uncommitted` could not initialize its
> in-process app-server client on this read-only host.
>
> Primary contracts are Solana's ordered/contextual `getMultipleAccounts` and
> genesis-hash RPC documentation, the Clock ABI, the upgradeable-loader v3
> Program/ProgramData layout, and Solana's public genesis constants:
> <https://solana.com/docs/rpc/http/getmultipleaccounts>,
> <https://solana.com/docs/rpc/http/getgenesishash>,
> <https://docs.rs/solana-clock/latest/solana_clock/struct.Clock.html>,
> <https://docs.rs/solana-loader-v3-interface/latest/solana_loader_v3_interface/state/enum.UpgradeableLoaderState.html>,
> and
> <https://github.com/solana-labs/solana/blob/master/sdk/src/genesis_config.rs>.
> Clock monotonicity is a versioned Agave compatibility assumption, not a
> universal protocol promise. It was audited at exact upstream commit
> `a4144392c8ffd8d0840e312ecc3a59d35533c005`: Tower floors timestamp against
> its ancestor, while Alpenglow requires the nanosecond footer time to exceed
> its parent before writing the seconds field:
> <https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/bank.rs#L2405-L2460>,
> <https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/bank.rs#L3333-L3368>,
> and
> <https://github.com/anza-xyz/agave/blob/a4144392c8ffd8d0840e312ecc3a59d35533c005/runtime/src/block_component_processor.rs#L653-L713>.
>
> Exact-SHA evidence at `5edb932503fdeebb72c029eba49c5f79653599fc`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-authority-resolver.test.ts test/session-intent.test.ts
> test/session-approval-coordinator.test.ts` passed **141/141**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test`
> passed **620/620**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core typecheck` and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core build` exited **0**. From `packages/core`, `node
> --input-type=module -e "const module = await
> import('@warden/core/transaction/session-authority'); if (typeof
> module.PinnedSessionAuthorityResolver !== 'function' || typeof
> module.ConnectionSessionAuthorityRpc !== 'function') process.exit(1);
> console.log('session-authority subpath resolves')"` exited **0**. `cargo test
> -p warden client_authority_resolver --lib` passed **3/3**. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
> passed **246/246**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension typecheck` and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
> exited **0**. After build, `node -e "const fs=require('node:fs');const path=require('node:path');const pattern=/PinnedSessionAuthorityResolver|ConnectionSessionAuthorityRpc|SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES|session authority resolver|session-authority/;const walk=d=>fs.readdirSync(d,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(d,e.name)):[path.join(d,e.name)]);const hit=walk('apps/extension/dist').find(f=>pattern.test(fs.readFileSync(f,'utf8')));if(hit){console.error(hit);process.exit(1)}console.log('extension dist resolver isolation: no matches')"`
> exited **0** with no matches. The
> preceding ledger-inclusive C4 SHA
> `01d6694da877b33022c02cc48c6815f38d2d35b5` passed `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
> The full gate for this new ledger-inclusive boundary is pending; do not
> transfer the preceding verdict.
>
> **No invariant status changes.** Do not promote `WRD-APR-01`,
> `WRD-APR-02`, `WRD-APR-03`, `WRD-TXI-01`, or `WRD-KEY-04`; therefore
> `docs/security/invariants.jsonl` is intentionally unchanged. The RPC endpoint
> remains an explicit trust terminus: a genesis check detects the wrong honest
> cluster, not a malicious server. Full ProgramData allocation is fetched six
> times per approval, imposing a real bandwidth/memory/availability cost.
> Program identity is rechecked through final signing, but a governed upgrade
> can still occur after signature and before landing. `solana-verify`
> trailing-zero code-hash parity is release-candidate **UNVERIFIED**; the full
> raw hash disambiguates bytes only if its pin comes from a reviewed release
> manifest. Loader/Clock layouts and Agave time monotonicity require explicit
> client-upgrade review.
>
> This remains runtime-unreachable. There is no trusted-RPC owner, reviewed
> release-pin manifest, real blockhash Connection adapter, provider/UI route,
> approval render, sender, confirmation owner, or durable replay. The extension
> deliberately imports none of the resolver. No live security product is
> deployable yet.
>
> **Next load-bearing slice:** research and implement a still-unreachable,
> chain-bound blockhash RPC adapter plus the smallest composition/config seam
> that can be constructed only from reviewed release pins and an explicitly
> trusted Connection. Re-audit the existing `SessionApprovalBlockhashClient`
> contract before coding, preserve provider closure, and do not claim a
> no-blind-sign invariant or add token semantics.

> ## 2026-08-31 C4 DETERMINISTIC MEMO INTENT — ONE SAFE VERB CLOSED, RUNTIME AUTHORITY STILL ABSENT
>
> Implementation commit `fa71bf3aef0269a73bb1881b29ba1a69ed932993`
> adds the separate opt-in `@warden/core/transaction/session-intent` boundary.
> The first contract was genuinely red: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-intent.test.ts` exited **1** before collection because
> `../src/transaction/session-intent.js` did not exist. A later hostile-getter
> regression was also red under that command: **83 passed / 2 failed**, exit
> **1**, because repeated property reads let bounded validation and subsequent
> copying observe different `messageBytes`/`authorizationState` arrays.
>
> The decoder returns a benign verdict for exactly one consequence: one
> account-less, 1–256-byte printable-ASCII Memo CPI. It accepts only an exact
> lookup-free v0 message with the session signer as its sole writable signer,
> seven canonical static keys, a nonzero blockhash, one SetComputeUnitLimit in
> the measured 120,000–1,400,000 range, one exact 128-KiB heap request, and one
> final Warden `execute`. The execute account indices, literal shipped Warden
> program id/discriminator, `root=None`, `payload=Some`, Borsh vector length,
> one inner instruction, logical Memo-program index, zero inner accounts, and
> end-of-input are all exact. Price/data-size/unknown/duplicate/reordered budget
> instructions, root/staged variants, lookups, extra instructions, aliases,
> account-role drift, unknown programs, multiple payloads, and non-printable or
> oversized Memo data fail closed. The result is a frozen primitive-only render
> object; it exposes no mutable byte alias.
>
> The resolver-state packet is fixed-width and versioned (`WRDAUTH` + v1) and
> copy-owns the owner, executable flag, and exact raw data of SmartAccount,
> SessionKey, and Registry. The decoder requires exact canonical lengths,
> owners, non-executable containers, account discriminators/versions, highest
> valid PDA bumps, SmartAccount cluster tag/Registry/generation/policy, a fully
> unfrozen state, policy version 1 with only known session-op bits and execute
> enabled, SessionKey identity/signer/generation/expiry/execute/list, canonical
> reserved bytes, and a structurally canonical Registry whose selected list
> contains exactly one tagless/no-role Memo entry. It pins the shipped Warden
> program literal rather than letting the resolver redefine the executable.
> Single-read snapshots close hostile-getter allocation/TOCTOU behavior at the
> public decoder boundary.
>
> The golden lookup-free v0 message is hand-pinned at 333 bytes. A production
> integration contract now constructs a SmartAccount-paid source Memo through
> `prepareSessionTransaction` and proves that the resulting final approval
> bytes equal that golden and decode successfully. Rust tests independently pin
> the exact SmartAccount, SessionKey, Registry, and `execute` discriminators and
> every client-consumed account offset/Borsh field. This prevents a same-size
> Rust layout reorder or Anchor discriminator drift from becoming a silent
> browser decoder bug.
>
> Primary-source research deliberately stopped this first decoder short of SPL
> Token. Solana's transaction format and Agave's ComputeBudget parser establish
> the outer shape; the Memo repository/IDL establishes its tagless account-less
> instruction; and the SPL Token instruction source establishes why program
> bytes alone cannot identify a transfer's actual mint, token-account owner,
> balance, or destination consequence. Sources:
> <https://solana.com/docs/core/transactions>,
> <https://github.com/anza-xyz/agave/blob/master/compute-budget-instruction/src/compute_budget_instruction_details.rs>,
> <https://github.com/solana-program/memo>,
> <https://github.com/solana-program/memo/blob/main/idl.json>, and
> <https://github.com/solana-program/token/blob/main/interface/src/instruction.rs>.
> A token verdict before a message-keyed account-state resolver exists would be
> blind-signing with nicer labels, so it remains blocked.
>
> Harsh review found and corrected load-bearing defects before the commit. The
> first account parser confused SmartAccount `root_nonce` at absolute offset
> 536 with freeze state and failed to inspect `frozen_at` at 552; the fixture now
> carries a used nonzero root nonce and Rust pins both offsets. The first PDA
> helper proved only that *a* supplied bump derived the address while calling it
> canonical; it now recomputes Anchor's highest valid bump, with an alternate
> valid-bump mutation that the old logic accepted. Earlier cuts also let a
> resolver self-consistently redefine the Warden program, accepted a matching
> future policy version, and copied byte inputs before their exact bounds were
> established. All were narrowed. No independent second-model review occurred;
> it remains **UNVERIFIED**.
>
> Exact-SHA evidence at `fa71bf3aef0269a73bb1881b29ba1a69ed932993`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-intent.test.ts` → **85/85**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **593/593**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core run typecheck` and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core run build`
> both exited **0**; `cargo test -p warden client_intent_decoder --lib` →
> **4/4**, exit **0**. The preceding ledger-inclusive coordinator SHA
> `f7232e1ddebc59df259875566397099023a23345` passed `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
> The full gate for this new ledger-inclusive boundary is pending; do not
> transfer the preceding verdict.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
> `WRD-TXI-01`, or `WRD-KEY-04`.** This is a narrow deterministic decoder, not
> the compound no-blind-sign product. No extension source imports it. There is
> no real resolver/RPC client, program-binary or ProgramData attestation,
> public-chain genesis-label mapping, cluster-authenticated time, approval UI,
> provider route, simulation, sender, confirmation owner, or durable replay.
> The fixed authority packet intentionally omits lamports/rent epoch because
> they do not authorize these three state accounts, but a real resolver must
> still reject absent/malformed accounts and obtain all three from one
> non-regressing authoritative context. Registry bytes are exact-compared but
> the decoder attests only the selected Memo rule; the deploy gate remains the
> complete-config control. A locally injected wall clock can be stale. A
> counterfeit/upgraded program at the pinned address is outside this packet.
> The module is 1,095 lines for one low-utility verb and is runtime-unreachable;
> compatibility and user value remain poor even though the byte contract is
> strong.
>
> **Next load-bearing slice:** implement a still-unreachable, fail-closed
> authority/RPC resolver that obtains SmartAccount, SessionKey, Registry, Warden
> Program/ProgramData identity, genesis, and a conservative time observation at
> fixed commitment/non-regressing context; emits this canonical packet; and is
> exercised through the real coordinator. First research the upgradeable-loader
> account contract and RPC snapshot guarantees. Keep every provider route
> closed. Do not add token semantics until the resolver also returns the exact
> transaction-referenced account state needed to identify mint/owner/balance/
> destination consequences.

> ## 2026-08-31 C3 SESSION-APPROVAL COORDINATOR — ORDERING CLOSED, REAL AUTHORITIES STILL ABSENT
>
> Implementation commit `cafced9c2f4725e0a95afc792fd0290acc01d28b`
> adds a separate opt-in `@warden/core/transaction/session-approval` domain.
> The focused contract was genuinely red first: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/session-approval-coordinator.test.ts` exited **1** before collection
> because `session-approval-coordinator.js` did not exist.
>
> The still-unreachable coordinator accepts structural authority-resolver,
> blockhash-RPC, synchronous local-intent, transactional approval-owner, and
> contextual keyring dependencies. It supports only `solana:signTransaction`;
> sign-and-send is rejected before authority or RPC work because durable send
> result ownership does not exist. Preparation copy-owns browser provenance and
> source bytes, resolves account/chain/genesis/program/session/registry/
> generation/policy plus a bounded canonical `authorizationState`, fetches one
> final blockhash at fixed `confirmed` commitment, requires a non-regressing
> context, resolves the same authority again, builds the final wrapped message,
> obtains a synchronous blocking intent verdict over those exact bytes, and
> creates the immutable approval from that message only. A bounded worker-memory
> capsule retains the authority/blockhash observation; worker restart still
> makes the shipped approval owner cancel every pending record.
>
> Approval consumes that capsule once. It rereads and exact-compares every record
> binding, makes a wrong UI digest drive the repository's atomic invalidation,
> re-resolves authority and reruns the local gate before the CAS, and atomically
> claims the exact digest. After claim it validates the original approved
> blockhash—never refreshes it—at the same cluster/commitment and monotonic
> context, re-resolves authority, and reruns the gate. Only then does it borrow
> the session seed. Inside the lease it matches all three AAD-bound public fields
> (SmartAccount, genesis hash, Warden program), performs one final monotonic
> authority read, runs the gate, and synchronously signs with no suspension
> between verdict and `signApprovedSessionMessage`. The coordinator strictly
> reparses the keyring result, recomputes the digest, compares signer/message/
> blockhash, and verifies Ed25519 again before returning isolated bytes.
>
> Harsh review changed the first green design: it unnecessarily held plaintext
> seed bytes over three RPC waits. Post-claim validity work now occurs before key
> borrow; only the unavoidable final authority read remains inside the abortable
> lease. Another initially green test claimed RPC/gate copy isolation without
> actually returning its mutable blockhash from the fake. That false-positive
> lane was corrected: resolver, RPC, and gate buffers are now independently
> mutated while the stored message/context remain exact.
>
> The extension keyring lease now exposes its already-authenticated genesis hash
> and Warden program id as callback-lifetime copies, clears them with the context,
> and compile-time implements the coordinator keyring interface. The real
> approval owner likewise compile-time implements the coordinator owner
> interface. These imports are type-only. The emitted background is 194,257
> bytes (prior boundary: 194,123); content and popup remain 8,269 and 3,229
> bytes. No manifest permission, CSP, storage schema, page, RPC endpoint,
> successful provider method, or runtime coordinator import was added.
>
> Exact-SHA evidence at `cafced9c2f4725e0a95afc792fd0290acc01d28b`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-approval-coordinator.test.ts` → **29/29**, exit **0**;
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **508/508**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **246/246**, exit **0**; core and extension
> typecheck/build commands all exited **0**; the compiled package subpath import
> resolves the coordinator and fixed commitment. After extension build, `rg -n
> "SessionApprovalCoordinator|session approval coordinator|signApprovedSessionMessage|prepareSessionTransaction|authorizationState"
> apps/extension/dist` exited **1** with no matches. The preceding
> ledger-inclusive SHA `3eb346ca141981c8a435b3abb41aadfef0eaaa1f` passed
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit
> **0**. The full gate for this new ledger-inclusive boundary is pending; do not
> transfer the preceding verdict.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
> `WRD-TXI-01`, or `WRD-KEY-04`.** The coordinator is an ordering contract
> exercised with fakes, not a complete authority. There is no real canonical
> account/session/registry resolver, live cluster-bound RPC client, or local
> program/discriminator/account-role/policy decoder. A permissive injected gate
> still makes structurally valid unknown-program signing possible. No approval
> UI renders the record; no provider or UI route can construct or approve it;
> navigation and Port teardown are not composed with a live capsule; and there
> is no end-to-end test using the real IndexedDB owner and real decrypted keyring
> together.
>
> The opaque `authorizationState` contract says it must contain every byte used
> by authority/policy decisions, but no implementation proves completeness or
> canonical encoding. Claim precedes RPC/keyring work, so an expired blockhash,
> resolver outage, lock, or final drift leaves a one-shot `approved` tombstone
> even though no signature escaped; durable result states/replay do not exist.
> One authority RPC still occurs while seed bytes are live. Authority can change
> immediately after the final observation, and a blockhash can expire
> immediately after validity; on-chain checks and a future sender must fail
> closed rather than refreshing this approval. Simulation, fees, send,
> confirmation, result replay, Chrome-floor/Brave coverage, independent Rust
> differential/fuzzing, and independent second-model review remain
> **UNVERIFIED**.
>
> **Next load-bearing slice:** implement a real deterministic local decoder/gate
> for the exact final lookup-free-v0 session message. It must validate the outer
> ComputeBudget/`execute` shape, literal Warden discriminator and Borsh framing,
> decode the embedded payload/account roles from bytes, allow only explicitly
> supported program/discriminator layouts, consume canonical authority state,
> and return no benign verdict for unknown/ambiguous input. Use independent
> hand-authored/golden mutations; keep the coordinator and every provider route
> runtime-unreachable until a real approval UI can render that same decode.

> ## 2026-08-31 C3 EXACT APPROVED-BYTE SIGNING — CRYPTOGRAPHIC SEAM CLOSED, AUTHORIZATION STILL OPEN
>
> Implementation commit `349e73aac0ea710c748d33fff151e0dd83a514c0`
> adds the first exact-message Ed25519 finalizer to the opt-in
> `@warden/core/transaction/session` boundary. The focused contract was
> genuinely red first: `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core exec vitest run test/session-transaction.test.ts`
> exited **1** with four failing signing contracts because
> `signApprovedSessionMessage` and its typed error did not exist.
>
> `signApprovedSessionMessage(rawMessage, sessionSeed)` accepts no blockhash
> override, caller-supplied public key, transaction builder, or mutable signature
> vector. It copy-owns the exact approval message and 32-byte seed, derives the
> Ed25519 public key, constructs the canonical one-signature/zero-slot envelope
> around those message bytes, and runs the independent strict parser. Only a
> lookup-free v0 message with exactly that derived key as its sole signer and a
> nonzero recent blockhash proceeds. Legacy, future versions, address lookups,
> malformed/trailing bytes, a whole transaction passed in place of a message,
> extra signers, mismatched seeds, zero blockhashes, and packets over 1,232 bytes
> fail with typed errors.
>
> Signing uses the exact-pinned `@noble/curves` 1.9.7 Ed25519 implementation,
> now an explicit production dependency rather than a dev-only direct import.
> The finalizer verifies the signature, changes only bytes 1..64 of the canonical
> transaction envelope, and reparses both strict-wire and web3 SDK views before
> returning. Message, transaction, signature, signer, and blockhash getters all
> return isolated copies; temporary seed/message/signature buffers are wiped in
> `finally` (JavaScript zeroization remains best effort). A Node/OpenSSL Ed25519
> verifier independently accepts the output over the approval message and
> rejects a one-byte mutation; it also rejects treating the whole unsigned
> transaction as the signed object.
>
> Current Solana primary RPC contracts sharpen the still-missing coordinator:
> [`getLatestBlockhash`](https://solana.com/docs/rpc/http/getlatestblockhash)
> returns the hash plus last-valid block height and a context slot;
> [`isBlockhashValid`](https://solana.com/docs/rpc/http/isblockhashvalid) checks
> that exact hash at a requested commitment and supports `minContextSlot`; and
> [`sendTransaction`](https://solana.com/docs/rpc/http/sendtransaction) relays
> bytes unchanged but an accepted response is not confirmation, blockhash expiry
> can still prevent landing, and status must be tracked separately. The next
> coordinator must bind these responses to the approval's canonical cluster and
> must never refresh the blockhash under an existing digest.
>
> Exact-SHA evidence at `349e73aac0ea710c748d33fff151e0dd83a514c0`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-transaction.test.ts` → **17/17**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **479/479**, exit **0**; core typecheck/build and extension typecheck/build all
> exited **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **246/246**, exit **0**. A built-module import resolves
> both prepare/sign functions and `pnpm --filter @warden/core list --depth 0`
> reports `@noble/curves@1.9.7` under production dependencies. The preceding
> ledger-inclusive SHA `b42432728a5f8ddee11950998581012c36ae05f8`
> passed `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh`, exit **0**. The full gate for this new ledger-inclusive
> boundary is pending; do not transfer the preceding verdict.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, `WRD-APR-03`,
> `WRD-TXI-01`, or `WRD-KEY-04`.** No shipped extension code imports this
> finalizer; every provider method is still fixed unavailable. The function is
> intentionally a cryptographic primitive, not a semantic authorization
> boundary: absent a privileged decoder/coordinator it can sign a structurally
> valid unknown-program v0 message. There is no local program/discriminator/
> account-role decoder, allowlist decision, authoritative account/network/
> program/session/policy resolver, approval UI, live blockhash RPC client,
> transactional composition of claim+revalidation, keyring lease consumption,
> sender, confirmation tracker, or replay-safe result owner. The native verifier
> is independent of the production JS implementation but there is still no Rust
> golden/fuzzer corpus or independent second-model review; both are
> **UNVERIFIED**.
>
> **Next load-bearing slice:** add an internal and still-unreachable session
> approval coordinator with injected authority, RPC, approval-owner, and keyring
> dependencies. Preparation must resolve and snapshot account/chain/genesis/
> program/session/registry/policy, fetch one latest blockhash with a context slot,
> build the final message, obtain a blocking local-decode verdict, and persist
> only that exact message. Approval must revalidate the same authority/policy,
> atomically claim the exact digest, check that bound blockhash with the same
> commitment and a non-regressing context, borrow the matching session seed,
> sign the claimed record bytes, and revalidate/reparse before release. Any
> expiry or mismatch consumes/cancels the attempt; it never rebuilds behind the
> user's approval. Keep provider methods closed and do not add send until durable
> result ownership exists.

> ## 2026-08-31 C3/C4 EXACT SESSION MESSAGE — WYSIWYS OBJECT CLOSED, COORDINATOR STILL OPEN
>
> Implementation commit `8c29a224780826c4e10f82667bc886da2bfa0acf`
> adds the first exact final-message builder for Warden's deliberately narrow
> session path. The contract was genuinely red before production code existed:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-transaction.test.ts` exited **1** before collection
> because `../src/transaction/session-transaction.js` did not exist.
>
> Primary-source research pins the object being approved. `VersionedTransaction`
> signs `message.serialize()`, while the transaction envelope also contains
> mutable signature slots. Wallet Standard supplies and returns serialized
> transactions, but Warden's advertised SmartAccount is a program-owned PDA and
> has no Ed25519 key; the returned transaction must therefore be a different
> session-signed `execute` wrapper. Approval's existing `rawMessage` field is now
> documented unambiguously as the exact serialized Solana **message**, never the
> whole transaction. Solana's durable-nonce contract additionally requires an
> `AdvanceNonceAccount` System instruction at index zero, so that source shape is
> detected and rejected before its lifetime can be silently replaced. Sources:
> [web3.js `VersionedTransaction`](https://github.com/solana-foundation/solana-web3.js/blob/master/src/transaction/versioned.ts),
> [Solana durable nonces](https://solana.com/developers/cookbook/transactions/durable-nonces),
> [transaction confirmation/expiration](https://solana.com/developers/cookbook/transactions/confirmation),
> and the Wallet Standard sources cited in the preceding envelope entry.
>
> `prepareSessionTransaction()` first runs the independent strict envelope
> parser against the requested SmartAccount. It accepts only one zero-filled
> source signature slot, so partial signatures and any other required signer
> fail closed. It rejects empty/compute-only intent, a first durable-nonce
> advance, and every instruction that names the Instructions sysvar. It then
> decompiles the lookup-free legacy/v0 source, invokes `wrapForExecute` with the
> real session delegate as signer and fee payer plus explicit SessionKey and
> Registry accounts, and rejects every privilege shape that generic execute
> cannot preserve.
>
> The builder emits the literal Anchor `execute` discriminator and exact Borsh
> session framing (`root=None`, `payload=Some(Vec<u8>)`), places normalized
> ComputeBudget instructions at top level, compiles a lookup-free v0 message with
> an explicit caller-supplied nonzero 32-byte blockhash, and allocates exactly one
> zero signature slot for the session delegate. The whole transaction—not merely
> the message—must fit 1,232 bytes. Before returning, it reparses the serialized
> final envelope and rechecks version, signer set, empty signature slot,
> blockhash, exact message bytes, execute data, every runtime-coalesced account
> key/flag, and reproduction of `accountsHash`. Every returned byte buffer is a
> fresh copy. `@warden/core/transaction/session` is a separate opt-in export;
> `@warden/core/transaction` remains the web3-independent parser-only boundary.
>
> The 12 focused contracts cover legacy and lookup-free-v0 sources, literal
> discriminator/Borsh bytes and physical account keys/flags, source/final
> blockhash separation, full-packet size, copy isolation, parser/export boundary
> separation, a real Ed25519 signature over the approved message (and failure
> after one-byte mutation), partial/co-signature refusal, requested-account and
> authority-alias refusal, empty/compute-only, durable nonce, Instructions
> sysvar, writable-PDA wrap incompatibility, malformed-source error provenance,
> invalid final blockhashes, and a source that fits while its wrapper exceeds the
> packet limit.
>
> Exact-SHA evidence at `8c29a224780826c4e10f82667bc886da2bfa0acf`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/session-transaction.test.ts` → **12/12**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **474/474**, exit **0**; core typecheck/build and extension typecheck/build all
> exited **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **246/246**, exit **0**. Built-package checks resolve
> `@warden/core/transaction/session` while proving the parser-only subpath does
> not export the builder. The preceding ledger-inclusive SHA
> `15315e64ce8d1de82f79d428d28dd42edc77a085` passed `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh`, exit **0**.
> The full gate for this new ledger-inclusive boundary is still pending; do not
> transfer the preceding SHA's verdict to this one.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, or `WRD-TXI-01`.** This module is
> not imported by the shipped extension and no provider method can reach it.
> There is still no authoritative account/cluster/genesis/program/session/policy
> resolver, current blockhash-validity RPC check, semantic decoder, allowlist
> verdict, simulation, record-creation coordinator, approval UI, digest claim,
> signer, sender, or result replay. Any nonzero 32-byte blockhash is structurally
> accepted; freshness must be checked against the bound cluster immediately
> before signing, and expiry must cancel/rebuild/reapprove rather than mutate the
> approved message. The builder is inline-only, rejects all LUTs, cannot stage an
> oversized payload, and refuses the generic writable-PDA shape—so common dApp
> transfers/authority instructions remain incompatible and need typed Warden
> paths. It still structurally wraps syntactically valid unknown programs; this
> is not C4 intent decode or a no-blind-sign verdict. There is no independent
> Rust final-message golden/fuzzer corpus. Independent second-model review
> remains **UNVERIFIED**.
>
> **Next load-bearing slice:** add an internal, still-unreachable approval
> coordinator around this object. It must consume authoritative account/network/
> program/session/policy context; fetch and bind a current blockhash; create the
> record from `prepared.messageBytes` only; on claim, transactionally recheck the
> exact digest plus current authority/policy and cluster blockhash validity;
> borrow the matching session seed; sign exactly those message bytes; and reparse
> the signed transaction before release. Keep provider methods closed until an
> approval UI renders a local semantic decode of that same final message. Run
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the
> final ledger-inclusive SHA before calling this loop boundary green.

> ## 2026-08-30 C3/C4 EXACT-BYTE TRANSACTION ENVELOPE — SYNTAX CLOSED, FINAL WRAPPED INTENT STILL OPEN
>
> Implementation commit `d49529c5f1d0796c7b5adfbb6d71327c1ce1c74b`
> adds the strict serialized-Solana-transaction boundary that must precede any
> approval creation. The first contract was genuinely red: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/transaction-envelope.test.ts` exited **1** before collection because
> `../src/transaction/envelope.js` did not exist.
>
> Primary-source research corrected the architecture. Wallet Standard supplies
> `transaction: Uint8Array` to `solana:signTransaction`; sign-and-send uses the
> same serialized transaction shape and requires an explicit chain. A Warden
> account is a program-owned PDA, so it cannot simply sign that dApp transaction:
> Warden must decode its instructions, wrap them in the on-chain `execute`
> instruction, and sign a distinct final outer transaction. Therefore an approval
> record created from only the incoming dApp bytes would be a false WYSIWYS claim.
> The approval must ultimately bind the exact final wrapped message and its
> recent-blockhash rules. Sources: Wallet Standard
> [`signTransaction.ts`](https://github.com/anza-xyz/wallet-standard/blob/master/packages/core/features/src/signTransaction.ts),
> [`signAndSendTransaction.ts`](https://github.com/anza-xyz/wallet-standard/blob/master/packages/core/features/src/signAndSendTransaction.ts),
> the [Solana Wallet Standard extension](https://github.com/wallet-standard/wallet-standard/blob/master/extensions/solana.md),
> [Solana transaction structure](https://solana.com/docs/core/transactions), and
> Anza's [v0 loaded-message implementation](https://github.com/anza-xyz/solana-sdk/blob/master/message/src/versions/v0/loaded.rs).
>
> `parseSerializedTransactionEnvelope()` is a browser-safe manual wire reader,
> independent of `@solana/web3.js`: it copy-owns the 1–1,232 input bytes; accepts
> only legacy or v0; enforces Solana's canonical one-to-three-byte ShortU16
> encoding; requires exact signature/header agreement and a writable fee payer;
> rejects duplicate static keys, payer-as-program, bad program/account indices,
> truncation, trailing bytes, and unknown versions; and optionally proves that a
> 32-byte requested wallet account is in the actual required-signer prefix. Every
> byte-bearing getter returns a fresh copy. V0 address lookups are parsed only far
> enough to validate framing and then blocked until a trusted, cluster-bound
> resolver exists. The package exports the boundary at
> `@warden/core/transaction`.
>
> The 11 focused contracts pin hand-authored legacy and lookup-free-v0 wire
> fixtures, compare each accepted fixture byte-for-byte with web3 as a
> differential oracle, test caller/reader buffer isolation, reject every proper
> prefix of both goldens, accept canonical two-byte ShortU16 while rejecting its
> alias, and cover size, signature, header, duplicate-key, index, lookup,
> requested-signer, unknown-version, and trailing-byte failures. The fixture
> expectations are not generated by the parser under test.
>
> Exact-SHA focused evidence at
> `d49529c5f1d0796c7b5adfbb6d71327c1ce1c74b`: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/transaction-envelope.test.ts` → **11/11**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **462/462**, exit **0**; and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core typecheck` plus `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build` both
> exited **0**.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, or `WRD-TXI-01`.** This is only a
> strict syntactic envelope. It deliberately accepts syntactically valid unknown
> programs, arbitrary signature contents, empty instruction vectors, and stale or
> zero blockhashes; it does not decode intent, resolve policy, authenticate
> cluster/account state, simulate, wrap, build the final transaction, create an
> approval, render a UI, or sign. It has fixed-vector and web3 differential
> coverage but not yet the full C4 parser/fuzzer corpus or an independent Rust
> differential lane. Lookup-table transactions are incompatible for now. No
> shipped extension path imports this package subpath, and all provider methods
> remain fixed-unavailable. Independent second-model review remains
> **UNVERIFIED**.
>
> **Next load-bearing slice:** consume the strict envelope in a final-wrap
> builder that decompiles only lookup-free messages, validates the requested
> SmartAccount signer role, calls `wrapForExecute`, constructs the exact outer
> transaction/message with explicit recent-blockhash semantics, reparses that
> final serialization, and only then permits the background coordinator to
> create the immutable approval record. Never create the approval from the
> original dApp transaction and later sign a different wrapper. Run `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the final
> ledger-inclusive SHA before calling this loop boundary green.

> ## 2026-08-30 C3 SHIPPED STARTUP OWNERSHIP — PENDING APPROVALS DIE WITH THE REAL WORKER
>
> Implementation commit `f3b4946468c0f4e8ad8b0a4bb093b48c43432841`
> moves the C3 approval repository from tested-but-tree-shaken source into the
> shipped MV3 worker without adding an approval route. The first runtime contract
> was genuinely red: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/runtime.test.ts` exited **1** with **1
> failure / 15 passes** because `startBackground()` ignored the approval startup
> lifecycle and called no invalidation method.
>
> `main.ts` now constructs the native IndexedDB repository and internal
> `ApprovalOwner`; the runtime requires that lifecycle rather than silently
> defaulting it away. Invalidation starts during the same top-level evaluation
> turn as synchronous runtime listener registration. The one internal readiness
> gate combines trusted Chrome-storage restriction, authenticated keyring wake
> restore, and approval invalidation, so the keyring facade stays unavailable
> until all three settle. Approval startup failure closes provider/popup Ports,
> removes global listeners, rejects readiness, and closes the repository.
> Initialization rollback, fatal record-change cleanup, and explicit disposal
> close it exactly once. The returned application exposes no approval owner,
> repository, record, or decision method.
>
> The shipped-extension Chromium lane now seeds a strict pending record directly
> into the production `warden-approvals-v1` database only after the live worker
> initialized it, proves the record is pending, kills that worker through CDP,
> wakes a new execution context through the existing provider Port, and observes
> the production startup owner change the record to `cancelled`. The separate
> temporary-extension lane still proves two-connection compare-and-set races,
> tamper deletion, wrong-digest invalidation, exact expiry, buffer isolation, and
> identical-payload independence. This is composed browser evidence rather than
> an assumption that a source module will be bundled.
>
> Exact-SHA focused evidence at `f3b4946468c0f4e8ad8b0a4bb093b48c43432841`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test` → **246/246**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck` → exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension build` → exit **0** with background/content/popup
> bundles of **194,123 / 8,269 / 3,229 bytes**; and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts` → **2/2**, exit **0**.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, or `WRD-APR-03`.** The shipped
> worker owns only fail-closed cleanup. No Port or page can create, read, render,
> approve, reject, or sign a record. There is still no authoritative account,
> network, or policy registry; exact-byte decoder; approval UI; current-state
> signer recheck; RPC; navigation cancellation; root ceremony; nonce consumer;
> or signed-result replay. A worker stop deliberately destroys availability for
> every pending request instead of resuming a dead Port. Same-extension trusted
> contexts still share IndexedDB, strict durability is a hint, and the browser
> measurement is one Chrome build rather than a browser/host/disk matrix. No
> manifest permission, host access, CSP directive, page, successful provider
> method, or network path changed. Independent second-model review remains
> **UNVERIFIED**. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before calling this
> loop boundary green.

> ## 2026-08-30 C3 TRANSACTIONAL APPROVAL-RECORD SUBSTRATE — REAL IDB RACE GREEN, WALLET STILL CLOSED
>
> Implementation commit `c3be2c1b248cee4bc1e99a2e0701207031a1487b`
> adds a strict core approval-record domain plus an internal extension owner and
> native IndexedDB repository. The first contracts were genuinely red. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec vitest
> run test/approval-record.test.ts` exited **1** before collection because
> `../src/approval/index.js` did not exist; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/approval-owner.test.ts` exited **1** because
> `@warden/core/approval` did not exist; and, after building core, `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts browser/approval-idb.pw.ts` exited
> **1** because `approval-store.js` did not exist.
>
> The closed record schema owns a background-minted 128-bit request id;
> canonical browser-owned HTTP(S) origin; tab, frame, and document identity;
> authoritative 32-byte account; exact method; explicit cluster, genesis hash,
> and program id; 1–1232 exact message bytes and their recomputed SHA-256;
> policy version; creation/expiry; and pending or one terminal state. Every byte
> field is copied at every domain/repository boundary. Lifetimes are positive
> and at most ten minutes. Pending records have no resolution time; non-expiry
> terminal states must precede expiry; expiry can occur only at or after it.
> Unknown fields, aliases, ambiguous origins, digest tamper, and inconsistent
> state/time combinations fail closed.
>
> One IndexedDB database/version/object store owns create, read-with-expiry,
> decision, and worker-start invalidation. Each check-and-set is one strict-
> durability `readwrite` transaction over the same store; overlapping scopes
> serialize. `add`, never `put`, creates ids. Exactly one pending-to-terminal
> decision wins. A wrong signing digest atomically changes the record to
> `invalidated`; a later correct retry cannot revive it. The exact deadline
> changes pending to `expired`. Malformed records are deleted. A clock moving
> before pending creation deletes rather than extends authority. Startup expires
> elapsed records and cancels every other pending record because its originating
> Port died. The store caps live pending records at 32 and all retained records
> at 128, and prunes ten-minute terminal tombstones.
>
> The real-Chromium contract bundles this same repository into a temporary MV3
> extension. It opens two independent database connections and proves one winner
> for approve/reject and approve/approve races; mutation of both caller input and
> returned typed arrays cannot change storage; two byte-identical dApp payloads
> under distinct ids remain independent; raw-message tamper is rejected and
> deleted; wrong-digest and exact-expiry paths are terminal; and killing the
> worker through CDP, waking it from an extension page, and observing a fresh
> execution global cancels the sole pending record. This follows Chrome's MV3
> requirement to persist important state across worker termination, Chrome's
> documentation that IndexedDB is available in extension workers, and the
> IndexedDB specification's atomic commit/rollback and serialization of
> overlapping read/write scopes:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage/>, and
> <https://www.w3.org/TR/IndexedDB/>.
>
> Exact-SHA focused evidence at `c3be2c1b248cee4bc1e99a2e0701207031a1487b`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test`
> → **451/451**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **244/244**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build` and
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck` both exited **0**; and `env npm_config_cache=/tmp/warden-npm-cache
> pnpm --filter @warden/extension exec playwright test -c playwright.config.ts
> browser/approval-idb.pw.ts` → **1/1**, exit **0**.
>
> **Do not promote `WRD-APR-01`, `WRD-APR-02`, or `WRD-APR-03`.** This substrate
> is deliberately not instantiated by `startBackground()` and is tree-shaken
> from the shipped bundle. No provider or popup route can create, view, or decide
> an approval. There is no authoritative account/network/policy registry,
> approval page, exact-byte decoder, signer, RPC, navigation cancellation, root
> ceremony, or durable signed-result replay. The raw-message digest does not MAC
> the other public record fields; those remain trusted-background data and a
> future signer must compare account, network, policy, and exact bytes against
> current authority immediately before use. Marking `approved` consumes the
> request before any future signature, so a crash is fail-closed but currently
> loses availability. IndexedDB `durability: "strict"` is a hint, not proof
> against browser/process/disk failure; terminal tombstones are bounded, and all
> trusted same-extension contexts share the database. The browser lane kills a
> worker, not the entire browser or host, and it is not a Chrome/Brave/version or
> disk-corruption matrix. Independent second-model review remains **UNVERIFIED**.
> Run `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on
> the final ledger-inclusive SHA before calling this loop boundary green.

> ## 2026-08-30 C2 ARGON2 HOST RESPONSIVENESS + REVOCATION — BROWSER GATE LIVE, PRODUCT FLOOR OPEN
>
> Implementation commit `125ad761b3af1879f42fa13135e5a07d57721223`
> replaces the production record paths' event-loop-blocking password KDF with a
> host-responsive and revocable path. The first contract was genuinely red:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core exec
> vitest run test/keyring-derive-async.test.ts` exited **1** with **3 failures / 0
> passes** because `deriveUnwrapKeyFromPasswordBytesAsync` did not exist. It now
> pins sync/async output equality, a real Node host-task yield, post-revocation
> result suppression, already-aborted pre-allocation refusal, and password-buffer
> wiping.
>
> The dependency is exact-pinned from `@noble/hashes` 1.8.0 to **2.4.0**. All
> direct v2 imports use its explicit `.js` exports; the deploy verifier's
> fail-closed external allow-list and byte attestation were deliberately updated
> and regenerated. No WASM dependency or `wasm-unsafe-eval` CSP exception was
> added. This keeps the current `script-src 'self'` extension boundary, but it
> also keeps Noble's documented pure-JavaScript native-attacker performance
> disadvantage. The provisional RFC 9106 second profile is **64 MiB / t=3 /
> p=4 / 32 bytes**. `p=4` describes Argon2 lanes; this pure-JS implementation
> does not turn those lanes into four CPU workers. The older historical handoff
> line below that says `p=1` is superseded and wrong.
>
> A Node measurement initially looked sufficient and was not. Noble 1.8's async
> driver yielded only through promises, so a zero-delay timer ran only after the
> approximately 2.4-second RFC-profile derivation. Noble 2.4's Node timer fallback
> reduced this host's derivation to approximately 1.0 second and let the timer run,
> but the first real command `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension bench:argon2` still exited **1** in an MV3 worker:
> Chromium's default `scheduler.yield()` continuations correctly outranked the
> queued timer and starved the would-be lock task until KDF completion. The fix
> starts Argon2 inside `scheduler.postTask(..., { priority: "background", signal })`.
> Its internal yields inherit both background priority and abort authority, so
> ordinary extension work can preempt and abort rejection runs Noble's matrix
> cleanup. Hosts without `postTask` use Noble's timer fallback; they remain
> responsive and suppress revoked output, but may finish the initialized KDF
> before cleanup. Primary scheduling references:
> <https://developer.chrome.com/blog/use-scheduler-yield>,
> <https://wicg.github.io/scheduling-apis/>, and
> <https://github.com/paulmillr/noble-hashes/releases/tag/2.4.0>.
>
> The benchmark is now a mandatory real-Chromium gate inside
> `.claude/test-gate.sh`, not a prose claim. It builds a temporary MV3 extension
> under the unchanged self-only CSP, runs five exact-profile derivations, checks
> a fixed 32-byte output, proves the caller password is zeroed, requires a delayed
> browser task to run before each derivation finishes, and separately requires an
> abort to reject with `KeyringLockedError`. Exact command at implementation SHA
> `125ad761b3af1879f42fa13135e5a07d57721223`: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> bench:argon2` → exit **0**. On Headless Chrome 151 / Linux 6.8 / AMD EPYC-Milan
> / 4 logical CPUs / 15.25 GiB RAM, elapsed milliseconds were **901.1 min / 901.8
> p50 / 927.1 p95-max**; a task requested at 50 ms ran at **53.1–67.7 ms**;
> revocation dispatched at **61.4 ms** and rejected **29.0 ms** later with the
> password buffer wiped. This measures one fast server, not a product floor.
>
> Record seal/open and the extension password lifecycle now use the async API.
> Every lock, record mutation, competing unlock, and startup restore revokes one
> pending derivation authority before its first suspension; local password/KEK/
> plaintext copies are scrubbed best effort and a revoked derivation cannot
> activate. Harsh review found another real race after the first green: startup
> restore could adopt a session that a superseded unlock had serialized just
> before final readback. The new deterministic test failed **1 / 14** before the
> fix; restore now clears and refuses a same-owner pending unlock rather than
> adopting it. Exact-SHA focused evidence: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **447/447**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **241/241**, exit **0**.
>
> **Do not promote `WRD-KEY-02`, `WRD-KEY-03`, or `WRD-KEY-04`, and do not call
> the Argon2 profile calibrated.** The required slowest-supported-desktop/browser
> matrix has not run, no latency acceptance band or production floor has been
> selected, stored records below any future floor are still accepted, and no
> attempt-rate/backoff policy exists. Cheap parameters remain necessary for tests
> but would be unsafe as product-created metadata. There is still no browser-
> reachable creation/unlock/sign flow, PRF real-device matrix, authoritative
> account registry, approval/RPC consumer, on-chain session-grant match, or
> real-key browser vector. Chrome 106's timer-fallback behavior is not measured by
> the Chrome 151 lane. JS zeroization is best effort. Independent second-model
> review remains **UNVERIFIED**. Run `env npm_config_cache=/tmp/warden-npm-cache
> bash .claude/test-gate.sh` on the final ledger-inclusive SHA before claiming
> this loop boundary green.

> ## 2026-08-30 C2 SELF-CONTAINED CONTEXT + AUTHENTICATED WAKE — INTERNAL BOUNDARY HARDENED, WALLET STILL OPEN
>
> Implementation commit `8653fed0b922e37a3998e96ca3f33f686daeeba7`
> removes caller-selected account/cluster/program context from normal extension
> unlock and signer use. The first contracts were genuinely red before
> implementation. `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core exec vitest run test/keyring-record-v2.test.ts` exited **1** with
> **3 failures / 0 passes** because the record did not own a context. `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/keyring-context-ownership.test.ts` exited **1** with **2
> failures / 0 passes** because the lifecycle still required caller context.
> A later harsh-review contract, `env npm_config_cache=/tmp/warden-npm-cache
> pnpm --filter @warden/extension exec vitest run
> test/keyring-lifecycle.test.ts test/runtime.test.ts`, exited **1** with **2
> failures / 25 passes**: wake restore accepted a context-tampered record on a
> public bundle-id match, and the supposedly hidden readiness facade exposed
> own `owner` and `gate` properties at JavaScript runtime.
>
> Core record v2 now embeds a strict canonical copy of all six public AAD fields
> beside the bounded KDF metadata. Those bytes participate in both outer-record
> binding and bundle AEAD, so a successful open authenticates the context; merely
> parsing locked storage does not. Record v2 rejects a caller-supplied context.
> The parser bounds the length before decoding, requires canonical keyring AAD
> for bundle v1, rejects truncation/version lies, and returns copy-owned fields.
> Record v1 remains core-decodable/openable only when explicit migration tooling
> supplies its legacy context; the extension refuses v1. There is no migration
> UI or shipped-record population, which is acceptable only while this remains a
> pre-alpha development extension.
>
> The extension derives the one acceptable origin from browser-owned
> `chrome.runtime.id` and requires its exact `chrome-extension://<id>` spelling;
> account, genesis hash, program id, key kind, and schema come only from record
> v2. Startup treats bundle-id equality as routing, not authentication: after
> restoring the KEK it opens the exact current record, validates the strict
> 32-byte session-signer payload, verifies account/bundle identity and exact
> persistent readback, and only then resolves readiness as restored. Any failure
> locks and removes session material. The public lifecycle is frozen and stores
> its owner/readiness gate in ECMAScript private fields; pre-ready calls reject,
> and pre-ready password bytes are overwritten synchronously.
>
> This follows Chrome's current primary documentation that runtime IDs are
> extension identifiers and extension resources use
> `chrome-extension://<extension-id>` origins, while storage access restriction
> and change notification remain browser storage controls rather than a CAS or
> authenticity primitive:
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/network-requests>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage/>.
>
> Exact-SHA focused evidence at
> `8653fed0b922e37a3998e96ca3f33f686daeeba7`: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **444/444**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **239/239**, exit **0**; both package
> `typecheck` commands exited **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension build`
> exited **0** with background/content/popup bundles of **147,880 / 8,269 /
> 3,229 bytes**; and `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test:browser` → **1/1**, exit **0**. The browser lane proves
> real runtime-origin-compatible records, worker wake mismatch cleanup, and live
> record-change cleanup; authenticated wake-open remains a deterministic unit
> measurement, not a real-browser password ceremony. These are implementation
> lanes, not the repository deploy gate. Run `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the final
> ledger-inclusive SHA before claiming this loop boundary green.
>
> **Do not promote `WRD-KEY-02`, `WRD-KEY-03`, or `WRD-KEY-04`.** There is still
> no browser-reachable creation/unlock/sign flow, authoritative account registry,
> on-chain proof that the seed matches a current session grant, approval owner,
> transaction/RPC consumer, production Argon2 benchmark/floor or attempt policy,
> PRF real-device matrix, v1 migration, or real-key browser vector. A callback
> can copy a seed or perform an irreversible side effect contrary to its contract;
> JavaScript overwrite is best effort. Chrome supplies no transaction/CAS,
> authenticated freshness, rollback, or durability guarantee; whole valid
> same-context records remain replayable, and cleanup rejection can retain KEK
> bytes. Production build-ID freeze versus authenticated origin migration remains
> the unresolved `WRD-ORG-01` owner decision. Independent second-model review
> remains **UNVERIFIED**.

> ## 2026-08-30 C2 AUTHENTICATED SESSION-SIGNER ACTIVATION — INTERNAL PATH LIVE, WALLET STILL OPEN
>
> Implementation commit `bddb0ccbab2aa55780b132fd1528b03a297e2124`
> closes the previously explicit gap between a canonical encrypted record and
> an activated extension unlock session. Both contracts were genuinely red
> before implementation. `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core exec vitest run test/session-signer-payload.test.ts`
> exited **1** with **5 failures / 0 passes** because the payload helpers did
> not exist. `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/keyring-lifecycle.test.ts` exited
> **1** before collection because `keyring-lifecycle.js` did not exist.
>
> The v1 plaintext schema is exactly one 32-byte Ed25519 seed. This is not an
> invented 64-byte secret-key format: the locked `@solana/web3.js` 1.98.4
> [upstream source](https://github.com/solana-foundation/solana-web3.js/blob/v1.98.4/src/keypair.ts#L70-L84)
> documents `Keypair.fromSeed` as a 32-byte input and constructs its 64-byte
> representation as `seed || derived public key`. The existing keyring AAD binds schema version 1 and
> `keyKind = session-signer`, so persisting the redundant public half would add
> a consistency field without adding entropy. Five core tests pin the exact
> length, bytes, copy ownership, and strict rejection of non-byte/31/33-byte
> inputs.
>
> `KeyringLifecycleOwner` is now the background's only persistent-record and
> ephemeral-session authority; neither raw owner escapes the runtime. Password
> activation snapshots and synchronously overwrites caller bytes, derives the
> KEK from bounded canonical metadata, authenticates the exact stored bundle
> and complete account/origin/genesis/program context, validates the strict
> plaintext schema, and destroys plaintext copies before committing only the
> KEK plus public binding/deadline data. Exact record readbacks before and after
> activation prevent a stale record from committing. Replacement, clear, and
> record-change events advance the same lifecycle transition and synchronously
> revoke pending unlocks and active seed leases.
>
> Local signer use reloads the persistent record, checks account and bundle id,
> authenticates it with the session KEK and caller-supplied full context, and
> lends isolated account/seed buffers only to a local callback. It rechecks the
> live deadline/revocation signal and exact record after that callback, scrubs
> every lease, and suppresses/zeros late output on lock or inconsistency. The
> harsh-review additions prove an unnotified out-of-band record swap zeros the
> callback's would-be result and locks the session; disappearance locks before
> the callback; explicit replacement aborts a pending lease synchronously; and
> an ordinary consumer exception scrubs its lease without spuriously revoking a
> healthy session.
>
> Exact-SHA focused evidence at `bddb0ccbab2aa55780b132fd1528b03a297e2124`:
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test`
> → **439/439**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **235/235**, exit **0**; both package
> `typecheck` commands exited **0**; the extension `build` exited **0** with
> background/content/popup bundles of **136,560 / 8,269 / 3,229 bytes**; and
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test:browser` → **1/1**, exit **0**. These are implementation lanes, not the
> repository deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before calling this
> loop boundary green.
>
> **Do not promote `WRD-KEY-02`, `WRD-KEY-03`, or `WRD-KEY-04`.** No browser-
> reachable unlock UI or signer exists. The browser lane measures wake and
> record-change behavior, not password entry or a real signature. There is no
> record creation/onboarding path, account+cluster+program configuration,
> on-chain proof that the encrypted seed is the currently granted session,
> approval owner, transaction builder/signer/send consumer, or RPC. Argon2's
> production floor is unbenchmarked; the focused fixtures intentionally use
> cheap test parameters. PRF remains without a real-device matrix. Context must
> be supplied again on each use, trusted storage has no transaction/CAS or
> authenticated freshness, and whole valid same-context records remain
> replayable. A delayed `storage.onChanged` event after a self-write may
> conservatively revoke a newly unlocked session, and future privileged handlers
> must enforce `background.ready` rather than merely receiving the internal
> owner. Independent second-model review remains **UNVERIFIED**.

> ## 2026-08-30 C2 LIVE RECORD-CHANGE REVOCATION — OUT-OF-BAND GAP NARROWED, KEYRING STILL OPEN
>
> Commit `0e3fc0f7b7119f41777c8dbbb98eecdef26db34a` makes an
> already-running worker revoke its session when Chrome reports any change to
> `warden.keyring-record.v1`. The focused contract was genuinely red before the
> implementation: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/runtime.test.ts` exited **1** with
> **1 failure / 12 passes** because the storage-change listener count was **0**
> instead of **1**. Exact-SHA focused evidence after implementation: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
> → **224/224**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension typecheck` → exit **0**; and `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test:browser` → **1/1**, exit **0**. These are focused lanes, not the
> repository deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before calling this
> loop boundary green.
>
> `startBackground()` now registers the global `storage.onChanged` listener in
> the same synchronous top-level turn as `runtime.onConnect`, before storage
> readiness settles. A `local` change containing the exact persistent-record
> property calls `UnlockSessionOwner.lock()`: transition invalidation, lease
> abort, and zeroization happen in the event callback before Chrome's
> asynchronous removal promise settles. Other storage areas and unrelated local
> keys are ignored. If removal rejects, memory remains locked but the stale
> serialized copy is acknowledged as still present; the worker disables its
> storage handler, disconnects already-open runtime Ports, stops accepting new
> Ports, and rejects a fatal lifecycle promise that production logs. Unit tests
> measure the live lease signal, late-use rejection, successful selective
> cleanup, stale-copy failure state, active-Port disconnect, and registration /
> readiness / disposal rollback paths.
>
> The mandatory Chromium lane now supplies two distinct measurements. First it
> exact-readback proves a mismatched v2 session before actual worker-target
> death, wakes a replacement execution context from the unchanged document, and
> observes only that session removed while an unrelated session canary survives.
> Then it exact-readback proves a session bound to the current record, replaces
> the local record with a different canonical bundle, and observes the real
> Chrome `storage.onChanged` path again remove only Warden's session property.
> This browser assertion measures event delivery and browser-owned bytes; it
> does **not** pretend those bytes prove active heap state. The unit lease test
> is the executable evidence for synchronous in-memory revocation.
>
> Chrome's current documentation says `storage.onChanged` reports changes by
> key and area, `storage.session` is in-memory for a browser session, and MV3
> event listeners must be registered synchronously at top level:
> <https://developer.chrome.com/docs/extensions/reference/api/storage/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events>,
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers#register-listeners-synchronously>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
>
> **Do not promote `WRD-KEY-03` or `WRD-KEY-04`.** This closes the known
> already-active/out-of-band notification gap, not the keyring product. Chrome
> still provides no transaction/CAS/durability or authenticated-event guarantee;
> a trusted writer can race, preserve a bundle id, or replay a whole older valid
> same-context record. Cleanup rejection can leave stale browser bytes, and a
> later replay to the old record can make those bytes relevant again. The fatal
> state closes today's zero-authority runtime routes, but every future privileged
> surface must share that health gate. There is still no composed record mutation
> owner, record creation, Argon2 benchmark/floor, PRF ceremony/device matrix,
> context-supplying record open, record-to-session derivation/activation,
> account registry, or signing/decrypt/export consumer. Independent second-model
> review remains **UNVERIFIED**.

> ## 2026-08-30 C2 SESSION→RECORD BINDING — REAL WORKER MISMATCH REMOVAL, KEYRING STILL OPEN
>
> Commit `c3b74eb3e93c9dde6eb29141d737e49bbc57c16f` binds the
> browser-managed unlock session to the public 16-byte bundle id of the
> canonical persistent keyring record. The initial focused lane was genuinely
> red: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension exec vitest run test/unlock-session.test.ts` exited **1**
> with **2 failures / 14 passes** because the stored schema was still v1 and a
> session for bundle A restored against bundle B. Exact-SHA focused evidence
> after implementation: `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension test` → **221/221**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck` and `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core build` each exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> test:browser` → **1/1**, exit **0**. These are focused lanes, not the
> repository deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before claiming this
> loop boundary green.
>
> `UnlockSessionOwner` now owns only `warden.unlock-session.v2`. Its strict
> record carries account, KDF, unwrap key, absolute deadlines, and the exact
> public bundle id; activation validates and snapshots the id before its first
> await, persists it, requires exact readback, and zeroes the owned copy on
> abort. Wake-time restore snapshots the bundle id decoded from the already
> validated local record and compares it in constant time. A mismatch removes
> the session and stays locked. The obsolete v1 slot is removed before every
> restore and by every replacement/lock cleanup, so a format bump cannot strand
> old unwrap-key bytes in a development profile.
>
> Harsh concurrency review found a real defect after the first focused green: a
> restore could read a stale mismatched record, a newer unlock could queue its
> replacement while that read was pending, and stale cleanup would then run
> behind and erase the newer session. Restore now checks its transition
> generation immediately after the awaited read and before parsing or enqueueing
> cleanup. The deterministic regression gates that exact interleaving and
> requires the newer v2 session to remain committed and usable.
>
> The mandatory Playwright lane now seeds a canonical persistent record, a
> structurally valid but differently bound v2 session, and an unrelated
> `storage.session` canary in the trusted worker. It exact-readback proves all
> three values, closes the actual MV3 service-worker target, wakes a replacement
> execution context from the unchanged page, and observes only the mismatched
> session removed while the canary survives. Thus blanket browser session loss
> cannot make this assertion green. Unit composition separately proves a
> matching session restores and a mismatch stays locked.
>
> **Do not promote `WRD-KEY-03` or `WRD-KEY-04`.** This closes the ordinary
> persistent-record/session identity gap, not the keyring product. The bundle
> id is not a fingerprint of every ciphertext byte and browser storage is not
> authenticated; a whole older valid same-context record can still replay.
> There is no record creation, Argon2 benchmark/floor, PRF ceremony/device
> matrix, record-to-session derivation/activation, account/context registry,
> signing/decrypt/export consumer, or composed mutation owner. An already-active
> worker does not listen for an out-of-band trusted-context record write, and
> Chrome supplies no transaction/CAS/durability guarantee. Cleanup rejection
> can leave stale session bytes in browser-managed storage. The browser vector
> uses structurally valid deterministic bytes, not a key derived through a real
> unlock ceremony. Independent second-model review remains **UNVERIFIED**.

> ## 2026-08-30 C2 PERSISTENT CHROME RECORD OWNER — STORAGE BOUNDARY PARTIAL, UNLOCK PATH OPEN
>
> Commit `7e18f275a839c2d88427a104b5814bb266fe445d` adds the first
> production `chrome.storage.local` owner for the core's encrypted keyring
> record. The initial focused lane was genuinely red: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/keyring-record-store.test.ts` exited **1** because
> `src/background/keyring-record-store.js` did not exist. Exact-SHA focused
> evidence after implementation: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/keyring-record-store.test.ts test/runtime.test.ts` →
> **23/23**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension typecheck`, `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build`, and
> `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> build` each exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension exec playwright test -c playwright.config.ts
> --repeat-each=3` → **3/3**, exit **0**. These are focused lanes, not the
> repository deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before claiming this
> loop boundary green.
>
> `PersistentKeyringRecordStore` owns exactly
> `warden.keyring-record.v1`. It accepts only the core's bounded, strict,
> canonical base64url encrypted record, validates before any storage call,
> serializes all operations through one owner, writes one property, and requires
> exact readback after replace or clear. Chrome operation rejection is preserved
> as a typed error with its cause. An acknowledged-but-mismatched replace is not
> “cleaned up” by deletion because storage is then ambiguous and deletion could
> erase the only valid prior record. The 13 adapter tests cover absence, malformed
> values, pre-write rejection, exact property/readback, competing replacements,
> rejected set/get, ambiguous replace, verified clear, ineffective clear, and a
> malformed adapter. Core independently owns the hand-built wire and canonical
> base64url vectors; this lane measures the storage owner rather than re-deriving
> that format.
>
> Startup still restricts both storage areas to `TRUSTED_CONTEXTS` before any
> read, but now validates the persistent record before examining a session.
> Missing persistent state removes stale session material without parsing it;
> malformed persistent state removes session material and rejects readiness.
> If validation and cleanup both fail, both causes survive in an `AggregateError`.
> The raw record store is deliberately **not** returned beside
> `UnlockSessionOwner`: exposing independent mutation would create an obvious
> old-session/new-record coherence bug. A future composed lifecycle owner must
> revoke the session before record replacement or removal.
>
> The real-browser lane now seeds a non-secret `storage.local` canary in the live
> service worker, reads it back there, then observes the actual Warden isolated
> content-script context receive a causal rejection from
> `chrome.storage.local.get`. This cannot green merely because the area was empty.
> The emitted bundles are background **79,103 bytes**, content **8,269 bytes**, and
> popup **3,229 bytes**. A precise scan of the background for `node:fs`,
> `node:url`, `storage.sync`, `localStorage`, `privateKey`, `secretKey`, and
> `mnemonic` has no match. Current Chrome documentation confirms that local
> storage is content-script-visible by default, `setAccessLevel()` can restrict
> it to trusted contexts, storage promises reject on failure, MV3 globals vanish
> on worker shutdown, and no transaction/CAS primitive is documented here:
> <https://developer.chrome.com/docs/extensions/reference/api/storage>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage/StorageArea/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>.
>
> **Do not promote `WRD-KEY-03` or `WRD-KEY-04`.** This is encrypted-record
> persistence and startup validation, not a usable keyring. There is no record
> creation UI, slow-device Argon2 benchmark/floor, PRF ceremony or compatibility
> matrix, account registry, context-supplying decrypt, record-to-session
> derivation/activation, signing/decrypt/export consumer, or worker-kill/wake
> vector with a seeded live record. The session does not yet carry the public
> bundle id, so startup can distinguish absent/corrupt state but cannot prove
> that a structurally valid session belongs to the currently stored record.
> Chrome documents neither transactional durability nor compare-and-swap;
> serialization covers only this owner, a future trusted page could race an
> out-of-band write, and replay of an older valid same-context record still needs
> an external freshness authority. Independent second-model review remains
> **UNVERIFIED**.

> ## 2026-08-30 C1 ZERO-AUTHORITY ACTION POPUP — REAL TOOLBAR SENDER, NO WALLET CAPABILITY
>
> Commit `14205821687cf3da51abfa12866985e2a545b15a` adds the first
> extension-owned popup route without connecting account, approval, storage,
> RPC, signing, decrypt, export, provider-success, or key authority. Exact-SHA
> focused evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **199/199**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck`, `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core build`, and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension build` each exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts --repeat-each=3` → **3/3**, exit
> **0**. These are focused lanes, not the repository deploy gate. Run `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the
> final ledger-inclusive SHA before calling this loop boundary green.
>
> The initial red lane was executable: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/popup-port.test.ts test/runtime.test.ts
> test/manifest-storage.test.ts` exited **1** because the popup modules were
> absent and the manifest had no action. The implemented manifest action points
> only to local `popup.html` and adds no permission. Its IIFE bundle has an
> exact two-source dependency allowlist (`popup/main.ts` and
> `popup-protocol.ts`) and is **3,229 bytes**. `rg -n
> 'chrome\.storage|privateKey|secretKey|approval|accounts|@warden/core|signTransaction|decrypt|export'
> apps/extension/dist/popup.js` exits **1** with no match. The separate
> `warden:popup:v1` language accepts one exact status request and can return
> only `WARDEN_POPUP_UNAVAILABLE`; it has no dispatch hook. One synchronous
> top-level `runtime.onConnect` owner now routes the exact provider and popup
> names, disconnects unknown names, and prevents independent child listeners
> from rejecting each other's Ports. Popup work is bounded to 16 active Ports,
> 16 requests per Port, unique correlations, and one live Port per supplied
> document id.
>
> Harsh browser review rejected the first “popup works” result: it navigated a
> normal tab directly to `popup.html`, so it measured a tab-hosted extension
> page rather than the browser action. Replacing it with
> `chrome.action.openPopup()` made the lane red: the real toolbar popup showed
> `data-boundary=closed`. A test-side worker observer then measured the
> browser-owned `Port.sender` on bundled Chromium **151.0.7922.34** as exactly
> `{id, origin: chrome-extension://<id>, url:
> chrome-extension://<id>/popup.html}`—no `documentId`,
> `documentLifecycle`, `tab`, or `frameId`. The prior unit fixture's
> mandatory document id was fiction. The corrected classifier accepts that
> exact tabless action shape and binds it to the extension origin/path plus
> browser Port lifetime. A tab-hosted privileged page still requires a document
> id and top frame. A same-id content script still has a web origin/URL and
> rejects before its payload is accepted.
>
> The Playwright lane now attaches to the actual action-popup target, reads the
> rendered unavailable state, and sends a second direct popup request so a
> hard-coded DOM label cannot pass the route. It separately tests direct
> extension-page navigation as the tab-hosted sender shape. It evaluates a
> popup-channel forgery inside Warden's real isolated content-script execution
> context and observes the causal disconnect, not an arbitrary negative wait.
> The toolbar vector is repeat-green **3/3**, but
> `chrome.action.openPopup()` itself is only an automation mechanism available
> in newer Chrome; this does not prove ordinary action-popup compatibility at
> the manifest's Chrome 106 floor. Chrome version/store/manual-install matrix
> evidence remains **UNVERIFIED**. References:
> <https://developer.chrome.com/docs/extensions/reference/api/action#method-openPopup>,
> <https://developer.chrome.com/docs/extensions/develop/ui/add-popup>,
> <https://developer.chrome.com/docs/extensions/reference/api/runtime#type-MessageSender>.
>
> A current discovery adapter was researched and deliberately not added.
> Wallet Standard core remains pinned for this review at
> `c49b56d60fbac2e68e0f3536707fa33030652f9e`, Anza wallet-standard at
> `4b6a165dc8fdedc28a59af05a72a0f91cefffc0d`, and the current Anza
> wallet-adapter at `ca731858affa36fa91b593cc670747b671c4589f`. Its
> `packages/core/base/src/standard.ts` compatibility predicate requires
> `standard:connect`, `standard:events`, and either
> `solana:signAndSendTransaction` or `solana:signTransaction`. An empty
> discovery wallet is filtered out; advertising those features before Warden
> has an authorized account, events, approvals, and an honest transaction path
> would lie about capability. Source:
> <https://github.com/anza-xyz/wallet-adapter/blob/ca731858affa36fa91b593cc670747b671c4589f/packages/core/base/src/standard.ts>.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** This closes a measured
> piece of the UI provenance boundary, but C1 still lacks the separate full-page
> approval route and every privileged method remains absent. There is no
> provider injection/registration, account or cluster authorization, approval
> record/digest/atomic winner, successful response/event schema, RPC, signer,
> pending-request recovery, or key use. The popup is an intentionally plain
> pre-alpha boundary status, not deployable wallet UX. Tabless action popups
> cannot be de-duplicated by document id because Chrome supplied none; the
> active-Port cap and lifetime are containment, not document identity.
> Independent second-model review remains **UNVERIFIED**.

> ## 2026-08-30 C1 LAZY PAGE BRIDGE — REAL CHROMIUM REACHABILITY, AUTHORITY STILL ZERO
>
> Commit `692e5509f7b4a62a8082aaccff2b9b89b8af315e` makes the named
> provider Port reachable from ordinary HTTP(S) frames through one static,
> default-isolated content script. Exact-SHA focused evidence: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
> → **180/180**, exit **0**; the corresponding extension `typecheck`, core
> `build`, and extension `build` commands each exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> playwright test -c playwright.config.ts` → **1/1**, exit **0**. This is not
> the repository deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache
> bash .claude/test-gate.sh` on the ledger-inclusive SHA before claiming this
> loop boundary green.
>
> The initial red lane was executable: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/content-bridge.test.ts test/manifest-storage.test.ts` failed
> because `src/content/bridge.js` did not exist and `content_scripts` was
> absent. The implemented outer wrapper has exactly `version`, direction-tagged
> `type`, and opaque `payload` fields. It accepts only same-window messages whose
> browser event origin equals the document's captured canonical HTTP(S) origin;
> neither check is treated as background authority. The background still parses
> the inner request and derives document/origin/tab/frame solely from
> `Port.sender`. Only the exact `WARDEN_METHOD_UNAVAILABLE` response may return;
> an unexpected background payload closes the bridge instead of crossing into
> the page.
>
> Harsh review rejected the first unit-green bridge because it opened a Port in
> every matching frame during `document_start`. That would wake Warden during
> ordinary browsing, spend the 256-Port budget on unrelated/ad frames, and leave
> a long-lived page dead after MV3 suspension. The committed bridge installs only
> a page listener, opens a Port on the first exact request, retains no eager
> reconnect loop, and lazily reconnects on the next request after disconnect. A
> stale synchronous send gets one fresh-Port retry; two failures close the
> bridge. The shared 1,024-request ceiling applies across every reconnect for one
> document, so reconnect cannot erase the abuse budget. The emitted-content
> dependency allowlist contains only `content/main.ts`, `content/bridge.ts`, and
> `provider-protocol.ts`; a background/storage/keyring/RPC import now fails the
> build.
>
> The mandatory Playwright lane loads `dist/` as a real unpacked MV3 extension.
> It receives the exact unavailable response from a top document and a
> cross-origin iframe, rejects a parent-to-child forged request using a later
> valid Port response as a causal ordering barrier, responds after same-tab
> navigation, closes the live service-worker CDP target, observes no remaining
> extension worker target, then wakes it from a new request in the **same page**.
> A CDP-injected pre-stop global is absent after wake, proving a new worker
> execution context rather than trusting Playwright's stale Worker wrapper.
> The first browser assertion itself was wrong: Node reports a
> `chrome-extension:` URL's `origin` as `null`; the corrected lane derives the
> extension id/URL prefix explicitly. A second false-green candidate—a 300 ms
> negative iframe wait—was replaced by the causal Port-ordering barrier.
>
> The manifest permission really expanded. Static `content_scripts.matches` for
> `http://*/*` and `https://*/*` is Chrome host access and can produce a broad
> read/change warning even though no separate `host_permissions` key exists.
> The permission and exclusions are documented in `apps/extension/README.md`.
> `file:`, browser/extension pages, data URLs, and opaque `about:blank`/`srcdoc`
> frames remain excluded; there is no `externally_connectable`, web-accessible
> resource, main-world injection, or Wallet Standard registration. Current
> Chrome references:
> <https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts>,
> <https://developer.chrome.com/docs/extensions/reference/manifest/content-scripts>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>.
> Wallet Standard core was inspected at `c49b56d60fbac2e68e0f3536707fa33030652f9e`
> and Anza's extension example at `4b6a165dc8fdedc28a59af05a72a0f91cefffc0d`;
> Warden did not copy the example's indiscriminate forwarding.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** This is still not a wallet
> provider: no page API is injected or registered, every method is unavailable,
> and no account, cluster, approval, UI route, RPC, key, or successful response
> exists. Same-page JavaScript can forge, observe, suppress, or spoof bridge
> traffic; the current unavailable-only response leaks no wallet state, but the
> successful provider design must treat the whole page as caller authority.
> The browser lane stops an idle/settled worker, not a pending privileged request;
> one Linux bundled-Chromium run does not establish Chrome-version/store/manual
> compatibility; navigation churn/tab-id reuse and the 1,024 ceiling's ecosystem
> compatibility remain unmeasured. Independent second-model review remains
> **UNVERIFIED**.

> ## 2026-08-30 C1 MV3 WAKE CORRECTION — LISTENER SYNCHRONOUS, AUTHORITY STILL ZERO
>
> Commit `26f3904c1d1497d81c8d3727387e62f0cc651f2a` corrects a
> load-bearing lifecycle defect in the previous provider-Port boundary. Exact-SHA
> focused evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **165/165**, exit **0**; the corresponding
> `typecheck` and `build` commands each exit **0**. This is not the repository
> deploy gate; run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the ledger-inclusive SHA before claiming this
> correction green.
>
> Chrome's MV3 contract requires event listeners in service workers to register
> synchronously during top-level script evaluation. The prior implementation at
> `6cabc403` installed `runtime.onConnect` only inside the promise that followed
> storage restriction and session restoration. That unit suite proved the wrong
> behavior: after worker suspension, the incoming connection that wakes the
> worker could arrive before the asynchronous listener existed and be missed.
> Official sources:
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/events>,
> <https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers>.
>
> The hostile lifecycle test first failed **3/3** new synchronous-registration
> assertions with zero listeners observed. The corrected startup installs only
> the already-audited zero-privilege boundary synchronously. A pre-readiness Port
> test proves a valid request returns only `WARDEN_METHOD_UNAVAILABLE` while the
> session storage read count remains zero. Storage restriction/session restore
> still define `background.ready`, the mandatory gate for every future
> storage-backed or privileged subsystem. Rejected readiness, explicit disposal,
> and synchronous bootstrap failure remove the wake listener. Harsh review found
> the synchronous-throw rollback gap in the first fix; its red test observed one
> leaked listener, and the final test now observes zero.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** No content script or provider
> can open the Port, and no account, UI, approval, key, RPC, or successful method
> is connected. Unit mocks now prove registration timing within one JS turn, not
> Chrome's real worker-stop/wake behavior. An unpacked-extension Chromium vector
> that opens the Port from a real top-level page and cross-origin iframe, then
> navigates/reconnects, remains required. Independent second-model review remains
> **UNVERIFIED**.

> ## 2026-08-30 C1 PROVIDER-PORT OWNER — EMITTED, ZERO PRIVILEGE, PAGE BRIDGE ABSENT
>
> Commit `2975296eeff4f1096146174be41649ec399590b5` installs the first
> production `runtime.onConnect` provider boundary, but deliberately gives it no
> account, approval, RPC, signing, decrypt, export, or dispatch hook. Exact-SHA
> focused evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **162/162**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension
> typecheck`, `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core build`, and `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/extension build` each exit **0**. These are not the repository
> deploy gate. Run `env npm_config_cache=/tmp/warden-npm-cache bash
> .claude/test-gate.sh` on the final ledger-inclusive SHA before claiming this
> loop boundary green.
>
> The initial hostile lane failed for the intended reasons: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/provider-port.test.ts test/runtime.test.ts` could not load the
> absent `provider-port.js`, and two runtime assertions failed because
> `startBackground` did not exist. The new per-Port owner binds the frozen
> browser-derived extension/document/origin/tab/frame tuple to each parsed,
> copied request; mints a separate 128-bit Web Crypto identity that is never
> returned to the page; refuses duplicate in-flight correlations; never reuses
> an internal id on one Port; caps 32 pending, 1,024 total requests per Port, and
> 256 active Ports; and permits only one owner for a browser `documentId`.
> Disconnect, malformed input, account change, boundary disposal, clock failure,
> and timer failure synchronously abort the exact owned lease. Expiry is enforced
> by an absolute-time check on every owner use plus a best-effort timer.
> Settlement and authority checks require the exact frozen lease object, not a
> page correlation or a coincidentally equal id from another Port.
>
> Storage restriction and session restoration finish before the global listener
> is installed. On a live Port, every syntactically valid method receives one frozen
> `WARDEN_METHOD_UNAVAILABLE` response carrying only the page correlation; every
> invalid sender, channel, or payload closes the Port. The built worker is
> **49,237 bytes** and contains `parseProviderRequest`, `warden:provider:v1`, the
> internal `req_` mint, and `WARDEN_METHOD_UNAVAILABLE`. `rg -n
> "node:fs|node:url|signMessage|signIn|warden:unlock|privateKey|secretKey"
> apps/extension/dist/background.js` exits **1** with no match. The first build
> exposed a real packaging defect: importing the broad `@warden/core` barrel
> pulled `node:fs` and `node:url` into the browser graph and failed resolution.
> Commit `2975296` fixes that by exporting/importing the browser-safe
> `@warden/core/constants` subpath; Node built-ins were not externalized or
> duplicated away.
>
> Harsh review repaired a false-green disposal test: its alleged two active Ports
> shared one `documentId`, so the second had already been rejected and multi-Port
> cleanup was never measured. The corrected test uses two live document owners.
> Disconnect coverage now also proves the released document slot accepts a
> replacement Port. Idle-expiry timers recheck absolute time and reschedule when
> fired early; the final authority check reaps expiry even if a timer is delayed.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** The current manifest still has
> no content script, injected provider, UI page, host permission,
> externally-connectable declaration, or web-accessible resource, so a webpage
> cannot reach this listener. There is no Wallet Standard `registerWallet`
> adapter, authorized-account/cluster binding, success/event schema, persistent
> request record, approval digest, idempotent sign/send path, or privileged UI
> route. `accountAddress` remains an untrusted lexical selector. Account-change
> cancellation exists only as an owner primitive because no account state is
> wired. Service-worker restart drops in-memory requests rather than resuming
> them. Chrome navigation is represented only by a mocked Port disconnect; an
> actual Chromium content-script/navigation vector is **UNVERIFIED**. The local
> TTL/cap choices are unmeasured compatibility limits. Independent second-model
> review also remains **UNVERIFIED**. The next safe slice must add an actual
> content-script/page bridge that still exposes no successful wallet method, then
> measure sender and disconnect behavior in Chromium before any authority is
> connected.

> ## 2026-08-30 C1 PROVIDER-SCHEMA BOUNDARY — CLOSED INPUT, ROUTER STILL ABSENT
>
> Commit `16663cb347707fc564698a9ac76a29ee987e9bd0` adds a pure,
> closed provider-request parser without making a provider or wallet method
> reachable. Exact-SHA focused evidence: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension test`
> → **130/130**, exit **0**; the corresponding `typecheck` and `build` commands
> each exit **0**. This is not the repository deploy gate. Run `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the final
> ledger-inclusive SHA before claiming this loop boundary green.
>
> The initial hostile lane failed for the intended reason: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/provider-message.test.ts` had **1 failed suite / 0 collected
> tests** because `provider-message.js` did not exist. The final 68-test lane
> accepts only exact version-1 JSON envelopes for `standard:connect`,
> `standard:disconnect`, `solana:signTransaction`, and
> `solana:signAndSendTransaction`. It rejects `signMessage`, `signIn`, the
> non-request `standard:events` feature, unknown methods, page-supplied
> origin/tab/frame/approval/policy context, extra or missing fields, malformed
> correlation ids, ambiguous options, sparse/non-byte/oversized transactions,
> unsupported chains, unsafe integers, cycles, and inputs over the local 16 KiB
> cap. Accepted byte arrays and normalized nested records are copied and frozen.
> The account address remains explicitly an untrusted lexical selector; a future
> handler must resolve it against its own authorized-account record.
>
> Harsh review caught and repaired one false-green test: the first oversized
> vector also carried an illegal `padding` field and only asserted an error type,
> so closed-field rejection could have passed even with a broken size gate. It
> now requires the exact size-limit error, proving global rejection happens
> before schema dispatch. TypeScript also rejected union-specific test accesses
> until the tests proved the method discriminator; the production union was not
> weakened to accommodate the tests.
>
> Current Wallet Standard declarations were re-read at Anza commit
> `4b6a165dc8fdedc28a59af05a72a0f91cefffc0d` and core commit
> `c49b56d60fbac2e68e0f3536707fa33030652f9e`. Transaction methods are variadic,
> take raw `Uint8Array` bytes and a `WalletAccount`, and define the exact
> commitment/send option fields; the eventual provider wrapper may split a batch
> into separately owned internal requests, while this privileged boundary accepts
> one transaction only. Chrome uses JSON serialization for extension messages,
> so the internal wire form deliberately uses dense number arrays rather than
> trusting typed-array or page-owned `WalletAccount` objects. Sources:
> <https://github.com/anza-xyz/wallet-standard>,
> <https://github.com/wallet-standard/wallet-standard>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>.
>
> The binding design contradiction is corrected in the specification: v1 no
> longer advertises `solana:signMessage` or `solana:signIn`. Wallet Standard
> provides only an optional `ed25519` signature type for those flows; a session
> signature cannot verify as Warden's advertised SmartAccount PDA, and Solana has
> no standard smart-account validation contract analogous to ERC-1271. Quietly
> returning a doomed signature would be compatibility theater, not support.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** `main.ts` imports neither the
> sender classifier nor this parser. After the exact-SHA passing build, `rg -n
> "parseProviderRequest|invalid provider request"
> apps/extension/dist/background.js` exited **1** with no match. There is still no
> provider, content script, response/event schema, named port, runtime listener,
> per-port request owner, duplicate-correlation rule, browser-minted security id,
> disconnect/navigation cancellation, authorized-account binding, approval
> record, or privileged method. The 16 KiB cap is a local protocol choice, not a
> measured compatibility ceiling, and the parser does not decode a Base58 selector
> into a 32-byte public key because authorization must compare it with a
> background-owned account anyway. The next safe slice is a zero-privilege port
> owner that binds the browser-owned tuple, parses every inbound value, mints its
> own request identity, and atomically cancels on disconnect—still returning a
> deterministic unavailable result instead of signing, decrypting, exporting, or
> approving anything. Independent second-model review remains **UNVERIFIED**; no
> result or review artefact was fabricated.

> ## 2026-08-30 C1 SENDER-CLASSIFIER BOUNDARY — PURE TUPLE, ROUTER STILL CLOSED
>
> Commit `fcf4a255e0809a41f6b8033db12b0fb4762ff40e` adds a pure
> `Port.sender` classifier without making a wallet method reachable. Exact-SHA
> focused evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **62/62**, exit **0**; the corresponding `typecheck`
> and `build` commands each exit **0**. This is not the repository deploy gate.
> Run `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on
> the final ledger-inclusive SHA before claiming this loop boundary green.
>
> The initial hostile lane failed for both intended reasons: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/extension exec
> vitest run test/manifest-storage.test.ts test/sender-provenance.test.ts` had
> **2 failed files**—the manifest still advertised Chrome 102 instead of 106,
> and the classifier module did not exist. The provider classifier now requires
> this extension's browser-owned sender id, a bounded document id, safe tab/frame
> ids, one canonical HTTP(S) frame origin, and a matching frame URL. It ignores
> the top-level `tab.url`, so a cross-origin child keeps its own origin, and its
> frozen tuple includes `documentId` so a reused tab/frame cannot silently look
> like the prior document. The privileged-UI classifier additionally requires
> the exact `chrome-extension://<runtime-id>` origin, an exact literal allowlisted
> path with no query/fragment/normalization ambiguity, and a top-level frame when
> hosted in a tab. A same-extension-id content-script mock with a web origin is
> rejected. Native, opaque, missing, mismatched, oversized, and non-active-at-open
> sender shapes fail closed.
>
> The manifest minimum moved from Chrome 102 to **106** because the classifier
> refuses senders without `MessageSender.documentId`; Chrome introduced that
> browser-owned document UUID in 106. Chrome also documents that `origin` may
> differ from `url` for `about:blank` and may be opaque for sandboxed frames, that
> an iframe sender URL is the iframe URL rather than its host page, and that
> `documentLifecycle` is only a port-creation snapshot which may already be stale.
> Chrome's messaging guidance says content scripts are less trustworthy and their
> messages should be treated as attacker-crafted; it also says ports disconnect
> when their tab/frame unloads. Sources:
> <https://developer.chrome.com/docs/extensions/reference/api/runtime>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/messaging>.
>
> **Do not promote `WRD-EXT-01` or `WRD-EXT-02`.** These are unit mocks, not an
> actual-browser content-script/popup/full-page vector. No UI page, provider,
> content script, port name, closed message schema, runtime listener, request
> owner, payload-context stripper, disconnect/navigation cancellation, account
> binding, or privileged method exists. The built worker intentionally does not
> import this unused source: after the passing build, `rg -n
> "classifyProviderSender|invalid sender provenance"
> apps/extension/dist/background.js` exited **1** with no match. That keeps the
> current artifact closed but means the classifier is not yet an exercised
> runtime control. Carrying `documentId` distinguishes two tuples; it does not by
> itself cancel the first request. `documentLifecycle` can go stale after open.
> HTTP origins are identified, not thereby trusted or authorized. The future
> router still controls the UI allowlist and could misconfigure it. The next safe
> slice is closed, per-channel message schemas and a zero-privilege port owner
> that binds this tuple and disconnects on every rejected shape—still before any
> signing, decrypt, export, approval, or account method. Independent second-model
> review remains **UNVERIFIED**; no result or review artefact was fabricated.

> ## 2026-08-30 C1 MV3 SESSION-OWNER BOUNDARY — LOADABLE SCAFFOLD, WALLET SURFACE OPEN
>
> Commit `36c7e4bee57dba4b2b7efce498d25818bcba4fb3` creates the first
> `apps/extension` production package without pretending it is a wallet. Exact-SHA
> focused evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/extension test` → **21/21**, exit **0**; the corresponding `typecheck`,
> `@warden/core build`, and `@warden/extension build` commands each exit **0**.
> This is not the repository deploy gate. Run `env
> npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the final
> ledger-inclusive SHA before claiming this loop boundary green; that gate now builds
> core, typechecks the extension, and bundles the extension after unit tests, so a
> browser/package failure can no longer hide behind Vitest transpilation.
>
> The development-only MV3 manifest requests only `storage`; it has no host or
> optional permissions, content script, provider, UI page, externally-connectable
> surface, or production manifest `key`. CSP permits only local scripts and objects.
> Both `storage.local` and `storage.session` are explicitly changed to
> `TRUSTED_CONTEXTS` before the worker reads session material. The new browser-safe
> `@warden/core/keyring` package subpath prevents Node-only deploy-verifier imports
> from entering the bundle; the initial build correctly failed on `node:fs` until
> that packaging defect was fixed rather than externalized.
>
> `UnlockSessionOwner` owns one stable controller per committed unlock, uses live
> `Date.now` by default, and stores one strict versioned JSON-array record in
> `storage.session` because Chrome documents arrays as serializable but generic
> objects such as typed arrays as typically becoming `{}`. Writes are serialized
> within one worker and exact-readback checked. Activation is unusable until
> remove→set→get verification commits; touch cannot revive a session that expires
> while storage is pending. Lock aborts and overwrites JS-owned key/account/result
> copies synchronously before a stalled removal settles. Worker construction first
> restricts both storage areas, then restores only a structurally valid live record;
> malformed, expired, mismatched-readback, and storage-error paths fail closed.
>
> The 15 owner tests are race measurements, not expected values derived from the
> implementation: pending activation and touch, lock during pending `sign`-labelled
> byte work, output zeroing before stalled cleanup, exact idle boundary, fresh-owner
> restoration, unknown stored fields, storage corruption, and rejected set/remove.
> Two bootstrap tests prove no session read occurs before *both* access restrictions
> settle; four manifest tests pin the closed surface and CSP. A fresh-profile
> Playwright Chromium command registered
> `chrome-extension://dbiijdmocimnnmdikokaaffeibkdcnhi/background.js` and evaluated
> the expected manifest plus `{}` session state at the worker. The first branded
> `google-chrome --load-extension` attempt explicitly said the flag was ignored;
> its exit 0 is **not** evidence. The passing smoke proves load/startup only: it did
> not kill and revive a seeded worker. Two consecutive same-checkout builds produced
> `background.js` SHA-256
> `0aede20565988db7f6ae6568e5093a9ca496c74e5271aa5ecfcaf3fb0a9c0d4b`
> and `manifest.json` SHA-256
> `6cca662416bd013d22f5170af994d8b9dc5f4b5178c5a5184967b4b39b9c6368`.
> That is explicitly **not** the two-isolated-builder `WRD-REL-01` invariant.
>
> Primary-source platform constraints were rechecked on 2026-08-30. Chrome says
> `storage.session`/`AccessLevel` are Chrome 102+, session storage is memory-only and
> cleared on disable/reload/update/browser restart, local storage is content-script
> visible by default, and `set`/`get`/`remove` promises may reject. Chrome also says
> an MV3 worker normally dies after 30 seconds idle and loses globals, so storage—not
> global memory—is the continuity boundary. Sources:
> <https://developer.chrome.com/docs/extensions/reference/api/storage>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage/StorageArea/>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle>,
> <https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions>.
>
> **Do not promote `WRD-KEY-*`, `WRD-EXT-*`, `WRD-ORG-01`, or `WRD-REL-01`.**
> There is no persistent `storage.local` keyring consumer, Argon2/PRF UI, actual
> signing/decrypt/export API, provider/message router, browser-owned sender
> classifier, approval/ceremony/hardware owner, real worker-kill/wake vector,
> production extension identity, mainnet account-creation surface, isolated-builder
> comparison, or store artifact. A key-use callback can perform an irreversible side
> effect before its final check unless callers obey the local-computation-only
> contract. Most seriously, if Chrome rejects `remove`, local memory locks but a
> stale live session record may survive and restore after a crash; Chrome exposes no
> transaction/CAS/durability primitive that turns a failed deletion into a guarantee.
> The next safe C1 slice is a pure, closed-schema classifier for browser-owned
> `Port.sender` provenance with the content-script-as-UI, forged-context,
> nested-frame, stale-port, and navigation red vectors—before any privileged method
> becomes callable. Independent second-model review remains **UNVERIFIED**; no result
> or review artefact was fabricated.

> ## 2026-08-30 C2 LOCK-REVOCATION BOUNDARY — CORE RACE CLOSED, SESSION OWNER OPEN
>
> Commit `c2e216fdf930be94fd29d406b6f6ce215743f0b6` adds the smallest honest
> explicit-lock primitive to the keyring core. Exact-SHA focused evidence: `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core test` →
> **434/434**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core build` → exit **0**. This is not the repository deploy gate;
> run `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` on the
> final ledger-inclusive SHA before claiming the loop boundary green.
>
> `UnlockCheck` now requires a stable, session-owned `AbortSignal` in addition to
> absolute deadlines and its live clock reader. Deadline, reader and signal identity
> are snapshotted. Record, bundle and AEAD scopes register abort listeners for their
> own JS-owned secret buffers, close the preflight/listener race with another sticky
> signal check, suppress results when lock wins before the final check, and remove
> listeners in `finally`. `KeyringLockedError` distinguishes explicit revocation from
> deadline expiry without turning authentication failures into an oracle.
>
> The first red lane was load-bearing: `env npm_config_cache=/tmp/warden-npm-cache
> pnpm --filter @warden/core exec vitest run test/keyring-deadlines.test.ts
> test/keyring-envelope.test.ts` produced **2 failures / 49 passes**. The pure guard
> ignored an aborted controller and decrypt returned plaintext after lock. Final
> focused coverage is **22 deadline + 31 envelope + 25 bundle + 18 record** tests.
> The strongest record vector starts real `subtle.encrypt`, stalls only its returned
> promise, aborts the owning controller, and measures the caller password/plaintext
> and captured AEAD input as all-zero while the public record promise is still
> unsettled. It then releases the gate and requires typed lock rejection. This tests
> retention timing, not merely eventual cleanup or an expected value derived from
> production code.
>
> Primary-source correction: DOM defines `AbortSignal.aborted` as sticky state and an
> abort event, so listener registration must be followed by a state check because an
> already-fired event is not replayed. WebCrypto `encrypt()`/`decrypt()` accept no
> `AbortSignal`; their algorithms copy input bytes before continuing crypto work in
> parallel. Therefore this boundary claims immediate cleanup of observable JS-owned
> copies and suppression of late results, **not** cancellation or erasure of a
> browser-internal copy. Sources: <https://dom.spec.whatwg.org/#abortsignal>,
> <https://w3c.github.io/webcrypto/#SubtleCrypto-method-encrypt>,
> <https://w3c.github.io/webcrypto/#SubtleCrypto-method-decrypt>.
>
> **Do not promote `WRD-KEY-03`.** No extension/session owner exists to create one
> controller per unlock, reuse its signal for every operation, abort synchronously
> before clearing `storage.session`, in-memory references, pending ceremonies,
> hardware transports and approval state, or rebuild that state after worker wake.
> A fresh per-call controller would make this primitive theater. A synchronous Argon2
> call cannot process an event-loop abort until it returns, and a returned byte array
> is not magically revocable: the final consumer must re-check the same authority
> immediately before sign/decrypt/export. There is no signing API, so the plan's
> required lock-during-pending-signing vector remains UNVERIFIED. Independent
> second-model review also remains UNVERIFIED; no review artefact was fabricated.

> ## 2026-08-30 C2 LIVE-DEADLINE BOUNDARY — ASYNC EXPIRY CLOSED, LIFECYCLE CANCELLATION OPEN
>
> Commit `968a71138922087cf887d8ce437ddcf35837c8e9` replaces the stale
> `UnlockCheck.now` sample with a live `readNow` clock authority. Exact-SHA focused
> evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core
> test` → **429/429**, exit **0**; `env npm_config_cache=/tmp/warden-npm-cache pnpm
> --filter @warden/core build` → exit **0**. This is not the repository deploy gate;
> run `.claude/test-gate.sh` on the final ledger-inclusive SHA before claiming the
> loop boundary green.
>
> Deadline values and reader identity are snapshotted before suspension. AEAD now
> reads the clock before key use and after each `importKey`, `encrypt`, and `decrypt`
> promise settles, including rejection paths. Envelope, bundle, and record wrappers
> re-check after their nested awaits. Record orchestration also re-checks immediately
> after synchronous Argon2id, because blocking the event loop does not stop wall time.
> If expiry crosses decryption, already-materialized plaintext is suppressed and its
> exact WebCrypto buffer is overwritten before the error escapes.
>
> The red lane was load-bearing: the old implementation produced **7 failures / 48
> passes** across envelope+bundle when the new contract was introduced. Final focused
> coverage is **19 deadline + 30 envelope + 25 bundle + 17 record** tests. Boundary
> tests advance the clock when the real WebCrypto `importKey`, `decrypt`, or `encrypt`
> promise resolves; they do not derive an expected result from the production check.
> The decrypt test retains the platform-returned `ArrayBuffer` and measures that every
> byte is zero after expiry. The legacy frozen-number shape, a throwing clock reader,
> caller mutation of deadline authority, and expiry after Argon2id are also pinned.
>
> Harsh review also removed a false blanket claim that every possible platform
> exception was normalized to a keyring error. Clock failures are typed, but callers
> must treat any unexpected WebCrypto/platform exception as fail-closed rather than
> authorization. A callback can still be miswired to return a constant; only the C1
> consumer can prove it supplies `Date.now`.
>
> **Do not promote `WRD-KEY-03`.** There is still no `apps/extension`, wake handler,
> trusted `storage.session` owner, or code that clears in-memory keys, session storage,
> pending ceremonies and hardware transports on expiry. A wall-clock deadline also
> does not cancel an operation after an explicit manual lock unless C1 provides a
> captured generation/cancellation authority. Library refusal is not lifecycle
> clearing. Independent second-model review remains UNVERIFIED; no row or artefact was
> fabricated.

> ## 2026-08-30 C2 PERSISTENT RECORD BOUNDARY — FORMAT CLOSED, ADAPTER/LIFECYCLE OPEN
>
> This block supersedes the earlier 2026-08-30 “next safe C2 slice” paragraph below.
> Commit `6ac4624b7eeb9e8bc434687f52b18d291edc5714` adds the record layer. Exact-SHA
> executable evidence: `env npm_config_cache=/tmp/warden-npm-cache pnpm --filter
> @warden/core test` → **420/420**, exit **0**; `env
> npm_config_cache=/tmp/warden-npm-cache pnpm --filter @warden/core build` → exit **0**.
> This is a focused package gate, not the repository deploy gate. Run the full gate on
> the final ledger-inclusive SHA; do not inherit the earlier SHA's result by prose.
>
> The persistent v1 value is now one strict binary record encoded as one canonical
> unpadded-base64url string: bounded Argon2id parameters + 16-byte salt, optional
> random 32-byte WebAuthn PRF input + independent 16-byte HKDF salt, and one KEK/DEK
> bundle. The exact metadata header is authenticated by every enrolled DEK wrap and
> by the payload, so PRF unlock rejects tampered password metadata and password unlock
> rejects tampered PRF metadata. PRF is truly optional: a credential/device without
> PRF now produces a password-only record instead of being blocked by a supposedly
> optional optimization. Argon metadata is rejected above 128 MiB / `t=10` / `p=16`
> before allocation; those are resource-exhaustion **ceilings**, never a measured
> password-hardening floor.
>
> `keyring-record.test.ts` has **16** tests: a hand-built binary vector, independent
> platform base64url comparison, every-prefix truncation sweep, strict flags/lengths,
> storage-value type/alphabet/canonical-tail checks, password-only + dual-route opens,
> outer-metadata tamper, cross-record splice, caller-mutation snapshot, and secret
> buffer cleanup on success/throw. `keyring-bundle.test.ts` is **24** tests and now has
> raw-WebCrypto vectors for record-bound AAD and the authenticated empty PRF slot.
> Derivation is **16** tests; envelope/AAD remain **27/21**.
>
> Hostile findings pinned red before fixes:
>
> 1. The prior dual-wrap API required PRF and therefore rejected valid non-PRF
>    credentials, contradicting the plan's mandatory password fallback.
> 2. Storing salts/parameters outside bundle AAD would let an attacker poison the
>    unused fallback while the other route continued to open successfully.
> 3. The first resource-ceiling test falsely passed because missing imported constants
>    became `undefined`, then `NaN`; exact constant pins exposed that wrong-attribute
>    green before implementation.
> 4. Malformed non-object Argon parameters escaped as raw `TypeError` rather than the
>    keyring's typed fail-closed error. The validator now rejects them explicitly.
>
> Primary-source platform findings: Chrome documents storage values as JSON
> serializable, `storage.local` as exposed to content scripts by default unless
> `setAccessLevel()` restricts it, and `storage.session` as trusted-context-only by
> default. It documents asynchronous `set()` success/failure but no transactional,
> CAS, or durable-write guarantee used here; this commit therefore claims only a
> one-value format, not atomic persistence. WebAuthn L3 defines PRFs over inputs of any
> length with 32-byte outputs and notes the security benefit of unpredictable inputs;
> v1 chooses a CSPRNG 32-byte input. Sources:
> <https://developer.chrome.com/docs/extensions/reference/api/storage/>,
> <https://developer.chrome.com/docs/extensions/reference/api/storage/StorageArea/>,
> <https://www.w3.org/TR/webauthn-3/#sctn-prf-extension>.
>
> **Do not promote `WRD-KEY-*`.** `apps/extension` and the Chrome adapter still do not
> exist. No code calls `storage.local.setAccessLevel(TRUSTED_CONTEXTS)`, serializes
> competing writers, verifies write/readback, puts minimum live material in trusted
> `storage.session`, or clears it on wake/lock/expiry. `UnlockCheck.now` remains one
> fixed preflight instant, so it does not re-read wall clock after each `await`. AEAD
> rejects partial/context splices but cannot reject replay of an entire older valid
> same-context record without an external freshness authority. Real-device PRF and
> slowest-desktop Argon2 remain UNVERIFIED; C1a's production-origin/migration decision
> remains owner-blocking. Independent second-model review remains UNVERIFIED for the
> host-policy reasons in the block below; no review row or artefact was fabricated.

> ## 2026-08-30 C2 KEK/DEK BOUNDARY — PRIMITIVE CLOSED, PRODUCT INVARIANT OPEN
>
> **Full gate green @`2b19883c8acedbd97633d3df24b9ea5556a6422f`:**
> `env npm_config_cache=/tmp/warden-npm-cache bash .claude/test-gate.sh` → exit **0**;
> `@warden/core` **400/400**, ui-tokens **11/11**, txbudget **8/8**, WebAuthn
> Playwright **1/1**, Rust **674 passed / 0 failed / 1 ignored**. The cache override is
> required only because this sandbox refuses npm's default `/root/.npm/_cacache`; the
> unoverridden run failed solely at `npm pack` with EROFS and is not a green gate.
>
> Commit `2b19883` closes the specific C2 construction gap called out below. The
> bundle format is now one random AES-256 DEK, one payload ciphertext, and two
> independently authenticated DEK wraps (Argon2id-password KEK and WebAuthn-PRF-HKDF
> KEK). Wrap AAD binds KDF/position, bundle id/version, component version, and all six
> Warden context fields. Payload AAD binds the exact encoded bytes of **both** wraps,
> so tampering or splicing the unused fallback poisons neither silently: both unlock
> routes fail closed. The strict bounded binary format has independent raw-WebCrypto
> vectors in both directions and a hand-built wire vector; expected ciphertext is not
> derived from production code.
>
> The hostile self-pass found two real async TOCTOU defects before commit: caller-owned
> plaintext/KEK/context buffers could be zeroed or mutated across WebCrypto awaits,
> producing a half-old/half-zero record, and the open path could authenticate a mixture
> of two mutable records. Both were pinned red then fixed by canonical snapshots and
> best-effort zeroing of private working copies. The old derivation test that claimed
> “same envelope” while actually sealing two different payload envelopes was removed.
>
> **Independent review is still UNVERIFIED.** A read-only `codex review --base` attempt
> rejected the required custom prompt before model startup; the equivalent ephemeral
> `codex exec -s read-only` attempt then failed client initialization with EROFS. A
> narrowly escalated retry was denied because initialization would write outside the
> authorized workspace. No model finding, review artefact, run row, or scorecard row was
> produced; do not claim second-model review green. The older canonical Codex range
> `c5a4514..77a8273` below remains owed independently of this new range
> `ac21fa3..2b19883`.
>
> **Research correction:** RFC 9106's second recommended Argon2id profile is 64 MiB,
> `t=3`, **`p=4`**, not `p=1`; the provisional constant and pin were corrected. This
> remains explicitly **UNVERIFIED** as a product floor until measured on the slowest
> supported desktop. Envelope-encryption shape was checked against Google Cloud KMS's
> DEK/KEK guidance; AES-GCM/IV requirements against NIST SP 800-38D; WebAuthn PRF's
> 32-byte output against WebAuthn L3; and `wrapKey()` extractability behavior against
> WebCrypto Level 2. Primary sources:
> <https://www.rfc-editor.org/rfc/rfc9106.html>,
> <https://docs.cloud.google.com/kms/docs/envelope-encryption>,
> <https://csrc.nist.gov/pubs/sp/800/38/d/final>,
> <https://www.w3.org/TR/webauthn-3/>, <https://www.w3.org/TR/WebCryptoAPI/>.
>
> **Do not promote `WRD-KEY-*`.** What remains is the actual product: `apps/extension`
> does not exist; no production record owns Argon2/PRF salts and parameters; no
> `storage.local`/trusted-only `storage.session` adapter consumes this format; no worker
> wake, lock, cancellation-generation, or expiry-clearing path exists; the real-device
> PRF matrix and slowest-device Argon2 benchmark do not exist. C1a's production
> extension-origin/migration decision is still owner-blocking. The next safe C2 slice
> may define the complete salt/parameter + bundle record and atomic storage contract,
> but it must not pretend to discharge C1 lifecycle enforcement.

> ## 2026-08-23 CODEX DIRECT ATTEMPT — BLOCKED / UNVERIFIED
>
> `scripts/review.sh c5a4514ab5e36faa6b4450bad7103f3f1cb5a7ca 6d714b29a24afdce97ec269404f95c34143b6c03 --kind task-diff`
> was run against exact `HEAD` `6d714b29a24afdce97ec269404f95c34143b6c03` with the pinned
> `gpt-5.6-sol@max` reviewer. The sandboxed attempt stopped before model startup
> with `Read-only file system (os error 30)`; one narrowly escalated retry cleared
> that initialization failure, reached the reviewer, and exited **1** after the
> OpenAI cybersecurity content filter fired. **The canonical Codex round remains
> owed; no review-green or gate-green claim is valid for this attempt.**
>
> Failure-state verification: `git status --porcelain=v1` and
> `git diff --name-only` were empty at the same SHA; `REVIEW-RUNS.jsonl` remained
> 101 lines and `REVIEW-SCORECARD.jsonl` remained 233 lines. The last recorded
> round is still the non-equivalent Grok fallback over `c5a4514..77a8273`.
> Only ignored expectation/schema artifacts were left; there is no result
> `.json`/`.raw.json` for the attempted Codex round. Do not hand-write a run row.
> Safe next action: obtain Trusted Access for Cyber or retry this exact command
> later without weakening the model, seed set, or range.

> ## 2026-08-23 CLOSE — READ THIS FIRST; it supersedes every block below.
>
> **Gate green @`89bfac2`:** `bash .claude/test-gate.sh` → exit **0**, Rust **674
> passed / 0 failed / 1 ignored**, `@warden/core` **377**, ui-tokens 11, spike 8.
> Ledger: **89 invariants**, 56 `test-covered`, 32 `unimplemented`. **101 recorded
> review rounds.**
>
> ### What is OWED (do these first)
> 1. **A Codex round over `c5a4514..77a8273`.** Round 101 was run by `grok-4.3`
>    through the new lane and does **NOT** discharge this. It is recorded with an
>    explicit caveat: materially shallower than Codex, and it ruled `WRD-EXEC-09`
>    `not_applicable` when that range is exactly what changed it. Retry
>    `scripts/review.sh` when the OpenAI content filter clears (it blocked 3× on
>    2026-08-23; a ~24 h wait cleared an identical block the day before).
> 2. **The C2 KEK/DEK slice.** The plan requires "an Argon2id password path that
>    can always unlock the same envelope". As built the password and PRF paths
>    derive DIFFERENT unwrap keys, so they cannot open one envelope. Needs one
>    random data key sealed twice. Deliberately unbuilt rather than half-built.
> 3. **The Argon2id benchmark.** `PROVISIONAL_ARGON2ID_PARAMS` (64 MiB/t=3/p=1) is
>    labelled `UNVERIFIED`. The plan requires measuring on the slowest supported
>    desktop before choosing a floor. **Do not cite it as measured.**
>
> ### What changed today
> - **WRDF-0105 took three rounds and the fix was wrong twice.** Final: a
>   **proven** drain (third-party T2022 account 9,000 → 0 via a real
>   `TransferChecked`, zero outflow, no cap debit) closed at `631291a`, then the
>   **class** closed at `89bfac2` — `execute` now fails closed on
>   `has_unrecognized_ext` or `UNMODELED_AUTHORITY_DANGERS`
>   (`DANGER_TRANSFER_HOOK | DANGER_CONFIDENTIAL`), err **6077**. Only 2 of 17
>   Token-2022 authority roles are extracted; the rest are refused rather than
>   guessed at.
> - **`WRD-EXEC-09` is HALF true by design** (transfer_hook + confidential now
>   unconditional in generic `execute`; permanent_delegate + transfer_fee are
>   deliberately NOT, pinned by two narrowness tests). Row stays `unimplemented` —
>   the text likely wants splitting rather than promoting.
> - **`WRD-CAP-09` was split** (WRDF-0108 caught the main loop promoting it while
>   its statement certifies the unbuilt `execute_pending`). New **`WRD-CAP-10`**
>   carries that conjunct at `unimplemented`.
> - **B4 done** as a narrow per-invariant pass; 8 rows promoted with per-test
>   evidence and honest caveats.
> - **C2 keyring core** built in `packages/core/src/keyring/`. All `WRD-KEY-*` rows
>   stay `unimplemented`: nothing produces or consumes the envelopes yet.
> - **`scripts/review-grok.sh`** — provider-independent recorded review lane.
>   Use `--max-chars 1000000`; the 600 K default elides whole-file context and
>   Grok (correctly) refuses to rule on an incomplete evidence base.
>
> ### Standing lesson from today
> Three of the day's findings were defects in the **adjudicator's** work, not the
> code's: a false invariant promotion from reading a truncated statement, a case
> dropped from a worker brief that the reviewer had explicitly named, and
> malformed provenance written into the scorecard *while fixing a finding about
> dishonest bookkeeping*. Also two false "green" claims from reading a piped exit
> code. **Verify against the whole artefact, and capture the real exit status.**

> **2026-08-23 — READ BEFORE THE 08-22 BLOCK BELOW; it supersedes it.**
> The Codex round this file recorded as *owed* has RUN and is recorded:
> `scripts/review.sh 9a427aa 0039681 --kind task-diff`, gpt-5.6-sol@max, 67
> seeded invariants, thread `phase1b/grok-remediation/round-1`, artefact
> `.superpowers/reviews/003968100ad1-20260823T090301Z.json` in REVIEW-RUNS.jsonl.
> No content-filter block this time — treat the 08-22 block as transient, not as
> a property of the diff. **4 findings, all ACCEPTED:** WRDF-0104 (important —
> System-owned durable-nonce + Loader-v4 accounts are outside
> `UNSUPPORTED_WRITABLE_OWNERS`, so root `execute` can move value unmetered),
> WRDF-0105 (important — `deny_scan` keys on the DIRECT payload program, so a
> forwarding CPI carries the PDA's propagated signer into FreezeAccount or a
> nested MintTo→Burn round-trip on a vault-controlled mint), WRDF-0106 (minor —
> the out-mint platform-fee floor uses NET output as its basis, but Jupiter's
> `outAmount` is already net of the fee, so the 85 bps floor under-charges),
> WRDF-0107 (minor — ledger/doc contradiction + green-gate claims naming no
> command or SHA; corrected in CLAUDE.md and PHASE1B-MEASUREMENTS.md).
>
> **B4 is DONE** (2026-08-23) as the narrow, per-invariant-verified pass the
> 08-22 entry called for — NOT a batch flip. 8 rows promoted with per-test
> evidence; WRD-FRZ-03 deliberately stays `unimplemented` (compound over the
> unbuilt `execute_pending`). Ledger 48 → 56 `test-covered`. Gate green at
> `86907bb`: `bash .claude/test-gate.sh`, exit 0, 655 Rust / 301 core / 11
> ui-tokens. The B4 line in the 08-22 block below is therefore CLOSED; its
> remaining "immediate open choices" are **C1** (MV3 extension) and **C2**
> (keyring).

> **GROK EXPLOIT AUDIT 2026-08-22 — READ FIRST.** Independent adversarial
> pass at `9a427aa35dd6e1f89c3fe00e5b1dd482118a87c6` (`phase1b`). Pickup
> memo: [`docs/security/GROK-EXPLOIT-AUDIT-2026-08-22.md`](security/GROK-EXPLOIT-AUDIT-2026-08-22.md).
> Program findings to patch before C1/C2/B4/vanity/UI: **GROK-EXP-03**
> (root `execute` can Stake/Vote/ProgramData-withdraw with no cap debit),
> **GROK-EXP-05** (session `swap` skips the registry and forwards the PDA
> signer into Jupiter `route` hops — same class, no root ceremony),
> **GROK-EXP-01** (swap treasury-fee floor is 1 unit, not 85 bps),
> **GROK-EXP-02** (root `execute` MintTo is unmetered if the PDA is mint
> authority), **GROK-EXP-04** (empty session execute skips the list-id-0
> gate and can consume a Stage), **GROK-EXP-06** (nested close + same-pubkey
> reincarnation evades the disappearance detector — Important spec-hole,
> not a proven unmetered vault drain), **GROK-EXP-07** (TS GrantBody
> comment drops `prior_authority_hash`; brick, not a forge — add
> `encodeGrantBody` before C3).
> **REMEDIATION DONE 2026-08-22:** all seven triaged; the six reproducible/
> confirmed findings are patched with red-at-BASE→green regressions (17 new
> GROK tests + inverted repro fixtures), full gate green. EXP-06's
> nested-both-halves case is a documented §5.3 residual (fee-payer-only, no
> vault net-loss), not closed. See docs/program/PHASE1B-MEASUREMENTS.md
> "GROK exploit-audit remediation" and the Codex sol@max review round in
> docs/security/REVIEW-RUNS.jsonl. No invariant `status` was promoted (B4
> stays deferred).
>
> **STATUS UPDATE 2026-08-22 — Phase 1B PROGRAM WORK COMPLETE.** All Phase 1B tasks
> (0/10/1/2b/2/3/4/5/6/8) plus **Task 11** (deploy-gate: WRD-DEP-01 governance/hash + WRD-DEP-02
> adapter-Registry) and **Task 9** (spec → rev 9 close-out) are DONE — 283 `@warden/core` tests,
> whole `phase1b` branch pushed. The Warden landing page is SHIPPED LIVE at drinkerlabs.info/warden/.
> The Phase-1B run order below is HISTORICAL; do not "resume Phase 1B" — it's finished.
> **What actually remains are OWNER decisions and later phases, not more 1B implementation:**
> (1) the C1a `create_account` production-origin + freeze-vs-migration decision before any public
> account creation; (2) an external security audit + the on-chain deploy (the L7 deploy-gate is
> built and tested but UNVERIFIED against a live cluster); (3) counsel sign-off on WRDF-0050
> (Squads AGPL lineage), WRDF-0089 (Squads reader), and the Jupiter-IDL note in THIRD_PARTY_NOTICES.md;
> (4) the client-security-hardening (C1+), vanity (V1+), and UI (U0+) plans, at their stated
> dependency boundaries. Release-candidate residuals are enumerated in PHASE1B-MEASUREMENTS.md.
> Read CLAUDE.md + the spec (rev 9) for the current truth before acting.
>
> **CLIENT TRACK (post-1B) — C2a DONE 2026-08-22.** `assertionToCompact()` (strict-DER + mandatory
> low-S) is built + unit-verified in `packages/core/src/webauthn/assertion.ts` and converged through
> Codex sol@max (round 4 = 0 findings @`3f56914`). **`WRD-SIG-01` intentionally stays `unimplemented`**
> (WRDF-0103): its binding acceptance needs the recorded high-S assertion through the REAL on-chain
> secp256r1 precompile end-to-end via the **C3** production ceremony builder (not yet built) — the
> in-process Noble check is a proxy, not the precompile. **B4 (ledger-honesty promotion) is NOT a batch
> flip:** of the 9 stale-unimplemented invariants, WRD-FRZ-03 needs `execute_pending` (Phase 1C),
> WRD-DENY-02 + WRD-EXEC-08 have no covering test found, and WRD-DENY-01 is only partial — so only a
> narrow, per-invariant-verified pass is legitimate. Immediate open choices: **C1** (MV3 extension trust
> boundary — large greenfield, wants owner visibility), the **narrow B4 pass**, or **C2** (keyring).
> See `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md` §C2a for detail.

TO / Claude Code

TASK / Read the dated research memo, resume Phase 1B in its documented order, execute the client-security plan at its permitted boundaries, carry the approved optional vanity-primary-account feature through V0 and then V1–V6 only after its SDK/extension dependencies are stable, and execute UI U0–U10 only at the design/client/mobile boundaries stated in its plan.

CWD / `/opt/warden`

BASE / Start from the committed `phase1b` HEAD containing this handoff. Before editing, run `git rev-parse HEAD` and verify `e5b5a19a9fb982c95ea294d0fc36ef1fd701096a` is an ancestor; record the actual starting SHA because this handoff cannot self-reference its own commit.

READ / `docs/OVERNIGHT-HANDOFF-2026-08-19.md` first; `CLAUDE.md`; `docs/superpowers/plans/2026-08-18-warden-phase1b-execute-swap.md`; `docs/superpowers/plans/2026-08-19-warden-client-security-hardening.md`; `docs/superpowers/plans/2026-08-19-warden-vanity-primary-account.md`; `docs/research/2026-08-19-wallet-ui-extension-mobile.md`; `docs/superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md`; `docs/design/figma.md`; `docs/superpowers/specs/2026-08-18-warden-wallet-design.md`; `docs/security/invariants.jsonl`; `docs/security/PRIOR-ART-FINDINGS.md`; `docs/security/THREATMODEL.md`; `docs/security/RELEASE-INTEGRITY.md`; `docs/research/2026-08-18-security-assurance-and-wallet-landscape.md`.

WRITE (edit lease) / Only the files assigned by the next unfinished Phase 1B task. At a clean boundary, client C0 and vanity V0 may edit their named spec/security ledgers, generated invariant Markdown, and ledger-presence tests. UI U0–U2 may edit Figma and `docs/design/figma.md` only under an explicit design lease; those frames do not authorize generated-token or extension-code edits. After Phase 1B Task 8 stabilizes the client SDK, use vanity V1–V3's leases for `packages/core/**`, new `packages/vanity-pda/**`, tests, and build/security ledgers. Client C1 must establish the production extension trust boundary before UI U7 or vanity V4–V6 edits `apps/extension/**`. Native mobile remains research/prototype-only until the owner authorizes implementation and framework selection. One active edit lease and one heavy build at a time. Do not spawn subagents unless the owner explicitly grants a number.

DO_NOT_TOUCH / `/var/www/**`; live deployments or accounts; publisher/store accounts; secrets or keypairs; `.superpowers/**`; `/root/.codex/session-graphs/**`; unrelated user changes; production `programs/warden/**` outside the active Phase 1B lease. The existing `/opt/vanity-bot/**` is read-only evidence only: never import its source, protocol, WASM, or generated assets. Never import production code from `spikes/**`.

ACCEPT / Preserve the Phase 1B order; seed client and vanity invariants before implementation; bind approvals and rendered intent to exact serialized bytes; keep simulation advisory; make authentication gate key release; derive vanity addresses only by grinding a public 32-byte salt for the root-bound Warden PDA; enforce 1–4 ASCII Base58 characters at every layer; default to suffix and case-insensitive matching with an exact-capitalization warning; independently re-derive worker results; perform confirmed account readback before copy/fund/receive; never treat a partial-address match as recipient verification; use exact-address provenance, full-address comparison, fresh authentication, and policy/timelock for poisoning controls; keep origin/decode/simulation/policy as independent UI axes; correct meaningful light warning indicators to at least 3:1; assign work across popup/side-panel/approval-window/full-tab surfaces; treat native mobile credential/link/privacy parity as UNVERIFIED pending real-device spikes; run the full merged-SHA gates; report every green gate with its exact command and SHA.

SIDE_EFFECTS / Repository documentation/code/test edits, Figma edits made under an explicit design lease, generated invariant/token Markdown or CSS produced by their source-controlled generators, and local build/benchmark/browser/accessibility artifacts only. No deploy, live-account mutation, credential creation/rotation, private-key generation/export, remote vanity acceleration, analytics change, store publication, external message, or secret handling without separate authorization.

RETURN / Merged SHA; `git status`; exact commands and results at that SHA; invariant status changes and evidence paths; Figma page/node ids and native-size capture paths; contrast/target/overflow measurements; state-matrix coverage; worker/CSP/storage/permission/network changes; benchmark, browser, accessibility, mobile-device, and comprehension artifacts; remaining UNVERIFIED items; owner decisions; confirmation of no unauthorized external side effects.

## Where to resume

**The governing document is now
[`2026-08-20-warden-research-adjudication-and-campaign-plan.md`](superpowers/plans/2026-08-20-warden-research-adjudication-and-campaign-plan.md)**
(joint Claude + Codex `sol@max` adjudication of this whole research corpus,
SHIP-DOC after three rounds). It sets the order and supersedes the priority list
that was here. Confirm branch/plan state rather than assuming the historical base
is still HEAD.

Landed base: the L0 harness gate, slot freshness, conservation, proof-of-
possession at account creation, the invariant ledger, and repo supply-chain
gates — **plus the 2026-08-20 A0 assurance pass** (executable review lane;
`REVIEW-RUNS.jsonl` recording every round incl. zero-finding; retrospective
threat-model deltas; five RED-verified conservation fund-loss fixes;
`WRD-CONS-*` unit-layer ledger rows). A0 close-out and the five fixes are in
`docs/program/PHASE1B-MEASUREMENTS.md`.

Also **C0+V0 DONE** (2026-08-20, 9 Codex docs rounds, close-out in
`docs/program/PHASE1B-MEASUREMENTS.md`): 26 client/vanity/deploy invariants seeded
at honest `unimplemented`; C1a / C2a / C4b / Task 5E / Task 11R / the Task 2 split
written into their source plans; V4/U7/V2 gating corrected; spec §6.1 vanity
section; cross-cluster AAD and 7-iteration deploy-gate governance hardened.

Remaining, in campaign-plan order:

1. **Task 2 DONE** (2026-08-20, 2A `204a118` + 2B `4c8575a`, 4 review rounds → 0
   findings): `test-mutator` + `test-jup-mock` + 18 harness smoke tests;
   `.claude/test-gate.sh` builds/checks both new `.so`. Close-out in
   `docs/program/PHASE1B-MEASUREMENTS.md`.
2. **Task 3 DONE** (`a7b7824`…`300face`, 7 review
   rounds → WRDF-0034..0044 all adopted+fixed; full gate re-run at the fix SHA,
   282 lib + 42 integration + 104 TS tests, clippy clean): Registry zero-copy
   state, selector-derivation rule (match on the `(program_id, selector)` pair;
   disc_len 8/1/4/0), `registry_allows` with `(program,selector)` authority-
   position role validators (fail-closed), default adapters, `init_registry`
   (upgrade-authority-gated), `grant_session` allowlist validation, `create_account`
   optional registry (**bound into the root ceremony**, CreateBody 183→215 B),
   TS/Rust parity, integration suite. NB: the System program id IS
   `Pubkey::default()`, so used slots are bounded by `n_entries`.
   **Round 5** (`3361d2c`) closed the round-4 deferrals for real:
   - **WRDF-0044** — `grant_session` now takes the account's `Registry` account,
     loads it, and requires `is_allocated_list(program_allowlist_id)` (not just
     structural `is_valid_list_id`) for any non-zero id. A grant can no longer
     persist a dangling list id that a Phase-1C mutable-registry update could
     silently activate without a fresh root ceremony. On-chain RED/GREEN:
     `grant_with_unallocated_allowlist_id_rejected` (id 3 → `InvalidAllowlistId`)
     and `grant_with_allocated_allowlist_id_accepted` (id 1 stored) — the latter
     is the positive on-chain grant that was the documented follow-up, now
     delivered. `WRD-SESS-07` inverted from "must be 0" to "must resolve to an
     allocated list".
   - **WRDF-0042** — TS core exports a canonical `encodeCreateBody` (215 B incl.
     the trailing registry `Pubkey`); doc corrected from 183 B; the pinned
     action-hash vector now validates the exported API, not a hand-roll.
   - **WRDF-0043** — full `./.claude/test-gate.sh` re-run on the fix SHA.
   Round 7 confirmation returned **0 findings at `300face`** — Task 3 is DONE.
   **Task 4 DONE — code-complete** (`d47d8ce`…`08a8b56`): stage_open/chunk/
   finalize/close, content-addressed + creator-bound Stage PDA, 23 integration
   tests incl. the ND-SQD3-LO-01 squat class (closed by construction), MEASURED
   stage_chunk cap **977 B v0/client** (979 legacy); whole-task sol@max review
   CONVERGED (5 rounds, WRDF-0045..0049). WRDF-0050 = owner/counsel
   release-blocker carried (blocks SHIP, not code).
   **Task 5 (`execute`) CODE-COMPLETE** (`a7efe93`…`3632deb`, parts 1–5):
   session/root (XOR) × inline/staged (XOR); fixed deny-list on BOTH paths
   before the registry; adapter registry on the session path;
   `conservation::snapshot`+`compare_and_account` around a real `invoke_signed`
   CPI loop; per-mint caps → `buckets::debit`; stage consume-once (WRD-STAGE-02).
   `OP_EXECUTE_ACTION=0x07` + TS `encodeExecuteBody`, cross-language-pinned. 320
   lib + 25 `tests/execute.rs` (real SPL+mutator CPIs) + 109 TS; clippy clean.
   Two design findings resolved: per-ix duplicate-index reject relaxed
   (vault-sweep close names the PDA twice); PDA-not-writable moved from the pure
   parser into `enforce_pda_writable` (handler, post-`deny_scan`) so the rule-4a
   vault-sweep close can credit the PDA while a writable PDA stays refused
   elsewhere. Errors 6056/6057.
   **Task 5 DONE (2026-08-21).** 4 sol@max review rounds converged (no new
   program findings by round 4): WRDF-0053 whole-logical-list uniqueness fixed
   (6059) + WRDF-0051 Jupiter direct-guard (6058, defense-in-depth, claim
   corrected round 2) + WRDF-0055 ceremony-bound-submitter doc+test + WRDF-0056
   WRD-EXEC-07 narrowed + WRDF-0057 gate evidence recorded. Standing
   `deferred`: 0051-nested → Task 6 adapter preflight; 0052 events → Task 5E;
   0054 dead System adapter → Task-3 hygiene. **Sweep verdict (measured, in
   PHASE1B-MEASUREMENTS §Task 5): the caps are HEAP-bound —
   `MAX_EXECUTE_ACCOUNTS_TOTAL=24` / `MAX_EXECUTE_WRITABLE=20`** (22-writable
   OK / 24 OOM on the default 32 KiB heap; `RequestHeapFrame` inert under
   Anchor's capped allocator; worst CU 83.8k ≪ 360k; v0+ALT ≤ 486 B),
   boundary-tested on-chain. **Task 6 PREREQUISITE DONE (@7936419):** a custom SBF heap
   allocator (`src/heap.rs`, `custom-heap` feature, default ON — uncapped
   upward bump, runtime-frame-bounded, fail-closed past it) replaced the
   entrypoint's 32 KiB-capped default. PROVEN: heap frames now work (mutator
   `heap_hog` 100 KiB fails without / OK with a 128 KiB frame); execute
   re-sweep hit 30-writable at 113k CU with a frame. **Caps lifted 24/20 →
   `MAX_EXECUTE_ACCOUNTS_TOTAL=32` / `MAX_EXECUTE_WRITABLE=28`**, boundary-
   tested; **client contract: the wrapper injects a `RequestHeapFrame` sized
   for the shape on any execute past ~24 accounts** (like the CU limit). Tables
   in PHASE1B-MEASUREMENTS §"Task 6 heap lift". **Task 6 (swap) DONE @949c1f5** — Jupiter v6-pinned adapter, 4 sol@max
   rounds → 0 program findings by round 4. Program+disc pin (real v6 / mock
   under --features test-jup), platform_fee_bps==85, CANONICAL source/dest/fee
   ATAs + PDA authority, net conservation. Native swaps REJECTED in 1B (CRITICAL
   WRDF-0061). Realized fund-loss bound stacked 4-deep: route_hash root-binding
   (0058) + treasury-fee-taken (0059) + writable-vault pinning (0065) +
   canonical-ATA pinning (0070), over net conservation + caps. IDL pinned
   (jup-ag/jupiter-cpi sha256 764ea6d7…). CI publishes a clean default-profile
   production .so + pin attestation. **Deferred, NOT 1B defects:** byte-exact
   Vec<RoutePlanStep> parse before mainnet (WRDF-0031/0059); structured events →
   Task 5E (WRDF-0052). **Task 8 (TS execute client) DONE @ef69e23** — `packages/core`
   `payload.ts` codec + `wrapForExecute` (build→compile→decompile the outer ix, derive
   accounts_hash+caps from runtime-COALESCED effective metas = one source of truth;
   fail-closed rejects for third-party signer / writable PDA / writable root signer;
   payload⊆outer subset guard; ComputeBudget hoist+normalize with CU-floor + always-on
   sized RequestHeapFrame + caller-frame align/range validation; client caps) +
   cross-language golden fixtures (read-only vectors + gate `git diff` drift guard).
   **9 sol@max rounds → round 9 = 0 findings.** SDK product code converged @round 3;
   rounds 4–8 hardened the review LEDGER itself (golden fixtures, scorecard reproducer +
   remediation provenance, CI shallow-clone fail-close, gate-contains-fix ancestry).
   WRD-EXEC-11/12 test-covered; gate green @d73118f. **Deferred, non-blocking:** a typed
   vault-sweep CloseAccount payload builder; an on-chain relayer/optional-alias execute
   integration (client subset guard + Rust cross-language hash oracle cover it short of
   that). **NOW: Task 11R (deploy-gate RPC), then Task 9 (close-out + spec rev 9).**
   **C1a needs a program change** (`create_account` must
   compare against a pinned production `rp_id_hash`, not just self-consistency —
   WRDF-0016/0027) plus the owner's freeze-vs-migration decision.
3. Corrected gating (was C1-only): **V4 waits for C1a + C2a + C3 + C4**; **U7
   token export waits for U0–U2 acceptance** (and live receipt rendering for
   C3 + C4). Client C1's trust boundary still precedes UI U7 and vanity V4.
4. **Task 11 is PARTIAL** — its deployment gate is spec + partial dry-run
   (`docs/security/DEPLOY-GATE.md`); Task 11R owns the RPC checks before Task 9.
5. Keep native mobile at prototype/research scope until the owner authorizes an
   implementation framework and real-device spikes close credential, verified-
   link, MWA, and capture/privacy uncertainties.

Owner decisions owed (none block C0+V0 or Task 2): the C1a freeze-production-ID
vs authenticated-migration choice; a U0–U2 Figma design lease (for a session
after the current two); scheduling the real-device WebAuthn PRF spike; the
Certora quote at 1B close-out; a Task-9 baseline exception for the pre-A0 review
rounds that were never recorded (recommended: approve, gap named honestly); and
CI `fetch-depth: 0` so the evidence-at-SHA ledger gate is load-bearing in CI.

## Plans to carry forward

- [`2026-08-20-warden-research-adjudication-and-campaign-plan.md`](superpowers/plans/2026-08-20-warden-research-adjudication-and-campaign-plan.md) — **governing order**
- [`2026-08-19-warden-client-security-hardening.md`](superpowers/plans/2026-08-19-warden-client-security-hardening.md)
- [`2026-08-19-warden-vanity-primary-account.md`](superpowers/plans/2026-08-19-warden-vanity-primary-account.md)
- [`2026-08-19-wallet-ui-extension-mobile.md`](research/2026-08-19-wallet-ui-extension-mobile.md)
- [`2026-08-19-warden-s-tier-ui-mobile.md`](superpowers/plans/2026-08-19-warden-s-tier-ui-mobile.md)

The client plan addresses the largest process holes found in the wallet-source
comparison: key lifecycle, browser message provenance, approval single-use
semantics, exact-bytes intent, simulator binding, recovery export, and release
authority.

The vanity plan records a **go** decision with a narrow design: an optional first
SmartAccount address, not a master private key. Warden already derives the PDA
from `Keccak256("WARDEN/seed/v1" || root_pubkey33 || salt32)`, so the feature
searches salts locally and preserves the passkey root. Four characters is a hard
cap. Suffix and case-insensitive matching are defaults; exact capitalization is
optional and explicitly warned as slower.

The UI research and U0–U10 plan define “S-tier” as measurable comprehension,
state coverage, accessibility, privacy, responsive behavior, token parity, and
real-device evidence—not visual polish alone. Warden Receipt is the flagship
surface, and the popup is only one part of the extension architecture.

## Vanity corrections that must survive handoff

- Base58 excludes only `0`, `O`, `I`, and `l`. All other Base58 characters are
  admissible in 1–4 character prefix/suffix requests.
- Do not copy `/opt/vanity-bot`'s first-character whitelist or special `J` rule;
  it assumes a fixed 44-character encoding and rejects valid 43-character
  addresses. A session-local probe found a valid Warden PDA beginning with `W`.
- Do not copy its `33^n` case estimate or fixed "remaining" countdown. Prefix
  probabilities are character/length dependent and search completion is
  geometric; show calibrated 50%/95% probability windows.
- Do not reuse the bot's private-key-producing WASM or message shape. The Warden
  worker returns only salt/owner-seed/address/bump metadata and is independently
  verified through the supported core derivation.
- Freeze program id, cluster/config, account seed, and seed-domain version before
  any long search. A change to any of them changes the target address.
- Vanity is cosmetic, never identity. Full-address, saved-contact, and
  address-poisoning defenses ship with it.

No build or test gate was run merely because these proposal documents exist. Do
not infer an implemented feature or a green build from this handoff.
