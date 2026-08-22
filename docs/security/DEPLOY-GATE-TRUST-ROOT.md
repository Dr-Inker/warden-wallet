# Deploy-gate trust root & terminus (WRDF-0092)

The L7 deploy gate (`scripts/deploy-gate.sh` + `packages/core/scripts/deploy-gate-verify.ts`)
refuses to deploy unless a set of governance/hash/release facts hold. This note states
**exactly what the gate authenticates and where its trust root terminates** — so the
verifier-substitution question (raised across review rounds 8→10) has a definite, honest
answer instead of an infinite regress.

## What the gate authenticates
1. **Remote / on-chain facts** — upgrade authority, Squads 3-of-5 config (members, masks,
   threshold, time-lock, configAuthority, no actionable stale proposal), audited Squads
   code hash, on-chain Warden program code hash — cross-checked against pinned, committed
   config and the CLI-supplied identities. **These checks establish the internal
   *consistency* of the RPC's responses, not their *authenticity*: the genesis hash and
   every account are read through one `Connection`, so a malicious endpoint that returns
   the expected genesis and fabricates self-consistent account bytes (e.g. ProgramData
   whose bytes hash to the pinned release) can forge checks 1/2/4a.** The RPC is therefore
   a **declared trusted input** (see terminus below), not an authenticated one — the
   operator must point the gate at a known-good endpoint (or, if malicious RPCs are moved
   into the threat model, a multi-endpoint quorum, which is not implemented today). What
   the gate *does* defend against, given a trusted RPC, is a stale/weak/attacker
   governance config, a wrong program or authority identity, and a release-hash mismatch.
2. **The release artifact** — the RELEASE-INTEGRITY row is bound non-self-referentially
   (clean tree + release-sha an ancestor of HEAD) and parsed by one canonical parser to a
   unique `manifest:<name>@<digest>` + artifact hash.
3. **The verifier's own SOURCE** — `verify_source_attestation` re-hashes the committed
   verdict-bearing closure (`docs/security/verifier-attestation.json`: the entrypoint plus
   every `src/deploy/*.ts` it transitively imports) and **refuses, fatally, before any
   verifier invocation** on a missing manifest, an entrypoint-identity mismatch, or any
   attested file that is missing or altered. This catches a swapped `.ts` or a decoy
   entrypoint **independently of the clean-tree check**, which is blind to gitignored
   `node_modules`.

### What closure discovery does and does NOT prove
The attested closure is discovered by statically parsing the entrypoint's import graph, and
every discovered file is sha256-pinned. Be precise about the guarantee:

- **What the pin proves.** For the graph discovery *does* find, the pinned bytes are
  authenticated: a swapped or missing `.ts` in that graph is refused. For the **actual**
  verifier — which uses only static relative imports plus three allow-listed dependencies
  (`@solana/web3.js`, `@noble/hashes/sha2`, `node:fs`) and `process` for argv/exit — the
  graph is discovered completely and pinned exactly.
- **What it does NOT prove (the honest limit).** Static discovery is **not** a sound
  analysis of arbitrary code. A reflective language always admits further aliases —
  `Reflect.get(globalThis, "eval")(readFileSync("./x.js"))` reaches `eval` through a string
  argument no finite name list can enumerate. So the pin authenticates the *indirection*
  present in the attested source, **not the bytes reached through a reflective load**. If a
  verifier source file that *already passed review* contained such a reflective load of an
  un-pinned file, a later clean descendant could swap that file without tripping any pin.
- **Defense in depth, not a completeness proof.** Discovery still rejects fail-closed the
  demonstrated and common vectors — a disallowed specifier (anything but a relative import
  or an exact `PERMITTED_EXTERNAL` entry: absolute paths, `file:`/`data:` URLs, surprise
  packages, `node:module`), a dynamic `import()`, `import x = require(...)`, a non-literal
  specifier, an out-of-repo resolution, and references to reflective/eval APIs (`eval`,
  `Function`, `getBuiltinModule`, `createRequire`, `require`, `.binding`, `Reflect`,
  `globalThis`, `global`, `.constructor`). This raises the bar but is explicitly **not**
  claimed complete.

**Residual and where it terminates.** Closing the reflective residual *soundly* requires a
**runtime permission boundary** — executing the pinned verifier under a policy that denies
reading/loading any un-approved file (e.g. Node's permission model). That is **deferred**
as a hardening for a real deploy candidate, not a Phase-1B blocker. In the interim the
operative control against malicious reflective code *entering* an attested verifier file is
the **two-model review lane** (every commit is adversarially reviewed by Codex — which is
exactly how this residual was found), plus the human owner's review. Attestation defends
against file placement/swap by an actor who *cannot* pass review; a reflective self-exfil
requires committing reviewed code, which is that review lane's boundary, not the pin's.

## Where the trust root terminates (the declared external assumption)
Below the attested source lies the **JavaScript execution toolchain** — the Node runtime,
the `tsx` transpiler, and their `packages/core/node_modules` closure — and the **host OS**.
The gate does **not** authenticate these, and no in-repo mechanism can:

- `node_modules` is gitignored, so a file placed there is invisible to the clean-tree
  check; hashing the entire transitive dependency + runtime closure from within the same
  untrusted runtime is circular.
- **An actor who can replace a file under `node_modules` already has local write/execute on
  the deploy host** and can equally replace `scripts/deploy-gate.sh` itself, the `node`
  binary, `sha256sum`, `git`, or the shell. A gate cannot defend a host that is already
  executing attacker-controlled code; the attempt is an infinite regress
  (env → PATH → node_modules → tsx → node → OS → firmware).

This is the **same kind of terminus already accepted elsewhere in Warden**: the Squads
audited-**code hash** is pinned and the trust root declared to terminate there because a
program's bytes are not otherwise verifiable while upgradeable (WRDF-0017 r6), and the RPC
is a **declared trusted input** cross-checked but not itself authenticated. The local
execution toolchain is one more such terminus.

### Operator obligation (how the assumption is discharged)
Run the gate from a **clean checkout on a trusted host or hermetic CI**, with a toolchain
provisioned by the normal (locked) install — not on a host whose `node_modules`, PATH, or
system binaries an adversary can write. This is the standard precondition of any
build-time security gate.

## Correction to the round-9 record
The round-9 commit/ledger claimed "no PATH, no shell/Node hook can substitute the
verifier." That was an **overclaim**: the gate had removed the outer `pnpm`/PATH lookup,
but `tsx` lived in gitignored `node_modules` and `dirname`/`node` were still resolved
outside the attested set. Round 10 (WRDF-0092/0088) narrows the true guarantee to the one
stated above — source is authenticated; the runtime below it is a declared terminus — and
removes the two cheap residual PATH lookups (`dirname` replaced by shell parameter
expansion; the preflight invoked by repo-relative path after `cd`).
