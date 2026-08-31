# Next Session — Claude Security, Vanity, and UI Handoff

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
