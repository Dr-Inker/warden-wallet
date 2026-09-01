# Warden extension boundary

This is a pre-alpha development extension. It must not be used with real funds.

## Deterministic upload artifact

From a clean committed tree, with the exact Node and pnpm versions pinned in the
root `package.json` and `.node-version`, run:

```sh
pnpm --filter @warden/extension release:gate
```

The command rebuilds the extension and writes four ignored, local artifacts
under `apps/extension/release/`:

- `unpacked/`, with files normalized to mode `0644`, directories to `0755`, and
  every mtime to `1980-01-01T00:00:00.000Z`;
- `warden-extension-<version>.zip`, a classic non-ZIP64 STORE archive with
  UTF-8 paths in byte-sorted order, no comments/extras, the same fixed metadata,
  and `manifest.json` at the archive root;
- `warden-extension-<version>.artifact.json`, which binds the clean source SHA,
  lockfile hash, exact Node/pnpm/esbuild versions, every path/size/mode/file
  hash, a payload-tree hash, the reviewed permission/CSP/update-URL snapshot,
  the complete ZIP hash, and the exact dependency-evidence sidecar bytes; and
- `warden-extension-<version>.sbom.json`, a canonical production-dependency
  evidence record generated from pnpm's installed `--prod` dependency graph
  and declared-license report. It binds the clean source and ZIP hash, excludes
  host paths and unsaved dependencies, preserves `Unknown` as reported, and
  labels bundle coverage `not-asserted`.

The verifier reparses the ZIP under a deliberately strict canonical grammar,
compares every file and release-policy field, checks the normalized unpacked
tree, verifies both directions of the ZIP/evidence/manifest binding, and runs
`unzip -t` as an independent format reader. To compare another canonical
upload ZIP and evidence sidecar against an already reviewed artifact manifest:

```sh
node apps/extension/scripts/verify-release.mjs \
  /path/to/candidate.zip /path/to/reviewed.artifact.json \
  /path/to/candidate.sbom.json
```

Chrome's current Web Store contract requires an upload ZIP with
`manifest.json` at its root; see [Prepare your extension](https://developer.chrome.com/docs/webstore/prepare)
and [Publish in the Chrome Web Store](https://developer.chrome.com/docs/webstore/publish).
This lane creates and verifies that upload artifact and package-manager
production closure only. The sidecar does **not** assert that every listed
package contributed bytes to the emitted browser bundle, that no unlisted input
contributed bytes, that a declared license is legally sufficient, or that a
vulnerability scan passed. The lane also does not parse or normalize a
Web-Store-returned CRX, authenticate the adjacent JSON, prove two independent
builders agree, publish anything, or replace publisher-account and review
controls. Replacing the ZIP and both unsigned, co-generated JSON files is not
detected unless the reviewed manifest/hash is anchored somewhere the builder
cannot rewrite.

## Manifest permissions

- `storage` is used by the background service worker for encrypted persistent
  state and the ephemeral unlock-session record. Startup immediately restricts
  both `chrome.storage.local` and `chrome.storage.session` to trusted extension
  contexts, so the content script cannot read either area.
- Static `content_scripts.matches` for `http://*/*` and `https://*/*` lets the
  isolated bridge run at `document_start` in every ordinary web frame. Chrome
  treats these match patterns as host access and may show a broad read/change
  warning. This is a real permission cost, not “no host permission” merely
  because the manifest has no separate `host_permissions` key.
- The background's internal approval launcher uses basic `chrome.windows`
  create/get/remove events, which require no added manifest permission. The
  `tabs` permission remains absent, so the launcher neither reads tab URLs nor
  accepts a caller-selected URL. Chrome receives only the fixed extension page
  documented by the
  [`windows` API](https://developer.chrome.com/docs/extensions/reference/api/windows).

## Persistent keyring boundary

The background recognizes one canonical encrypted keyring record under
`warden.keyring-record.v1` in `chrome.storage.local`. The adapter validates the
strict self-contained binary record v2 before a write, serializes calls through
that adapter, writes only that property, and requires exact readback after replace
or clear. The stable property name is not the binary format version. Record v2
stores the complete public account/origin/key-kind/schema/genesis/program context
in canonical bounded bytes. Core record v1 remains available to explicit
migration tooling, but this extension refuses it and currently has no migration
workflow. Startup does not restore session material until the persistent value is
present and well formed; absence removes the session without parsing it, while
corruption removes the session and rejects readiness.

The ephemeral session schema is v2 and stores the public 16-byte bundle id next
to the account, unwrap key, and deadlines. Wake-time restoration snapshots the
id decoded from the current persistent record and removes a live, well-formed
session if its id differs. An id match is only routing: the restored KEK must
open the exact current record, the plaintext must pass the strict signer schema,
the account/bundle must match, and exact persistent readback must remain stable
before readiness reports a restored session. The obsolete v1 session-storage
slot is removed before restore, so a format bump does not strand old unwrap-key
bytes. This does not authenticate locked browser storage or provide freshness by
itself; context becomes authenticated only through successful record opening.

The worker registers `chrome.storage.onChanged` synchronously during top-level
startup, before any readiness promise settles. Any `local`-area change that
contains the keyring property conservatively locks the session: owned key bytes
are zeroed and live leases are aborted in the event callback before asynchronous
removal of both session schema keys settles. Changes in another area and changes
to unrelated local properties do not lock. If Chrome rejects session cleanup,
the worker remains locally locked, disables its storage-change handler, closes
existing runtime Ports, stops accepting new Ports, and reports the failure
through its fatal lifecycle promise. The stale serialized session can still
remain in browser-managed storage; closing the runtime surface is not a
durability claim.

The background exposes one composed lifecycle owner rather than the raw record
adapter or raw session owner. Its replace and clear operations synchronously
revoke live and pending leases before changing the persistent record. Internal
password activation consumes the caller's byte buffer, derives a KEK from the
record's bounded Argon2 metadata, authenticates that exact record and its stored
context, and rejects unless its plaintext is exactly the v1 32-byte Ed25519
seed. The acceptable origin is derived from `chrome.runtime.id`; callers cannot
resupply account/origin/genesis/program context. Only
the account, public bundle id, KEK, and absolute deadlines enter the ephemeral
session; the seed does not. A local-only signer use reloads the exact record,
authenticates it with the session KEK and record-owned context, lends isolated
account/seed buffers to one callback, rechecks the record and deadline after the
callback, and overwrites the lease and any suppressed result on lock, expiry,
inconsistency, or failure. A frozen readiness facade exposes no raw owner/gate
properties and refuses every lifecycle operation until trusted-storage setup and
wake restoration settle.

This is an internal trust boundary, not a wallet method. The callback is
explicitly forbidden from sending or committing an irreversible side effect
before its enclosing owner completes the final checks. There is no transaction
signer consumer yet, and JavaScript overwrite remains best-effort rather than a
VM memory-erasure claim. Chrome does not document a transaction,
compare-and-swap, rollback, or durable-write primitive for storage, so
serialized same-owner calls and exact readback are not an atomicity or freshness
claim. The global change listener narrows a different trusted context's
out-of-band write to fail-closed revocation after Chrome emits the event; it
does not serialize that writer, authenticate event freshness, or prevent replay
of an older valid record. See Chrome's
[`storage.onChanged` API](https://developer.chrome.com/docs/extensions/reference/api/storage/)
and its requirement to register MV3 event listeners
[synchronously at top level](https://developer.chrome.com/docs/extensions/develop/migrate/to-service-workers#register-listeners-synchronously).

The real-browser lane seeds and reads back a non-secret local-storage canary in
the service worker, then causally observes the actual Warden content-script
world being denied access. This proves the tested browser boundary, not broad
version compatibility. It also exact-readback proves a matching v2 session and
an unrelated session canary, replaces the persistent record from the live
worker, and observes only Warden's session removed. The unit lane separately
proves the same event synchronously aborts an active in-memory lease; storage
bytes alone cannot measure heap revocation. Focused lifecycle tests use a real
sealed signer record and password derivation, but the browser lane still does
not type a password or produce a signature. There is still no record-creation
UI, Argon2 production floor, PRF ceremony/device matrix, account and cluster
registry, on-chain session-grant verification, or decrypt/sign/export consumer.

## Approval-record substrate

The shipped background constructs an internal C3 approval owner backed by a
native IndexedDB repository. A strict record copy owns the background-resolved
origin, tab/frame/document identity, account, method, explicit cluster and
genesis, program id, exact serialized bytes, SHA-256 message digest, policy
version, and bounded lifetime. One object store and one `readwrite` transaction
own each pending-to-terminal transition. Competing IndexedDB connections
therefore have one winner; a digest mismatch burns the record as `invalidated`,
expiry wins at the exact deadline, malformed stored bytes are deleted, and a
worker startup pass cancels rather than resumes every live pending record. The
store caps retained and pending records and keeps short terminal tombstones so
ordinary retries cannot reuse an approval during the retention window.

This remains a partial approval feature, not an approval-to-signature product.
`startBackground()` gates all internal readiness on startup invalidation and
closes the repository whenever initialization, fatal cleanup, or disposal closes
the runtime. A dedicated extension-only `/approval.html?request=req_<128-bit
lowercase hex>` Port can read one pending record, receive a strict primitive
projection decoded from its authenticated exact message bytes, and durably
reject or cancel that same record. It cannot create, enumerate, approve, claim,
sign, send, access the keyring, or return provider success. The page exposes the
exact technical projection behind a native disclosure and uses a conservative
wall-plus-monotonic countdown; page expiry, navigation, and Port loss make the
request non-actionable in durable storage.

The shipped worker also owns an internal approval-window launcher. Its only
caller inputs are a strict request id and an `AbortSignal`; URL, popup type,
focus, dimensions, opener status, and browser window id are background-owned.
It checks the durable row before and after `chrome.windows.create`, detects a
create-to-close race with `windows.get`, limits and deduplicates in-flight
requests, and maps `windows.onRemoved` or provider abort to exact durable
cancellation. An unprovable cancellation closes the entire runtime through the
fatal lifecycle. Disposal stops waiters promptly, removes or later closes owned
windows, and deliberately starts no new repository transition before the parent
closes IndexedDB; the mandatory next-worker startup pass invalidates anything
abandoned by worker death. MV3 global memory is therefore never continuity.

No browser message route receives the launcher, and every provider/popup method
still returns unavailable. There is still no production release registry,
authoritative account/network/policy composition, approve/sign/RPC consumer,
signed-result replay route, or root ceremony. A temporary-extension Chromium
contract now proves the real permissionless popup has the exact extension URL,
popup type, focus, and user-close cancellation. It also force-stops the exact
worker while a second popup and pending row remain, proves the popup outlives
the lost in-memory map, then observes the replacement worker's startup pass
cancel the row. Headless Chrome expanded the requested `720×600` bounds to
`1280×720`, so the fixed dimensions are a measured request, not a browser-
enforced layout guarantee. Earlier browser lanes cover
IndexedDB competing connections, tamper/worker restart, the production approval
render, navigation/reject/expiry races, and exact technical values. IndexedDB
transaction serialization is evidence for the tested compare-and-set;
`durability: "strict"` remains a browser hint, not proof against browser,
process, or disk failure. Trusted same-extension contexts share this database
and remain inside the trust boundary.

A separate C12 provider-to-preparation owner is unit-tested but deliberately
excluded by the production build graph. It can bind an exact live provider
lease to a trusted account/chain selection, the strict coordinator, one durable
approval id, and the window launcher; disconnect or open failure can cancel only
that exact durable binding. It has no emitted selection resolver, release, RPC
endpoint, signer, or provider result writer. The emitted worker must reject any
accidental import of this module until those authorities are source-owned and
reviewed.

C13 adds that selection resolver as another deliberately excluded boundary. It
resolves a repository-committed release name before inspecting a zero-argument
Connection factory or any keyring capability, authenticates the encrypted
keyring record, derives only the Ed25519 public half from the signer seed, and
requires two identical public identity snapshots from the same exact unlock
generation. The C12 owner carries that generation's revocation signal through
preparation and the approval-window lifetime, so lock, record replacement, or
same-bytes re-unlock closes the window and cancels the exact durable row. The
production release registry is empty, there is no configured endpoint, and the
build rejects both C12 and C13 from the worker; the emitted provider therefore
remains fixed unavailable. Because the v1 encrypted payload stores only the
seed, selection currently decrypts it twice to derive the public key internally.

C14 adds a third excluded boundary for MV3-safe provider operation ownership and
signed-result replay. A SHA-256 identity commits the exact parsed provider
request to Chrome-owned origin/tab/frame/document provenance while excluding
volatile worker request ids and timestamps. A separate native IndexedDB journal
claims that identity before approval preparation, binds the one durable approval
id/digest afterward, and startup-fails any interrupted preparation rather than
retrying it. A replacement worker can replay a retained bound locator without
preparing or signing again. The journal is bounded (32 preparing, 128 retained,
ten-minute terminal retention), so this is a bounded replay guarantee, not
eternal deduplication or a disk-failure proof.

The excluded terminal owner rechecks the operation, approved record, exact
browser provenance, account, chain, and digest, then uses the core durable
result verifier to reparse and cryptographically verify the committed signed
transaction without RPC or keyring access. `Port.postMessage` is not treated as
a page acknowledgment; a failed enqueue leaves the same result replayable and
future page code must deduplicate its stable correlation id.

C15 splits C12 into hidden `prepare()` and idempotent `open()` phases, then
composes them through C14: claim operation, prepare/prove the exact approval,
commit its id/digest binding, and only then open the review window. Bind
uncertainty, Port loss, authority revocation, malformed handles, and open failure
cancel the exact approval; a retained binding is replay-only and never prepares
or opens again. This ordering is still unit-level composition. Native C14
IndexedDB/restart behavior is browser-tested separately, and raw C12 open/launch
remains an internal bypass that must not be production-wired. The build forbids
all C12–C15 owners and the success response schema from the worker; the emitted
provider remains fixed unavailable.

C16 adds a still-unshipped main-world `solana:signTransaction` request owner.
It validates and copies one closed request, mints a 128-bit correlation before
posting, installs the pending Promise first, retains every issued id as a
bounded document-lifetime tombstone, and removes the exact entry before the
first success/error settlement. One module instance permits only one owner per
page even after disposal; absolute TTL checks, 32 pending / 1,024 issued limits,
and collision failure bound the registry. Duplicate or conflicting terminal
responses cannot attach to a later owner-created request.

This is page-Promise idempotence, not page authentication. Same-page scripts can
observe, forge, suppress, or disrupt main-world traffic and are the caller trust
principal. C22 now extends this excluded owner with the initiating absolute
deadline and an identity-bound receipt: the first exact terminal settles once,
and an exact duplicate re-sends the same receipt without re-settling. It is not
injected, registered, or included in any production bundle; the future
MAIN-world lane must prove single evaluation in real Chromium before relying on
its module-scoped one-owner guard. The emitted provider remains fixed
unavailable.

C20–C22 add excluded content/background recovery and settlement owners. C20
retains the canonical request through one Port replacement and does not remove
it after terminal forwarding or page receipt; only the background's exact
settled acknowledgment releases it. C21 permits an overlapping replacement
Port only after the complete Chrome provenance and SHA-256 operation identity
match. C22 carries C16's original deadline unchanged through both owners, sends
an identity-bound expiry cancellation, and keeps the background request lease
until the current generation presents the deterministic operation receipt after
the delivery flow has returned exact completion proof. Real Chromium covers an
overlap, forced MV3 worker death, and a replacement lease expiring at the
initiating deadline without a fabricated terminal. The build input graph and
artifact scan keep this entire protocol absent from shipped code.

C23 adds one browser-only success composition without changing that production
boundary. A temporary MV3 extension routes one HTTP-page request through the
real C16 MAIN-world owner, C20 content owner, C21/C22 background transport,
C12–C19 durable operation and approval owners, IndexedDB repositories, a
password-authenticated keyring generation, the pinned authority resolver, and
the production approval UI. Its `Connection`, release pins, seed, password, and
low-cost Argon2id parameters are deterministic fixtures and are never copied
into `dist`. The popup renders the exact origin, account, network, memo, and
SHA-256 digest before enabling approval.

After approval, the Chromium contract deserializes the page result and proves
that its message bytes equal the durable pre-approval bytes, independently
recomputes the digest, verifies the Ed25519 signature against the authenticated
session public key, and compares the complete result with the durable IndexedDB
result. It also proves one create/claim/complete/signer use, one navigation, the
expected RPC calls, and settled volatile owners. Core transaction construction
now uses browser-native `Uint8Array` instead of two Node-only `Buffer`
constructors; the focused core test deletes the global `Buffer` before invoking
the real rewrite path.

At C23 this was uninterrupted test provenance only. C24 now adds one precise
restart cut: after `completeSigning()` has committed the signed outcome to the
durable approval row, but before the original worker can continue the provider
flow, the Chromium contract removes the serialized unlock session and closes
the actual service-worker target. A different boot starts ready-but-locked,
invalidates no completed signing state, performs no selection, RPC, approval,
keyring, or signing work, and replays the exact durable bytes to the unchanged
page through the retained operation. The returned, durable, and reviewed
message bytes and digest match, the signature independently verifies, and the
receipt protocol settles all non-document volatile owners.

C24 also corrects the browser harness: fixture authority is initialized once,
and later boots call the real authenticated restore path instead of reseeding
and unlocking on every worker start. This proves only replacement inside one
loaded browser session.

C25 brackets the other side of that commit. It pauses after the contextual
keyring callback has returned transaction bytes but before the coordinator can
reparse them or call `completeSigning()`, removes the unlock session, and kills
the real worker. At the cut, a new `signerResultsProduced` measurement is one
while completion is zero and durable bytes are absent. The locked replacement
atomically marks the unresolved attempt `failed/worker-restarted`, uses the
retained bound operation to deliver one generic failure, and performs no
selection, RPC, approval mutation beyond startup invalidation, key use, or
signing. The attempt stays number 1; page and durable signed bytes remain null.

C26 cuts the remaining in-flight interval without replacing the repository.
The browser-only worker delegates the signed-envelope write to the native
`IDBObjectStore.put`, observes that request's real `success` event, records a
non-secret marker, and synchronously holds the event open. An independent
extension page removes restart authority and closes the actual service-worker
target while the strict transaction is still unable to finish its JavaScript
event dispatch. The replacement accepts only the transaction's two atomic
durable outcomes: exact committed bytes, replayed and cryptographically checked
without signer authority; or one unresolved attempt converted to
`failed/worker-restarted` with no returned or durable bytes. Both branches ban a
second selection, RPC read, approval claim, signer lease, completion, or signing
attempt. The lane validates this allowed union; it does not claim that repeated
runs observed both outcomes.

C27 cuts after the real signed terminal has been enqueued and the unchanged page
has settled and emitted its receipt, but before the background transport can
record its posted generation, finish the flow, prove exact delivery, or accept
that receipt. A browser-only Port wrapper delegates to native `postMessage`
first and holds before returning. After the actual worker target is killed, a
locked replacement performs no selection, RPC, approval, key, or signing work.
It replays the durable terminal; the content owner matches it to the retained
terminal and receipt identity, re-sends the receipt without forwarding a second
page response, and receives settlement. Content pending falls from one to zero
while the complete page observation stays unchanged at one Promise settlement,
one receipt post, one navigation, and the independently verified signed bytes.

C28 cuts after the background has accepted that exact receipt, finished the
delivery lease, cleared the active binding, and entered the final settlement
send, but before the browser-only wrapper delegates that send to native
`Port.postMessage`. The wrapper requires the settlement identity to equal the
signed terminal already sent over the same real Port. At the cut the page still
has one settlement and one receipt while content retains one pending entry. The
actual worker target is killed, and a locked replacement replays the same
durable terminal, receives the retained receipt, and clears content pending
without a second page response or any selection, RPC, approval, key, or signing
work. A unit-level post hook independently proves that the production delivery
lease is already inactive when settlement enqueue begins.

This is the nearest deterministic boundary Chrome exposes, not proof of a
native settlement already enqueued but not yet delivered to content. Simulating
that stronger claim by dropping an incoming event would test the fixture rather
than worker lifecycle, so it remains explicitly unverified. These contracts
also do not cover death during preparation, pending approval, or after terminal
enqueue but before page settlement. Target termination within one loaded browser
is not whole-browser restart or power loss. Chrome documents that
`storage.session` is cleared on browser restart, and IndexedDB's `strict`
durability setting remains a user-agent hint rather than a stable-media
guarantee. The fixture markers, native-method hook, Port wrapper, counters, and
inert control page are test instrumentation, not an onboarding or
account-registry design. This graph still does not register or inject Wallet
Standard, configure a live trusted RPC/release, define production KDF policy,
send a transaction, or make the production provider reachable. Future
activation must replace the fixed-unavailable provider behind the existing
single central Port router, not install an independent `runtime.onConnect`
listener.

The bridge is excluded from `file:`, browser-internal, extension, data, and
opaque `about:blank`/`srcdoc` documents. It opens no background Port during
ordinary browsing: an exact, same-document request envelope opens one lazily,
and the next request reconnects after MV3 suspension without an eager wake loop.
One document can forward at most 1,024 matching envelopes across all such
reconnections. It has no main-world injected script, web-accessible resource,
external connection, account state, approval state, RPC, key access, or
successful wallet method. Same-page JavaScript can forge or suppress page
messages; background code therefore derives provenance only from Chrome-owned
`Port.sender` fields and treats every bridged payload as hostile.

## Action popup

The manifest action loads the extension-owned `popup.html`; declaring this
popup adds no manifest permission. Its bundle is constrained to the popup entry
and its separate protocol module. It cannot import the provider bridge, core,
storage, session, approval, RPC, or key modules.

The popup protocol has one exact request and one fixed unavailable response. It
grants no wallet authority and shows only that wallet controls are not enabled.
The background accepts the channel only from this extension's exact origin and
`/popup.html` path. Tab-hosted extension pages must also provide a document id
and top-frame identity. Current Chromium omits document and tab fields for its
browser-owned toolbar popup, so that sender shape is instead bounded by the
exact extension origin/path, Port lifetime, a 16-Port concurrency cap, and 16
requests per Port. A content script has the same extension id but a web
origin/URL and is rejected before its payload is read.

The real-browser lane opens the toolbar popup with `chrome.action.openPopup()`,
measures its browser-owned sender, reads the rendered status, and sends a direct
popup-protocol request. That automation API requires a newer Chromium than the
manifest's Chrome 106 floor; compatibility of the ordinary toolbar action on
the floor still needs a separate version-matrix run before release.

`externally_connectable`, `web_accessible_resources`, `host_permissions`, and
`optional_host_permissions` stay absent. Any future expansion requires a
manifest test, threat-model update, and real-browser evidence.
