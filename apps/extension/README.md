# Warden extension boundary

This is a pre-alpha development extension. It must not be used with real funds.

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

This is a fail-closed persistence substrate, not a usable approval feature.
`startBackground()` gates all internal readiness on startup invalidation and
closes the repository whenever initialization, fatal cleanup, or disposal closes
the runtime. No Port or page can create, read, or resolve a record. There is no
authoritative account/network/policy registry, approval page, exact-byte decoder,
signer/RPC consumer, signed-result replay, navigation cancellation, or root
ceremony. A temporary-extension Chromium contract opens two independent database
connections, races decisions, and mutates stored message bytes. The shipped-
extension lane separately seeds its production database, kills and wakes the MV3
worker through the real provider Port, and observes startup cancel that pending
record. The unit runtime contract separately proves readiness stays closed until
the same invalidation settles. IndexedDB transaction serialization is evidence
for the tested compare-and-set; `durability: "strict"` remains a browser hint,
not proof against browser, process, or disk failure. Trusted same-extension
contexts share this database and remain inside the trust boundary.

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
