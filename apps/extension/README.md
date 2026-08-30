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
strict core record before a write, serializes calls through that adapter, writes
only that property, and requires exact readback after replace or clear. Startup
does not restore session material until this persistent value is present and
well formed; absence removes the session without parsing it, while corruption
removes the session and rejects readiness.

The raw record adapter is deliberately not exposed by the background runtime.
A future mutation path must compose record replacement with session revocation;
otherwise an old unwrap key could remain live beside a new record. Chrome does
not document a transaction, compare-and-swap, rollback, or durable-write
primitive for this area, so serialized same-owner calls and readback are not an
atomicity or freshness claim. A different trusted context could still race an
out-of-band write, and replay of an older valid record remains unsolved without
an external freshness authority.

The real-browser lane seeds and reads back a non-secret local-storage canary in
the service worker, then causally observes the actual Warden content-script
world being denied access. This proves the tested browser boundary, not broad
version compatibility. There is still no record-creation UI, Argon2 benchmark,
PRF ceremony, record-to-session activation, account registry, decrypt/sign/export
consumer, or persistent-record/session identifier binding.

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
