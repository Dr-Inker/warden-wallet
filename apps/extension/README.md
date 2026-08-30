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

`externally_connectable`, `web_accessible_resources`, `host_permissions`, and
`optional_host_permissions` stay absent. Any future expansion requires a
manifest test, threat-model update, and real-browser evidence.
