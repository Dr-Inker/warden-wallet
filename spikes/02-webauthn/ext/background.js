// Trivial MV3 service worker. Not used for any WebAuthn logic — it exists solely
// so the test harness can deterministically discover this unpacked extension's
// id via ctx.waitForEvent("serviceworker"). chrome://extensions and the CDP
// Extensions.loadUnpacked method are both unavailable under headless
// Chrome-for-Testing, so this is the reliable path (see result.md).
