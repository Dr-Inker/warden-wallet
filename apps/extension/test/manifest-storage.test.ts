import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import {
  restrictStorageToTrustedContexts,
  type ExtensionStorageAccessApi,
} from "../src/background/storage-access.js";

describe("MV3 manifest keeps explicit, permission-minimal reachability boundaries", () => {
  it("limits the static isolated content script to HTTP(S) documents", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../manifest.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
    expect(manifest.manifest_version).toBe(3);
    // Port provenance requires MessageSender.documentId, introduced in Chrome 106.
    // Advertising 102 while rejecting every pre-106 sender would be a false support claim.
    expect(manifest.minimum_chrome_version).toBe("106");
    expect(manifest.permissions).toEqual(["storage"]);
    expect(manifest.background).toEqual({ service_worker: "background.js", type: "module" });
    expect(manifest.action).toEqual({ default_popup: "popup.html" });
    // With `world` omitted Chrome runs static content scripts in ISOLATED by
    // default. The explicit manifest field arrived after our Chrome 106 floor;
    // exact-object equality also prevents a later switch to MAIN from hiding.
    expect(manifest.content_scripts).toEqual([
      {
        matches: ["http://*/*", "https://*/*"],
        js: ["content.js"],
        run_at: "document_start",
        all_frames: true,
      },
    ]);
    for (const forbidden of [
      "host_permissions",
      "optional_host_permissions",
      "externally_connectable",
      "web_accessible_resources",
    ]) {
      expect(manifest).not.toHaveProperty(forbidden);
    }
  });

  it("ships a local-code-only CSP and does not silently bless the spike id as production", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../manifest.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
    expect(manifest).not.toHaveProperty("key");
    expect(manifest.content_security_policy).toEqual({
      extension_pages: "script-src 'self'; object-src 'self';",
    });
    expect(JSON.stringify(manifest)).not.toContain("unsafe-eval");
    expect(JSON.stringify(manifest)).not.toContain("wasm-unsafe-eval");
  });

  it("keeps the approval document on emitted local assets with no inline handlers", async () => {
    const html = await readFile(new URL("../approval.html", import.meta.url), "utf8");
    expect(html).toContain('<link rel="stylesheet" href="approval.css">');
    expect(html).toContain('<script src="approval.js"></script>');
    expect(html.match(/<script\b/gi)).toHaveLength(1);
    expect(html).not.toMatch(/<script(?:\s[^>]*)?>\s*[^<\s]/i);
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/(?:src|href)=["']https?:/i);
  });
});

describe("storage access is explicitly restricted before runtime use", () => {
  it("sets both persistent and session storage to TRUSTED_CONTEXTS", async () => {
    const local = { setAccessLevel: vi.fn(async () => undefined) };
    const session = { setAccessLevel: vi.fn(async () => undefined) };
    await restrictStorageToTrustedContexts({ local, session });
    expect(local.setAccessLevel).toHaveBeenCalledOnce();
    expect(session.setAccessLevel).toHaveBeenCalledOnce();
    expect(local.setAccessLevel).toHaveBeenCalledWith({ accessLevel: "TRUSTED_CONTEXTS" });
    expect(session.setAccessLevel).toHaveBeenCalledWith({ accessLevel: "TRUSTED_CONTEXTS" });
  });

  it("fails closed if either Chrome access-level call rejects", async () => {
    const storage: ExtensionStorageAccessApi = {
      local: { setAccessLevel: async () => Promise.reject(new Error("local denied")) },
      session: { setAccessLevel: async () => undefined },
    };
    await expect(restrictStorageToTrustedContexts(storage)).rejects.toThrow("local denied");
  });
});
