import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import {
  restrictStorageToTrustedContexts,
  type ExtensionStorageAccessApi,
} from "../src/background/storage-access.js";

describe("MV3 manifest starts from the closed permission boundary", () => {
  it("requests storage only and exposes no page, host, script, or external connection surface", async () => {
    const manifest = JSON.parse(
      await readFile(new URL("../manifest.json", import.meta.url), "utf8"),
    ) as Record<string, unknown>;
    expect(manifest.manifest_version).toBe(3);
    // Port provenance requires MessageSender.documentId, introduced in Chrome 106.
    // Advertising 102 while rejecting every pre-106 sender would be a false support claim.
    expect(manifest.minimum_chrome_version).toBe("106");
    expect(manifest.permissions).toEqual(["storage"]);
    expect(manifest.background).toEqual({ service_worker: "background.js", type: "module" });
    for (const forbidden of [
      "host_permissions",
      "optional_host_permissions",
      "content_scripts",
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
