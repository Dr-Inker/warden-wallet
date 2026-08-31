import { expect, chromium, test, type BrowserContext } from "@playwright/test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { build } from "esbuild";

const scriptDirectory = resolve(import.meta.dirname, "../scripts");

async function liveExtensionWorker(context: BrowserContext, origin?: string) {
  for (const worker of [...context.serviceWorkers()].reverse()) {
    if (!worker.url().startsWith(origin ?? "chrome-extension://")) continue;
    try {
      await worker.evaluate(() => true);
      return worker;
    } catch {
      // Playwright retains wrappers for service-worker targets Chrome closed.
    }
  }
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith(origin ?? "chrome-extension://"),
    timeout: 30_000,
  });
}

test("permissionless approval popups cancel on user close and worker death", async () => {
  const temporaryParent = resolve(tmpdir());
  const extensionDirectory = await mkdtemp(
    join(temporaryParent, "warden-approval-window-browser-"),
  );
  const expectedPrefix = `${temporaryParent}${sep}warden-approval-window-browser-`;
  if (!resolve(extensionDirectory).startsWith(expectedPrefix)) {
    throw new Error("approval-window temporary directory escaped its expected parent");
  }

  let context: BrowserContext | undefined;
  try {
    await build({
      entryPoints: {
        background: join(scriptDirectory, "approval-window-browser-worker.ts"),
      },
      outdir: extensionDirectory,
      bundle: true,
      platform: "browser",
      target: "chrome106",
      format: "esm",
      sourcemap: false,
      legalComments: "none",
    });
    const manifest = {
      manifest_version: 3,
      name: "Warden Approval Window Browser Contract",
      version: "0.0.0",
      minimum_chrome_version: "106",
      background: { service_worker: "background.js", type: "module" },
      content_security_policy: {
        extension_pages: "script-src 'self'; object-src 'self'",
      },
    };
    await writeFile(
      join(extensionDirectory, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      join(extensionDirectory, "approval.html"),
      "<!doctype html><meta charset=utf-8><title>Warden approval window contract</title><main>Approval review contract</main>\n",
      "utf8",
    );

    expect(Object.hasOwn(manifest, "permissions")).toBe(false);
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionDirectory}`,
        `--load-extension=${extensionDirectory}`,
        "--headless=new",
      ],
    });
    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;
    const expectedUrl = `${extensionOrigin}/approval.html?request=req_${"9a".repeat(16)}`;
    const popupPagePromise = context.waitForEvent("page", {
      predicate: (page) => page.url() === expectedUrl,
      timeout: 30_000,
    });
    const resultPromise = worker.evaluate(async (request) => {
      const runner = (globalThis as unknown as {
        __wardenApprovalWindowOpen?: (
          input: typeof request,
        ) => Promise<unknown>;
      }).__wardenApprovalWindowOpen;
      if (typeof runner !== "function") {
        throw new Error("approval-window browser runner is unavailable");
      }
      return runner(request);
    }, {
      requestId: `req_${"9a".repeat(16)}`,
      messageByte: 0x9a,
    });
    const [popupPage, result] = await Promise.all([
      popupPagePromise,
      resultPromise,
    ]) as [Awaited<typeof popupPagePromise>, {
      requestId: string;
      permissions: unknown;
      createCalls: Array<{
        url: string;
        type: string;
        focused: boolean;
        width: number;
        height: number;
        setSelfAsOpener: boolean;
      }>;
      popups: Array<{
        id?: number;
        type?: string;
        focused?: boolean;
        width?: number;
        height?: number;
      }>;
      fatals: string[];
    }];

    expect(popupPage.url()).toBe(expectedUrl);
    expect(result.requestId).toBe(`req_${"9a".repeat(16)}`);
    expect(result.permissions).toEqual([]);
    expect(result.fatals).toEqual([]);
    expect(result.createCalls).toEqual([{
      url: expectedUrl,
      type: "popup",
      focused: true,
      width: 720,
      height: 600,
      setSelfAsOpener: false,
    }]);
    expect(result.popups).toHaveLength(1);
    expect(result.popups[0]).toMatchObject({
      type: "popup",
      focused: true,
    });
    expect(Number.isSafeInteger(result.popups[0]!.width)).toBe(true);
    expect(Number.isSafeInteger(result.popups[0]!.height)).toBe(true);
    expect(result.popups[0]!.width).toBeGreaterThan(0);
    expect(result.popups[0]!.height).toBeGreaterThan(0);
    await expect(popupPage.locator("main")).toHaveText("Approval review contract");

    await popupPage.close();
    await expect.poll(async () => {
      const liveWorker = await liveExtensionWorker(context!, extensionOrigin);
      return liveWorker.evaluate(async (requestId) => {
        const reader = (globalThis as unknown as {
          __wardenApprovalWindowRead?: (
            id: string,
          ) => Promise<{ state: string | null; fatals: string[] }>;
        }).__wardenApprovalWindowRead;
        if (typeof reader !== "function") {
          throw new Error("approval-window state reader is unavailable");
        }
        return reader(requestId);
      }, result.requestId);
    }).toEqual({ state: "cancelled", fatals: [] });

    const restartRequestId = `req_${"9b".repeat(16)}`;
    const restartUrl = `${extensionOrigin}/approval.html?request=${restartRequestId}`;
    const restartWorker = await liveExtensionWorker(context, extensionOrigin);
    const restartPopupPromise = context.waitForEvent("page", {
      predicate: (page) => page.url() === restartUrl,
      timeout: 30_000,
    });
    const restartResultPromise = restartWorker.evaluate(async (request) => {
      const runner = (globalThis as unknown as {
        __wardenApprovalWindowOpen?: (
          input: typeof request,
        ) => Promise<unknown>;
      }).__wardenApprovalWindowOpen;
      if (typeof runner !== "function") {
        throw new Error("approval-window browser runner is unavailable");
      }
      return runner(request);
    }, {
      requestId: restartRequestId,
      messageByte: 0x9b,
    });
    const [restartPopup, restartResult] = await Promise.all([
      restartPopupPromise,
      restartResultPromise,
    ]) as [Awaited<typeof restartPopupPromise>, typeof result];
    expect(restartPopup.url()).toBe(restartUrl);
    expect(restartResult.createCalls.at(-1)).toEqual({
      url: restartUrl,
      type: "popup",
      focused: true,
      width: 720,
      height: 600,
      setSelfAsOpener: false,
    });
    expect(await restartWorker.evaluate(async (requestId) => {
      const reader = (globalThis as unknown as {
        __wardenApprovalWindowRead?: (
          id: string,
        ) => Promise<{ state: string | null; fatals: string[] }>;
      }).__wardenApprovalWindowRead;
      if (typeof reader !== "function") {
        throw new Error("approval-window state reader is unavailable before restart");
      }
      return reader(requestId);
    }, restartRequestId)).toEqual({ state: "pending", fatals: [] });

    const marker = "approval-window-map-must-not-survive-worker-death";
    await restartWorker.evaluate((value) => {
      (globalThis as unknown as { __wardenApprovalWindowMarker?: string })
        .__wardenApprovalWindowMarker = value;
    }, marker);
    const controlPage = await context.newPage();
    const cdp = await context.newCDPSession(controlPage);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" && candidate.url.startsWith(extensionOrigin));
    expect(target, "approval-window worker exists before forced stop").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);
    await expect.poll(async () => {
      const current = await cdp.send("Target.getTargets");
      return current.targetInfos.filter((candidate) =>
        candidate.type === "service_worker" &&
        candidate.url.startsWith(extensionOrigin)).length;
    }).toBe(0);
    expect(restartPopup.isClosed()).toBe(false);

    // The old in-memory window-id map died with the worker. Closing the orphaned
    // popup wakes a fresh worker; startup invalidation, not that lost map, must
    // cancel the durable row before any review route can become ready.
    await restartPopup.close();
    const replacement = await liveExtensionWorker(context, extensionOrigin);
    expect(await replacement.evaluate(() =>
      (globalThis as unknown as { __wardenApprovalWindowMarker?: string })
        .__wardenApprovalWindowMarker ?? null)).toBeNull();
    await expect.poll(async () => replacement.evaluate(async (requestId) => {
      const reader = (globalThis as unknown as {
        __wardenApprovalWindowRead?: (
          id: string,
        ) => Promise<{ state: string | null; fatals: string[] }>;
      }).__wardenApprovalWindowRead;
      if (typeof reader !== "function") {
        throw new Error("approval-window state reader is unavailable after restart");
      }
      return reader(requestId);
    }, restartRequestId)).toEqual({ state: "cancelled", fatals: [] });
  } finally {
    await context?.close();
    if (resolve(extensionDirectory).startsWith(expectedPrefix)) {
      await rm(extensionDirectory, { recursive: true, force: true });
    }
  }
});
