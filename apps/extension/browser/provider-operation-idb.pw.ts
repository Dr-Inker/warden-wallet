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

test("provider operation CAS survives MV3 worker death without preparing twice", async () => {
  const temporaryParent = resolve(tmpdir());
  const extensionDirectory = await mkdtemp(
    join(temporaryParent, "warden-provider-operation-browser-"),
  );
  const expectedPrefix = `${temporaryParent}${sep}warden-provider-operation-browser-`;
  if (!resolve(extensionDirectory).startsWith(expectedPrefix)) {
    throw new Error("provider-operation temporary directory escaped its parent");
  }

  let context: BrowserContext | undefined;
  try {
    await build({
      entryPoints: {
        background: join(scriptDirectory, "provider-operation-browser-worker.ts"),
      },
      outdir: extensionDirectory,
      bundle: true,
      platform: "browser",
      target: "chrome106",
      format: "esm",
      sourcemap: false,
      legalComments: "none",
    });
    await writeFile(
      join(extensionDirectory, "manifest.json"),
      `${JSON.stringify({
        manifest_version: 3,
        name: "Warden Provider Operation Browser Contract",
        version: "0.0.0",
        minimum_chrome_version: "106",
        background: { service_worker: "background.js", type: "module" },
        content_security_policy: {
          extension_pages: "script-src 'self'; object-src 'self'",
        },
      }, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      join(extensionDirectory, "wake.html"),
      "<!doctype html><meta charset=utf-8><title>Warden operation wake</title>\n",
      "utf8",
    );

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
    const before = await worker.evaluate(async () => {
      const runner = (globalThis as unknown as {
        __wardenProviderOperationBeforeRestart?: () => Promise<unknown>;
      }).__wardenProviderOperationBeforeRestart;
      if (typeof runner !== "function") {
        throw new Error("provider-operation before-restart runner is unavailable");
      }
      return runner();
    }) as {
      initialInvalidated: number;
      prepareCalls: number;
      race: Array<{
        status: "fulfilled" | "rejected";
        created?: boolean;
        state?: string;
        approvalId?: string | null;
        errorName?: string;
      }>;
      boundKey: string;
      boundState: string | null;
      boundApprovalId: string | null;
      interruptedKey: string;
      interruptedState: string;
      stableCorrelation: string;
      interruptedCorrelation: string;
    };

    expect(before.initialInvalidated).toBe(0);
    expect(before.prepareCalls).toBe(1);
    expect(before.race.filter((entry) => entry.created === true)).toHaveLength(1);
    expect(before.race.filter((entry) => entry.status === "rejected").every(
      (entry) => entry.errorName === "ProviderOperationStateError",
    )).toBe(true);
    expect(before.boundKey).toMatch(/^op_[0-9a-f]{64}$/);
    expect(before.boundState).toBe("bound");
    expect(before.boundApprovalId).toBe(`req_${"ab".repeat(16)}`);
    expect(before.interruptedKey).toMatch(/^op_[0-9a-f]{64}$/);
    expect(before.interruptedState).toBe("preparing");

    await worker.evaluate(() => {
      (globalThis as unknown as { __wardenOperationMarker?: string })
        .__wardenOperationMarker = "must-not-survive-provider-operation-restart";
    });
    const controlPage = await context.newPage();
    const cdp = await context.newCDPSession(controlPage);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" && candidate.url.startsWith(extensionOrigin));
    expect(target, "provider-operation worker exists before forced stop").toBeDefined();
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

    await controlPage.goto(`${extensionOrigin}/wake.html`);
    const wake = await controlPage.evaluate(async () => {
      const runtime = (globalThis as unknown as {
        readonly chrome: {
          readonly runtime: {
            sendMessage(message: unknown): Promise<unknown>;
          };
        };
      }).chrome.runtime;
      return runtime.sendMessage({ type: "wake" });
    });
    expect(wake).toEqual({ ready: true });
    const replacement = await liveExtensionWorker(context, extensionOrigin);
    expect(await replacement.evaluate(() =>
      (globalThis as unknown as { __wardenOperationMarker?: string })
        .__wardenOperationMarker ?? null)).toBeNull();
    const after = await replacement.evaluate(async (input) => {
      const runner = (globalThis as unknown as {
        __wardenProviderOperationAfterRestart?: (
          value: typeof input,
        ) => Promise<unknown>;
      }).__wardenProviderOperationAfterRestart;
      if (typeof runner !== "function") {
        throw new Error("provider-operation after-restart runner is unavailable");
      }
      return runner(input);
    }, {
      boundKey: before.boundKey,
      interruptedKey: before.interruptedKey,
      stableCorrelation: before.stableCorrelation,
      interruptedCorrelation: before.interruptedCorrelation,
    });
    expect(after).toEqual({
      invalidated: 1,
      replayCreated: false,
      replayState: "bound",
      replayApprovalId: `req_${"ab".repeat(16)}`,
      replayPrepareCalls: 0,
      interruptedRetry: [{
        status: "rejected",
        errorName: "ProviderOperationStateError",
      }],
      interruptedPrepareCalls: 0,
      boundState: "bound",
      interruptedState: "failed",
      interruptedFailureCode: "worker-restarted",
    });
  } finally {
    await context?.close();
    await rm(extensionDirectory, { recursive: true, force: true });
  }
});
