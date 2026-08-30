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
      // Playwright retains wrappers for targets closed through CDP.
    }
  }
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith(origin ?? "chrome-extension://"),
    timeout: 30_000,
  });
}

test("IndexedDB approval claims are atomic and pending records die with the worker", async () => {
  const temporaryParent = resolve(tmpdir());
  const extensionDirectory = await mkdtemp(
    join(temporaryParent, "warden-approval-browser-"),
  );
  const expectedPrefix = `${temporaryParent}${sep}warden-approval-browser-`;
  if (!resolve(extensionDirectory).startsWith(expectedPrefix)) {
    throw new Error("approval browser temporary directory escaped its expected parent");
  }

  let context: BrowserContext | undefined;
  try {
    await build({
      entryPoints: {
        background: join(scriptDirectory, "approval-browser-worker.ts"),
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
        name: "Warden Approval Browser Contract",
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
      "<!doctype html><meta charset=utf-8><title>Warden approval wake</title>\n",
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
        __wardenApprovalBeforeRestart?: () => Promise<unknown>;
      }).__wardenApprovalBeforeRestart;
      if (typeof runner !== "function") throw new Error("approval runner is unavailable");
      return runner();
    }) as {
      initialInvalidated: number;
      copiedRawMessage: number[];
      raceResults: Array<{ status: string; state?: string }>;
      raceState: string;
      doubleResults: Array<{ status: string; state?: string }>;
      doubleState: string;
      corruptResult: Array<{ status: string; errorName?: string }>;
      corruptRead: unknown;
      mismatchResult: Array<{ status: string; errorName?: string }>;
      mismatchState: string;
      mismatchRetry: Array<{ status: string; errorName?: string }>;
      expiryResult: Array<{ status: string; errorName?: string }>;
      expiryState: string;
      identicalDigestMatches: boolean;
      identicalStates: string[];
      restartId: string;
    };

    expect(before.initialInvalidated).toBe(0);
    expect(before.copiedRawMessage).toEqual([0x10, 2, 3, 4]);
    expect(before.raceResults.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(before.raceResults.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(["approved", "rejected"]).toContain(before.raceState);
    expect(before.doubleResults.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(before.doubleResults.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(before.doubleState).toBe("approved");
    expect(before.corruptResult).toEqual([
      { status: "rejected", errorName: "ApprovalRecordFormatError" },
    ]);
    expect(before.corruptRead).toBeNull();
    expect(before.mismatchResult).toEqual([
      { status: "rejected", errorName: "ApprovalDigestMismatchError" },
    ]);
    expect(before.mismatchState).toBe("invalidated");
    expect(before.mismatchRetry).toEqual([
      { status: "rejected", errorName: "ApprovalStateConflictError" },
    ]);
    expect(before.expiryResult).toEqual([
      { status: "rejected", errorName: "ApprovalStateConflictError" },
    ]);
    expect(before.expiryState).toBe("expired");
    expect(before.identicalDigestMatches).toBe(true);
    expect(before.identicalStates).toEqual(["approved", "rejected"]);

    const marker = "must-not-survive-approval-worker-death";
    await worker.evaluate((value) => {
      (globalThis as unknown as { __wardenApprovalWorkerMarker?: string })
        .__wardenApprovalWorkerMarker = value;
    }, marker);
    const controlPage = await context.newPage();
    const cdp = await context.newCDPSession(controlPage);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" && candidate.url.startsWith(extensionOrigin));
    expect(target, "approval service worker exists before forced stop").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", { targetId: target!.targetId });
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
      (globalThis as unknown as { __wardenApprovalWorkerMarker?: string })
        .__wardenApprovalWorkerMarker ?? null)).toBeNull();
    const after = await replacement.evaluate(async (id) => {
      const runner = (globalThis as unknown as {
        __wardenApprovalAfterRestart?: (recordId: string) => Promise<unknown>;
      }).__wardenApprovalAfterRestart;
      if (typeof runner !== "function") throw new Error("approval restart runner unavailable");
      return runner(id);
    }, before.restartId);
    expect(after).toMatchObject({ invalidated: 1, state: "cancelled" });
  } finally {
    await context?.close();
    await rm(extensionDirectory, { recursive: true, force: true });
  }
});
