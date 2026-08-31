import {
  chromium,
  expect,
  test,
  type BrowserContext,
  type Page,
} from "@playwright/test";
import { PublicKey, VersionedTransaction } from "@solana/web3.js";
import { createHash, createPublicKey, verify } from "node:crypto";
import {
  copyFile,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { build } from "esbuild";

const appDirectory = resolve(import.meta.dirname, "..");
const scriptDirectory = resolve(appDirectory, "scripts");
const EXPECTED_MEMO = "C23 exact-byte browser success";

interface TestServer {
  readonly origin: string;
  close(): Promise<void>;
}

interface PageSignStatus {
  readonly state: "pending" | "signed" | "failed";
  readonly sourceTransaction: number[];
  readonly signedTransaction: number[] | null;
  readonly error: string | null;
  readonly pendingCount: number;
  readonly href: string;
  readonly navigationEntries: number;
}

interface WorkerStatus {
  readonly bootId: string;
  readonly ready: boolean;
  readonly keyringStartup: "seeded" | "restored" | "locked";
  readonly checkpointReached: string | null;
  readonly fatalErrors: string[];
  readonly startupInvalidatedApprovals: number;
  readonly startupInvalidatedOperations: number;
  readonly keyringUnlocked: boolean;
  readonly providerPortRoutes: number;
  readonly approvalPortRoutes: number;
  readonly selectionCalls: number;
  readonly identityReads: number;
  readonly approvalCreates: number;
  readonly signingClaims: number;
  readonly signingCompletions: number;
  readonly signerLeaseUses: number;
  readonly latestApprovalId: string | null;
  readonly approvalState: string | null;
  readonly signingState: string | null;
  readonly signingAttemptNumber: number | null;
  readonly account: string;
  readonly sessionSigner: string;
  readonly rawMessage: number[] | null;
  readonly messageDigestHex: string | null;
  readonly durableSignedTransaction: number[] | null;
  readonly rpc: {
    readonly genesisCalls: number;
    readonly accountCalls: number;
    readonly latestBlockhashCalls: number;
    readonly blockhashValidityCalls: number;
  };
  readonly activeActions: number;
  readonly activeApprovalRequests: number;
  readonly activeFlows: number;
  readonly activeDocuments: number;
}

async function startServer(pageScript: string): Promise<TestServer> {
  const server: Server = createServer((request, response) => {
    if (request.url === "/fixture-page.js") {
      response.writeHead(200, {
        "content-type": "text/javascript; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(pageScript);
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(`<!doctype html>
<html><head><meta charset="utf-8"><title>Warden exact-byte success</title>
<script defer src="/fixture-page.js"></script></head><body>
<main>C23 exact-byte signing fixture</main></body></html>`);
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("exact-byte fixture server has no TCP address");
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => error === undefined
          ? resolveClose()
          : rejectClose(error));
      });
    },
  };
}

async function createExtension(): Promise<{
  readonly directory: string;
  readonly pageScript: string;
}> {
  const temporaryParent = resolve(tmpdir());
  const directory = await mkdtemp(join(
    temporaryParent,
    "warden-provider-sign-success-browser-",
  ));
  const expectedPrefix =
    `${temporaryParent}${sep}warden-provider-sign-success-browser-`;
  if (!resolve(directory).startsWith(expectedPrefix)) {
    throw new Error("exact-byte temporary directory escaped its parent");
  }

  try {
    await build({
      entryPoints: {
        background: join(
          scriptDirectory,
          "provider-sign-success-browser-worker.ts",
        ),
      },
      outdir: directory,
      bundle: true,
      platform: "browser",
      target: "chrome106",
      format: "esm",
      sourcemap: false,
      legalComments: "none",
    });
    await build({
      entryPoints: {
        content: join(
          scriptDirectory,
          "provider-runtime-transport-browser-content.ts",
        ),
        approval: join(appDirectory, "src/approval/main.ts"),
      },
      outdir: directory,
      bundle: true,
      platform: "browser",
      target: "chrome106",
      format: "iife",
      sourcemap: false,
      legalComments: "none",
    });
    await build({
      entryPoints: [
        join(scriptDirectory, "provider-sign-success-browser-page.ts"),
      ],
      outfile: join(directory, "fixture-page.js"),
      bundle: true,
      platform: "browser",
      target: "chrome106",
      format: "iife",
      sourcemap: false,
      legalComments: "none",
    });
    await Promise.all([
      copyFile(
        join(appDirectory, "approval.html"),
        join(directory, "approval.html"),
      ),
      copyFile(
        join(appDirectory, "approval.css"),
        join(directory, "approval.css"),
      ),
    ]);
    await writeFile(
      join(directory, "manifest.json"),
      `${JSON.stringify({
        manifest_version: 3,
        name: "Warden Exact-Byte Signing Browser Contract",
        version: "0.0.0",
        minimum_chrome_version: "106",
        permissions: ["storage"],
        background: { service_worker: "background.js", type: "module" },
        content_scripts: [{
          matches: ["http://127.0.0.1/*"],
          js: ["content.js"],
          run_at: "document_start",
        }],
        content_security_policy: {
          extension_pages: "script-src 'self'; object-src 'self'",
        },
      }, null, 2)}\n`,
      "utf8",
    );
    return {
      directory,
      pageScript: await readFile(join(directory, "fixture-page.js"), "utf8"),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

async function liveExtensionWorker(
  context: BrowserContext,
  origin = "chrome-extension://",
) {
  for (const worker of [...context.serviceWorkers()].reverse()) {
    if (!worker.url().startsWith(origin)) continue;
    try {
      await worker.evaluate(() => true);
      return worker;
    } catch {
      // Playwright retains stopped service-worker wrappers.
    }
  }
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith(origin),
    timeout: 30_000,
  });
}

async function readWorkerStatus(
  context: BrowserContext,
  origin?: string,
  approvalId?: string,
): Promise<WorkerStatus> {
  const worker = await liveExtensionWorker(context, origin);
  return worker.evaluate(async (id) => {
    const read = (globalThis as unknown as {
      __wardenProviderSignSuccessStatus?: (
        approvalId?: string,
      ) => Promise<WorkerStatus>;
    }).__wardenProviderSignSuccessStatus;
    if (typeof read !== "function") {
      throw new Error("exact-byte worker status is unavailable");
    }
    return read(id);
  }, approvalId);
}

async function readContentPending(page: Page): Promise<number> {
  return page.evaluate(() => new Promise<number>((resolvePending, rejectPending) => {
    const nonce = `probe_${Date.now()}_${Math.random()}`;
    const timer = setTimeout(() => {
      removeEventListener("message", listener);
      rejectPending(new Error("content status probe timed out"));
    }, 2_000);
    const listener = (event: MessageEvent): void => {
      if (
        event.source !== window ||
        event.origin !== location.origin ||
        event.data?.type !== "warden:test:content-status-response" ||
        event.data?.nonce !== nonce
      ) return;
      clearTimeout(timer);
      removeEventListener("message", listener);
      resolvePending(event.data.pendingCount as number);
    };
    addEventListener("message", listener);
    postMessage({ type: "warden:test:content-status-request", nonce }, location.origin);
  }));
}

test("real Chromium returns exactly the reviewed message after one authenticated signature", async () => {
  const extension = await createExtension();
  let server: TestServer | undefined;
  let context: BrowserContext | undefined;
  try {
    server = await startServer(extension.pageScript);
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extension.directory}`,
        `--load-extension=${extension.directory}`,
        "--headless=new",
      ],
    });
    const page = await context.newPage();
    await page.goto(server.origin);
    await expect.poll(async () => {
      const worker = await readWorkerStatus(context!);
      const pageStatus = await page.evaluate(() =>
        (globalThis as unknown as { __wardenPageSignStatus?: PageSignStatus })
          .__wardenPageSignStatus,
      );
      return {
        fatalErrors: worker.fatalErrors,
        latestApprovalId: worker.latestApprovalId,
        pageError: pageStatus?.error ?? null,
        pageState: pageStatus?.state ?? "missing",
        selectionCalls: worker.selectionCalls,
        activeDocuments: worker.activeDocuments,
        contentPending: await readContentPending(page),
      };
    }).toEqual({
      fatalErrors: [],
      latestApprovalId: expect.stringMatching(/^req_[0-9a-f]{32}$/),
      pageError: null,
      pageState: "pending",
      selectionCalls: 1,
      activeDocuments: 1,
      contentPending: 1,
    });
    const existingPopup = context.pages().find((candidate) =>
      candidate.url().startsWith("chrome-extension://") &&
      candidate.url().includes("/approval.html?request=req_"));
    const popup = existingPopup ?? await context.waitForEvent("page", {
      predicate: (candidate) =>
        candidate.url().startsWith("chrome-extension://") &&
        candidate.url().includes("/approval.html?request=req_"),
      timeout: 30_000,
    });

    await expect.poll(async () => {
      const worker = await readWorkerStatus(context!);
      return {
        popupState: await popup.locator("#approval-status").getAttribute("data-state"),
        popupText: await popup.locator("#approval-status").textContent(),
        popupErrors: (await popup.pageErrors()).map(
          (error) => `${error.name}: ${error.message}`,
        ),
        popupConsole: (await popup.consoleMessages()).map(
          (message) => `${message.type()}: ${message.text()}`,
        ),
        providerPortRoutes: worker.providerPortRoutes,
        approvalPortRoutes: worker.approvalPortRoutes,
        fatalErrors: worker.fatalErrors,
        approvalState: worker.approvalState,
        activeActions: worker.activeActions,
        activeApprovalRequests: worker.activeApprovalRequests,
      };
    }).toEqual({
      popupState: "review",
      popupText: expect.stringContaining("ready for approval"),
      popupErrors: [],
      popupConsole: [],
      providerPortRoutes: 1,
      approvalPortRoutes: 1,
      fatalErrors: [],
      approvalState: "pending",
      activeActions: 1,
      activeApprovalRequests: 1,
    });
    const reviewed = await readWorkerStatus(context);
    expect(reviewed).toMatchObject({
      bootId: expect.stringMatching(/^[0-9a-f]{32}$/),
      ready: true,
      keyringStartup: "seeded",
      checkpointReached: null,
      fatalErrors: [],
      startupInvalidatedApprovals: 0,
      startupInvalidatedOperations: 0,
      keyringUnlocked: true,
      selectionCalls: 1,
      identityReads: 2,
      approvalCreates: 1,
      signingClaims: 0,
      signingCompletions: 0,
      signerLeaseUses: 0,
      approvalState: "pending",
      signingState: null,
    });
    expect(reviewed.latestApprovalId).toMatch(/^req_[0-9a-f]{32}$/);
    expect(reviewed.rawMessage?.length).toBeGreaterThan(0);
    expect(reviewed.messageDigestHex).toMatch(/^[0-9a-f]{64}$/);
    expect(reviewed.durableSignedTransaction).toBeNull();

    await expect(popup.locator("#request-origin")).toHaveText(server.origin);
    await expect(popup.locator("#memo-value")).toHaveText(EXPECTED_MEMO);
    await expect(popup.locator("#network-value")).toHaveText("Solana Devnet");
    await expect(popup.locator("#account-value")).toHaveText(reviewed.account);
    await expect(popup.locator("#digest-value")).toHaveText(
      reviewed.messageDigestHex!,
    );
    await expect(popup.locator("#capability-title")).toHaveText(
      "Signing enabled.",
    );
    await expect(popup.locator("#capability-message")).toContainText(
      "durable signed result",
    );
    await expect(popup.locator("[data-action=approve]")).toBeEnabled();
    expect(popup.url()).toBe(
      `chrome-extension://${new URL((await liveExtensionWorker(context)).url()).hostname}` +
      `/approval.html?request=${reviewed.latestApprovalId}`,
    );

    await popup.locator("[data-action=approve]").click();
    await expect.poll(() => page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    )).toMatchObject({
      state: "signed",
      error: null,
      pendingCount: 0,
      href: `${server.origin}/`,
      navigationEntries: 1,
    });

    const pageStatus = await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    );
    if (pageStatus.signedTransaction === null || reviewed.rawMessage === null) {
      throw new Error("signed page bytes or reviewed message bytes are absent");
    }
    expect(pageStatus.signedTransaction).not.toEqual(pageStatus.sourceTransaction);
    const returnedBytes = Uint8Array.from(pageStatus.signedTransaction);
    const returned = VersionedTransaction.deserialize(returnedBytes);
    const returnedMessage = returned.message.serialize();
    expect([...returnedMessage]).toEqual(reviewed.rawMessage);
    expect(createHash("sha256").update(returnedMessage).digest("hex")).toBe(
      reviewed.messageDigestHex,
    );
    expect(returned.signatures).toHaveLength(1);
    const publicKey = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(new PublicKey(reviewed.sessionSigner).toBytes()),
      ]),
      format: "der",
      type: "spki",
    });
    expect(verify(
      null,
      returnedMessage,
      publicKey,
      returned.signatures[0]!,
    )).toBe(true);

    await expect.poll(async () => ({
      ...await readWorkerStatus(context!),
      contentPending: await readContentPending(page),
    })).toMatchObject({
      fatalErrors: [],
      providerPortRoutes: 1,
      approvalPortRoutes: 1,
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 1,
      signerLeaseUses: 1,
      approvalState: "approved",
      signingState: "signed",
      signingAttemptNumber: 1,
      activeActions: 0,
      activeApprovalRequests: 0,
      activeFlows: 0,
      activeDocuments: 1,
      contentPending: 0,
      rpc: {
        genesisCalls: 8,
        accountCalls: 6,
        latestBlockhashCalls: 1,
        blockhashValidityCalls: 1,
      },
    });
    const terminal = await readWorkerStatus(context);
    expect(terminal.durableSignedTransaction).toEqual(
      pageStatus.signedTransaction,
    );
    expect(await page.evaluate(() => document.location.href)).toBe(
      `${server.origin}/`,
    );
  } finally {
    try {
      await context?.close();
    } finally {
      try {
        await server?.close();
      } finally {
        const expectedPrefix =
          `${resolve(tmpdir())}${sep}warden-provider-sign-success-browser-`;
        if (resolve(extension.directory).startsWith(expectedPrefix)) {
          await rm(extension.directory, { recursive: true, force: true });
        }
      }
    }
  }
});

test("durable signed bytes replay after MV3 death without restoring signer authority", async () => {
  const extension = await createExtension();
  let server: TestServer | undefined;
  let context: BrowserContext | undefined;
  try {
    server = await startServer(extension.pageScript);
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extension.directory}`,
        `--load-extension=${extension.directory}`,
        "--headless=new",
      ],
    });
    const firstWorker = await liveExtensionWorker(context);
    const extensionOrigin =
      `chrome-extension://${new URL(firstWorker.url()).hostname}`;
    await firstWorker.evaluate(() => {
      const arm = (globalThis as unknown as {
        __wardenProviderSignSuccessArmCheckpoint?: (stage: string) => void;
      }).__wardenProviderSignSuccessArmCheckpoint;
      if (typeof arm !== "function") {
        throw new Error("restart checkpoint control is unavailable");
      }
      arm("after-signing-committed");
    });

    const page = await context.newPage();
    await page.goto(server.origin);
    await expect.poll(() => readWorkerStatus(context!)).toMatchObject({
      bootId: expect.stringMatching(/^[0-9a-f]{32}$/),
      keyringStartup: "seeded",
      fatalErrors: [],
      selectionCalls: 1,
      approvalCreates: 1,
      signingClaims: 0,
      checkpointReached: null,
    });
    const existingPopup = context.pages().find((candidate) =>
      candidate.url().startsWith(extensionOrigin) &&
      candidate.url().includes("/approval.html?request=req_"));
    const popup = existingPopup ?? await context.waitForEvent("page", {
      predicate: (candidate) =>
        candidate.url().startsWith(extensionOrigin) &&
        candidate.url().includes("/approval.html?request=req_"),
      timeout: 30_000,
    });
    await expect(popup.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "review",
    );
    await popup.locator("[data-action=approve]").click();

    await expect.poll(() => readWorkerStatus(context!)).toMatchObject({
      fatalErrors: [],
      checkpointReached: "after-signing-committed",
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 1,
      signerLeaseUses: 1,
      approvalState: "approved",
      signingState: "signed",
      signingAttemptNumber: 1,
      activeActions: 1,
      activeApprovalRequests: 1,
      activeFlows: 1,
      activeDocuments: 1,
    });
    const committed = await readWorkerStatus(context);
    if (
      committed.latestApprovalId === null ||
      committed.rawMessage === null ||
      committed.durableSignedTransaction === null
    ) {
      throw new Error("durable pre-restart signing evidence is absent");
    }
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus.state,
    )).toBe("pending");
    expect(await readContentPending(page)).toBe(1);

    // Make replacement-worker signer restoration impossible. Recovery must be
    // authorized only by the already-committed operation + approval result.
    await firstWorker.evaluate(async () => {
      const storage = (globalThis as unknown as {
        chrome: {
          storage: {
            session: { remove(key: string): Promise<void> };
          };
        };
      }).chrome.storage.session;
      await storage.remove("warden.unlock-session.v2");
    });
    const controlPage = await context.newPage();
    const cdp = await context.newCDPSession(controlPage);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" &&
      candidate.url.startsWith(extensionOrigin));
    expect(target, "signing worker exists before the committed-result cut")
      .toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);

    await expect.poll(() => page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    )).toMatchObject({
      state: "signed",
      error: null,
      pendingCount: 0,
      href: `${server.origin}/`,
      navigationEntries: 1,
    });
    const replacement = await readWorkerStatus(
      context,
      extensionOrigin,
      committed.latestApprovalId,
    );
    expect(replacement).toMatchObject({
      ready: true,
      keyringStartup: "locked",
      checkpointReached: null,
      fatalErrors: [],
      startupInvalidatedApprovals: 0,
      startupInvalidatedOperations: 0,
      keyringUnlocked: false,
      providerPortRoutes: 1,
      selectionCalls: 0,
      identityReads: 0,
      approvalCreates: 0,
      signingClaims: 0,
      signingCompletions: 0,
      signerLeaseUses: 0,
      latestApprovalId: committed.latestApprovalId,
      approvalState: "approved",
      signingState: "signed",
      signingAttemptNumber: 1,
      activeActions: 0,
      activeApprovalRequests: 0,
      activeFlows: 0,
      activeDocuments: 1,
      rpc: {
        genesisCalls: 0,
        accountCalls: 0,
        latestBlockhashCalls: 0,
        blockhashValidityCalls: 0,
      },
    });
    expect(replacement.bootId).not.toBe(committed.bootId);
    expect(replacement.rawMessage).toEqual(committed.rawMessage);
    expect(replacement.messageDigestHex).toBe(committed.messageDigestHex);
    expect(replacement.durableSignedTransaction).toEqual(
      committed.durableSignedTransaction,
    );
    expect(await readContentPending(page)).toBe(0);

    const pageStatus = await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    );
    if (pageStatus.signedTransaction === null) {
      throw new Error("replacement worker returned no signed bytes");
    }
    expect(pageStatus.signedTransaction).toEqual(
      committed.durableSignedTransaction,
    );
    expect(pageStatus.signedTransaction).not.toEqual(pageStatus.sourceTransaction);
    const returned = VersionedTransaction.deserialize(
      Uint8Array.from(pageStatus.signedTransaction),
    );
    const returnedMessage = returned.message.serialize();
    expect(returned.signatures).toHaveLength(1);
    expect([...returnedMessage]).toEqual(committed.rawMessage);
    expect(createHash("sha256").update(returnedMessage).digest("hex")).toBe(
      committed.messageDigestHex,
    );
    const publicKey = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(new PublicKey(committed.sessionSigner).toBytes()),
      ]),
      format: "der",
      type: "spki",
    });
    expect(verify(
      null,
      returnedMessage,
      publicKey,
      returned.signatures[0]!,
    )).toBe(true);
  } finally {
    try {
      await context?.close();
    } finally {
      try {
        await server?.close();
      } finally {
        const expectedPrefix =
          `${resolve(tmpdir())}${sep}warden-provider-sign-success-browser-`;
        if (resolve(extension.directory).startsWith(expectedPrefix)) {
          await rm(extension.directory, { recursive: true, force: true });
        }
      }
    }
  }
});
