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
const SIGNING_COMMIT_CHECKPOINT_STORAGE_KEY =
  "warden:test:signing-commit-request-succeeded-v1";
const TERMINAL_ENQUEUED_CHECKPOINT_STORAGE_KEY =
  "warden:test:terminal-enqueued-v1";
const SETTLEMENT_ENQUEUE_CHECKPOINT_STORAGE_KEY =
  "warden:test:before-settlement-enqueue-v1";

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
  readonly terminalSettlements: number;
  readonly pageReceiptPosts: number;
  readonly lastPageReceipt: Readonly<{
    readonly correlationId: string;
    readonly receiptId: string;
    readonly expiresAt: number;
  }> | null;
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
  readonly signerResultsProduced: number;
  readonly latestApprovalId: string | null;
  readonly approvalState: string | null;
  readonly signingState: string | null;
  readonly signingAttemptNumber: number | null;
  readonly signingFailureCode: string | null;
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

interface SigningCommitCheckpointMarker {
  readonly stage: "during-signing-commit";
  readonly bootId: string;
  readonly approvalId: string;
  readonly attemptId: string;
  readonly attemptNumber: number;
  readonly transactionBytesLength: number;
  readonly selectionCalls: number;
  readonly approvalCreates: number;
  readonly signingClaims: number;
  readonly signingCompletions: number;
  readonly signerLeaseUses: number;
  readonly signerResultsProduced: number;
  readonly rpc: WorkerStatus["rpc"];
}

interface TerminalEnqueuedCheckpointMarker {
  readonly stage: "after-terminal-enqueued";
  readonly bootId: string;
  readonly approvalId: string;
  readonly correlationId: string;
  readonly receiptId: string;
  readonly expiresAt: number;
  readonly signedTransaction: number[];
  readonly selectionCalls: number;
  readonly approvalCreates: number;
  readonly signingClaims: number;
  readonly signingCompletions: number;
  readonly signerLeaseUses: number;
  readonly signerResultsProduced: number;
  readonly rpc: WorkerStatus["rpc"];
}

interface SettlementEnqueueCheckpointMarker {
  readonly stage: "before-settlement-enqueue";
  readonly bootId: string;
  readonly approvalId: string;
  readonly correlationId: string;
  readonly receiptId: string;
  readonly expiresAt: number;
  readonly signedTransaction: number[];
  readonly selectionCalls: number;
  readonly approvalCreates: number;
  readonly signingClaims: number;
  readonly signingCompletions: number;
  readonly signerLeaseUses: number;
  readonly signerResultsProduced: number;
  readonly rpc: WorkerStatus["rpc"];
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
      writeFile(
        join(directory, "control.html"),
        "<!doctype html><meta charset=\"utf-8\"><title>Warden test control</title>\n",
        "utf8",
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

async function readSigningCommitCheckpoint(
  extensionPage: Page,
): Promise<SigningCommitCheckpointMarker | null> {
  return extensionPage.evaluate(async (key) => {
    const storage = (globalThis as unknown as {
      chrome: {
        storage: {
          session: {
            get(key: string): Promise<Record<string, unknown>>;
          };
        };
      };
    }).chrome.storage.session;
    const stored = await storage.get(key);
    return (stored[key] ?? null) as SigningCommitCheckpointMarker | null;
  }, SIGNING_COMMIT_CHECKPOINT_STORAGE_KEY);
}

async function readTerminalEnqueuedCheckpoint(
  extensionPage: Page,
): Promise<TerminalEnqueuedCheckpointMarker | null> {
  return extensionPage.evaluate(async (key) => {
    const storage = (globalThis as unknown as {
      chrome: {
        storage: {
          session: {
            get(key: string): Promise<Record<string, unknown>>;
          };
        };
      };
    }).chrome.storage.session;
    const stored = await storage.get(key);
    return (stored[key] ?? null) as TerminalEnqueuedCheckpointMarker | null;
  }, TERMINAL_ENQUEUED_CHECKPOINT_STORAGE_KEY);
}

async function readSettlementEnqueueCheckpoint(
  extensionPage: Page,
): Promise<SettlementEnqueueCheckpointMarker | null> {
  return extensionPage.evaluate(async (key) => {
    const storage = (globalThis as unknown as {
      chrome: {
        storage: {
          session: {
            get(key: string): Promise<Record<string, unknown>>;
          };
        };
      };
    }).chrome.storage.session;
    const stored = await storage.get(key);
    return (stored[key] ?? null) as SettlementEnqueueCheckpointMarker | null;
  }, SETTLEMENT_ENQUEUE_CHECKPOINT_STORAGE_KEY);
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
      signerResultsProduced: 0,
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
      signerResultsProduced: 1,
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
      signerResultsProduced: 1,
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
      signerResultsProduced: 0,
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

test("uncommitted signature is abandoned after MV3 death without signer retry", async () => {
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
        throw new Error("precommit checkpoint control is unavailable");
      }
      arm("after-signature-produced");
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
      checkpointReached: "after-signature-produced",
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 0,
      signerLeaseUses: 1,
      signerResultsProduced: 1,
      keyringUnlocked: true,
      approvalState: "approved",
      signingState: "signing",
      signingAttemptNumber: 1,
      signingFailureCode: null,
      durableSignedTransaction: null,
      activeActions: 1,
      activeApprovalRequests: 1,
      activeFlows: 1,
      activeDocuments: 1,
      rpc: {
        genesisCalls: 8,
        accountCalls: 6,
        latestBlockhashCalls: 1,
        blockhashValidityCalls: 1,
      },
    });
    const produced = await readWorkerStatus(context);
    if (produced.latestApprovalId === null || produced.rawMessage === null) {
      throw new Error("precommit signing evidence is absent");
    }
    expect(produced.durableSignedTransaction).toBeNull();
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    )).toMatchObject({
      state: "pending",
      signedTransaction: null,
      error: null,
      pendingCount: 0,
      href: `${server.origin}/`,
      navigationEntries: 1,
    });
    expect(await readContentPending(page)).toBe(1);

    // Deny the replacement any signer authority. A signature that existed
    // only in the killed worker must never be reconstructed or delivered.
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
    expect(target, "signing worker exists before the precommit cut").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);

    await expect.poll(() => page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    )).toMatchObject({
      state: "failed",
      signedTransaction: null,
      error: "ProviderPageTerminalError: Provider request failed",
      pendingCount: 0,
      href: `${server.origin}/`,
      navigationEntries: 1,
    });
    const replacement = await readWorkerStatus(
      context,
      extensionOrigin,
      produced.latestApprovalId,
    );
    expect(replacement).toMatchObject({
      ready: true,
      keyringStartup: "locked",
      checkpointReached: null,
      fatalErrors: [],
      startupInvalidatedApprovals: 1,
      startupInvalidatedOperations: 0,
      keyringUnlocked: false,
      providerPortRoutes: 1,
      selectionCalls: 0,
      identityReads: 0,
      approvalCreates: 0,
      signingClaims: 0,
      signingCompletions: 0,
      signerLeaseUses: 0,
      signerResultsProduced: 0,
      latestApprovalId: produced.latestApprovalId,
      approvalState: "approved",
      signingState: "failed",
      signingAttemptNumber: 1,
      signingFailureCode: "worker-restarted",
      durableSignedTransaction: null,
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
    expect(replacement.bootId).not.toBe(produced.bootId);
    expect(replacement.rawMessage).toEqual(produced.rawMessage);
    expect(replacement.messageDigestHex).toBe(produced.messageDigestHex);
    expect(produced.signerLeaseUses + replacement.signerLeaseUses).toBe(1);
    expect(
      produced.signerResultsProduced + replacement.signerResultsProduced,
    ).toBe(1);
    expect(produced.signingCompletions + replacement.signingCompletions).toBe(0);
    expect(await readContentPending(page)).toBe(0);
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

test("in-flight strict signing commit resolves to one durable outcome after MV3 death", async () => {
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
        throw new Error("in-flight commit checkpoint control is unavailable");
      }
      arm("during-signing-commit");
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
    const reviewed = await readWorkerStatus(context);
    if (
      reviewed.latestApprovalId === null ||
      reviewed.rawMessage === null ||
      reviewed.messageDigestHex === null
    ) {
      throw new Error("in-flight commit review evidence is absent");
    }
    await popup.locator("[data-action=approve]").click();

    await expect.poll(() => readSigningCommitCheckpoint(popup)).toMatchObject({
      stage: "during-signing-commit",
      bootId: reviewed.bootId,
      approvalId: reviewed.latestApprovalId,
      attemptId: expect.stringMatching(/^attempt_[0-9a-f]{32}$/),
      attemptNumber: 1,
      transactionBytesLength: expect.any(Number),
      selectionCalls: 1,
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 1,
      signerLeaseUses: 1,
      signerResultsProduced: 1,
      rpc: {
        genesisCalls: 8,
        accountCalls: 6,
        latestBlockhashCalls: 1,
        blockhashValidityCalls: 1,
      },
    });
    const marker = await readSigningCommitCheckpoint(popup);
    if (marker === null || marker.transactionBytesLength <= 0) {
      throw new Error("native signing-completion request did not reach success");
    }
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    )).toMatchObject({
      state: "pending",
      signedTransaction: null,
      error: null,
      href: `${server.origin}/`,
      navigationEntries: 1,
    });
    expect(await readContentPending(page)).toBe(1);

    // The worker is synchronously held inside the real IDBRequest success
    // event. Use the independent extension page to revoke restart authority.
    await popup.evaluate(async () => {
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
    expect(target, "worker exists during the native signing commit").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);

    await expect.poll(() => page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus.state,
    )).toMatch(/^(signed|failed)$/);
    const pageStatus = await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    );
    const replacement = await readWorkerStatus(
      context,
      extensionOrigin,
      reviewed.latestApprovalId,
    );
    expect(replacement).toMatchObject({
      ready: true,
      keyringStartup: "locked",
      checkpointReached: null,
      fatalErrors: [],
      startupInvalidatedOperations: 0,
      keyringUnlocked: false,
      providerPortRoutes: 1,
      selectionCalls: 0,
      identityReads: 0,
      approvalCreates: 0,
      signingClaims: 0,
      signingCompletions: 0,
      signerLeaseUses: 0,
      signerResultsProduced: 0,
      latestApprovalId: reviewed.latestApprovalId,
      approvalState: "approved",
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
    expect(replacement.bootId).not.toBe(marker.bootId);
    expect(replacement.rawMessage).toEqual(reviewed.rawMessage);
    expect(replacement.messageDigestHex).toBe(reviewed.messageDigestHex);
    expect(await readContentPending(page)).toBe(0);

    if (replacement.signingState === "signed") {
      expect(replacement).toMatchObject({
        startupInvalidatedApprovals: 0,
        signingFailureCode: null,
      });
      expect(pageStatus).toMatchObject({
        state: "signed",
        error: null,
        pendingCount: 0,
        href: `${server.origin}/`,
        navigationEntries: 1,
      });
      if (
        replacement.durableSignedTransaction === null ||
        pageStatus.signedTransaction === null
      ) {
        throw new Error("committed branch lacks durable or returned bytes");
      }
      expect(pageStatus.signedTransaction).toEqual(
        replacement.durableSignedTransaction,
      );
      expect(pageStatus.signedTransaction).not.toEqual(
        pageStatus.sourceTransaction,
      );
      const returned = VersionedTransaction.deserialize(
        Uint8Array.from(pageStatus.signedTransaction),
      );
      const returnedMessage = returned.message.serialize();
      expect(returned.signatures).toHaveLength(1);
      expect([...returnedMessage]).toEqual(reviewed.rawMessage);
      expect(createHash("sha256").update(returnedMessage).digest("hex")).toBe(
        reviewed.messageDigestHex,
      );
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
    } else {
      expect(replacement).toMatchObject({
        startupInvalidatedApprovals: 1,
        signingState: "failed",
        signingFailureCode: "worker-restarted",
        durableSignedTransaction: null,
      });
      expect(pageStatus).toMatchObject({
        state: "failed",
        signedTransaction: null,
        error: "ProviderPageTerminalError: Provider request failed",
        pendingCount: 0,
        href: `${server.origin}/`,
        navigationEntries: 1,
      });
    }
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

test("page-settled signed result reaches one background settlement after MV3 death", async () => {
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
        throw new Error("terminal-enqueue checkpoint control is unavailable");
      }
      arm("after-terminal-enqueued");
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
    const reviewed = await readWorkerStatus(context);
    if (
      reviewed.latestApprovalId === null ||
      reviewed.rawMessage === null ||
      reviewed.messageDigestHex === null
    ) {
      throw new Error("terminal-enqueue review evidence is absent");
    }
    const extensionControl = await context.newPage();
    await extensionControl.goto(`${extensionOrigin}/control.html`);
    await popup.locator("[data-action=approve]").click();

    await expect.poll(() =>
      readTerminalEnqueuedCheckpoint(extensionControl)
    ).toMatchObject({
      stage: "after-terminal-enqueued",
      bootId: reviewed.bootId,
      approvalId: reviewed.latestApprovalId,
      correlationId: expect.stringMatching(/^page_[0-9a-f]{32}$/),
      receiptId: expect.stringMatching(/^delivery_[0-9a-f]{64}$/),
      expiresAt: expect.any(Number),
      signedTransaction: expect.any(Array),
      selectionCalls: 1,
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 1,
      signerLeaseUses: 1,
      signerResultsProduced: 1,
      rpc: {
        genesisCalls: 8,
        accountCalls: 6,
        latestBlockhashCalls: 1,
        blockhashValidityCalls: 1,
      },
    });
    const marker = await readTerminalEnqueuedCheckpoint(extensionControl);
    if (marker === null || marker.signedTransaction.length === 0) {
      throw new Error("signed terminal was not enqueued before the cut");
    }
    await expect.poll(async () => ({
      page: await page.evaluate(() =>
        (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
          .__wardenPageSignStatus,
      ),
      contentPending: await readContentPending(page),
    })).toMatchObject({
      page: {
        state: "signed",
        signedTransaction: marker.signedTransaction,
        error: null,
        pendingCount: 0,
        href: `${server.origin}/`,
        navigationEntries: 1,
        terminalSettlements: 1,
        pageReceiptPosts: 1,
        lastPageReceipt: {
          correlationId: marker.correlationId,
          receiptId: marker.receiptId,
          expiresAt: marker.expiresAt,
        },
      },
      contentPending: 1,
    });
    const pageSettledBeforeCut = await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    );

    // The real terminal has reached the page and its receipt has reached the
    // content owner, but the worker is still inside native Port.postMessage().
    // Remove restart authority before closing that actual service-worker target.
    await extensionControl.evaluate(async () => {
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
    expect(target, "worker exists after page receipt but before settlement")
      .toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);

    await expect.poll(async () => ({
      page: await page.evaluate(() =>
        (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
          .__wardenPageSignStatus,
      ),
      contentPending: await readContentPending(page),
    })).toEqual({
      page: pageSettledBeforeCut,
      contentPending: 0,
    });
    const replacement = await readWorkerStatus(
      context,
      extensionOrigin,
      reviewed.latestApprovalId,
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
      signerResultsProduced: 0,
      latestApprovalId: reviewed.latestApprovalId,
      approvalState: "approved",
      signingState: "signed",
      signingAttemptNumber: 1,
      signingFailureCode: null,
      durableSignedTransaction: marker.signedTransaction,
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
    expect(replacement.bootId).not.toBe(marker.bootId);
    expect(replacement.rawMessage).toEqual(reviewed.rawMessage);
    expect(replacement.messageDigestHex).toBe(reviewed.messageDigestHex);

    const returned = VersionedTransaction.deserialize(
      Uint8Array.from(marker.signedTransaction),
    );
    const returnedMessage = returned.message.serialize();
    expect(returned.signatures).toHaveLength(1);
    expect([...returnedMessage]).toEqual(reviewed.rawMessage);
    expect(createHash("sha256").update(returnedMessage).digest("hex")).toBe(
      reviewed.messageDigestHex,
    );
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

test("accepted page receipt recovers when MV3 dies before settlement enqueue", async () => {
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
        throw new Error("settlement-enqueue checkpoint control is unavailable");
      }
      arm("before-settlement-enqueue");
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
    const reviewed = await readWorkerStatus(context);
    if (
      reviewed.latestApprovalId === null ||
      reviewed.rawMessage === null ||
      reviewed.messageDigestHex === null
    ) {
      throw new Error("settlement-enqueue review evidence is absent");
    }
    const extensionControl = await context.newPage();
    await extensionControl.goto(`${extensionOrigin}/control.html`);
    await popup.locator("[data-action=approve]").click();

    await expect.poll(() =>
      readSettlementEnqueueCheckpoint(extensionControl)
    ).toMatchObject({
      stage: "before-settlement-enqueue",
      bootId: reviewed.bootId,
      approvalId: reviewed.latestApprovalId,
      correlationId: expect.stringMatching(/^page_[0-9a-f]{32}$/),
      receiptId: expect.stringMatching(/^delivery_[0-9a-f]{64}$/),
      expiresAt: expect.any(Number),
      signedTransaction: expect.any(Array),
      selectionCalls: 1,
      approvalCreates: 1,
      signingClaims: 1,
      signingCompletions: 1,
      signerLeaseUses: 1,
      signerResultsProduced: 1,
      rpc: {
        genesisCalls: 8,
        accountCalls: 6,
        latestBlockhashCalls: 1,
        blockhashValidityCalls: 1,
      },
    });
    const marker = await readSettlementEnqueueCheckpoint(extensionControl);
    if (marker === null || marker.signedTransaction.length === 0) {
      throw new Error("receipt acceptance did not reach settlement enqueue");
    }
    await expect.poll(async () => ({
      page: await page.evaluate(() =>
        (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
          .__wardenPageSignStatus,
      ),
      contentPending: await readContentPending(page),
    })).toMatchObject({
      page: {
        state: "signed",
        signedTransaction: marker.signedTransaction,
        error: null,
        pendingCount: 0,
        href: `${server.origin}/`,
        navigationEntries: 1,
        terminalSettlements: 1,
        pageReceiptPosts: 1,
        lastPageReceipt: {
          correlationId: marker.correlationId,
          receiptId: marker.receiptId,
          expiresAt: marker.expiresAt,
        },
      },
      contentPending: 1,
    });
    const pageSettledBeforeCut = await page.evaluate(() =>
      (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
        .__wardenPageSignStatus,
    );

    // The production owner has accepted the exact page receipt, finished the
    // delivery lease, and entered Port.postMessage(settled), but the browser-
    // only wrapper has not delegated that final enqueue to Chrome. Remove
    // restart authority before closing that actual service-worker target.
    await extensionControl.evaluate(async () => {
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
    expect(target, "worker exists after receipt and before settlement enqueue")
      .toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: target!.targetId,
    });
    expect(closed.success).toBe(true);

    await expect.poll(async () => ({
      page: await page.evaluate(() =>
        (globalThis as unknown as { __wardenPageSignStatus: PageSignStatus })
          .__wardenPageSignStatus,
      ),
      contentPending: await readContentPending(page),
    })).toEqual({
      page: pageSettledBeforeCut,
      contentPending: 0,
    });
    const replacement = await readWorkerStatus(
      context,
      extensionOrigin,
      reviewed.latestApprovalId,
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
      signerResultsProduced: 0,
      latestApprovalId: reviewed.latestApprovalId,
      approvalState: "approved",
      signingState: "signed",
      signingAttemptNumber: 1,
      signingFailureCode: null,
      durableSignedTransaction: marker.signedTransaction,
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
    expect(replacement.bootId).not.toBe(marker.bootId);
    expect(replacement.rawMessage).toEqual(reviewed.rawMessage);
    expect(replacement.messageDigestHex).toBe(reviewed.messageDigestHex);

    const returned = VersionedTransaction.deserialize(
      Uint8Array.from(marker.signedTransaction),
    );
    const returnedMessage = returned.message.serialize();
    expect(returned.signatures).toHaveLength(1);
    expect([...returnedMessage]).toEqual(reviewed.rawMessage);
    expect(createHash("sha256").update(returnedMessage).digest("hex")).toBe(
      reviewed.messageDigestHex,
    );
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
