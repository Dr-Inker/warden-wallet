import { expect, chromium, test, type BrowserContext, type Page } from "@playwright/test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { build } from "esbuild";

const scriptDirectory = resolve(import.meta.dirname, "../scripts");
const CORRELATION_ID = "browser_restart_0123456789";
const OVERLAP_CORRELATION_ID = "browser_overlap_0123456789";
const DEADLINE_CORRELATION_ID = "browser_deadline_01234567";
const ACCOUNT = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";

interface TestServer {
  readonly origin: string;
  close(): Promise<void>;
}

interface WorkerStatus {
  readonly bootId: string;
  readonly startupInvalidated: number;
  readonly preparationCalls: number;
  readonly volatileCalls: number;
  readonly identityDigestCalls: number;
  readonly identityDigestCompletions: number;
  readonly activeDocuments: number;
  readonly ownedDeliveries: number;
  readonly latestCorrelationId: string | null;
  readonly latestExpiresAt: number | null;
}

function signRequest(correlationId: string): Record<string, unknown> {
  return {
    version: 1,
    type: "request",
    correlationId,
    method: "solana:signTransaction",
    params: {
      accountAddress: ACCOUNT,
      transaction: [1, 2, 3, 4],
      chain: "solana:devnet",
      options: { preflightCommitment: "confirmed", minContextSlot: 42 },
    },
  };
}

function deliveryRequest(
  correlationId: string,
  expiresAt = Date.now() + 2 * 60 * 1_000,
): Record<string, unknown> {
  return {
    version: 1,
    type: "warden:provider:transport-request",
    expiresAt,
    payload: signRequest(correlationId),
  };
}

function pageMarkup(): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Warden runtime transport fixture</title></head>
<body><script>
  globalThis.__wardenResponses = [];
  globalThis.__wardenTerminals = [];
  globalThis.__wardenReceipts = [];
  globalThis.__wardenPortEvents = [];
  // Audit finding X-1: terminal responses and page receipts cross the one
  // MessagePort the content owner transfers, never the window. This fixture
  // therefore performs the same one-shot claim a real main-world owner does.
  globalThis.__wardenCapability = null;
  const onTerminal = (data, viaCapability) => {
    if (data?.type !== "warden:provider:response") return;
    const terminal = data.payload;
    if (terminal?.version !== 1 || terminal?.type !== "warden:provider:transport-terminal") return;
    globalThis.__wardenTerminals.push(terminal);
    globalThis.__wardenResponses.push(terminal.payload);
    const receipt = {
      version: 1,
      type: "warden:provider:transport-receipt",
      correlationId: terminal.correlationId,
      receiptId: terminal.receiptId,
      expiresAt: terminal.expiresAt,
    };
    globalThis.__wardenReceipts.push(receipt);
    const envelope = {
      version: 1,
      type: "warden:provider:receipt",
      payload: receipt,
    };
    // Acknowledge over whichever channel delivered the terminal. The C22
    // content owner speaks over the capability; the raw-Port overlap driver in
    // scripts/provider-runtime-transport-browser-overlap-content.ts is a test
    // driver that never claims one and still uses the window.
    if (viaCapability) globalThis.__wardenCapability.postMessage(envelope);
    else postMessage(envelope, location.origin);
  };
  addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    if (
      event.data?.version === 1 &&
      event.data?.type === "warden:provider:capability" &&
      globalThis.__wardenCapability === null
    ) {
      const port = event.ports?.[0] ?? null;
      if (port !== null) {
        globalThis.__wardenCapability = port;
        port.addEventListener("message", (portEvent) => onTerminal(portEvent.data, true));
        port.start();
      }
    }
    if (event.ports?.length !== 1) onTerminal(event.data, false);
    if (typeof event.data?.type === "string" && event.data.type.startsWith("warden:test:port-")) {
      globalThis.__wardenPortEvents.push(event.data);
    }
  });
  postMessage({
    version: 1,
    type: "warden:provider:capability-request",
  }, location.origin);
  globalThis.__sendWardenRequest = (request) => postMessage({
    version: 1,
    type: "warden:provider:request",
    payload: request,
  }, location.origin);
  globalThis.__openWardenPort = (request) => postMessage({
    type: "warden:test:open-port",
    request,
  }, location.origin);
</script></body></html>`;
}

async function startServer(): Promise<TestServer> {
  const server: Server = createServer((_request, response) => {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(pageMarkup());
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
    throw new Error("runtime transport fixture server has no TCP address");
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => error === undefined ? resolveClose() : rejectClose(error));
      });
    },
  };
}

async function liveExtensionWorker(context: BrowserContext, origin?: string) {
  for (const worker of [...context.serviceWorkers()].reverse()) {
    if (!worker.url().startsWith(origin ?? "chrome-extension://")) continue;
    try {
      await worker.evaluate(() => true);
      return worker;
    } catch {
      // Playwright retains dead service-worker wrappers.
    }
  }
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith(origin ?? "chrome-extension://"),
    timeout: 30_000,
  });
}

async function readStatus(context: BrowserContext, origin?: string): Promise<WorkerStatus> {
  const worker = await liveExtensionWorker(context, origin);
  return worker.evaluate(async () => {
    const status = (globalThis as unknown as {
      __wardenProviderRuntimeTransportStatus?: () => Promise<WorkerStatus>;
    }).__wardenProviderRuntimeTransportStatus;
    if (typeof status !== "function") throw new Error("transport status is unavailable");
    return status();
  });
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
        event.data?.nonce !== nonce ||
        !Number.isSafeInteger(event.data?.pendingCount)
      ) {
        return;
      }
      clearTimeout(timer);
      removeEventListener("message", listener);
      resolvePending(event.data.pendingCount as number);
    };
    addEventListener("message", listener);
    postMessage({
      type: "warden:test:content-status-request",
      nonce,
    }, location.origin);
  }));
}

async function createExtension(contentEntry: string): Promise<string> {
  const temporaryParent = resolve(tmpdir());
  const extensionDirectory = await mkdtemp(
    join(temporaryParent, "warden-provider-runtime-browser-"),
  );
  const expectedPrefix = `${temporaryParent}${sep}warden-provider-runtime-browser-`;
  if (!resolve(extensionDirectory).startsWith(expectedPrefix)) {
    throw new Error("runtime transport temporary directory escaped its parent");
  }
  await build({
    entryPoints: {
      background: join(scriptDirectory, "provider-runtime-transport-browser-worker.ts"),
      content: join(scriptDirectory, contentEntry),
    },
    outdir: extensionDirectory,
    bundle: true,
    platform: "browser",
    target: "chrome106",
    format: "esm",
    sourcemap: false,
    legalComments: "none",
  });
  await writeFile(join(extensionDirectory, "manifest.json"), `${JSON.stringify({
    manifest_version: 3,
    name: "Warden Provider Runtime Transport Browser Contract",
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
  }, null, 2)}\n`, "utf8");
  return extensionDirectory;
}

test("real Chromium replacement Port preserves one volatile delivery lease", async () => {
  const extensionDirectory = await createExtension(
    "provider-runtime-transport-browser-overlap-content.ts",
  );
  const server = await startServer();
  let context: BrowserContext | undefined;
  try {
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionDirectory}`,
        `--load-extension=${extensionDirectory}`,
        "--headless=new",
      ],
    });
    const page = await context.newPage();
    await page.goto(server.origin);
    const carried = deliveryRequest(OVERLAP_CORRELATION_ID);
    await page.evaluate((request) => {
      (globalThis as unknown as { __openWardenPort(value: unknown): void })
        .__openWardenPort(request);
    }, carried);
    await expect.poll(() => readStatus(context!)).toMatchObject({
      startupInvalidated: 0,
      volatileCalls: 1,
      identityDigestCalls: 2,
      identityDigestCompletions: 2,
      activeDocuments: 1,
      ownedDeliveries: 1,
    });

    await page.evaluate((request) => {
      (globalThis as unknown as { __openWardenPort(value: unknown): void })
        .__openWardenPort(request);
    }, carried);
    await expect.poll(async () => ({
      status: await readStatus(context!),
      events: await page.evaluate(() =>
        (globalThis as unknown as { __wardenPortEvents: unknown[] }).__wardenPortEvents),
    })).toMatchObject({
      status: {
        volatileCalls: 1,
        identityDigestCalls: 4,
        identityDigestCompletions: 4,
        activeDocuments: 1,
        ownedDeliveries: 1,
      },
      events: expect.arrayContaining([
        expect.objectContaining({ type: "warden:test:port-disconnect", index: 0 }),
      ]),
    });

    const worker = await liveExtensionWorker(context);
    await worker.evaluate(() => {
      const release = (globalThis as unknown as {
        __wardenProviderRuntimeTransportRelease?: () => void;
      }).__wardenProviderRuntimeTransportRelease;
      if (typeof release !== "function") throw new Error("transport release is unavailable");
      release();
    });
    await expect.poll(() => page.evaluate(() =>
      (globalThis as unknown as { __wardenPortEvents: unknown[] }).__wardenPortEvents,
    )).toEqual(expect.arrayContaining([
      expect.objectContaining({
        type: "warden:test:port-message",
        index: 1,
        payload: expect.objectContaining({
          correlationId: OVERLAP_CORRELATION_ID,
          type: "warden:provider:transport-terminal",
          payload: {
            version: 1,
            type: "response",
            correlationId: OVERLAP_CORRELATION_ID,
            ok: false,
            error: {
              code: "WARDEN_REQUEST_CANCELLED",
              message: "Provider request was cancelled",
            },
          },
        }),
      }),
    ]));
    await expect.poll(() => readStatus(context!)).toMatchObject({
      volatileCalls: 1,
      identityDigestCalls: 4,
      identityDigestCompletions: 4,
      activeDocuments: 1,
      ownedDeliveries: 0,
    });
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenReceipts: unknown[] }).__wardenReceipts,
    )).toHaveLength(1);
  } finally {
    await context?.close();
    await server.close();
    await rm(extensionDirectory, { recursive: true, force: true });
  }
});

test("C20 resend reaches one C14/C19 terminal result after real MV3 worker death", async () => {
  const extensionDirectory = await createExtension(
    "provider-runtime-transport-browser-content.ts",
  );
  const server = await startServer();
  let context: BrowserContext | undefined;
  try {
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionDirectory}`,
        `--load-extension=${extensionDirectory}`,
        "--headless=new",
      ],
    });
    const page = await context.newPage();
    await page.goto(server.origin);
    const carried = deliveryRequest(CORRELATION_ID);
    await page.evaluate((request) => {
      (globalThis as unknown as { __sendWardenRequest(value: unknown): void })
        .__sendWardenRequest(request);
    }, carried);

    await expect.poll(() => readStatus(context!)).toMatchObject({
      startupInvalidated: 0,
      preparationCalls: 1,
      activeDocuments: 1,
      ownedDeliveries: 1,
    });
    const before = await readStatus(context);
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenResponses: unknown[] }).__wardenResponses,
    )).toEqual([]);

    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;
    const cdp = await context.newCDPSession(page);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" && candidate.url.startsWith(extensionOrigin));
    expect(target, "runtime transport worker exists before forced stop").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", { targetId: target!.targetId });
    expect(closed.success).toBe(true);

    await expect.poll(() => page.evaluate((correlationId) => {
      const responses = (globalThis as unknown as {
        __wardenResponses: Array<{ correlationId?: unknown }>;
      }).__wardenResponses;
      return responses.find((response) => response.correlationId === correlationId) ?? null;
    }, CORRELATION_ID)).toEqual({
      version: 1,
      type: "response",
      correlationId: CORRELATION_ID,
      ok: false,
      error: {
        code: "WARDEN_REQUEST_CANCELLED",
        message: "Provider request was cancelled",
      },
    });
    await expect.poll(() => readStatus(context!, extensionOrigin)).toMatchObject({
      startupInvalidated: 1,
      preparationCalls: 1,
      activeDocuments: 1,
      ownedDeliveries: 0,
    });
    const after = await readStatus(context, extensionOrigin);
    expect(after.bootId).not.toBe(before.bootId);
    expect(await page.evaluate(() =>
      (globalThis as unknown as { __wardenResponses: unknown[] }).__wardenResponses,
    )).toHaveLength(1);
  } finally {
    await context?.close();
    await server.close();
    await rm(extensionDirectory, { recursive: true, force: true });
  }
});

test("near-deadline MV3 worker death cannot extend the initiating deadline", async () => {
  const extensionDirectory = await createExtension(
    "provider-runtime-transport-browser-content.ts",
  );
  const server = await startServer();
  let context: BrowserContext | undefined;
  try {
    context = await chromium.launchPersistentContext("", {
      headless: false,
      args: [
        `--disable-extensions-except=${extensionDirectory}`,
        `--load-extension=${extensionDirectory}`,
        "--headless=new",
      ],
    });
    const page = await context.newPage();
    await page.goto(server.origin);
    const expiresAt = Date.now() + 8_000;
    const carried = deliveryRequest(DEADLINE_CORRELATION_ID, expiresAt);
    await page.evaluate((request) => {
      (globalThis as unknown as { __sendWardenRequest(value: unknown): void })
        .__sendWardenRequest(request);
    }, carried);

    await expect.poll(() => readStatus(context!)).toMatchObject({
      startupInvalidated: 0,
      preparationCalls: 1,
      ownedDeliveries: 1,
      latestCorrelationId: DEADLINE_CORRELATION_ID,
      latestExpiresAt: expiresAt,
    });

    const waitBeforeCloseMs = Math.max(0, expiresAt - Date.now() - 3_000);
    if (waitBeforeCloseMs > 0) await page.waitForTimeout(waitBeforeCloseMs);
    const remainingAtClose = expiresAt - Date.now();
    expect(remainingAtClose).toBeGreaterThan(0);
    expect(remainingAtClose).toBeLessThanOrEqual(3_250);

    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;
    const cdp = await context.newCDPSession(page);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((candidate) =>
      candidate.type === "service_worker" && candidate.url.startsWith(extensionOrigin));
    expect(target, "runtime transport worker exists before near-deadline stop")
      .toBeDefined();
    const closed = await cdp.send("Target.closeTarget", { targetId: target!.targetId });
    expect(closed.success).toBe(true);

    await page.waitForTimeout(1_000);
    expect(await readStatus(context, extensionOrigin)).toMatchObject({
      startupInvalidated: 1,
      preparationCalls: 1,
      ownedDeliveries: 1,
      latestCorrelationId: DEADLINE_CORRELATION_ID,
      latestExpiresAt: expiresAt,
    });

    const waitAfterExpiryMs = Math.max(0, expiresAt - Date.now() + 150);
    if (waitAfterExpiryMs > 0) await page.waitForTimeout(waitAfterExpiryMs);
    await expect.poll(() => readStatus(context!, extensionOrigin)).toMatchObject({
      startupInvalidated: 1,
      preparationCalls: 1,
      ownedDeliveries: 0,
      latestCorrelationId: DEADLINE_CORRELATION_ID,
      latestExpiresAt: expiresAt,
    });
    expect(await readContentPending(page)).toBe(0);
    expect(await page.evaluate(() => ({
      responses: (globalThis as unknown as { __wardenResponses: unknown[] })
        .__wardenResponses,
      terminals: (globalThis as unknown as { __wardenTerminals: unknown[] })
        .__wardenTerminals,
      receipts: (globalThis as unknown as { __wardenReceipts: unknown[] })
        .__wardenReceipts,
    }))).toEqual({ responses: [], terminals: [], receipts: [] });
  } finally {
    await context?.close();
    await server.close();
    await rm(extensionDirectory, { recursive: true, force: true });
  }
});
