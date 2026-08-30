import {
  expect,
  chromium,
  test,
  type BrowserContext,
  type CDPSession,
  type Frame,
  type Page,
} from "@playwright/test";
import { createServer, type Server } from "node:http";
import { resolve } from "node:path";

const EXTENSION_DIRECTORY = resolve(import.meta.dirname, "../dist");
const PAGE_REQUEST_TYPE = "warden:provider:request";
const PAGE_RESPONSE_TYPE = "warden:provider:response";

interface TestServer {
  readonly origin: string;
  close(): Promise<void>;
}

interface BrowserExtensionPort {
  readonly onMessage: {
    addListener(listener: (message: unknown) => void): void;
  };
  readonly onDisconnect: {
    addListener(listener: () => void): void;
  };
  postMessage(message: unknown): void;
  disconnect(): void;
}

interface BrowserExtensionRuntime {
  readonly lastError?: { readonly message: string };
  connect(options: { readonly name: string }): BrowserExtensionPort;
}

interface BrowserExtensionActionApi {
  openPopup(): Promise<void>;
}

let attachedCommandId = 0;

async function sendAttachedTargetCommand(
  cdp: CDPSession,
  sessionId: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const id = ++attachedCommandId;
  const response = new Promise<unknown>((resolveResponse, rejectResponse) => {
    const onMessage = (event: { readonly sessionId: string; readonly message: string }) => {
      if (event.sessionId !== sessionId) return;
      let message: {
        readonly id?: number;
        readonly result?: unknown;
        readonly error?: { readonly message?: string };
      };
      try {
        message = JSON.parse(event.message) as typeof message;
      } catch (error) {
        cdp.off("Target.receivedMessageFromTarget", onMessage);
        rejectResponse(error);
        return;
      }
      if (message.id !== id) return;
      cdp.off("Target.receivedMessageFromTarget", onMessage);
      if (message.error !== undefined) {
        rejectResponse(new Error(message.error.message ?? "attached CDP command failed"));
      } else {
        resolveResponse(message.result);
      }
    };
    cdp.on("Target.receivedMessageFromTarget", onMessage);
  });
  await cdp.send("Target.sendMessageToTarget", {
    sessionId,
    message: JSON.stringify({ id, method, params }),
  });
  return response;
}

function pageMarkup(frameOrigin?: string): string {
  const frame = frameOrigin === undefined
    ? ""
    : `<iframe id="cross-origin-frame" src="${frameOrigin}/frame"></iframe>`;
  return `<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Warden bridge fixture</title></head>
  <body>
    ${frame}
    <script>
      globalThis.__wardenResponses = [];
      globalThis.__wardenWindowRequests = [];
      addEventListener("message", (event) => {
        const data = event.data;
        if (
          data !== null &&
          typeof data === "object" &&
          data.version === 1 &&
          data.type === ${JSON.stringify(PAGE_REQUEST_TYPE)}
        ) {
          globalThis.__wardenWindowRequests.push(data.payload?.correlationId);
        }
        if (
          event.source === window &&
          event.origin === location.origin &&
          data !== null &&
          typeof data === "object" &&
          data.version === 1 &&
          data.type === ${JSON.stringify(PAGE_RESPONSE_TYPE)}
        ) {
          globalThis.__wardenResponses.push(data.payload);
        }
      });
      globalThis.__sendWardenRequest = (correlationId) => {
        postMessage({
          version: 1,
          type: ${JSON.stringify(PAGE_REQUEST_TYPE)},
          payload: {
            version: 1,
            type: "request",
            correlationId,
            method: "standard:connect",
            params: {},
          },
        }, location.origin);
      };
    </script>
  </body>
</html>`;
}

async function startServer(render: (path: string) => string): Promise<TestServer> {
  const server: Server = createServer((request, response) => {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end(render(request.url ?? "/"));
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
    throw new Error("HTTP fixture server did not expose a TCP address");
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

async function extensionWorker(context: BrowserContext) {
  const current = context.serviceWorkers().find((worker) =>
    worker.url().startsWith("chrome-extension://"));
  if (current !== undefined) return current;
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith("chrome-extension://"),
  });
}

async function sendAndRead(target: Page | Frame, correlationId: string) {
  await target.evaluate((id) => {
    const send = (globalThis as unknown as {
      __sendWardenRequest?: (requestId: string) => void;
    }).__sendWardenRequest;
    if (typeof send !== "function") throw new Error("fixture sender is unavailable");
    send(id);
  }, correlationId);

  await expect.poll(async () => target.evaluate((id) => {
    const responses = (globalThis as unknown as {
      __wardenResponses?: Array<{ correlationId?: unknown }>;
    }).__wardenResponses ?? [];
    return responses.find((response) => response.correlationId === id) ?? null;
  }, correlationId)).toEqual({
    version: 1,
    type: "response",
    correlationId,
    ok: false,
    error: {
      code: "WARDEN_METHOD_UNAVAILABLE",
      message: "Warden provider methods are not enabled",
    },
  });
}

test("real MV3 bridge binds each frame/document and wakes after worker termination", async () => {
  const frameServer = await startServer(() => pageMarkup());
  const topServer = await startServer((path) =>
    path === "/top" ? pageMarkup(frameServer.origin) : pageMarkup());
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_DIRECTORY}`,
      `--load-extension=${EXTENSION_DIRECTORY}`,
      "--headless=new",
    ],
  });

  try {
    const page = await context.newPage();
    await page.goto(`${topServer.origin}/top`);
    await sendAndRead(page, "browser_top_0123456789");

    const crossOriginFrame = page.frames().find((frame) =>
      frame.url() === `${frameServer.origin}/frame`);
    expect(crossOriginFrame, "cross-origin iframe loaded").toBeDefined();
    await sendAndRead(crossOriginFrame!, "browser_frame_01234567");

    await page.evaluate(({ frameOrigin, correlationId, requestType }) => {
      const iframe = document.querySelector<HTMLIFrameElement>("#cross-origin-frame");
      iframe?.contentWindow?.postMessage({
        version: 1,
        type: requestType,
        payload: {
          version: 1,
          type: "request",
          correlationId,
          method: "standard:connect",
          params: {},
        },
      }, frameOrigin);
    }, {
      frameOrigin: frameServer.origin,
      correlationId: "browser_parent_forgery_01",
      requestType: PAGE_REQUEST_TYPE,
    });
    await expect.poll(async () => crossOriginFrame!.evaluate(() =>
      (globalThis as unknown as { __wardenWindowRequests?: unknown[] })
        .__wardenWindowRequests ?? [])).toContain("browser_parent_forgery_01");
    // A valid same-frame request is the causal barrier. Port ordering means a
    // wrongly forwarded parent request would have produced its response before
    // this later valid response; no arbitrary negative timeout is involved.
    await sendAndRead(crossOriginFrame!, "browser_frame_barrier_01");
    expect(await crossOriginFrame!.evaluate(() =>
      (globalThis as unknown as {
        __wardenResponses?: Array<{ correlationId?: unknown }>;
      }).__wardenResponses?.some(
        (response) => response.correlationId === "browser_parent_forgery_01",
      ) ?? false)).toBe(false);

    await page.goto(`${topServer.origin}/same-tab-navigation`);
    await sendAndRead(page, "browser_navigate_0123456");

    const worker = await extensionWorker(context);
    const extensionId = new URL(worker.url()).hostname;
    expect(extensionId).toMatch(/^[a-p]{32}$/);
    const extensionOrigin = `chrome-extension://${extensionId}`;
    const preStopMarker = "pre-stop-worker-global";
    await worker.evaluate((marker) => {
      (globalThis as unknown as { __wardenPreStopMarker?: string })
        .__wardenPreStopMarker = marker;
    }, preStopMarker);
    const cdp = await context.newCDPSession(page);
    const { targetInfos } = await cdp.send("Target.getTargets");
    const workerTarget = targetInfos.find((target) =>
      target.type === "service_worker" && target.url.startsWith(extensionOrigin));
    expect(workerTarget, "extension service-worker target exists before forced stop").toBeDefined();
    const closed = await cdp.send("Target.closeTarget", {
      targetId: workerTarget!.targetId,
    });
    expect(closed.success).toBe(true);
    // Playwright retains a Worker wrapper after CDP closes its target, so the
    // context.serviceWorkers() array is not a liveness oracle. Measure the CDP
    // target itself: the exact pre-stop target must disappear and no extension
    // worker target may remain before the next document opens a Port.
    await expect.poll(async () => {
      const currentTargets = await cdp.send("Target.getTargets");
      return currentTargets.targetInfos
        .filter((target) =>
          target.type === "service_worker" && target.url.startsWith(extensionOrigin))
        .map((target) => target.targetId);
    }).toEqual([]);

    // The content document does not navigate here. Its prior Port was severed
    // by worker termination; this next request must lazily open a new Port and
    // wake the worker without an eager reconnect loop.
    await sendAndRead(page, "browser_worker_wake_0123");
    await expect.poll(async () => {
      const currentTargets = await cdp.send("Target.getTargets");
      return currentTargets.targetInfos
        .filter((target) =>
          target.type === "service_worker" && target.url.startsWith(extensionOrigin))
        .map((target) => target.targetId);
    }).not.toEqual([]);
    const replacementTargets = await cdp.send("Target.getTargets");
    const replacementTargetIds = replacementTargets.targetInfos
      .filter((target) =>
        target.type === "service_worker" && target.url.startsWith(extensionOrigin))
      .map((target) => target.targetId);
    expect(replacementTargetIds).not.toEqual([]);
    // Chromium can reuse the extension service-worker Target id across a stop.
    // A CDP-injected global is an execution-context probe: it must be gone in
    // the worker that handled the post-navigation wake request.
    await expect.poll(async () => {
      for (const candidate of [...context.serviceWorkers()].reverse()) {
        if (!candidate.url().startsWith(extensionOrigin)) continue;
        try {
          return await candidate.evaluate(() =>
            (globalThis as unknown as { __wardenPreStopMarker?: string })
              .__wardenPreStopMarker ?? null);
        } catch {
          // A retained Playwright wrapper for the closed target is not live.
        }
      }
      return "no-live-extension-worker";
    }).toBe(null);

    // Exercise WRD-EXT-02 in the browser-owned content-script execution world,
    // not through a page mock. That world shares sender.id with the extension,
    // but its sender URL/origin are the web document and must not authorize the
    // popup channel. The disconnect event is the causal result; no negative
    // timeout stands in for rejection.
    const executionContexts = new Map<number, {
      readonly id: number;
      readonly origin: string;
      readonly auxData?: { readonly isDefault?: boolean; readonly type?: string };
    }>();
    cdp.on("Runtime.executionContextCreated", ({ context: executionContext }) => {
      executionContexts.set(executionContext.id, executionContext);
    });
    await cdp.send("Runtime.enable");
    const contentContextId = await expect.poll(() => {
      const candidate = [...executionContexts.values()].find((executionContext) =>
        executionContext.origin === extensionOrigin &&
        executionContext.auxData?.isDefault === false &&
        executionContext.auxData?.type === "isolated");
      return candidate?.id ?? null;
    }).not.toBeNull().then(() => {
      const candidate = [...executionContexts.values()].find((executionContext) =>
        executionContext.origin === extensionOrigin &&
        executionContext.auxData?.isDefault === false &&
        executionContext.auxData?.type === "isolated");
      if (candidate === undefined) throw new Error("Warden content-script world disappeared");
      return candidate.id;
    });
    const forgedPopup = await cdp.send("Runtime.evaluate", {
      contextId: contentContextId,
      awaitPromise: true,
      returnByValue: true,
      expression: `new Promise((resolve) => {
        const port = chrome.runtime.connect({ name: "warden:popup:v1" });
        port.onMessage.addListener((message) => resolve({ kind: "message", message }));
        port.onDisconnect.addListener(() => {
          void chrome.runtime.lastError;
          resolve({ kind: "disconnect" });
        });
        port.postMessage({
          version: 1,
          type: "request",
          correlationId: "browser_forged_popup_01",
          method: "popup:getBoundaryStatus",
          params: {},
        });
      })`,
    });
    expect(forgedPopup.exceptionDetails).toBeUndefined();
    expect(forgedPopup.result.value).toEqual({ kind: "disconnect" });

    const liveWorkers = [...context.serviceWorkers()].reverse();
    let actionWorker: (typeof liveWorkers)[number] | undefined;
    for (const candidate of liveWorkers) {
      try {
        const hasActionApi = await candidate.evaluate(() => {
          const chromeApi = (globalThis as unknown as {
            readonly chrome?: { readonly action?: BrowserExtensionActionApi };
          }).chrome;
          return typeof chromeApi?.action?.openPopup === "function";
        });
        if (hasActionApi) {
          actionWorker = candidate;
          break;
        }
      } catch {
        // Playwright can retain wrappers for stopped service workers.
      }
    }
    expect(actionWorker, "a live worker exposes chrome.action.openPopup").toBeDefined();

    // Seed a non-secret canary from the trusted worker, then prove the actual
    // isolated content-script world cannot read storage.local. An empty read
    // would be a false green, so the canary must exist before the denied call.
    const storageCanaryKey = "warden.browser-storage-canary";
    const trustedStorageReadback = await actionWorker!.evaluate(async (key) => {
      const local = (globalThis as unknown as {
        readonly chrome: {
          readonly storage: {
            readonly local: {
              set(items: Record<string, unknown>): Promise<void>;
              get(key: string): Promise<Record<string, unknown>>;
            };
          };
        };
      }).chrome.storage.local;
      await local.set({ [key]: "trusted-worker-only" });
      return local.get(key);
    }, storageCanaryKey);
    expect(trustedStorageReadback).toEqual({
      [storageCanaryKey]: "trusted-worker-only",
    });
    const contentStorageRead = await cdp.send("Runtime.evaluate", {
      contextId: contentContextId,
      awaitPromise: true,
      returnByValue: true,
      expression:
        "(async () => { try { const value = await chrome.storage.local.get(" +
        JSON.stringify(storageCanaryKey) +
        "); return { kind: \"value\", value }; } catch { return { kind: \"rejected\" }; } })()",
    });
    expect(contentStorageRead.exceptionDetails).toBeUndefined();
    expect(contentStorageRead.result.value).toEqual({ kind: "rejected" });
    await actionWorker!.evaluate(async (key) => {
      const local = (globalThis as unknown as {
        readonly chrome: {
          readonly storage: {
            readonly local: {
              remove(key: string): Promise<void>;
            };
          };
        };
      }).chrome.storage.local;
      await local.remove(key);
    }, storageCanaryKey);

    await actionWorker!.evaluate(() => {
      const workerGlobal = globalThis as unknown as {
        __wardenObservedActionPopupSender?: unknown;
        readonly chrome: {
          readonly runtime: {
            readonly onConnect: {
              addListener(listener: (port: {
                readonly name: string;
                readonly sender: unknown;
              }) => void): void;
            };
          };
        };
      };
      workerGlobal.chrome.runtime.onConnect.addListener((port) => {
        if (port.name === "warden:popup:v1") {
          workerGlobal.__wardenObservedActionPopupSender = port.sender;
        }
      });
    });
    await actionWorker!.evaluate(() => {
      const action = (globalThis as unknown as {
        readonly chrome: { readonly action: BrowserExtensionActionApi };
      }).chrome.action;
      void action.openPopup();
    });
    await expect.poll(async () => {
      const targets = await cdp.send("Target.getTargets");
      return targets.targetInfos.find((target) =>
        target.url === `${extensionOrigin}/popup.html`)?.targetId ?? null;
    }).not.toBeNull();
    const actionTargets = await cdp.send("Target.getTargets");
    const actionPopupTarget = actionTargets.targetInfos.find((target) =>
      target.url === `${extensionOrigin}/popup.html`);
    expect(actionPopupTarget, "chrome.action.openPopup created its own target").toBeDefined();
    const attached = await cdp.send("Target.attachToTarget", {
      targetId: actionPopupTarget!.targetId,
      flatten: false,
    });
    await sendAttachedTargetCommand(cdp, attached.sessionId, "Runtime.enable");
    const actionPopupStatus = await sendAttachedTargetCommand(
      cdp,
      attached.sessionId,
      "Runtime.evaluate",
      {
        expression: `({
          boundary: document.querySelector("#boundary-status")?.dataset.boundary,
          text: document.querySelector("#boundary-status")?.textContent
        })`,
        returnByValue: true,
      },
    ) as { readonly result?: { readonly value?: unknown } };
    const observedActionPopupSender = await actionWorker!.evaluate(() =>
      (globalThis as unknown as { __wardenObservedActionPopupSender?: unknown })
        .__wardenObservedActionPopupSender ?? null);
    expect(observedActionPopupSender).toEqual({
      id: extensionId,
      origin: extensionOrigin,
      url: `${extensionOrigin}/popup.html`,
    });
    expect(actionPopupStatus.result?.value).toEqual({
      boundary: "unavailable",
      text: "Wallet controls are not enabled in this pre-alpha build.",
    });

    const actionPopupResponse = await sendAttachedTargetCommand(
      cdp,
      attached.sessionId,
      "Runtime.evaluate",
      {
        expression: `new Promise((resolve, reject) => {
          const port = chrome.runtime.connect({ name: "warden:popup:v1" });
          port.onMessage.addListener((message) => {
            resolve(message);
            port.disconnect();
          });
          port.onDisconnect.addListener(() => {
            const error = chrome.runtime.lastError;
            if (error !== undefined) reject(new Error(error.message));
          });
          port.postMessage({
            version: 1,
            type: "request",
            correlationId: "browser_action_popup_01",
            method: "popup:getBoundaryStatus",
            params: {},
          });
        })`,
        awaitPromise: true,
        returnByValue: true,
      },
    ) as { readonly result?: { readonly value?: unknown }; readonly exceptionDetails?: unknown };
    expect(actionPopupResponse.exceptionDetails).toBeUndefined();
    expect(actionPopupResponse.result?.value).toEqual({
      version: 1,
      type: "response",
      correlationId: "browser_action_popup_01",
      ok: false,
      error: {
        code: "WARDEN_POPUP_UNAVAILABLE",
        message: "Warden popup methods are not enabled",
      },
    });
    await cdp.send("Target.detachFromTarget", { sessionId: attached.sessionId });

    // Chrome's official automation fallback is direct navigation. Keep it as
    // a second sender shape and use a direct Port request so a hard-coded popup
    // label cannot make the route green.
    const popupPage = await context.newPage();
    await popupPage.goto(`${extensionOrigin}/popup.html`);
    await expect(popupPage.locator("#boundary-status")).toHaveAttribute(
      "data-boundary",
      "unavailable",
    );
    expect(await popupPage.locator("#boundary-status").textContent()).toBe(
      "Wallet controls are not enabled in this pre-alpha build.",
    );

    const popupResponse = await popupPage.evaluate(() => new Promise((resolve, reject) => {
      const runtime = (globalThis as unknown as {
        readonly chrome: { readonly runtime: BrowserExtensionRuntime };
      }).chrome.runtime;
      const port = runtime.connect({ name: "warden:popup:v1" });
      port.onMessage.addListener((message) => {
        resolve(message);
        port.disconnect();
      });
      port.onDisconnect.addListener(() => {
        const error = runtime.lastError;
        if (error !== undefined) reject(new Error(error.message));
      });
      port.postMessage({
        version: 1,
        type: "request",
        correlationId: "browser_popup_direct_01",
        method: "popup:getBoundaryStatus",
        params: {},
      });
    }));
    expect(popupResponse).toEqual({
      version: 1,
      type: "response",
      correlationId: "browser_popup_direct_01",
      ok: false,
      error: {
        code: "WARDEN_POPUP_UNAVAILABLE",
        message: "Warden popup methods are not enabled",
      },
    });
  } finally {
    await context.close();
    await topServer.close();
    await frameServer.close();
  }
});
