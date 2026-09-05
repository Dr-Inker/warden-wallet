import { allowedTestUrl, getChrome, parseTestRequest, TEST_PORT, type Port, type TestRequest } from "./protocol.js";

const chrome = getChrome();
const walletUrl = chrome.runtime.getURL("wallet.html");
interface Pending { external: Port; review?: Port; tab?: number; url: string; origin: string; request: TestRequest;
  timer: ReturnType<typeof setTimeout>; ready: Promise<void>; terminal: boolean; }
let pending: Pending | undefined;
let lastRequest = 0;
const close = (p: Pending, result?: unknown) => {
  if (p.terminal) return;
  p.terminal = true;
  clearTimeout(p.timer);
  if (pending === p) pending = undefined;
  if (result) { try { p.external.postMessage(result); } catch { /* disconnected */ } }
  try { p.external.disconnect(); } catch { /* disconnected */ }
  try { p.review?.disconnect(); } catch { /* disconnected */ }
};
chrome.action.onClicked.addListener(() => { void chrome.tabs.create({ url: walletUrl, active: true }); });
chrome.runtime.onConnectExternal.addListener(port => {
  const sender = port.sender;
  const origin = allowedTestUrl(sender?.url);
  if (port.name !== TEST_PORT || !origin || sender?.origin !== origin || sender.id || sender.frameId !== 0 ||
      !Number.isInteger(sender.tab?.id) || !sender.documentId || pending || Date.now() - lastRequest < 2000) {
    port.disconnect(); return;
  }
  // Reserve capacity before the first message; an idle port cannot fan out.
  let received = false;
  let disconnected = false;
  const idle = setTimeout(() => port.disconnect(), 3000);
  lastRequest = Date.now();
  port.onDisconnect.addListener(() => { disconnected = true; clearTimeout(idle); if (pending?.external === port) close(pending); });
  port.onMessage.addListener(value => {
    if (received || disconnected) { if (pending?.external === port) close(pending); port.disconnect(); return; }
    received = true;
    clearTimeout(idle);
    const request = parseTestRequest(value);
    if (!request || pending) { port.disconnect(); return; }
    const url = `${walletUrl}?review=${crypto.randomUUID()}`;
    const p: Pending = { external: port, origin, request, url, ready: Promise.resolve(), terminal: false,
      timer: setTimeout(() => close(p, { ok: false, error: "Request expired. Reconnect and review again." }), 300_000) };
    pending = p;
    p.ready = chrome.tabs.create({ url, active: true }).then(tab => {
      if (!Number.isInteger(tab.id)) throw new Error("No review tab");
      p.tab = tab.id;
      if (p.terminal) void chrome.tabs.remove(tab.id!).catch(() => {});
    }).catch(() => close(p, { ok: false, error: "Could not open the wallet review" }));
  });
});
chrome.runtime.onConnect.addListener(port => {
  const p = pending;
  if (!p || port.name !== "warden:devnet-review:v1") { port.disconnect(); return; }
  // tabs.create may resolve after document_start; bind only after its tab ID
  // exists, and compare the Chrome-owned document URL and top-level tab.
  void p.ready.then(() => {
    const sender = port.sender;
    if (pending !== p || p.terminal || p.review || sender?.id !== chrome.runtime.id || sender.url !== p.url ||
        sender.frameId !== 0 || sender.tab?.id !== p.tab || !sender.documentId) { port.disconnect(); return; }
    p.review = port;
    port.onDisconnect.addListener(() => { if (!p.terminal) close(p, { ok: false, error: "Wallet review closed" }); });
    port.onMessage.addListener(result => {
      // A bound review keeps the MV3 worker alive during the passkey prompt;
      // an open port alone does not extend the worker's idle lifetime.
      if (result && typeof result === "object" && Object.keys(result).length === 1 &&
          (result as { keepAlive?: unknown }).keepAlive === true) return;
      close(p, result);
    });
    port.postMessage({ origin: p.origin, request: p.request });
  });
});
chrome.tabs.onRemoved.addListener(id => { if (pending?.tab === id) close(pending, { ok: false, error: "User rejected or closed the wallet request" }); });
