import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { assertPasskey, checkDevnet, confirmTestSignature, devnetConnection, enrollPasskey, getRootState,
  prepareCeremony, rootInstructions, sendTestTransaction, validateWallet, type ProgramPin, type WalletMetadata } from "@warden/core/devnet";
import { getChrome, parseTestRequest, type Port, type TestRequest } from "./protocol.js";

declare const __DEVNET_PROGRAM_PIN__: ProgramPin;
const pin = __DEVNET_PROGRAM_PIN__;
const chrome = getChrome();
const connection = devnetConnection();
const payer = Keypair.generate(); // Fee payer lives only in this document; never serialized.
const WALLET_KEY = "warden:devnet-passkey:v1";
const RECEIPT_KEY = "warden:devnet-last-attempt:v1";
const origin = `chrome-extension://${chrome.runtime.id}`;
const isReview = new URL(location.href).searchParams.has("review");
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
let port: Port | undefined;
let request: TestRequest | undefined;
let active = !isReview;
let busy = false;
let uncertain = false;
let lastSignature: string | undefined;
const message = (text: string) => { element("status").textContent = text; };
const live = () => { if (!active) throw new Error("The website request is no longer active. Reconnect from the test page."); };
const setButtons = () => {
  for (const button of document.querySelectorAll<HTMLButtonElement>("button[data-write]")) button.disabled = busy || !active || uncertain;
  element<HTMLButtonElement>("approve").disabled = busy || !active || uncertain || !request;
  element<HTMLButtonElement>("reject").disabled = busy || !active;
  element<HTMLButtonElement>("check-receipt").disabled = busy || !lastSignature;
};
const receipt = (signature: string) => {
  lastSignature = signature;
  const link = element<HTMLAnchorElement>("transaction");
  link.href = `https://explorer.solana.com/tx/${encodeURIComponent(signature)}?cluster=devnet`;
  link.textContent = signature;
  link.hidden = false;
};
async function wallet(): Promise<WalletMetadata> {
  return validateWallet((await chrome.storage.local.get(WALLET_KEY))[WALLET_KEY], origin);
}
async function refresh(): Promise<void> {
  const saved = (await chrome.storage.local.get(WALLET_KEY))[WALLET_KEY];
  if (saved) {
    const w = validateWallet(saved, origin);
    element("account").textContent = w.address;
    const balance = await connection.getBalance(new PublicKey(w.address), "confirmed");
    element("balance").textContent = `${balance / 1e9} SOL (includes account rent)`;
  }
  const fees = await connection.getBalance(payer.publicKey, "confirmed");
  element("fee-balance").textContent = `${fees / 1e9} devnet SOL`;
}
async function execute(task: () => Promise<void>, readOnly = false): Promise<void> {
  if (busy) return;
  busy = true; setButtons();
  try {
    await navigator.locks.request("warden-devnet-wallet-write", { ifAvailable: true }, async lock => {
      if (!lock) throw new Error("Another Warden test tab is busy. Finish it first.");
      if (!readOnly) live();
      await task();
    });
  } catch (error) {
    message(error instanceof Error ? error.message : "The devnet operation failed");
  } finally { busy = false; setButtons(); }
}
async function send(instructions: Parameters<typeof sendTestTransaction>[3]): Promise<string> {
  live();
  const prior = (await chrome.storage.local.get(RECEIPT_KEY))[RECEIPT_KEY] as { pending?: boolean } | undefined;
  if (prior?.pending) throw new Error("A previous transaction still needs checking. Use Check transaction in the original wallet tab, or reopen this tab.");
  return sendTestTransaction(connection, pin, payer, instructions, async (signature, lastValidBlockHeight) => {
    live();
    receipt(signature); uncertain = true;
    const record = { signature, pending: true, lastValidBlockHeight };
    await chrome.storage.local.set({ [RECEIPT_KEY]: record });
    const readback = (await chrome.storage.local.get(RECEIPT_KEY))[RECEIPT_KEY] as typeof record | undefined;
    if (readback?.signature !== signature || readback.pending !== true) throw new Error("Could not save the transaction receipt");
    live();
    message("Submitting to devnet. Confirmation is pending; keep this tab open.");
  });
}
async function confirmed(signature: string): Promise<void> {
  await chrome.storage.local.set({ [RECEIPT_KEY]: { signature, pending: false } });
  uncertain = false;
  message("Transaction confirmed on Solana devnet.");
}
element("fee-account").textContent = payer.publicKey.toBase58();
element("extension-id").textContent = chrome.runtime.id;
element("program-hash").textContent = pin.sha256;
element("review").hidden = !isReview;

element("airdrop").onclick = () => void execute(async () => {
  if (uncertain) throw new Error("Check the previous transaction first");
  await checkDevnet(connection, pin); live();
  message("Requesting 1 devnet SOL for this tab's temporary fee payer…");
  const signature = await connection.requestAirdrop(payer.publicKey, 1_000_000_000);
  receipt(signature);
  await confirmTestSignature(connection, signature);
  await refresh();
  message("Temporary fee payer funded. You can now create or fund your test wallet.");
});
element("create").onclick = () => void execute(async () => {
  if (uncertain) throw new Error("Check the previous transaction first");
  await checkDevnet(connection, pin); live();
  const funds = await connection.getBalance(payer.publicKey);
  if (funds < 40_000_000) throw new Error("Fund the temporary fee payer first (at least 0.04 devnet SOL)");
  let saved = (await chrome.storage.local.get(WALLET_KEY))[WALLET_KEY];
  if (!saved) {
    message("Create your Warden devnet passkey in the browser prompt…");
    live();
    saved = await enrollPasskey(origin, chrome.runtime.id);
    // Persist public metadata BEFORE broadcasting. An interrupted create can
    // resume with the same credential and PDA rather than orphaning the wallet.
    await chrome.storage.local.set({ [WALLET_KEY]: saved });
  }
  const w = await wallet();
  const existing = await connection.getAccountInfo(new PublicKey(w.address));
  if (existing) { await getRootState(connection, w); await refresh(); message("This passkey wallet already exists on devnet."); return; }
  const slot = await connection.getSlot("confirmed");
  const now = await connection.getBlockTime(slot);
  if (now === null) throw new Error("Devnet block time is unavailable");
  const ceremony = prepareCeremony(w, { generation: 0n, nonce: 0n, policyVersion: 1 }, "create", slot, now);
  live(); message("Approve account creation with your passkey…");
  const assertion = await assertPasskey(w, ceremony);
  live();
  const signature = await send(rootInstructions(w, payer.publicKey, ceremony, assertion, "create"));
  await confirmed(signature);
  await getRootState(connection, w);
  await refresh();
});
element("fund").onclick = () => void execute(async () => {
  if (uncertain) throw new Error("Check the previous transaction first");
  await checkDevnet(connection, pin);
  const w = await wallet();
  await getRootState(connection, w); live();
  const signature = await send([SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: new PublicKey(w.address), lamports: 50_000_000 })]);
  await confirmed(signature); await refresh();
});
element("refresh").onclick = () => void execute(async () => { await checkDevnet(connection, pin); await refresh(); message("Devnet program and balances checked."); }, true);
element("check-receipt").onclick = () => void execute(async () => {
  if (!lastSignature) return;
  // A rejected request can still have an in-flight send. This readback never
  // signs another transfer or sends a result to a disconnected website.
  const status = (await connection.getSignatureStatuses([lastSignature], { searchTransactionHistory: true })).value[0];
  if (!status) {
    const stored = (await chrome.storage.local.get(RECEIPT_KEY))[RECEIPT_KEY] as { signature?: string; lastValidBlockHeight?: number } | undefined;
    if (stored?.signature === lastSignature && Number.isSafeInteger(stored.lastValidBlockHeight) &&
        await connection.getBlockHeight("finalized") > stored.lastValidBlockHeight!) {
      await chrome.storage.local.set({ [RECEIPT_KEY]: { signature: lastSignature, pending: false } });
      uncertain = false; message("Transaction expired without a receipt. You can request a new approval."); return;
    }
    throw new Error("No confirmed receipt yet. Do not repeat the transfer; check again shortly.");
  }
  if (status.err) {
    await chrome.storage.local.set({ [RECEIPT_KEY]: { signature: lastSignature, pending: false } });
    uncertain = false; message(`Transaction failed on devnet: ${JSON.stringify(status.err)}`); return;
  }
  if (status.confirmationStatus !== "confirmed" && status.confirmationStatus !== "finalized") throw new Error("Confirmation is still pending");
  await confirmed(lastSignature); await refresh();
}, true);
element("reject").onclick = () => {
  if (busy) return; // Once a send starts, show its receipt; no false cancellation.
  port?.postMessage({ ok: false, error: "User rejected the request" });
  active = false; setButtons(); message("Request rejected.");
};
element("approve").onclick = () => void execute(async () => {
  try {
  if (!request || uncertain) throw new Error("No approvable request");
  const approved = request; // Immutable copy from the worker, never read from editable page fields.
  await checkDevnet(connection, pin);
  const w = await wallet();
  const state = await getRootState(connection, w); live();
  if (approved.method === "connect") {
    port?.postMessage({ ok: true, account: w.address, network: "solana:devnet" });
    active = false; message("Connected. Return to the test website."); return;
  }
  if (approved.account !== w.address) throw new Error("The website requested a different wallet. Reconnect first.");
  const slot = await connection.getSlot("confirmed");
  const now = await connection.getBlockTime(slot);
  if (now === null) throw new Error("Devnet block time is unavailable");
  const destination = new PublicKey(approved.destination);
  const amount = BigInt(approved.lamports);
  const ceremony = prepareCeremony(w, state, "transfer", slot, now, destination, amount);
  live(); message("Approve the displayed devnet transfer with your passkey…");
  const assertion = await assertPasskey(w, ceremony);
  live();
  const current = await getRootState(connection, w);
  if (current.nonce !== state.nonce || current.generation !== state.generation) throw new Error("Wallet state changed during approval. Reconnect and review again.");
  const signature = await send(rootInstructions(w, payer.publicKey, ceremony, assertion, "transfer", destination, amount));
  await confirmed(signature);
  if (active) port?.postMessage({ ok: true, account: w.address, network: "solana:devnet", signature });
  active = false; message("Transfer confirmed. Return to the website to view the receipt.");
  } catch (error) {
    const text = error instanceof Error ? error.message : "Wallet approval failed";
    if (active) port?.postMessage({ ok: false, error: text, ...(uncertain && lastSignature ? { signature: lastSignature } : {}) });
    active = false;
    throw error;
  }
});

if (isReview) {
  port = chrome.runtime.connect({ name: "warden:devnet-review:v1" });
  const heartbeat = setInterval(() => {
    if (active) { try { port?.postMessage({ keepAlive: true }); } catch { active = false; setButtons(); } }
  }, 15_000);
  port.onMessage.addListener(value => {
    const v = value as { origin?: unknown; request?: unknown };
    const parsed = parseTestRequest(v?.request);
    if (request || !parsed || typeof v.origin !== "string") { port?.disconnect(); return; }
    request = parsed; active = true;
    element("request-origin").textContent = v.origin;
    element("request-details").textContent = parsed.method === "connect" ? "Share your verified devnet wallet address with this site." :
      `Send ${Number(parsed.lamports) / 1e9} devnet SOL\nFrom: ${parsed.account}\nTo: ${parsed.destination}`;
    element("approve").textContent = parsed.method === "connect" ? "Approve connection" : "Approve transfer with passkey";
    setButtons();
  });
  port.onDisconnect.addListener(() => { clearInterval(heartbeat); const ignored = chrome.runtime.lastError; void ignored; active = false; setButtons(); });
}
void (async () => {
  try {
    const stored = (await chrome.storage.local.get(RECEIPT_KEY))[RECEIPT_KEY] as { signature?: unknown; pending?: unknown } | undefined;
    if (stored && typeof stored.signature === "string" && /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(stored.signature)) {
      receipt(stored.signature); uncertain = stored.pending === true;
    }
    await checkDevnet(connection, pin);
    await refresh();
    message(uncertain ? "A previous transaction needs checking before another transfer." : "Devnet program matches this test build. Follow the steps above.");
  } catch (error) { message(error instanceof Error ? error.message : "Devnet check failed"); }
  setButtons();
})();
