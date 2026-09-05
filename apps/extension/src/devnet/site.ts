import { isAccountAddress } from "../account-registry-protocol.js";
import { TEST_PORT, type Port, type TestRequest, type TestResult } from "./protocol.js";

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
let account: string | undefined;
let busy = false;
function status(text: string) { el("status").textContent = text; }
function render() {
  el<HTMLButtonElement>("connect").disabled = busy;
  el<HTMLButtonElement>("transfer").disabled = busy || !account;
  el<HTMLButtonElement>("disconnect").disabled = busy || !account;
  el<HTMLInputElement>("extension").disabled = busy || !!account;
  el("account").textContent = account ?? "Not connected";
}
async function request(value: TestRequest): Promise<TestResult> {
  const id = el<HTMLInputElement>("extension").value.trim();
  if (!/^[a-p]{32}$/.test(id)) throw new Error("Paste the extension ID shown in the Warden devnet wallet tab");
  const runtime = (globalThis as unknown as { chrome?: { runtime?: {
    connect(id: string, options: { name: string }): Port; lastError?: { message?: string };
  } } }).chrome?.runtime;
  if (!runtime?.connect) throw new Error("Load the Warden devnet test extension in Chrome, then reload this page");
  return new Promise((resolve, reject) => {
    const port = runtime.connect(id, { name: TEST_PORT });
    let finished = false;
    const finish = (result?: TestResult, error?: Error) => {
      if (finished) return;
      finished = true; clearTimeout(timer); port.disconnect();
      if (error) reject(error); else resolve(result!);
    };
    const timer = setTimeout(() => finish(undefined, new Error("Wallet request timed out. Check the wallet's transaction receipt before trying again.")), 330_000);
    port.onDisconnect.addListener(() => {
      const ignored = runtime.lastError; void ignored;
      finish(undefined, new Error("Wallet disconnected or review closed. If you approved a transfer, check its receipt in the wallet before trying again."));
    });
    port.onMessage.addListener(raw => {
      const result = raw as TestResult;
      if (!result || typeof result !== "object" || typeof result.ok !== "boolean" ||
          (result.ok && (!isAccountAddress(result.account) || result.network !== "solana:devnet" ||
            (value.method === "transfer" && (result.account !== value.account || typeof result.signature !== "string" || !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(result.signature))))) ||
          (!result.ok && typeof result.error !== "string")) {
        finish(undefined, new Error("Invalid response from the devnet extension")); return;
      }
      finish(result);
    });
    port.postMessage(value);
  });
}
async function run(value: TestRequest) {
  if (busy) return;
  busy = true; render(); status("Review this request in the Warden extension tab.");
  el("transaction").hidden = true;
  try {
    const result = await request(value);
    if (!result.ok) {
      if (result.signature && /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(result.signature)) {
        const link = el<HTMLAnchorElement>("transaction");
        link.href = `https://explorer.solana.com/tx/${encodeURIComponent(result.signature)}?cluster=devnet`;
        link.textContent = `Check unconfirmed transaction: ${result.signature}`;
        link.hidden = false;
      }
      throw new Error(result.error);
    }
    account = result.account;
    if (value.method === "connect") {
      status("Connected to your Warden wallet on Solana devnet.");
    } else if (result.signature) {
      const link = el<HTMLAnchorElement>("transaction");
      link.href = `https://explorer.solana.com/tx/${encodeURIComponent(result.signature)}?cluster=devnet`;
      link.textContent = `View confirmed transaction: ${result.signature}`;
      link.hidden = false;
      status("Transfer confirmed on Solana devnet.");
    }
  } catch (error) { status(error instanceof Error ? error.message : "Wallet request failed"); }
  finally { busy = false; render(); }
}
el("connect").onclick = () => void run({ method: "connect" });
el("disconnect").onclick = () => { account = undefined; render(); status("Disconnected from this page."); };
el("transfer-form").onsubmit = event => {
  event.preventDefault();
  if (!account || busy) return;
  const destination = el<HTMLInputElement>("destination").value.trim();
  const amount = el<HTMLInputElement>("amount").value.trim();
  if (!isAccountAddress(destination) || destination === account) { status("Enter a valid Solana recipient different from your wallet"); return; }
  if (!/^0\.[0-9]{1,9}$/.test(amount)) { status("Enter a decimal SOL amount with at most 9 places"); return; }
  const lamports = BigInt(amount.slice(2).padEnd(9, "0"));
  if (lamports < 1n || lamports > 10_000_000n) { status("Choose an amount between 1 lamport and 0.01 devnet SOL"); return; }
  void run({ method: "transfer", account, destination, lamports: lamports.toString() });
};
render();
