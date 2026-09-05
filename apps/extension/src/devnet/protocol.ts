import { isAccountAddress as isSolanaPublicAddress } from "../account-registry-protocol.js";

export const TEST_PORT = "warden:devnet-test:v1";
export type TestRequest = { method: "connect" } | { method: "transfer"; account: string; destination: string; lamports: string };
export type TestResult = { ok: true; account: string; network: "solana:devnet"; signature?: string } |
  { ok: false; error: string; signature?: string };
export function allowedTestUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (!["https://wardenwallet.io", "http://localhost:4173", "http://127.0.0.1:4173"].includes(url.origin) ||
        !["/test", "/test/", "/test/index.html"].includes(url.pathname) || url.username || url.password) return null;
    return url.origin;
  } catch { return null; }
}
export function parseTestRequest(value: unknown): TestRequest | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  const keys = Object.keys(v).sort().join(",");
  if (keys === "method" && v.method === "connect") return { method: "connect" };
  if (keys !== "account,destination,lamports,method" || v.method !== "transfer" ||
      typeof v.account !== "string" || !isSolanaPublicAddress(v.account) ||
      typeof v.destination !== "string" || !isSolanaPublicAddress(v.destination) || v.destination === v.account ||
      typeof v.lamports !== "string" || !/^[1-9][0-9]{0,7}$/.test(v.lamports) || BigInt(v.lamports) > 10_000_000n) return null;
  return { method: "transfer", account: v.account, destination: v.destination, lamports: v.lamports };
}
export interface Port {
  name: string;
  sender?: { id?: string; url?: string; origin?: string; frameId?: number; documentId?: string; tab?: { id?: number } };
  postMessage(value: unknown): void;
  disconnect(): void;
  onMessage: { addListener(fn: (value: unknown) => void): void };
  onDisconnect: { addListener(fn: () => void): void };
}
export interface TestChrome {
  runtime: {
    id: string;
    lastError?: { message?: string };
    getURL(path: string): string;
    connect(options: { name: string }): Port;
    onConnect: { addListener(fn: (port: Port) => void): void };
    onConnectExternal: { addListener(fn: (port: Port) => void): void };
  };
  action: { onClicked: { addListener(fn: () => void): void } };
  tabs: {
    create(options: { url: string; active: boolean }): Promise<{ id?: number }>;
    remove(id: number): Promise<void>;
    onRemoved: { addListener(fn: (id: number) => void): void };
  };
  storage: { local: {
    get(key: string): Promise<Record<string, unknown>>;
    set(data: Record<string, unknown>): Promise<void>;
  } };
}
export const getChrome = (): TestChrome => (globalThis as unknown as { chrome: TestChrome }).chrome;
