import { describe, expect, it, vi } from "vitest";
import { PublicKey } from "@solana/web3.js";
import { AccountRegistryOwner, ACCOUNT_REGISTRY_STORAGE_KEY } from "../src/background/account-registry.js";
import { isAccountAddress, parseAccountRegistry, parseAccountRequest, parseAccountResponse } from "../src/account-registry-protocol.js";

const FIRST = "FTPSf3Po3uMpD9KRxWZtaqM27t7zCR8k7oAgz22u2eEC";
const SECOND = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const EMPTY = { version: 1, accounts: [], selectedAddress: null };
function request(method = "accounts:list", params: Record<string, unknown> = {}) {
  return { version: 1, type: "request", correlationId: "account_request_12345", method, params };
}
function storageHarness() {
  const data: Record<string, unknown> = {};
  const storage = {
    get: vi.fn(async (key: string) => Object.hasOwn(data, key) ? { [key]: structuredClone(data[key]) } : {}),
    set: vi.fn(async (items: Record<string, unknown>) => { Object.assign(data, structuredClone(items)); }),
  };
  return { data, storage, owner: new AccountRegistryOwner(storage) };
}

describe("public account registry", () => {
  it("persists two named accounts, selection, removal and last-account empty state across worker recreation", async () => {
    const h = storageHarness();
    expect(await h.owner.execute(request())).toEqual(EMPTY);
    await h.owner.execute(request("accounts:add", { address: FIRST, label: "Primary" }));
    await h.owner.execute(request("accounts:add", { address: SECOND, label: "Savings" }));
    const restarted = new AccountRegistryOwner(h.storage);
    expect(await restarted.execute(request())).toEqual({ version: 1, accounts: [
      { address: FIRST, label: "Primary" }, { address: SECOND, label: "Savings" },
    ], selectedAddress: SECOND });
    expect((await restarted.execute(request("accounts:select", { address: FIRST }))).selectedAddress).toBe(FIRST);
    expect((await restarted.execute(request("accounts:remove", { address: FIRST }))).selectedAddress).toBe(SECOND);
    expect(await restarted.execute(request("accounts:remove", { address: SECOND }))).toEqual(EMPTY);
    expect(Object.keys(h.data)).toEqual([ACCOUNT_REGISTRY_STORAGE_KEY]);
  });

  it("serializes concurrent additions and snapshots caller-owned input", async () => {
    const h = storageHarness();
    const first = request("accounts:add", { address: FIRST, label: "Original" });
    const pending = h.owner.execute(first);
    first.params.label = "Mutated";
    const second = h.owner.execute(request("accounts:add", { address: SECOND, label: "Second" }));
    await Promise.all([pending, second]);
    expect((await h.owner.execute(request())).accounts).toEqual([
      { address: FIRST, label: "Original" }, { address: SECOND, label: "Second" },
    ]);
  });

  it("refuses duplicate addresses, unknown selections and removals without changing storage", async () => {
    const h = storageHarness();
    await h.owner.execute(request("accounts:add", { address: FIRST, label: "Original" }));
    for (const command of [request("accounts:add", { address: FIRST, label: "Replacement" }),
      request("accounts:select", { address: SECOND }), request("accounts:remove", { address: SECOND })]) {
      await expect(h.owner.execute(command)).rejects.toThrow();
    }
    expect(h.storage.set).toHaveBeenCalledTimes(1);
    expect((await h.owner.execute(request())).accounts[0]?.label).toBe("Original");
  });

  it("refuses malformed persisted data and preserves it instead of resetting the registry", async () => {
    const h = storageHarness();
    h.data[ACCOUNT_REGISTRY_STORAGE_KEY] = { ...EMPTY, selectedAddress: FIRST };
    await expect(h.owner.execute(request())).rejects.toThrow();
    await expect(h.owner.execute(request("accounts:add", { address: FIRST, label: "A" }))).rejects.toThrow();
    expect(h.storage.set).not.toHaveBeenCalled();
    expect(h.data[ACCOUNT_REGISTRY_STORAGE_KEY]).toEqual({ ...EMPTY, selectedAddress: FIRST });
  });

  it("reports failed and mismatched writes, then rereads persisted state on retry", async () => {
    const h = storageHarness();
    h.storage.set.mockRejectedValueOnce(new Error("quota"));
    await expect(h.owner.execute(request("accounts:add", { address: FIRST, label: "A" }))).rejects.toThrow("quota");
    h.storage.set.mockResolvedValueOnce(undefined);
    await expect(h.owner.execute(request("accounts:add", { address: FIRST, label: "A" }))).rejects.toThrow("verified");
    expect(await h.owner.execute(request())).toEqual(EMPTY);
    await h.owner.execute(request("accounts:add", { address: FIRST, label: "A" }));
    expect((await h.owner.execute(request())).selectedAddress).toBe(FIRST);
  });

  it("cancels a disconnected request waiting on storage before it can write", async () => {
    const h = storageHarness();
    let resolve!: (value: Record<string, unknown>) => void;
    h.storage.get.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    let active = true;
    const pending = h.owner.execute(request("accounts:add", { address: FIRST, label: "A" }), () => active);
    await Promise.resolve();
    active = false;
    resolve({});
    await expect(pending).rejects.toThrow("cancelled");
    expect(h.storage.set).not.toHaveBeenCalled();
  });

  it("bounds the registry at twenty entries without losing existing records", async () => {
    const h = storageHarness();
    const accounts = Array.from({ length: 20 }, (_, index) => ({
      address: new PublicKey(new Uint8Array(32).fill(index + 1)).toBase58(), label: `Account ${index + 1}`,
    }));
    h.data[ACCOUNT_REGISTRY_STORAGE_KEY] = { version: 1, accounts, selectedAddress: accounts[0]!.address };
    await expect(h.owner.execute(request("accounts:add", { address: FIRST, label: "Overflow" }))).rejects.toThrow();
    expect(h.storage.set).not.toHaveBeenCalled();
    expect((await h.owner.execute(request())).accounts).toEqual(accounts);
  });

  it("bounds queued operations even while storage is stalled and ports expire", async () => {
    const h = storageHarness();
    let release!: (value: Record<string, unknown>) => void;
    h.storage.get.mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
    let active = true;
    const pending = Array.from({ length: 16 }, () => h.owner.execute(request(), () => active));
    const settled = Promise.allSettled(pending);
    await expect(h.owner.execute(request())).rejects.toThrow("queue is full");
    active = false;
    release({});
    expect((await settled).every((result) => result.status === "rejected")).toBe(true);
    expect(await h.owner.execute(request())).toEqual(EMPTY);
  });
});

describe("closed public metadata language", () => {
  it("accepts canonical 32-byte base58 addresses including off-curve addresses", () => {
    for (const value of [FIRST, SECOND, "11111111111111111111111111111111", "So11111111111111111111111111111111111111112"]) {
      expect(isAccountAddress(value)).toBe(true);
    }
    // Independent implementation exercises leading-zero and high-byte encodings.
    for (let byte = 0; byte < 256; byte++) {
      const bytes = new Uint8Array(32).fill(byte);
      expect(isAccountAddress(new PublicKey(bytes).toBase58())).toBe(true);
    }
    for (const value of ["1".repeat(31), "1".repeat(33), "z".repeat(44), "0".repeat(32), ` ${FIRST}`, `${FIRST}\n`]) {
      expect(isAccountAddress(value)).toBe(false);
    }
  });

  it("rejects secret, authority, origin and unknown fields before any storage call", () => {
    const h = storageHarness();
    for (const command of [
      { ...request(), origin: "https://forged.example" },
      request("accounts:add", { address: FIRST, label: "A", privateKey: "secret" }),
      request("accounts:add", { address: FIRST, label: "A", approved: true }),
      request("accounts:sign", { address: FIRST }),
      request("accounts:select", { address: FIRST, chain: "solana:devnet" }),
      request("accounts:list", { address: FIRST }),
    ]) expect(() => h.owner.execute(command)).toThrow();
    expect(h.storage.get).not.toHaveBeenCalled();
    expect(h.storage.set).not.toHaveBeenCalled();
  });

  it("rejects ambiguous labels and non-data properties, and copies accepted requests", () => {
    for (const label of ["", " ", " A", "A ", "A\nB", "A\u202eB", "a".repeat(41)]) {
      expect(() => parseAccountRequest(request("accounts:add", { address: FIRST, label }))).toThrow();
    }
    const getter = vi.fn(() => FIRST);
    expect(() => parseAccountRequest(request("accounts:add", { get address() { return getter(); }, label: "A" }))).toThrow();
    expect(getter).not.toHaveBeenCalled();
    const raw = request("accounts:add", { address: FIRST, label: "A" });
    const parsed = parseAccountRequest(raw);
    raw.params.address = SECOND;
    expect(parsed.params).toEqual({ address: FIRST, label: "A" });
    expect(Object.isFrozen(parsed.params)).toBe(true);
  });

  it("rejects duplicate records, sparse records and forged successful responses", () => {
    const account = { address: FIRST, label: "A" };
    expect(() => parseAccountRegistry({ version: 1, accounts: [account, account], selectedAddress: FIRST })).toThrow();
    expect(() => parseAccountRegistry({ version: 1, accounts: new Array(1), selectedAddress: FIRST })).toThrow();
    const response = { version: 1, type: "response", correlationId: "account_response_1234", ok: true, result: EMPTY };
    expect(parseAccountResponse(response)).toEqual(response);
    expect(() => parseAccountResponse({ ...response, approved: true })).toThrow();
    expect(() => parseAccountResponse({ ...response, result: { ...EMPTY, selectedAddress: FIRST } })).toThrow();
  });
});
