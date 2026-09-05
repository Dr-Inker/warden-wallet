import {
  MAX_SAVED_ACCOUNTS,
  exactFields,
  parseAccountRegistry,
  parseAccountRequest,
  type AccountRegistry,
} from "../account-registry-protocol.js";

export const ACCOUNT_REGISTRY_STORAGE_KEY = "warden:public-accounts:v1";
export interface AccountRegistryStorage {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

/** One worker owns the queue. Always reread disk; never overwrite corrupt data. */
export class AccountRegistryOwner {
  private tail: Promise<unknown> = Promise.resolve();
  private pending = 0;
  constructor(private readonly storage: AccountRegistryStorage) {}

  private async load(): Promise<AccountRegistry> {
    const raw = await this.storage.get(ACCOUNT_REGISTRY_STORAGE_KEY);
    if (exactFields(raw, [])) return parseAccountRegistry({ version: 1, accounts: [], selectedAddress: null });
    if (!exactFields(raw, [ACCOUNT_REGISTRY_STORAGE_KEY])) throw new Error("Invalid storage response");
    return parseAccountRegistry(raw[ACCOUNT_REGISTRY_STORAGE_KEY]);
  }

  execute(value: unknown, active: () => boolean = () => true): Promise<AccountRegistry> {
    // Snapshot and validate before crossing an async boundary.
    const request = parseAccountRequest(value);
    if (this.pending >= 16) return Promise.reject(new Error("Account queue is full"));
    this.pending++;
    const assertActive = (): void => { if (!active()) throw new Error("Account request cancelled"); };
    const operation = this.tail.then(async () => {
      assertActive();
      const current = await this.load();
      assertActive();
      if (request.method === "accounts:list") return current;
      let accounts = [...current.accounts];
      let selectedAddress = current.selectedAddress;
      const address = request.params.address;
      const existing = accounts.find((account) => account.address === address);
      if (request.method === "accounts:add") {
        if (existing || accounts.length >= MAX_SAVED_ACCOUNTS) throw new Error("Cannot add account");
        accounts.push(request.params);
        selectedAddress = address;
      } else {
        if (!existing) throw new Error("Account is not saved");
        if (request.method === "accounts:select") selectedAddress = address;
        else {
          accounts = accounts.filter((account) => account.address !== address);
          if (selectedAddress === address) selectedAddress = accounts[0]?.address ?? null;
        }
      }
      const next = parseAccountRegistry({ version: 1, accounts, selectedAddress });
      assertActive();
      await this.storage.set({ [ACCOUNT_REGISTRY_STORAGE_KEY]: next });
      const readback = await this.load();
      if (JSON.stringify(readback) !== JSON.stringify(next)) throw new Error("Account write could not be verified");
      return readback;
    });
    const settled = operation.finally(() => { this.pending--; });
    this.tail = settled.catch(() => undefined);
    return settled;
  }
}
