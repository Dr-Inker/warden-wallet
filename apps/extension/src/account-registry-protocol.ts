/** Public account metadata only. Selection never grants signing authority. */
export const ACCOUNT_REGISTRY_PORT_NAME = "warden:accounts:v1";
export const MAX_SAVED_ACCOUNTS = 20;
export const MAX_ACCOUNT_LABEL_LENGTH = 40;

export interface SavedAccount {
  readonly address: string;
  readonly label: string;
}
export interface AccountRegistry {
  readonly version: 1;
  readonly accounts: readonly SavedAccount[];
  readonly selectedAddress: string | null;
}
export type AccountCommand =
  | { readonly method: "accounts:list"; readonly params: Record<never, never> }
  | { readonly method: "accounts:add"; readonly params: SavedAccount }
  | { readonly method: "accounts:select" | "accounts:remove"; readonly params: { readonly address: string } };
export type AccountRequest = AccountCommand & {
  readonly version: 1;
  readonly type: "request";
  readonly correlationId: string;
};
export type AccountResponse = {
  readonly version: 1;
  readonly type: "response";
  readonly correlationId: string;
} & ({ readonly ok: true; readonly result: AccountRegistry } |
  { readonly ok: false; readonly error: "ACCOUNTS_UNAVAILABLE" });

export function exactFields(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === fields.length && fields.every((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return descriptor !== undefined && Object.hasOwn(descriptor, "value");
  });
}

/** Canonical base58 encoding of exactly 32 bytes; off-curve PDAs are valid. */
export function isAccountAddress(value: unknown): value is string {
  if (typeof value !== "string" || value !== value.trim() || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) return false;
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let number = 0n;
  for (const character of value) number = number * 58n + BigInt(alphabet.indexOf(character));
  let length = 0;
  for (let remaining = number; remaining > 0n; remaining >>= 8n) length++;
  for (const character of value) {
    if (character !== "1") break;
    length++;
  }
  return length === 32;
}

export function isAccountLabel(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 &&
    value.length <= MAX_ACCOUNT_LABEL_LENGTH && value === value.trim() &&
    !/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value);
}

function validId(value: unknown): value is string {
  return typeof value === "string" && value === value.trim() && /^[A-Za-z0-9_-]{16,64}$/.test(value);
}

export function parseAccountRequest(value: unknown): AccountRequest {
  if (!exactFields(value, ["version", "type", "correlationId", "method", "params"]) ||
    value.version !== 1 || value.type !== "request" || !validId(value.correlationId)) {
    throw new Error("Invalid account request");
  }
  const params = value.params;
  let command: AccountCommand;
  if (value.method === "accounts:list" && exactFields(params, [])) {
    command = { method: value.method, params: Object.freeze({}) };
  } else if (value.method === "accounts:add" && exactFields(params, ["address", "label"]) &&
    isAccountAddress(params.address) && isAccountLabel(params.label)) {
    command = { method: value.method, params: Object.freeze({ address: params.address, label: params.label }) };
  } else if ((value.method === "accounts:select" || value.method === "accounts:remove") &&
    exactFields(params, ["address"]) && isAccountAddress(params.address)) {
    command = { method: value.method, params: Object.freeze({ address: params.address }) };
  } else {
    throw new Error("Invalid account request");
  }
  return Object.freeze({ version: 1, type: "request", correlationId: value.correlationId, ...command });
}

export function parseAccountRegistry(value: unknown): AccountRegistry {
  if (!exactFields(value, ["version", "accounts", "selectedAddress"]) || value.version !== 1 ||
    !Array.isArray(value.accounts) || value.accounts.length > MAX_SAVED_ACCOUNTS) {
    throw new Error("Invalid account registry");
  }
  const seen = new Set<string>();
  const accounts: SavedAccount[] = [];
  for (const account of value.accounts) {
    if (!exactFields(account, ["address", "label"]) || !isAccountAddress(account.address) ||
      !isAccountLabel(account.label) || seen.has(account.address)) throw new Error("Invalid saved account");
    seen.add(account.address);
    accounts.push(Object.freeze({ address: account.address, label: account.label }));
  }
  if (accounts.length === 0 ? value.selectedAddress !== null :
    typeof value.selectedAddress !== "string" || !seen.has(value.selectedAddress)) {
    throw new Error("Invalid account selection");
  }
  return Object.freeze({ version: 1, accounts: Object.freeze(accounts), selectedAddress: value.selectedAddress as string | null });
}

export function parseAccountResponse(value: unknown): AccountResponse {
  if (!(exactFields(value, ["version", "type", "correlationId", "ok", "result"]) ||
    exactFields(value, ["version", "type", "correlationId", "ok", "error"])) ||
    value.version !== 1 || value.type !== "response" || !validId(value.correlationId)) {
    throw new Error("Invalid account response");
  }
  const header = { version: 1 as const, type: "response" as const, correlationId: value.correlationId };
  if (value.ok === true) return Object.freeze({ ...header, ok: true, result: parseAccountRegistry(value.result) });
  if (value.ok === false && value.error === "ACCOUNTS_UNAVAILABLE") {
    return Object.freeze({ ...header, ok: false, error: "ACCOUNTS_UNAVAILABLE" });
  }
  throw new Error("Invalid account response");
}
