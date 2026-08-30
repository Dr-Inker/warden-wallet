import { MAX_TX_BYTES } from "@warden/core";

export const MAX_PROVIDER_MESSAGE_BYTES = 16 * 1024;
export const MAX_TRANSACTION_BYTES = MAX_TX_BYTES;

export type ProviderChain =
  | "solana:mainnet"
  | "solana:devnet"
  | "solana:testnet"
  | "solana:localnet";

export type ProviderCommitment = "processed" | "confirmed" | "finalized";

export interface ProviderSignTransactionOptions {
  readonly preflightCommitment: ProviderCommitment | null;
  readonly minContextSlot: number | null;
}

export interface ProviderSignAndSendOptions extends ProviderSignTransactionOptions {
  readonly commitment: ProviderCommitment | null;
  readonly skipPreflight: boolean | null;
  readonly maxRetries: number | null;
}

interface ProviderRequestBase {
  readonly version: 1;
  readonly type: "request";
  readonly correlationId: string;
}

export interface ProviderConnectRequest extends ProviderRequestBase {
  readonly method: "standard:connect";
  readonly params: Readonly<{ silent: boolean }>;
}

export interface ProviderDisconnectRequest extends ProviderRequestBase {
  readonly method: "standard:disconnect";
  readonly params: Readonly<Record<never, never>>;
}

export interface ProviderSignTransactionRequest extends ProviderRequestBase {
  readonly method: "solana:signTransaction";
  readonly params: Readonly<{
    /** Untrusted selector only. The handler must resolve it against authorized accounts. */
    requestedAccountAddress: string;
    transaction: readonly number[];
    chain: ProviderChain | null;
    options: Readonly<ProviderSignTransactionOptions>;
  }>;
}

export interface ProviderSignAndSendRequest extends ProviderRequestBase {
  readonly method: "solana:signAndSendTransaction";
  readonly params: Readonly<{
    /** Untrusted selector only. The handler must resolve it against authorized accounts. */
    requestedAccountAddress: string;
    transaction: readonly number[];
    chain: ProviderChain;
    options: Readonly<ProviderSignAndSendOptions>;
  }>;
}

export type ProviderRequest =
  | ProviderConnectRequest
  | ProviderDisconnectRequest
  | ProviderSignTransactionRequest
  | ProviderSignAndSendRequest;

export class ProviderMessageFormatError extends Error {
  constructor(message: string) {
    super(`invalid provider request: ${message}`);
    this.name = "ProviderMessageFormatError";
  }
}

const ROOT_FIELDS = ["correlationId", "method", "params", "type", "version"] as const;
const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const ACCOUNT_ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TEXT_ENCODER = /* @__PURE__ */ new TextEncoder();

const PROVIDER_CHAINS: ReadonlySet<string> = new Set([
  "solana:mainnet",
  "solana:devnet",
  "solana:testnet",
  "solana:localnet",
]);
const COMMITMENTS: ReadonlySet<string> = new Set([
  "processed",
  "confirmed",
  "finalized",
]);

function invalid(message: string): never {
  throw new ProviderMessageFormatError(message);
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireClosedFields(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  name: string,
): void {
  const allowed = new Set([...required, ...optional]);
  const fields = Object.keys(value);
  if (
    fields.some((field) => !allowed.has(field)) ||
    required.some((field) => !Object.hasOwn(value, field))
  ) {
    invalid(`${name} has missing or unknown fields`);
  }
}

function assertWireSize(value: unknown): void {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    invalid("request is not JSON serializable");
  }
  if (serialized === undefined) invalid("request is not JSON serializable");
  if (TEXT_ENCODER.encode(serialized).byteLength > MAX_PROVIDER_MESSAGE_BYTES) {
    invalid(`request exceeds the ${MAX_PROVIDER_MESSAGE_BYTES}-byte limit`);
  }
}

function requireCorrelationId(value: unknown): string {
  if (typeof value !== "string" || !CORRELATION_ID_PATTERN.test(value)) {
    invalid("correlation id is malformed");
  }
  return value;
}

function requireAccountAddress(value: unknown): string {
  if (typeof value !== "string" || !ACCOUNT_ADDRESS_PATTERN.test(value)) {
    invalid("requested account address is malformed");
  }
  return value;
}

function requireChain(value: unknown): ProviderChain {
  if (typeof value !== "string" || !PROVIDER_CHAINS.has(value)) {
    invalid("chain is malformed or unsupported");
  }
  return value as ProviderChain;
}

function requireCommitment(value: unknown, name: string): ProviderCommitment {
  if (typeof value !== "string" || !COMMITMENTS.has(value)) {
    invalid(`${name} is malformed`);
  }
  return value as ProviderCommitment;
}

function requireNonNegativeSafeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    invalid(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

function requireTransaction(value: unknown): readonly number[] {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > MAX_TRANSACTION_BYTES
  ) {
    invalid(`transaction must contain 1 to ${MAX_TRANSACTION_BYTES} bytes`);
  }

  const transaction = new Array<number>(value.length);
  for (let index = 0; index < value.length; index++) {
    if (!Object.hasOwn(value, index)) {
      invalid("transaction must be a dense byte array");
    }
    const byte = value[index];
    if (!Number.isInteger(byte) || (byte as number) < 0 || (byte as number) > 255) {
      invalid(`transaction[${index}] is not a byte`);
    }
    transaction[index] = byte as number;
  }
  return Object.freeze(transaction);
}

function optionalCommitment(
  options: Record<string, unknown>,
  field: "preflightCommitment" | "commitment",
): ProviderCommitment | null {
  if (!Object.hasOwn(options, field)) return null;
  return requireCommitment(options[field], field);
}

function optionalNonNegativeSafeInteger(
  options: Record<string, unknown>,
  field: "minContextSlot" | "maxRetries",
): number | null {
  if (!Object.hasOwn(options, field)) return null;
  return requireNonNegativeSafeInteger(options[field], field);
}

function parseSignTransactionOptions(value: unknown): Readonly<ProviderSignTransactionOptions> {
  if (value === undefined) {
    return Object.freeze({ preflightCommitment: null, minContextSlot: null });
  }
  const options = requireRecord(value, "signTransaction options");
  requireClosedFields(
    options,
    [],
    ["preflightCommitment", "minContextSlot"],
    "signTransaction options",
  );
  return Object.freeze({
    preflightCommitment: optionalCommitment(options, "preflightCommitment"),
    minContextSlot: optionalNonNegativeSafeInteger(options, "minContextSlot"),
  });
}

function parseSignAndSendOptions(value: unknown): Readonly<ProviderSignAndSendOptions> {
  if (value === undefined) {
    return Object.freeze({
      preflightCommitment: null,
      minContextSlot: null,
      commitment: null,
      skipPreflight: null,
      maxRetries: null,
    });
  }
  const options = requireRecord(value, "signAndSendTransaction options");
  requireClosedFields(
    options,
    [],
    [
      "preflightCommitment",
      "minContextSlot",
      "commitment",
      "skipPreflight",
      "maxRetries",
    ],
    "signAndSendTransaction options",
  );

  let skipPreflight: boolean | null = null;
  if (Object.hasOwn(options, "skipPreflight")) {
    if (typeof options.skipPreflight !== "boolean") {
      invalid("skipPreflight must be a boolean");
    }
    skipPreflight = options.skipPreflight;
  }

  return Object.freeze({
    preflightCommitment: optionalCommitment(options, "preflightCommitment"),
    minContextSlot: optionalNonNegativeSafeInteger(options, "minContextSlot"),
    commitment: optionalCommitment(options, "commitment"),
    skipPreflight,
    maxRetries: optionalNonNegativeSafeInteger(options, "maxRetries"),
  });
}

function baseRequest(correlationId: string): ProviderRequestBase {
  return { version: 1, type: "request", correlationId };
}

function parseConnect(
  correlationId: string,
  value: unknown,
): ProviderConnectRequest {
  const params = requireRecord(value, "standard:connect params");
  requireClosedFields(params, [], ["silent"], "standard:connect params");
  let silent = false;
  if (Object.hasOwn(params, "silent")) {
    if (typeof params.silent !== "boolean") invalid("silent must be a boolean");
    silent = params.silent;
  }
  return Object.freeze({
    ...baseRequest(correlationId),
    method: "standard:connect",
    params: Object.freeze({ silent }),
  });
}

function parseDisconnect(
  correlationId: string,
  value: unknown,
): ProviderDisconnectRequest {
  const params = requireRecord(value, "standard:disconnect params");
  requireClosedFields(params, [], [], "standard:disconnect params");
  return Object.freeze({
    ...baseRequest(correlationId),
    method: "standard:disconnect",
    params: Object.freeze({}),
  });
}

function parseSignTransaction(
  correlationId: string,
  value: unknown,
): ProviderSignTransactionRequest {
  const params = requireRecord(value, "solana:signTransaction params");
  requireClosedFields(
    params,
    ["accountAddress", "transaction"],
    ["chain", "options"],
    "solana:signTransaction params",
  );

  const chain = Object.hasOwn(params, "chain") ? requireChain(params.chain) : null;
  let options: Readonly<ProviderSignTransactionOptions>;
  if (Object.hasOwn(params, "options")) {
    if (params.options === undefined) invalid("options must not be undefined");
    options = parseSignTransactionOptions(params.options);
  } else {
    options = parseSignTransactionOptions(undefined);
  }

  return Object.freeze({
    ...baseRequest(correlationId),
    method: "solana:signTransaction",
    params: Object.freeze({
      requestedAccountAddress: requireAccountAddress(params.accountAddress),
      transaction: requireTransaction(params.transaction),
      chain,
      options,
    }),
  });
}

function parseSignAndSend(
  correlationId: string,
  value: unknown,
): ProviderSignAndSendRequest {
  const params = requireRecord(value, "solana:signAndSendTransaction params");
  requireClosedFields(
    params,
    ["accountAddress", "transaction", "chain"],
    ["options"],
    "solana:signAndSendTransaction params",
  );

  let options: Readonly<ProviderSignAndSendOptions>;
  if (Object.hasOwn(params, "options")) {
    if (params.options === undefined) invalid("options must not be undefined");
    options = parseSignAndSendOptions(params.options);
  } else {
    options = parseSignAndSendOptions(undefined);
  }

  return Object.freeze({
    ...baseRequest(correlationId),
    method: "solana:signAndSendTransaction",
    params: Object.freeze({
      requestedAccountAddress: requireAccountAddress(params.accountAddress),
      transaction: requireTransaction(params.transaction),
      chain: requireChain(params.chain),
      options,
    }),
  });
}

/**
 * Parse the JSON-compatible, page-controlled provider envelope into a closed,
 * immutable request. This establishes syntax only: sender provenance, account
 * authorization, network binding, policy, approval and request IDs must all be
 * supplied or minted by later privileged layers.
 */
export function parseProviderRequest(value: unknown): ProviderRequest {
  assertWireSize(value);
  const request = requireRecord(value, "request");
  requireClosedFields(request, ROOT_FIELDS, [], "request");
  if (request.version !== 1) invalid("version must be 1");
  if (request.type !== "request") invalid("type must be request");
  const correlationId = requireCorrelationId(request.correlationId);

  switch (request.method) {
    case "standard:connect":
      return parseConnect(correlationId, request.params);
    case "standard:disconnect":
      return parseDisconnect(correlationId, request.params);
    case "solana:signTransaction":
      return parseSignTransaction(correlationId, request.params);
    case "solana:signAndSendTransaction":
      return parseSignAndSend(correlationId, request.params);
    default:
      invalid("method is unsupported");
  }
}
