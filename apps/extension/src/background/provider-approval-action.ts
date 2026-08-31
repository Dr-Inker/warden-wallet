//! Still-unreachable C17 approval-page action capability registry.
//!
//! The durable approval row is not sufficient authority to sign: the exact
//! live coordinator that prepared it owns a volatile authority capsule. This
//! registry binds that capability to one background-minted id and digest before
//! a review window is opened. The approval page can ask only for the id already
//! fixed by browser provenance; it never supplies a digest, key, release, RPC,
//! or transaction and never receives signed bytes.

import { APPROVAL_DIGEST_BYTES } from "@warden/core/approval";

export const MAX_ACTIVE_PROVIDER_APPROVAL_ACTIONS = 32;

const APPROVAL_ID_PATTERN = /^req_[0-9a-f]{32}$/;

export interface ProviderApprovalActionRegistration {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  /** Exact provider/keyring/window lifetime owned by the preparation path. */
  readonly signal: AbortSignal;
  /** Resolve true only after the exact signed result is durable. */
  approve(): Promise<boolean>;
  /** Resolve true only after the exact approval is terminal or absent. */
  settle(): Promise<boolean>;
}

interface ActionEntry {
  readonly id: string;
  readonly messageDigest: Uint8Array;
  readonly signal: AbortSignal;
  readonly approveCapability: () => Promise<boolean>;
  readonly settleCapability: () => Promise<boolean>;
  readonly onAbort: () => void;
  approvePromise: Promise<boolean> | undefined;
  settlePromise: Promise<boolean> | undefined;
  active: boolean;
}

export class ProviderApprovalActionStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider approval action: ${message}`, options);
    this.name = "ProviderApprovalActionStateError";
  }
}

function stateError(message: string, cause?: unknown): never {
  throw new ProviderApprovalActionStateError(
    message,
    cause === undefined ? {} : { cause },
  );
}

function requireObject(value: unknown, name: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    stateError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireApprovalId(value: unknown): string {
  if (typeof value !== "string" || !APPROVAL_ID_PATTERN.test(value)) {
    stateError("approval id is malformed");
  }
  return value;
}

function requireDigest(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== APPROVAL_DIGEST_BYTES) {
    stateError(
      `message digest must contain exactly ${APPROVAL_DIGEST_BYTES} bytes`,
    );
  }
  return value.slice();
}

function requireSignal(value: unknown): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly aborted?: unknown }).aborted !== "boolean" ||
    typeof (value as { readonly addEventListener?: unknown }).addEventListener !== "function" ||
    typeof (value as { readonly removeEventListener?: unknown }).removeEventListener !== "function"
  ) {
    stateError("approval lifetime signal is malformed");
  }
  return value as AbortSignal;
}

function requireMethod<T extends object, K extends keyof T>(
  owner: T,
  key: K,
  name: string,
): T[K] {
  let method: unknown;
  try {
    method = owner[key];
  } catch (error) {
    stateError(`${name} access failed`, error);
  }
  if (typeof method !== "function") stateError(`${name} must be a function`);
  return method.bind(owner) as T[K];
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

/**
 * Volatile capability router for the one live MV3 worker generation.
 *
 * Durable rows survive a worker restart, but pending signing authority does
 * not. Startup invalidation remains the persistence owner; this registry never
 * reconstructs a coordinator from a row and never retries an approval action.
 */
export class ProviderApprovalActionOwner {
  readonly #entries = new Map<string, ActionEntry>();
  #disposed = false;

  get activeCount(): number {
    return this.#entries.size;
  }

  #assertUsable(): void {
    if (this.#disposed) stateError("owner is disposed");
  }

  #remove(entry: ActionEntry): void {
    if (!entry.active) return;
    entry.active = false;
    if (this.#entries.get(entry.id) === entry) this.#entries.delete(entry.id);
    try {
      entry.signal.removeEventListener("abort", entry.onAbort);
    } catch {
      // The map and active bit are authoritative after a hostile signal throws.
    }
    entry.messageDigest.fill(0);
  }

  register(value: ProviderApprovalActionRegistration): void {
    this.#assertUsable();
    const registration = requireObject(
      value,
      "approval action registration",
    ) as unknown as ProviderApprovalActionRegistration;
    let id: string;
    let messageDigest: Uint8Array | undefined;
    let signal: AbortSignal;
    try {
      id = requireApprovalId(registration.id);
      if (this.#entries.has(id)) stateError("approval action is already registered");
      if (this.#entries.size >= MAX_ACTIVE_PROVIDER_APPROVAL_ACTIONS) {
        stateError("approval action capacity exhausted");
      }
      messageDigest = requireDigest(registration.messageDigest);
      signal = requireSignal(registration.signal);
    } catch (error) {
      messageDigest?.fill(0);
      if (error instanceof ProviderApprovalActionStateError) throw error;
      stateError("approval action registration access failed", error);
    }

    let approveCapability: () => Promise<boolean>;
    let settleCapability: () => Promise<boolean>;
    try {
      approveCapability = requireMethod(
        registration,
        "approve",
        "approval action approve",
      );
      settleCapability = requireMethod(
        registration,
        "settle",
        "approval action settle",
      );
    } catch (error) {
      messageDigest.fill(0);
      throw error;
    }
    let entry!: ActionEntry;
    const onAbort = (): void => this.#remove(entry);
    entry = {
      id,
      messageDigest,
      signal,
      approveCapability,
      settleCapability,
      onAbort,
      approvePromise: undefined,
      settlePromise: undefined,
      active: true,
    };
    this.#entries.set(id, entry);
    try {
      signal.addEventListener("abort", onAbort, { once: true });
      if (signal.aborted) {
        this.#remove(entry);
        stateError("approval action lifetime already ended");
      }
    } catch (error) {
      if (entry.active) {
        entry.active = false;
        if (this.#entries.get(id) === entry) this.#entries.delete(id);
        try {
          signal.removeEventListener("abort", onAbort);
        } catch {
          // Registration is already rejected and the entry is unreachable.
        }
        messageDigest.fill(0);
      }
      if (error instanceof ProviderApprovalActionStateError) throw error;
      stateError("lifetime listener registration failed", error);
    }
  }

  /** Match a trusted durable digest without exposing the registered copy. */
  canApprove(idValue: unknown, digestValue: unknown): boolean {
    if (this.#disposed) return false;
    if (
      typeof idValue !== "string" ||
      !APPROVAL_ID_PATTERN.test(idValue) ||
      !(digestValue instanceof Uint8Array) ||
      digestValue.length !== APPROVAL_DIGEST_BYTES
    ) {
      return false;
    }
    const entry = this.#entries.get(idValue);
    return entry !== undefined &&
      entry.active &&
      !entry.signal.aborted &&
      entry.approvePromise === undefined &&
      entry.settlePromise === undefined &&
      bytesEqual(entry.messageDigest, digestValue);
  }

  approve(idValue: unknown): Promise<boolean> {
    try {
      this.#assertUsable();
      const id = requireApprovalId(idValue);
      const entry = this.#entries.get(id);
      if (entry === undefined || !entry.active || entry.signal.aborted) {
        stateError("approval action is unavailable");
      }
      if (entry.settlePromise !== undefined) {
        stateError("approval action is already settling");
      }
      if (entry.approvePromise !== undefined) return entry.approvePromise;
      entry.approvePromise = Promise.resolve().then(async () => {
        const proven = await entry.approveCapability();
        if (proven !== true) {
          stateError("approval capability returned no durable signing proof");
        }
        if (
          !entry.active ||
          entry.signal.aborted ||
          this.#entries.get(entry.id) !== entry
        ) {
          stateError("lifetime ended during approval");
        }
        return true;
      });
      return entry.approvePromise;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  settle(idValue: unknown): Promise<boolean> {
    try {
      this.#assertUsable();
      const id = requireApprovalId(idValue);
      const entry = this.#entries.get(id);
      if (entry === undefined || !entry.active) return Promise.resolve(false);
      if (entry.settlePromise !== undefined) return entry.settlePromise;
      entry.settlePromise = Promise.resolve().then(async () => {
        if (entry.approvePromise !== undefined) {
          await entry.approvePromise.catch(() => undefined);
        }
        if (!entry.active || this.#entries.get(entry.id) !== entry) return false;
        const proven = await entry.settleCapability();
        if (proven !== true) {
          stateError("settlement capability returned no terminal proof");
        }
        this.#remove(entry);
        return true;
      });
      return entry.settlePromise;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  /** Parent teardown owns durable cancellation; this drops only volatile routes. */
  dispose(): void {
    if (this.#disposed) return;
    this.#disposed = true;
    for (const entry of [...this.#entries.values()]) this.#remove(entry);
  }
}
