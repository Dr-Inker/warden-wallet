//! Still-unreachable C18 approval-terminal -> signed-result composition owner.
//!
//! C12/C15 publish only a boolean terminal proof; signed transaction bytes stay
//! in the durable approval result store and can leave the worker only through
//! C14's strict replay verifier. A retained C14 operation bypasses preparation
//! and takes the same delivery path. This module owns no Port listener, release,
//! RPC endpoint, keyring, signer, approval page, or page acknowledgment.

import type { OwnedProviderRequest } from "./provider-port.js";
import type { ProviderTerminalDeliveryLease } from "./provider-terminal-result.js";
import type { ProviderSignedTransactionResponse } from "./provider-terminal-protocol.js";

export const MAX_ACTIVE_PROVIDER_SIGNED_RESULT_FLOWS = 32;

export interface ProviderApprovalFlowLauncher {
  launch(lease: ProviderTerminalDeliveryLease): Promise<unknown>;
}

export interface ProviderSignedResultDeliverer {
  deliver(lease: ProviderTerminalDeliveryLease): Promise<unknown>;
}

export interface ProviderSignedResultFlowOwnerOptions {
  readonly approvals: ProviderApprovalFlowLauncher;
  readonly results: ProviderSignedResultDeliverer;
}

export interface ProviderSignedResultFlowResult {
  readonly kind: "delivered";
  /** True only when C15 found an already-retained operation binding. */
  readonly replayed: boolean;
}

export class ProviderSignedResultFlowStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`provider signed result flow: ${message}`, options);
    this.name = "ProviderSignedResultFlowStateError";
  }
}

interface BoundDependencies {
  readonly launchApproval: ProviderApprovalFlowLauncher["launch"];
  readonly deliverResult: ProviderSignedResultDeliverer["deliver"];
}

interface BoundDeliveryLease extends ProviderTerminalDeliveryLease {
  readonly owned: OwnedProviderRequest;
}

type ApprovalLaunchSnapshot =
  | Readonly<{
      readonly kind: "opened";
      readonly terminal: Promise<unknown>;
    }>
  | Readonly<{
      readonly kind: "replay-required";
    }>;

function stateError(message: string, cause?: unknown): never {
  throw new ProviderSignedResultFlowStateError(
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

function bindDependencies(value: unknown): BoundDependencies {
  const options = requireObject(value, "options");
  const approvals = requireObject(
    options.approvals,
    "approval flow owner",
  ) as unknown as ProviderApprovalFlowLauncher;
  const results = requireObject(
    options.results,
    "signed result owner",
  ) as unknown as ProviderSignedResultDeliverer;
  return Object.freeze({
    launchApproval: requireMethod(approvals, "launch", "approvals.launch"),
    deliverResult: requireMethod(results, "deliver", "results.deliver"),
  });
}

function requireSignal(value: unknown): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly aborted?: unknown }).aborted !== "boolean" ||
    typeof (value as { readonly addEventListener?: unknown }).addEventListener !== "function" ||
    typeof (value as { readonly removeEventListener?: unknown }).removeEventListener !== "function"
  ) {
    stateError("provider request signal is malformed");
  }
  return value as AbortSignal;
}

function bindLease(value: unknown): BoundDeliveryLease {
  const lease = requireObject(
    value,
    "provider delivery lease",
  ) as unknown as ProviderTerminalDeliveryLease;
  let owned: unknown;
  try {
    owned = lease.owned;
  } catch (error) {
    stateError("provider delivery lease owned access failed", error);
  }
  if (typeof owned !== "object" || owned === null) {
    stateError("provider delivery lease has no owned request");
  }
  requireSignal((owned as Partial<OwnedProviderRequest>).signal);
  const assertActive = requireMethod(lease, "assertActive", "lease.assertActive");
  const postMessage = requireMethod(lease, "postMessage", "lease.postMessage");
  const finish = requireMethod(lease, "finish", "lease.finish");
  return Object.freeze({
    owned: owned as OwnedProviderRequest,
    assertActive,
    postMessage: postMessage as (message: ProviderSignedTransactionResponse) => void,
    finish,
  });
}

function exactDataRecord(
  value: unknown,
  fields: readonly string[],
  name: string,
): Readonly<Record<string, unknown>> {
  const record = requireObject(value, name);
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(record);
  } catch (error) {
    stateError(`${name} fields are inaccessible`, error);
  }
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    stateError(`${name} has missing or unknown fields`);
  }
  const copy: Record<string, unknown> = {};
  for (const field of fields) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(record, field);
    } catch (error) {
      stateError(`${name}.${field} is inaccessible`, error);
    }
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      stateError(`${name}.${field} must be an enumerable data property`);
    }
    copy[field] = descriptor.value;
  }
  return Object.freeze(copy);
}

function snapshotLaunch(value: unknown): ApprovalLaunchSnapshot {
  const outer = requireObject(value, "approval launch result");
  let kind: unknown;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(outer, "kind");
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      stateError("approval launch result.kind must be an enumerable data property");
    }
    kind = descriptor.value;
  } catch (error) {
    if (error instanceof ProviderSignedResultFlowStateError) throw error;
    stateError("approval launch result.kind is inaccessible", error);
  }

  if (kind === "replay-required") {
    exactDataRecord(outer, ["kind"], "approval replay result");
    return Object.freeze({ kind });
  }
  if (kind !== "opened") stateError("approval launch result kind is unsupported");
  const opened = exactDataRecord(
    outer,
    ["kind", "approval", "terminal"],
    "opened approval result",
  );
  if (!(opened.terminal instanceof Promise)) {
    stateError("opened approval terminal must be a Promise");
  }
  return Object.freeze({
    kind,
    terminal: opened.terminal as Promise<unknown>,
  });
}

/**
 * Join one C15 approval flow to one C14 delivery lease without ever receiving
 * signed bytes. Repeated calls for the same exact in-memory request share one
 * Promise, while reconnects use C14's durable operation identity.
 */
export class ProviderSignedResultFlowOwner {
  readonly #dependencies: BoundDependencies;
  readonly #active = new Map<
    OwnedProviderRequest,
    Promise<ProviderSignedResultFlowResult>
  >();

  constructor(options: ProviderSignedResultFlowOwnerOptions) {
    this.#dependencies = bindDependencies(options);
  }

  get activeCount(): number {
    return this.#active.size;
  }

  deliver(
    leaseValue: ProviderTerminalDeliveryLease,
  ): Promise<ProviderSignedResultFlowResult> {
    try {
      const lease = bindLease(leaseValue);
      lease.assertActive();
      const existing = this.#active.get(lease.owned);
      if (existing !== undefined) return existing;
      if (this.#active.size >= MAX_ACTIVE_PROVIDER_SIGNED_RESULT_FLOWS) {
        stateError("active flow capacity exhausted");
      }

      let flow!: Promise<ProviderSignedResultFlowResult>;
      flow = Promise.resolve().then(async () => {
        try {
          lease.assertActive();
          const launch = snapshotLaunch(
            await this.#dependencies.launchApproval(lease),
          );
          const replayed = launch.kind === "replay-required";
          if (!replayed) {
            const signed = await launch.terminal;
            if (typeof signed !== "boolean") {
              stateError("approval terminal proof is not boolean");
            }
            if (!signed) stateError("approval terminal has no signed result");
          }

          // C14 rechecks every durable binding and the live lease. The boolean
          // terminal is a scheduling proof, never authority to construct bytes.
          lease.assertActive();
          const delivered = await this.#dependencies.deliverResult(lease);
          if (delivered !== true) {
            stateError("terminal delivery returned no proof");
          }
          return Object.freeze({ kind: "delivered", replayed });
        } finally {
          if (this.#active.get(lease.owned) === flow) {
            this.#active.delete(lease.owned);
          }
        }
      });
      this.#active.set(lease.owned, flow);
      return flow;
    } catch (error) {
      return Promise.reject(error);
    }
  }
}
