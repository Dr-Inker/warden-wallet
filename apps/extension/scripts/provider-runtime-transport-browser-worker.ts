//! Browser-only C22/C20/C14/C19 composition. Never copied into the product build.

import {
  ProviderOperationOwner,
  type ProviderOperationPreparation,
} from "../src/background/provider-operation.js";
import { IndexedDbProviderOperationRepository } from "../src/background/provider-operation-store.js";
import {
  ProviderRuntimeTransportOwner,
  type ProviderRuntimeTransportFlow,
  type ProviderRuntimeTransportLease,
} from "../src/background/provider-runtime-transport.js";
import { ProviderTerminalOutcomeOwner } from "../src/background/provider-terminal-outcome.js";
import { createProviderTerminalFailureResponse } from "../src/background/provider-terminal-protocol.js";
import type { ProviderOperationDigestSource } from "../src/background/provider-operation.js";
import type { ProviderRuntimeApi } from "../src/background/provider-port.js";

const DATABASE_NAME = "warden-provider-runtime-transport-browser-contract-v1";
const PREPARATION_CALLS_KEY = "warden.provider-runtime.preparation-calls.v1";

interface BrowserStorageArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

interface BrowserChrome {
  readonly runtime: ProviderRuntimeApi;
  readonly storage: { readonly local: BrowserStorageArea };
}

class CountingDigest implements ProviderOperationDigestSource {
  calls = 0;
  completed = 0;

  async digest(bytes: Uint8Array): Promise<Uint8Array> {
    this.calls++;
    const result = new Uint8Array(
      await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer),
    );
    this.completed++;
    return result;
  }
}

function bootIdentity(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

const chromeApi = (globalThis as unknown as { readonly chrome: BrowserChrome }).chrome;
const repository = new IndexedDbProviderOperationRepository({
  databaseName: DATABASE_NAME,
});
const operations = new ProviderOperationOwner(repository);
const startup = operations.invalidateAfterWorkerRestart();
const terminal = new ProviderTerminalOutcomeOwner({
  operations: repository,
  approvals: {
    async read(): Promise<never> {
      throw new Error("failed operation must not read an approval");
    },
    async readSigning(): Promise<never> {
      throw new Error("failed operation must not read a signing outcome");
    },
  },
  signed: {
    async deliver(): Promise<never> {
      throw new Error("failed operation must not enter signed delivery");
    },
  },
});
const digest = new CountingDigest();
const bootId = bootIdentity();
let volatileCalls = 0;
let releaseVolatile: (() => void) | null = null;
let latestCorrelationId: string | null = null;
let latestExpiresAt: number | null = null;
const observedLeases = new Set<ProviderRuntimeTransportLease>();

function ownedDeliveryCount(): number {
  let count = 0;
  for (const lease of observedLeases) {
    try {
      lease.assertActive();
      count++;
    } catch {
      // Receipt settlement, expiry, or worker cleanup removed this lease.
    }
  }
  return count;
}

async function preparationCalls(): Promise<number> {
  const stored = await chromeApi.storage.local.get(PREPARATION_CALLS_KEY);
  const value = stored[PREPARATION_CALLS_KEY];
  return Number.isSafeInteger(value) && (value as number) >= 0
    ? value as number
    : 0;
}

async function recordPreparationCall(): Promise<void> {
  const count = await preparationCalls();
  await chromeApi.storage.local.set({ [PREPARATION_CALLS_KEY]: count + 1 });
}

async function neverFinishPreparation(): Promise<ProviderOperationPreparation> {
  await recordPreparationCall();
  return new Promise(() => {});
}

const flow: ProviderRuntimeTransportFlow = {
  async deliver(lease: ProviderRuntimeTransportLease): Promise<unknown> {
    observedLeases.add(lease);
    latestCorrelationId = lease.owned.request.correlationId;
    latestExpiresAt = lease.owned.expiresAt;
    if (lease.owned.request.correlationId.startsWith("browser_overlap_")) {
      volatileCalls++;
      await new Promise<void>((resolve) => {
        releaseVolatile = resolve;
      });
      lease.assertActive();
      lease.postMessage(createProviderTerminalFailureResponse(
        lease.owned.request.correlationId,
        "WARDEN_REQUEST_CANCELLED",
      ));
      if (!lease.finish()) throw new Error("overlap delivery ownership was lost");
      return Object.freeze({ kind: "delivered", replayed: false });
    }

    const startupInvalidated = await startup;
    try {
      await operations.prepare(lease, neverFinishPreparation);
      throw new Error("browser preparation unexpectedly completed");
    } catch {
      if (
        startupInvalidated > 0 &&
        lease.owned.request.correlationId.startsWith("browser_deadline_")
      ) {
        const delayMs = Math.max(0, lease.owned.expiresAt - Date.now() + 50);
        await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
      }
      if (await terminal.deliver(lease) !== true) {
        throw new Error("durable restart failure was not delivered");
      }
      return Object.freeze({ kind: "delivered", replayed: true });
    }
  },
};

const transport = new ProviderRuntimeTransportOwner(chromeApi.runtime, flow, {
  digestSource: digest,
});

Object.assign(globalThis, {
  __wardenProviderRuntimeTransportStatus: async () => ({
    bootId,
    startupInvalidated: await startup,
    preparationCalls: await preparationCalls(),
    volatileCalls,
    identityDigestCalls: digest.calls,
    identityDigestCompletions: digest.completed,
    activeDocuments: transport.activeDocumentCount,
    ownedDeliveries: ownedDeliveryCount(),
    latestCorrelationId,
    latestExpiresAt,
  }),
  __wardenProviderRuntimeTransportRelease: () => {
    const release = releaseVolatile;
    releaseVolatile = null;
    release?.();
  },
});
