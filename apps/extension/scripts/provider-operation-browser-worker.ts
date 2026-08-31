import type { OwnedProviderRequest } from "../src/background/provider-port.js";
import {
  ProviderOperationOwner,
  deriveProviderOperationIdentity,
  type ProviderOperationRequestLease,
} from "../src/background/provider-operation.js";
import {
  IndexedDbProviderOperationRepository,
} from "../src/background/provider-operation-store.js";

const DATABASE_NAME = "warden-provider-operation-browser-contract-v1";
const APPROVAL_ID = `req_${"ab".repeat(16)}`;
const APPROVAL_DIGEST = new Uint8Array(32).fill(0x44);
const EXTENSION_ID = "a".repeat(32);

function owned(
  correlationId: string,
  volatileIdByte: number,
  now: number,
): OwnedProviderRequest {
  return Object.freeze({
    id: `req_${volatileIdByte.toString(16).padStart(2, "0").repeat(16)}`,
    provenance: Object.freeze({
      kind: "provider" as const,
      extensionId: EXTENSION_ID,
      documentId: "provider-operation-browser-document",
      origin: "https://provider-operation-browser.example",
      tabId: 17,
      frameId: 0,
    }),
    request: Object.freeze({
      version: 1 as const,
      type: "request" as const,
      correlationId,
      method: "solana:signTransaction" as const,
      params: Object.freeze({
        requestedAccountAddress: "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2",
        transaction: Object.freeze([1, 2, 3, 4]),
        chain: "solana:devnet" as const,
        options: Object.freeze({
          preflightCommitment: "confirmed" as const,
          minContextSlot: 7,
        }),
      }),
    }),
    createdAt: now,
    expiresAt: now + 60_000,
    signal: new AbortController().signal,
  });
}

function lease(value: OwnedProviderRequest): ProviderOperationRequestLease {
  return Object.freeze({
    owned: value,
    assertActive(): void {
      if (value.signal.aborted) throw new Error("browser request is inactive");
    },
  });
}

function result(value: PromiseSettledResult<unknown>) {
  if (value.status === "rejected") {
    return {
      status: value.status,
      errorName: value.reason instanceof Error
        ? value.reason.name
        : typeof value.reason,
    };
  }
  const resolution = value.value as {
    readonly created: boolean;
    readonly record: { readonly state: string; readonly approvalId: string | null };
  };
  return {
    status: value.status,
    created: resolution.created,
    state: resolution.record.state,
    approvalId: resolution.record.approvalId,
  };
}

const repository = new IndexedDbProviderOperationRepository({
  databaseName: DATABASE_NAME,
});
const owner = new ProviderOperationOwner(repository);
const startup = owner.invalidateAfterWorkerRestart();

async function runBeforeRestart() {
  const initialInvalidated = await startup;
  const now = Date.now();
  const stableCorrelation = "browser_bound_0123456789";
  const firstOwned = owned(stableCorrelation, 0x11, now);
  const secondOwned = owned(stableCorrelation, 0x22, now);
  const competingRepository = new IndexedDbProviderOperationRepository({
    databaseName: DATABASE_NAME,
  });
  const competingOwner = new ProviderOperationOwner(competingRepository);
  let prepareCalls = 0;
  const prepare = async () => {
    prepareCalls++;
    return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
  };
  const race = await Promise.allSettled([
    owner.prepare(lease(firstOwned), prepare),
    competingOwner.prepare(lease(secondOwned), prepare),
  ]);
  const boundIdentity = await deriveProviderOperationIdentity(firstOwned);
  const bound = await repository.read({
    key: boundIdentity.key,
    now: Date.now(),
  });

  const interruptedCorrelation = "browser_interrupted_0123";
  const interruptedOwned = owned(interruptedCorrelation, 0x33, now);
  const interruptedIdentity = await deriveProviderOperationIdentity(interruptedOwned);
  const interrupted = await repository.claim({
    identity: interruptedIdentity,
    createdAt: interruptedOwned.createdAt,
    expiresAt: interruptedOwned.expiresAt,
    now: Date.now(),
  });
  competingOwner.close();

  return {
    initialInvalidated,
    prepareCalls,
    race: race.map(result),
    boundKey: boundIdentity.key,
    boundState: bound?.state ?? null,
    boundApprovalId: bound?.approvalId ?? null,
    interruptedKey: interruptedIdentity.key,
    interruptedState: interrupted.record.state,
    stableCorrelation,
    interruptedCorrelation,
    originalCreatedAt: now,
  };
}

async function runAfterRestart(input: {
  readonly boundKey: string;
  readonly interruptedKey: string;
  readonly stableCorrelation: string;
  readonly interruptedCorrelation: string;
}) {
  const invalidated = await startup;
  const now = Date.now();
  let replayPrepareCalls = 0;
  const replay = await owner.prepare(
    lease(owned(input.stableCorrelation, 0x44, now)),
    async () => {
      replayPrepareCalls++;
      return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
    },
  );
  let interruptedPrepareCalls = 0;
  const interruptedRetry = await Promise.allSettled([
    owner.prepare(
      lease(owned(input.interruptedCorrelation, 0x55, now)),
      async () => {
        interruptedPrepareCalls++;
        return { id: APPROVAL_ID, messageDigest: APPROVAL_DIGEST };
      },
    ),
  ]);
  const bound = await repository.read({ key: input.boundKey, now: Date.now() });
  const interrupted = await repository.read({
    key: input.interruptedKey,
    now: Date.now(),
  });
  return {
    invalidated,
    replayCreated: replay.created,
    replayState: replay.record.state,
    replayApprovalId: replay.record.approvalId,
    replayPrepareCalls,
    interruptedRetry: interruptedRetry.map(result),
    interruptedPrepareCalls,
    boundState: bound?.state ?? null,
    interruptedState: interrupted?.state ?? null,
    interruptedFailureCode: interrupted?.failureCode ?? null,
  };
}

type RuntimeMessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void,
) => boolean | void;

const chromeApi = (globalThis as unknown as {
  readonly chrome: {
    readonly runtime: {
      readonly onMessage: {
        addListener(listener: RuntimeMessageListener): void;
      };
    };
  };
}).chrome;

chromeApi.runtime.onMessage.addListener((_message, _sender, sendResponse) => {
  void startup.then(
    () => sendResponse({ ready: true }),
    (error: unknown) => sendResponse({
      ready: false,
      error: error instanceof Error ? error.name : typeof error,
    }),
  );
  return true;
});

Object.assign(globalThis, {
  // Bundled only by provider-operation-idb.pw.ts into a temporary extension.
  __wardenProviderOperationBeforeRestart: runBeforeRestart,
  __wardenProviderOperationAfterRestart: runAfterRestart,
});
