import type { ApprovalCreateParams } from "@warden/core/approval";

import { ApprovalOwner } from "../src/background/approval-owner.js";
import {
  APPROVAL_DATABASE_VERSION,
  APPROVAL_OBJECT_STORE_NAME,
  IndexedDbApprovalRecordRepository,
} from "../src/background/approval-store.js";

const DATABASE_NAME = "warden-approval-browser-contract-v1";
const fill = (length: number, value: number): Uint8Array =>
  new Uint8Array(length).fill(value);

function input(idByte: number, now: number): ApprovalCreateParams {
  return {
    id: `req_${idByte.toString(16).padStart(2, "0").repeat(16)}`,
    origin: "https://browser-contract.example",
    tabId: 7,
    frameId: 0,
    documentId: `browser-document-${idByte}`,
    account: fill(32, 0x11),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: fill(32, 0x22),
    programId: fill(32, 0x33),
    rawMessage: new Uint8Array([idByte, 2, 3, 4]),
    policyVersion: 1,
    createdAt: now,
    expiresAt: now + 60_000,
  };
}

function openRawDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, APPROVAL_DATABASE_VERSION);
    request.onerror = () => reject(request.error ?? new Error("raw IndexedDB open failed"));
    request.onsuccess = () => resolve(request.result);
  });
}

async function corruptRawMessage(id: string): Promise<void> {
  const database = await openRawDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction(
        APPROVAL_OBJECT_STORE_NAME,
        "readwrite",
        { durability: "strict" },
      );
      let operationError: unknown;
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(
        operationError ?? transaction.error ?? new Error("tamper transaction aborted"),
      );
      transaction.onerror = () => {};
      const store = transaction.objectStore(APPROVAL_OBJECT_STORE_NAME);
      const request = store.get(id);
      request.onsuccess = () => {
        try {
          const value = request.result as { rawMessage?: unknown } | undefined;
          if (value === undefined || !(value.rawMessage instanceof Uint8Array)) {
            throw new Error("approval record unavailable for tamper contract");
          }
          value.rawMessage[0] = value.rawMessage[0]! ^ 0xff;
          store.put(value);
        } catch (error) {
          operationError = error;
          transaction.abort();
        }
      };
    });
  } finally {
    database.close();
  }
}

function settled<T>(result: PromiseSettledResult<T>): {
  readonly status: "fulfilled" | "rejected";
  readonly state?: string;
  readonly errorName?: string;
} {
  return result.status === "fulfilled"
    ? {
        status: "fulfilled",
        state: (result.value as { readonly state?: string }).state,
      }
    : {
        status: "rejected",
        errorName: result.reason instanceof Error
          ? result.reason.name
          : typeof result.reason,
      };
}

const repository = new IndexedDbApprovalRecordRepository({
  databaseName: DATABASE_NAME,
});
const owner = new ApprovalOwner(repository);
const startup = owner.invalidateAfterWorkerRestart();

async function runBeforeRestart() {
  const initialInvalidated = await startup;
  const now = Date.now();

  const copiedInput = input(0x10, now);
  const copied = await owner.create(copiedInput);
  copiedInput.rawMessage.fill(0xff);
  copied.rawMessage.fill(0xee);
  copied.messageDigest.fill(0);
  const copiedView = await owner.read(copied.id);
  await owner.cancel(copied.id);

  const race = await owner.create(input(0x20, now));
  const competingRepository = new IndexedDbApprovalRecordRepository({
    databaseName: DATABASE_NAME,
  });
  const competingOwner = new ApprovalOwner(competingRepository);
  const raceResults = await Promise.allSettled([
    owner.claimForSigning(race.id, race.messageDigest),
    competingOwner.reject(race.id),
  ]);
  const raceView = await owner.read(race.id);

  const double = await owner.create(input(0x30, now));
  const doubleResults = await Promise.allSettled([
    owner.claimForSigning(double.id, double.messageDigest),
    competingOwner.claimForSigning(double.id, double.messageDigest),
  ]);
  const doubleView = await owner.read(double.id);
  competingOwner.close();

  const corrupt = await owner.create(input(0x40, now));
  await corruptRawMessage(corrupt.id);
  const corruptResult = await Promise.allSettled([
    owner.claimForSigning(corrupt.id, corrupt.messageDigest),
  ]);
  const corruptRead = await owner.read(corrupt.id);

  const mismatched = await owner.create(input(0x41, now));
  const wrongDigest = mismatched.messageDigest.slice();
  wrongDigest[0] = wrongDigest[0]! ^ 0xff;
  const mismatchResult = await Promise.allSettled([
    owner.claimForSigning(mismatched.id, wrongDigest),
  ]);
  const mismatchView = await owner.read(mismatched.id);
  const mismatchRetry = await Promise.allSettled([
    owner.claimForSigning(mismatched.id, mismatched.messageDigest),
  ]);

  let logicalNow = 10_000;
  const expiryRepository = new IndexedDbApprovalRecordRepository({
    databaseName: DATABASE_NAME,
  });
  const expiryOwner = new ApprovalOwner(expiryRepository, {
    readNow: () => logicalNow,
  });
  const expiring = await expiryOwner.create(input(0x42, logicalNow));
  logicalNow = expiring.expiresAt;
  const expiryResult = await Promise.allSettled([
    expiryOwner.claimForSigning(expiring.id, expiring.messageDigest),
  ]);
  const expiryView = await expiryOwner.read(expiring.id);
  expiryOwner.close();

  const identicalFirstInput = input(0x43, now);
  const identicalSecondInput = {
    ...input(0x44, now),
    documentId: identicalFirstInput.documentId,
    rawMessage: identicalFirstInput.rawMessage.slice(),
  };
  const identicalFirst = await owner.create(identicalFirstInput);
  const identicalSecond = await owner.create(identicalSecondInput);
  const identicalDigest = Array.from(identicalFirst.messageDigest);
  const identicalResults = await Promise.all([
    owner.claimForSigning(identicalFirst.id, identicalFirst.messageDigest),
    owner.reject(identicalSecond.id),
  ]);

  const restart = await owner.create(input(0x50, now));
  return {
    initialInvalidated,
    copiedRawMessage: Array.from(copiedView?.rawMessage ?? []),
    raceResults: raceResults.map(settled),
    raceState: raceView?.state,
    doubleResults: doubleResults.map(settled),
    doubleState: doubleView?.state,
    corruptResult: corruptResult.map(settled),
    corruptRead,
    mismatchResult: mismatchResult.map(settled),
    mismatchState: mismatchView?.state,
    mismatchRetry: mismatchRetry.map(settled),
    expiryResult: expiryResult.map(settled),
    expiryState: expiryView?.state,
    identicalDigestMatches:
      identicalDigest.join(",") === Array.from(identicalSecond.messageDigest).join(","),
    identicalStates: identicalResults.map((record) => record.state),
    restartId: restart.id,
  };
}

async function runAfterRestart(id: string) {
  const invalidated = await startup;
  const record = await owner.read(id);
  return {
    invalidated,
    state: record?.state ?? null,
    resolvedAt: record?.resolvedAt ?? null,
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

// Synchronous listener registration is the wake mechanism for the restart test.
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
  __wardenApprovalBeforeRestart: runBeforeRestart,
  __wardenApprovalAfterRestart: runAfterRestart,
});
