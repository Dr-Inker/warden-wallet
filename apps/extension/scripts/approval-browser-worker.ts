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
const attempt = (value: number): string =>
  `attempt_${value.toString(16).padStart(2, "0").repeat(16)}`;

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
          const value = request.result as {
            approval?: { rawMessage?: unknown };
            rawMessage?: unknown;
          } | undefined;
          const rawMessage = value?.approval?.rawMessage ?? value?.rawMessage;
          if (value === undefined || !(rawMessage instanceof Uint8Array)) {
            throw new Error("approval record unavailable for tamper contract");
          }
          rawMessage[0] = rawMessage[0]! ^ 0xff;
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

async function downgradeToLegacyApprovedRecord(id: string): Promise<void> {
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
        operationError ?? transaction.error ?? new Error("legacy transaction aborted"),
      );
      transaction.onerror = () => {};
      const store = transaction.objectStore(APPROVAL_OBJECT_STORE_NAME);
      const request = store.get(id);
      request.onsuccess = () => {
        try {
          const value = request.result as { approval?: unknown } | undefined;
          if (value?.approval === undefined) {
            throw new Error("approval envelope unavailable for legacy contract");
          }
          store.put(value.approval);
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

function settled(result: PromiseSettledResult<unknown>): {
  readonly status: "fulfilled" | "rejected";
  readonly state?: string;
  readonly errorName?: string;
} {
  return result.status === "fulfilled"
    ? {
        status: "fulfilled",
        state: (() => {
          const value = result.value as {
            readonly state?: string;
            readonly outcome?: { readonly state?: string };
          };
          return value.outcome?.state ?? value.state;
        })(),
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
    owner.claimForSigning(race.id, race.messageDigest, attempt(0x20)),
    competingOwner.reject(race.id),
  ]);
  const raceView = await owner.read(race.id);
  const raceSigning = await owner.readSigning(race.id, race.messageDigest)
    .catch(() => null);
  if (raceSigning?.outcome.state === "signing") {
    await owner.failSigning(
      race.id,
      race.messageDigest,
      raceSigning.outcome.attemptId,
      "signing-failed",
    );
  }

  const double = await owner.create(input(0x30, now));
  const doubleResults = await Promise.allSettled([
    owner.claimForSigning(double.id, double.messageDigest, attempt(0x30)),
    competingOwner.claimForSigning(double.id, double.messageDigest, attempt(0x31)),
  ]);
  const doubleView = await owner.read(double.id);
  const doubleSigning = await owner.readSigning(double.id, double.messageDigest);
  if (doubleSigning?.outcome.state === "signing") {
    await owner.failSigning(
      double.id,
      double.messageDigest,
      doubleSigning.outcome.attemptId,
      "signing-failed",
    );
  }
  competingOwner.close();

  const corrupt = await owner.create(input(0x40, now));
  await corruptRawMessage(corrupt.id);
  const corruptResult = await Promise.allSettled([
    owner.claimForSigning(corrupt.id, corrupt.messageDigest, attempt(0x40)),
  ]);
  const corruptRead = await owner.read(corrupt.id);

  const mismatched = await owner.create(input(0x41, now));
  const wrongDigest = mismatched.messageDigest.slice();
  wrongDigest[0] = wrongDigest[0]! ^ 0xff;
  const mismatchResult = await Promise.allSettled([
    owner.claimForSigning(mismatched.id, wrongDigest, attempt(0x41)),
  ]);
  const mismatchView = await owner.read(mismatched.id);
  const mismatchRetry = await Promise.allSettled([
    owner.claimForSigning(mismatched.id, mismatched.messageDigest, attempt(0x42)),
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
    expiryOwner.claimForSigning(expiring.id, expiring.messageDigest, attempt(0x43)),
  ]);
  const expiryView = await expiryOwner.read(expiring.id);

  const mismatchedExpiry = await expiryOwner.create(input(0x4b, logicalNow));
  const mismatchedExpiryDigest = mismatchedExpiry.messageDigest.slice();
  mismatchedExpiryDigest[0] = mismatchedExpiryDigest[0]! ^ 0xff;
  logicalNow = mismatchedExpiry.expiresAt;
  const mismatchedExpiryResult = await Promise.allSettled([
    expiryOwner.claimForSigning(
      mismatchedExpiry.id,
      mismatchedExpiryDigest,
      attempt(0x4b),
    ),
  ]);
  const mismatchedExpiryView = await expiryOwner.read(mismatchedExpiry.id);
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
    owner.claimForSigning(
      identicalFirst.id,
      identicalFirst.messageDigest,
      attempt(0x44),
    ),
    owner.reject(identicalSecond.id),
  ]);
  await owner.failSigning(
    identicalFirst.id,
    identicalFirst.messageDigest,
    attempt(0x44),
    "signing-failed",
  );

  const completedInput = await owner.create(input(0x45, now));
  const completedClaim = await owner.claimForSigning(
    completedInput.id,
    completedInput.messageDigest,
    attempt(0x45),
  );
  const invalidCompletion = await Promise.allSettled([
    owner.completeSigning(
      completedInput.id,
      completedInput.messageDigest,
      completedClaim.outcome.attemptId,
      new Uint8Array(),
    ),
  ]);
  const afterInvalidCompletion = await owner.readSigning(
    completedInput.id,
    completedInput.messageDigest,
  );
  const completed = await owner.completeSigning(
    completedInput.id,
    completedInput.messageDigest,
    completedClaim.outcome.attemptId,
    Uint8Array.of(1, 2, 3, 4),
  );
  completed.outcome.transactionBytes!.fill(0);
  const completedReplay = await owner.readSigning(
    completedInput.id,
    completedInput.messageDigest,
  );
  const completedReclaim = await owner.claimForSigning(
    completedInput.id,
    completedInput.messageDigest,
    attempt(0x99),
  );

  const retriedInput = await owner.create(input(0x46, now));
  await owner.claimForSigning(
    retriedInput.id,
    retriedInput.messageDigest,
    attempt(0x46),
  );
  const failWithUntrustedCode = owner.failSigning.bind(owner) as unknown as (
    id: string,
    digest: Uint8Array,
    attemptId: string,
    failureCode: string,
  ) => Promise<unknown>;
  const invalidFailure = await Promise.allSettled([
    failWithUntrustedCode(
      retriedInput.id,
      retriedInput.messageDigest,
      attempt(0x46),
      "not-a-closed-failure-code",
    ),
  ]);
  const afterInvalidFailure = await owner.readSigning(
    retriedInput.id,
    retriedInput.messageDigest,
  );
  const failed = await owner.failSigning(
    retriedInput.id,
    retriedInput.messageDigest,
    attempt(0x46),
    "blockhash-invalid",
  );
  const retried = await owner.claimForSigning(
    retriedInput.id,
    retriedInput.messageDigest,
    attempt(0x47),
  );
  const staleCompletion = await Promise.allSettled([
    owner.completeSigning(
      retriedInput.id,
      retriedInput.messageDigest,
      attempt(0x46),
      Uint8Array.of(9, 8, 7),
    ),
  ]);
  const retriedCompletion = await owner.completeSigning(
    retriedInput.id,
    retriedInput.messageDigest,
    attempt(0x47),
    Uint8Array.of(9, 8, 7),
  );

  let rollbackNow = 50_000;
  const rollbackRepository = new IndexedDbApprovalRecordRepository({
    databaseName: DATABASE_NAME,
  });
  const rollbackOwner = new ApprovalOwner(rollbackRepository, {
    readNow: () => rollbackNow,
  });
  const rollbackInput = await rollbackOwner.create(input(0x48, rollbackNow));
  await rollbackOwner.claimForSigning(
    rollbackInput.id,
    rollbackInput.messageDigest,
    attempt(0x48),
  );
  rollbackNow--;
  const rollbackCompletion = await Promise.allSettled([
    rollbackOwner.completeSigning(
      rollbackInput.id,
      rollbackInput.messageDigest,
      attempt(0x48),
      Uint8Array.of(4, 8),
    ),
  ]);
  const afterRollback = await rollbackOwner.readSigning(
    rollbackInput.id,
    rollbackInput.messageDigest,
  );
  rollbackNow += 2;
  await rollbackOwner.failSigning(
    rollbackInput.id,
    rollbackInput.messageDigest,
    attempt(0x48),
    "signing-failed",
  );
  rollbackOwner.close();

  let futureNow = now + 60_000;
  const futureRepository = new IndexedDbApprovalRecordRepository({
    databaseName: DATABASE_NAME,
  });
  const futureOwner = new ApprovalOwner(futureRepository, {
    readNow: () => futureNow,
  });
  const futureInput = await futureOwner.create(input(0x49, futureNow));
  await futureOwner.claimForSigning(
    futureInput.id,
    futureInput.messageDigest,
    attempt(0x49),
  );
  const regressedStartupRepository = new IndexedDbApprovalRecordRepository({
    databaseName: DATABASE_NAME,
  });
  const regressedStartup = await Promise.allSettled([
    regressedStartupRepository.invalidatePending(now),
  ]);
  const afterRegressedStartup = await futureOwner.readSigning(
    futureInput.id,
    futureInput.messageDigest,
  );
  futureNow++;
  await futureOwner.failSigning(
    futureInput.id,
    futureInput.messageDigest,
    attempt(0x49),
    "signing-failed",
  );
  regressedStartupRepository.close();
  futureOwner.close();

  const legacyApproved = await owner.create(input(0x4a, now));
  await owner.claimForSigning(
    legacyApproved.id,
    legacyApproved.messageDigest,
    attempt(0x4a),
  );
  await downgradeToLegacyApprovedRecord(legacyApproved.id);
  const legacyApprovedRead = await Promise.allSettled([
    owner.read(legacyApproved.id),
  ]);
  const legacyApprovedAfter = await owner.read(legacyApproved.id);

  const restartPending = await owner.create(input(0x50, now));
  const restartSigning = await owner.create(input(0x51, now));
  await owner.claimForSigning(
    restartSigning.id,
    restartSigning.messageDigest,
    attempt(0x51),
  );
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
    mismatchedExpiryResult: mismatchedExpiryResult.map(settled),
    mismatchedExpiryState: mismatchedExpiryView?.state ?? null,
    identicalDigestMatches:
      identicalDigest.join(",") === Array.from(identicalSecond.messageDigest).join(","),
    identicalStates: identicalResults.map((record) =>
      "outcome" in record ? record.outcome.state : record.state),
    completedState: completedReplay?.outcome.state,
    completedBytes: Array.from(completedReplay?.outcome.transactionBytes ?? []),
    completedAttemptStable:
      completedReclaim.outcome.attemptId === completedClaim.outcome.attemptId,
    invalidCompletion: invalidCompletion.map(settled),
    afterInvalidCompletionState: afterInvalidCompletion?.outcome.state,
    invalidFailure: invalidFailure.map(settled),
    afterInvalidFailureState: afterInvalidFailure?.outcome.state,
    failedState: failed.outcome.state,
    failedCode: failed.outcome.failureCode,
    retryState: retried.outcome.state,
    retryAttemptNumber: retried.outcome.attemptNumber,
    staleCompletion: staleCompletion.map(settled),
    retriedCompletionState: retriedCompletion.outcome.state,
    rollbackCompletion: rollbackCompletion.map(settled),
    afterRollbackState: afterRollback?.outcome.state,
    regressedStartup: regressedStartup.map(settled),
    afterRegressedStartupState: afterRegressedStartup?.outcome.state,
    legacyApprovedRead: legacyApprovedRead.map(settled),
    legacyApprovedAfter,
    restartPendingId: restartPending.id,
    restartPendingDigest: Array.from(restartPending.messageDigest),
    restartSigningId: restartSigning.id,
    restartSigningDigest: Array.from(restartSigning.messageDigest),
    completedId: completedInput.id,
    completedDigest: Array.from(completedInput.messageDigest),
  };
}

async function runAfterRestart(input: {
  readonly pendingId: string;
  readonly pendingDigest: number[];
  readonly signingId: string;
  readonly signingDigest: number[];
  readonly completedId: string;
  readonly completedDigest: number[];
}) {
  const invalidated = await startup;
  const pending = await owner.read(input.pendingId);
  const signing = await owner.readSigning(
    input.signingId,
    Uint8Array.from(input.signingDigest),
  );
  const completed = await owner.readSigning(
    input.completedId,
    Uint8Array.from(input.completedDigest),
  );
  return {
    invalidated,
    pendingState: pending?.state ?? null,
    signingState: signing?.outcome.state ?? null,
    signingFailureCode: signing?.outcome.failureCode ?? null,
    completedState: completed?.outcome.state ?? null,
    completedBytes: Array.from(completed?.outcome.transactionBytes ?? []),
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
