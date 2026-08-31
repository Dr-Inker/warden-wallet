import {
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";

import { parseApprovalRequestId } from "../approval-protocol.js";

export const APPROVAL_WINDOW_WIDTH = 720;
export const APPROVAL_WINDOW_HEIGHT = 600;
export const MAX_ACTIVE_APPROVAL_WINDOWS = 16;

const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;

export interface ApprovalWindowCreateData {
  readonly url: string;
  readonly type: "popup";
  readonly focused: true;
  readonly width: number;
  readonly height: number;
  readonly setSelfAsOpener: false;
}

export interface ApprovalChromeWindow {
  readonly id?: number;
}

export interface ApprovalWindowRemovedEvent {
  addListener(listener: (windowId: number) => void): void;
  removeListener(listener: (windowId: number) => void): void;
}

/** The intentionally tiny subset of chrome.windows owned by approval launch. */
export interface ApprovalWindowsApi {
  readonly onRemoved: ApprovalWindowRemovedEvent;
  create(options: ApprovalWindowCreateData): Promise<ApprovalChromeWindow | undefined>;
  get(windowId: number): Promise<ApprovalChromeWindow>;
  remove(windowId: number): Promise<void>;
}

export interface ApprovalWindowRecordOwner {
  read(id: string): Promise<ApprovalRecord | null>;
  cancel(id: string): Promise<ApprovalRecord>;
}

export interface ApprovalWindowOwnerOptions {
  readonly runtimeId: string;
  readonly approvals: ApprovalWindowRecordOwner;
  readonly ready: Promise<unknown>;
  readonly onFatal: (error: unknown) => void;
}

export interface ApprovalWindowLauncher {
  /**
   * Open one background-authored review page for an already-owned request.
   * The AbortSignal is the only caller-controlled lifetime capability.
   */
  launch(requestId: string, signal: AbortSignal): Promise<void>;
}

export interface InstalledApprovalWindowOwner extends ApprovalWindowLauncher {
  dispose(): void;
}

export class ApprovalWindowStateError extends Error {
  constructor(message: string, options: ErrorOptions = {}) {
    super(`approval window owner: ${message}`, options);
    this.name = "ApprovalWindowStateError";
  }
}

interface WindowEntry {
  readonly requestId: string;
  readonly signal: AbortSignal;
  readonly onAbort: () => void;
  windowId: number | undefined;
  closed: boolean;
  closePromise: Promise<void> | undefined;
}

function requireWindowsApi(value: unknown): ApprovalWindowsApi {
  if (typeof value !== "object" || value === null) {
    throw new ApprovalWindowStateError("chrome.windows is unavailable");
  }
  const windows = value as Partial<ApprovalWindowsApi>;
  if (
    typeof windows.create !== "function" ||
    typeof windows.get !== "function" ||
    typeof windows.remove !== "function" ||
    typeof windows.onRemoved !== "object" ||
    windows.onRemoved === null ||
    typeof windows.onRemoved.addListener !== "function" ||
    typeof windows.onRemoved.removeListener !== "function"
  ) {
    throw new ApprovalWindowStateError(
      "chrome.windows must provide create/get/remove and onRemoved",
    );
  }
  return value as ApprovalWindowsApi;
}

function requireOwner(value: unknown): ApprovalWindowRecordOwner {
  if (typeof value !== "object" || value === null) {
    throw new ApprovalWindowStateError("approval owner must be an object");
  }
  const owner = value as Partial<ApprovalWindowRecordOwner>;
  if (typeof owner.read !== "function" || typeof owner.cancel !== "function") {
    throw new ApprovalWindowStateError("approval owner must provide read/cancel");
  }
  return value as ApprovalWindowRecordOwner;
}

function requireAbortSignal(value: unknown): AbortSignal {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly aborted?: unknown }).aborted !== "boolean" ||
    typeof (value as { readonly addEventListener?: unknown }).addEventListener !== "function" ||
    typeof (value as { readonly removeEventListener?: unknown }).removeEventListener !== "function"
  ) {
    throw new ApprovalWindowStateError("request lifetime must be an AbortSignal");
  }
  return value as AbortSignal;
}

function requireWindowId(value: unknown, operation: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ApprovalWindowStateError(
      `${operation} returned a malformed window id`,
    );
  }
  return value as number;
}

function clearRecord(value: ApprovalRecord | null | undefined): void {
  value?.account.fill(0);
  value?.genesisHash.fill(0);
  value?.programId.fill(0);
  value?.rawMessage.fill(0);
  value?.messageDigest.fill(0);
}

function safeReportFatal(report: (error: unknown) => void, error: unknown): void {
  try {
    report(error);
  } catch {
    // A throwing observer cannot turn an unproven cancellation into success.
  }
}

function combineFailure(
  primary: unknown,
  cleanup: unknown,
  message: string,
): unknown {
  return cleanup === undefined
    ? primary
    : new AggregateError([primary, cleanup], message);
}

/**
 * Own approval popup creation inside the background worker.
 *
 * No page/provider input can choose a URL, bounds, window id, or navigation.
 * This owner also has no approve/sign/RPC/keyring capability: it can only prove
 * one record pending, open its fixed review page, and cancel it on lifetime loss.
 */
export function installApprovalWindowOwner(
  windowsValue: unknown,
  options: ApprovalWindowOwnerOptions,
): InstalledApprovalWindowOwner {
  const windows = requireWindowsApi(windowsValue);
  if (typeof options !== "object" || options === null) {
    throw new ApprovalWindowStateError("options must be an object");
  }
  if (
    typeof options.runtimeId !== "string" ||
    !EXTENSION_ID_PATTERN.test(options.runtimeId)
  ) {
    throw new ApprovalWindowStateError("runtime extension id is malformed");
  }
  const approvals = requireOwner(options.approvals);
  if (!(options.ready instanceof Promise)) {
    throw new ApprovalWindowStateError("ready must be a Promise");
  }
  if (typeof options.onFatal !== "function") {
    throw new ApprovalWindowStateError("onFatal must be a function");
  }
  const ready = options.ready;
  const runtimeId = options.runtimeId;
  const reportFatal = options.onFatal;
  const requests = new Map<string, WindowEntry>();
  const windowIds = new Map<number, WindowEntry>();
  let disposed = false;
  const disposedOutcome = Object.freeze({ kind: "disposed" as const });
  let resolveDisposed!: (value: typeof disposedOutcome) => void;
  const disposedPromise = new Promise<typeof disposedOutcome>((resolve) => {
    resolveDisposed = resolve;
  });

  const waitWhileLive = async <T>(operation: Promise<T>): Promise<T> => {
    const outcome = await Promise.race([
      operation.then((value) => ({ kind: "value" as const, value })),
      disposedPromise,
    ]);
    if (outcome.kind === "disposed") {
      throw new ApprovalWindowStateError("approval window owner is disposed");
    }
    return outcome.value;
  };

  const snapshotPending = async (
    requestId: string,
    phase: "before" | "after",
  ): Promise<boolean> => {
    let returned: ApprovalRecord | null | undefined;
    let snapshot: ApprovalRecord | undefined;
    try {
      returned = await waitWhileLive(approvals.read(requestId));
      if (returned === null) return false;
      snapshot = snapshotApprovalRecord(returned);
      if (snapshot.id !== requestId) {
        throw new ApprovalWindowStateError(
          `approval owner returned the wrong request during ${phase}-launch read`,
        );
      }
      return snapshot.state === "pending";
    } finally {
      clearRecord(snapshot);
      clearRecord(returned);
    }
  };

  const cancelDurably = async (requestId: string): Promise<void> => {
    let returned: ApprovalRecord | undefined;
    let snapshot: ApprovalRecord | undefined;
    let cancelError: unknown;
    try {
      returned = await waitWhileLive(approvals.cancel(requestId));
      snapshot = snapshotApprovalRecord(returned);
      if (snapshot.id !== requestId || snapshot.state !== "cancelled") {
        throw new ApprovalWindowStateError(
          "approval owner returned a non-cancelled transition",
        );
      }
      return;
    } catch (error) {
      if (disposed) return;
      cancelError = error;
    } finally {
      clearRecord(snapshot);
      clearRecord(returned);
    }

    let current: ApprovalRecord | null | undefined;
    let currentSnapshot: ApprovalRecord | undefined;
    try {
      current = await waitWhileLive(approvals.read(requestId));
      if (current === null) return;
      currentSnapshot = snapshotApprovalRecord(current);
      if (currentSnapshot.id !== requestId) {
        throw new ApprovalWindowStateError(
          "approval owner returned the wrong request after cancellation failure",
        );
      }
    } catch (readError) {
      if (disposed) return;
      throw new AggregateError(
        [cancelError, readError],
        "approval cancellation and terminal-state read both failed",
      );
    } finally {
      clearRecord(currentSnapshot);
      clearRecord(current);
    }
    if (currentSnapshot !== undefined && currentSnapshot.state !== "pending") return;
    throw cancelError;
  };

  const removeWindow = async (windowId: number): Promise<void> => {
    await windows.remove(windowId);
  };

  const closeEntry = (
    entry: WindowEntry,
    removeOwnedWindow: boolean,
    cancelApproval: boolean,
  ): Promise<void> => {
    if (entry.closePromise !== undefined) return entry.closePromise;
    entry.closed = true;
    entry.signal.removeEventListener("abort", entry.onAbort);
    if (
      entry.windowId !== undefined &&
      windowIds.get(entry.windowId) === entry
    ) {
      windowIds.delete(entry.windowId);
    }
    const ownedWindowId = entry.windowId;
    entry.closePromise = (async () => {
      const errors: unknown[] = [];
      if (removeOwnedWindow && ownedWindowId !== undefined) {
        try {
          await waitWhileLive(removeWindow(ownedWindowId));
        } catch (error) {
          errors.push(error);
        }
      }
      if (cancelApproval) {
        try {
          await waitWhileLive(ready.then(() => undefined));
          if (!disposed) await cancelDurably(entry.requestId);
        } catch (error) {
          if (!disposed) errors.push(error);
        }
      }
      if (errors.length === 1) throw errors[0];
      if (errors.length > 1) {
        throw new AggregateError(errors, "approval window cleanup failed");
      }
    })().finally(() => {
      if (requests.get(entry.requestId) === entry) requests.delete(entry.requestId);
    });
    return entry.closePromise;
  };

  const onWindowRemoved = (windowIdValue: number): void => {
    if (disposed || !Number.isSafeInteger(windowIdValue) || windowIdValue < 0) return;
    const entry = windowIds.get(windowIdValue);
    if (entry === undefined) return;
    windowIds.delete(windowIdValue);
    void closeEntry(entry, false, true).catch((error: unknown) => {
      if (!disposed) safeReportFatal(reportFatal, error);
    });
  };

  try {
    windows.onRemoved.addListener(onWindowRemoved);
  } catch (error) {
    try {
      windows.onRemoved.removeListener(onWindowRemoved);
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        "approval window listener registration and cleanup both failed",
      );
    }
    throw error;
  }

  const launch = async (requestIdValue: string, signalValue: AbortSignal): Promise<void> => {
    if (disposed) {
      throw new ApprovalWindowStateError("approval window owner is disposed");
    }
    let requestId: string;
    try {
      requestId = parseApprovalRequestId(requestIdValue);
    } catch (error) {
      throw new ApprovalWindowStateError("request id is malformed", { cause: error });
    }
    const signal = requireAbortSignal(signalValue);
    if (requests.has(requestId)) {
      throw new ApprovalWindowStateError(
        "background already owns an approval window for this request",
      );
    }
    if (requests.size >= MAX_ACTIVE_APPROVAL_WINDOWS) {
      throw new ApprovalWindowStateError("approval window capacity exhausted");
    }

    let entry!: WindowEntry;
    const onAbort = (): void => {
      void closeEntry(entry, true, true).catch((error: unknown) => {
        if (!disposed) safeReportFatal(reportFatal, error);
      });
    };
    entry = {
      requestId,
      signal,
      onAbort,
      windowId: undefined,
      closed: false,
      closePromise: undefined,
    };
    requests.set(requestId, entry);
    signal.addEventListener("abort", onAbort, { once: true });

    let readySettled = false;
    let nonPendingWasProven = false;
    let primaryError: unknown;
    try {
      if (signal.aborted) {
        throw new ApprovalWindowStateError("approval request lifetime ended");
      }
      await waitWhileLive(ready.then(() => undefined));
      readySettled = true;
      if (disposed) {
        throw new ApprovalWindowStateError("approval window owner is disposed");
      }
      if (entry.closed || signal.aborted) {
        throw new ApprovalWindowStateError("approval request lifetime ended");
      }

      const initiallyPending = await snapshotPending(requestId, "before");
      if (!initiallyPending) {
        nonPendingWasProven = true;
        throw new ApprovalWindowStateError("pending approval is unavailable");
      }
      if (disposed) {
        throw new ApprovalWindowStateError("approval window owner is disposed");
      }
      if (entry.closed || signal.aborted) {
        throw new ApprovalWindowStateError("approval request lifetime ended");
      }

      let creation: Promise<ApprovalChromeWindow | undefined>;
      try {
        creation = Promise.resolve(windows.create({
          url: `chrome-extension://${runtimeId}/approval.html?request=${requestId}`,
          type: "popup",
          focused: true,
          width: APPROVAL_WINDOW_WIDTH,
          height: APPROVAL_WINDOW_HEIGHT,
          setSelfAsOpener: false,
        }));
      } catch (error) {
        throw new ApprovalWindowStateError("chrome.windows.create failed", {
          cause: error,
        });
      }
      let created: ApprovalChromeWindow | undefined;
      try {
        created = await waitWhileLive(creation);
      } catch (error) {
        if (disposed) {
          void creation.then(async (lateWindow) => {
            let lateWindowId: number;
            try {
              lateWindowId = requireWindowId(
                lateWindow?.id,
                "late chrome.windows.create",
              );
            } catch {
              return;
            }
            try {
              await removeWindow(lateWindowId);
            } catch {
              // The owner is gone; next startup invalidation owns durability.
            }
          }, () => undefined);
          throw error;
        }
        throw new ApprovalWindowStateError("chrome.windows.create failed", {
          cause: error,
        });
      }
      const windowId = requireWindowId(created?.id, "chrome.windows.create");

      if (disposed || entry.closed || signal.aborted) {
        try {
          await removeWindow(windowId);
        } catch (removeError) {
          if (!disposed) safeReportFatal(reportFatal, removeError);
        }
        throw new ApprovalWindowStateError(
          disposed
            ? "approval window owner is disposed"
            : "approval request lifetime ended",
        );
      }
      const existing = windowIds.get(windowId);
      if (existing !== undefined) {
        try {
          await removeWindow(windowId);
        } catch {
          // Both records are cancelled below; raw window-id reuse is never trusted.
        }
        void closeEntry(existing, false, true).catch((error: unknown) => {
          if (!disposed) safeReportFatal(reportFatal, error);
        });
        throw new ApprovalWindowStateError(
          "chrome.windows.create reused an active window id",
        );
      }
      entry.windowId = windowId;
      windowIds.set(windowId, entry);

      try {
        const observed = await waitWhileLive(windows.get(windowId));
        const observedId = requireWindowId(observed.id, "chrome.windows.get");
        if (observedId !== windowId) {
          throw new ApprovalWindowStateError(
            "chrome.windows.get returned the wrong window",
          );
        }
      } catch (error) {
        throw new ApprovalWindowStateError(
          "approval window disappeared during launch",
          { cause: error },
        );
      }
      if (disposed) {
        throw new ApprovalWindowStateError("approval window owner is disposed");
      }
      if (entry.closed || signal.aborted) {
        throw new ApprovalWindowStateError("approval request lifetime ended");
      }

      const stillPending = await snapshotPending(requestId, "after");
      if (!stillPending) {
        nonPendingWasProven = true;
        throw new ApprovalWindowStateError(
          "approval stopped being pending during launch",
        );
      }
      if (disposed) {
        throw new ApprovalWindowStateError("approval window owner is disposed");
      }
      if (entry.closed || signal.aborted) {
        throw new ApprovalWindowStateError("approval request lifetime ended");
      }
      return;
    } catch (error) {
      primaryError = error;
    }

    let cleanupError: unknown;
    if (entry.closePromise !== undefined) {
      try {
        await entry.closePromise;
      } catch (error) {
        cleanupError = error;
      }
    } else if (disposed) {
      entry.closed = true;
      entry.signal.removeEventListener("abort", entry.onAbort);
      if (requests.get(requestId) === entry) requests.delete(requestId);
      if (
        entry.windowId !== undefined &&
        windowIds.get(entry.windowId) === entry
      ) {
        windowIds.delete(entry.windowId);
      }
    } else {
      const cancelApproval = !nonPendingWasProven && (
        signal.aborted || readySettled
      );
      try {
        await closeEntry(entry, true, cancelApproval);
      } catch (error) {
        cleanupError = error;
        safeReportFatal(reportFatal, error);
      }
    }
    throw combineFailure(
      primaryError,
      cleanupError,
      "approval window launch and cleanup both failed",
    );
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    resolveDisposed(disposedOutcome);
    const cleanupErrors: unknown[] = [];
    try {
      windows.onRemoved.removeListener(onWindowRemoved);
    } catch (error) {
      cleanupErrors.push(error);
    }
    const entries = [...requests.values()];
    requests.clear();
    windowIds.clear();
    for (const entry of entries) {
      entry.closed = true;
      entry.signal.removeEventListener("abort", entry.onAbort);
      if (entry.windowId === undefined) continue;
      try {
        void Promise.resolve(windows.remove(entry.windowId)).catch(() => undefined);
      } catch (error) {
        // Startup invalidation, not teardown-time repository work, owns safety.
        cleanupErrors.push(error);
      }
    }
    if (cleanupErrors.length === 1) throw cleanupErrors[0];
    if (cleanupErrors.length > 1) {
      throw new AggregateError(cleanupErrors, "approval window teardown failed");
    }
  };

  return Object.freeze({ launch, dispose });
}
