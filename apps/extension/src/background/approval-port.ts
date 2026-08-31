import {
  snapshotApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";

import {
  APPROVAL_UI_PORT_NAME,
  createApprovalRejectedResponse,
  createApprovalReviewResponse,
  createApprovalUnavailableResponse,
  parseApprovalUiRequest,
  type ApprovalReviewDetails,
} from "../approval-protocol.js";
import {
  classifyApprovalUiSender,
  type ApprovalUiProvenance,
} from "./sender-provenance.js";
import type {
  ProviderRuntimeApi,
  ProviderRuntimePort,
} from "./provider-port.js";

export const MAX_ACTIVE_APPROVAL_UI_PORTS = 16;
const EXTENSION_ID_PATTERN = /^[a-p]{32}$/;

export interface ApprovalReviewOwner {
  read(id: string): Promise<ApprovalRecord | null>;
  reject(id: string): Promise<ApprovalRecord>;
  cancel(id: string): Promise<ApprovalRecord>;
}

export interface ApprovalReviewBoundaryOptions {
  readonly approvals: ApprovalReviewOwner;
  readonly ready: Promise<unknown>;
  readonly projectReview: (record: ApprovalRecord) => ApprovalReviewDetails;
  readonly onFatal: (error: unknown) => void;
}

export interface ApprovalReviewBoundary {
  dispose(): void;
}

export class ApprovalReviewPortStateError extends Error {
  constructor(message: string) {
    super(`approval review port: ${message}`);
    this.name = "ApprovalReviewPortStateError";
  }
}

function requireListenerEvent(
  value: unknown,
  name: string,
): asserts value is { addListener(listener: never): void; removeListener(listener: never): void } {
  if (
    typeof value !== "object" ||
    value === null ||
    typeof (value as { readonly addListener?: unknown }).addListener !== "function" ||
    typeof (value as { readonly removeListener?: unknown }).removeListener !== "function"
  ) {
    throw new ApprovalReviewPortStateError(`${name} listener event is unavailable`);
  }
}

function requirePort(value: unknown): ProviderRuntimePort {
  if (typeof value !== "object" || value === null) {
    throw new ApprovalReviewPortStateError("runtime Port is malformed");
  }
  const port = value as Partial<ProviderRuntimePort>;
  if (
    typeof port.name !== "string" ||
    typeof port.postMessage !== "function" ||
    typeof port.disconnect !== "function"
  ) {
    throw new ApprovalReviewPortStateError("runtime Port is malformed");
  }
  requireListenerEvent(port.onMessage, "Port.onMessage");
  requireListenerEvent(port.onDisconnect, "Port.onDisconnect");
  return port as ProviderRuntimePort;
}

function requireOwner(value: unknown): ApprovalReviewOwner {
  if (typeof value !== "object" || value === null) {
    throw new ApprovalReviewPortStateError("approval owner must be an object");
  }
  const owner = value as Partial<ApprovalReviewOwner>;
  for (const method of ["read", "reject", "cancel"] as const) {
    if (typeof owner[method] !== "function") {
      throw new ApprovalReviewPortStateError(`approval owner must provide ${method}()`);
    }
  }
  return value as ApprovalReviewOwner;
}

function safeDisconnect(port: ProviderRuntimePort): void {
  try {
    port.disconnect();
  } catch {
    // A disappearing or already-rejected Port is closed.
  }
}

function safeReportFatal(report: (error: unknown) => void, error: unknown): void {
  try {
    report(error);
  } catch {
    // The runtime fatal owner is authoritative; a throwing observer cannot
    // reopen a Port or make a failed durable cancellation safe.
  }
}

function snapshotTerminal(
  value: ApprovalRecord,
  id: string,
  expectedState: "rejected" | "cancelled",
): ApprovalRecord {
  const record = snapshotApprovalRecord(value);
  if (record.id !== id || record.state !== expectedState) {
    record.account.fill(0);
    record.genesisHash.fill(0);
    record.programId.fill(0);
    record.rawMessage.fill(0);
    record.messageDigest.fill(0);
    throw new ApprovalReviewPortStateError(
      `approval owner returned a non-${expectedState} transition`,
    );
  }
  return record;
}

function clearRecord(record: ApprovalRecord | null | undefined): void {
  record?.account.fill(0);
  record?.genesisHash.fill(0);
  record?.programId.fill(0);
  record?.rawMessage.fill(0);
  record?.messageDigest.fill(0);
}

/**
 * Install the only runtime route reachable from `approval.html`.
 *
 * The route can read one URL-bound pending record, emit one primitive review,
 * and durably reject or cancel it. It has no approval claim, keyring, signer,
 * provider response, RPC, account enumeration, or record-creation dependency.
 */
export function installApprovalReviewBoundary(
  runtime: ProviderRuntimeApi,
  options: ApprovalReviewBoundaryOptions,
): ApprovalReviewBoundary {
  if (
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.id !== "string" ||
    !EXTENSION_ID_PATTERN.test(runtime.id)
  ) {
    throw new ApprovalReviewPortStateError("runtime extension id is malformed");
  }
  requireListenerEvent(runtime.onConnect, "runtime.onConnect");
  if (typeof options !== "object" || options === null) {
    throw new ApprovalReviewPortStateError("options must be an object");
  }
  const approvals = requireOwner(options.approvals);
  if (!(options.ready instanceof Promise)) {
    throw new ApprovalReviewPortStateError("ready must be a Promise");
  }
  if (typeof options.projectReview !== "function") {
    throw new ApprovalReviewPortStateError("projectReview must be a function");
  }
  if (typeof options.onFatal !== "function") {
    throw new ApprovalReviewPortStateError("onFatal must be a function");
  }
  const ready = options.ready;
  const projectReview = options.projectReview;
  const reportFatal = options.onFatal;

  let disposed = false;
  const active = new Set<(disconnectPort: boolean, cancel: boolean) => void>();
  const activeRequests = new Map<
    string,
    (disconnectPort: boolean, cancel: boolean) => void
  >();
  const activeDocuments = new Map<
    string,
    (disconnectPort: boolean, cancel: boolean) => void
  >();

  const onConnect = (rawPort: ProviderRuntimePort): void => {
    let port: ProviderRuntimePort;
    try {
      port = requirePort(rawPort);
    } catch {
      return;
    }
    if (disposed || port.name !== APPROVAL_UI_PORT_NAME) {
      safeDisconnect(port);
      return;
    }

    let provenance: ApprovalUiProvenance;
    try {
      provenance = classifyApprovalUiSender({
        runtimeId: runtime.id,
        sender: port.sender,
      });
    } catch {
      safeDisconnect(port);
      return;
    }
    if (
      activeRequests.has(provenance.requestId) ||
      activeDocuments.has(provenance.documentId) ||
      active.size >= MAX_ACTIVE_APPROVAL_UI_PORTS
    ) {
      safeDisconnect(port);
      return;
    }

    let open = true;
    let busy = false;
    let phase: "awaiting-review" | "review-visible" | "terminal" =
      "awaiting-review";
    let cancellationStarted = false;
    const correlations = new Set<string>();

    const cancelDurably = (): void => {
      if (cancellationStarted || phase === "terminal") return;
      cancellationStarted = true;
      void (async () => {
        try {
          await ready;
        } catch {
          // Startup failure already closes the entire runtime surface. Do not
          // treat an unavailable repository as a second cancellation verdict.
          return;
        }
        if (disposed) return;
        try {
          const cancelled = snapshotTerminal(
            await approvals.cancel(provenance.requestId),
            provenance.requestId,
            "cancelled",
          );
          clearRecord(cancelled);
          phase = "terminal";
          return;
        } catch (cancelError) {
          if (disposed) {
            // Parent teardown has removed every route and will close the owner;
            // the next startup invalidation, not a late repository read, owns
            // this record now.
            return;
          }
          let current: ApprovalRecord | null | undefined;
          try {
            current = await approvals.read(provenance.requestId);
            if (current === null || current.state !== "pending") {
              phase = "terminal";
              return;
            }
          } catch (readError) {
            safeReportFatal(
              reportFatal,
              new AggregateError(
                [cancelError, readError],
                "approval cancellation and terminal-state read both failed",
              ),
            );
            return;
          } finally {
            clearRecord(current);
          }
          safeReportFatal(reportFatal, cancelError);
        }
      })();
    };

    const close = (disconnectPort: boolean, cancel: boolean): void => {
      if (!open) return;
      open = false;
      active.delete(close);
      if (activeRequests.get(provenance.requestId) === close) {
        activeRequests.delete(provenance.requestId);
      }
      if (activeDocuments.get(provenance.documentId) === close) {
        activeDocuments.delete(provenance.documentId);
      }
      correlations.clear();
      try {
        port.onMessage.removeListener(onMessage);
      } catch {
        // The open flag is authoritative; listener cleanup is best effort.
      }
      try {
        port.onDisconnect.removeListener(onDisconnect);
      } catch {
        // The open flag is authoritative; listener cleanup is best effort.
      }
      if (cancel) cancelDurably();
      if (disconnectPort) safeDisconnect(port);
    };

    const postUnavailableAndClose = (correlationId: string, cancel: boolean): void => {
      if (!open) return;
      try {
        port.postMessage(createApprovalUnavailableResponse(correlationId));
      } catch {
        // Closing and durable cancellation remain the authority.
      }
      close(true, cancel);
    };

    const handleReview = async (correlationId: string): Promise<void> => {
      let current: ApprovalRecord | null | undefined;
      try {
        await ready;
        current = await approvals.read(provenance.requestId);
        if (!open) return;
        if (current === null || current.state !== "pending") {
          phase = "terminal";
          postUnavailableAndClose(correlationId, false);
          return;
        }
        const projected = projectReview(current);
        const response = createApprovalReviewResponse(correlationId, projected);
        if (response.result.requestId !== provenance.requestId) {
          throw new ApprovalReviewPortStateError(
            "review projection changed the URL-bound request id",
          );
        }
        port.postMessage(response);
        phase = "review-visible";
        busy = false;
      } catch {
        if (open) postUnavailableAndClose(correlationId, true);
      } finally {
        clearRecord(current);
      }
    };

    const handleReject = async (correlationId: string): Promise<void> => {
      let terminal: ApprovalRecord | null | undefined;
      try {
        // Reaching review-visible proves handleReview already crossed the one
        // startup gate. Do not insert another microtask before the durable CAS:
        // an immediate page teardown may otherwise win cancellation even after
        // the user's explicit rejection click.
        terminal = snapshotTerminal(
          await approvals.reject(provenance.requestId),
          provenance.requestId,
          "rejected",
        );
        phase = "terminal";
        if (!open) return;
        port.postMessage(
          createApprovalRejectedResponse(correlationId, provenance.requestId),
        );
        busy = false;
      } catch {
        if (!open) return;
        let current: ApprovalRecord | null | undefined;
        try {
          current = await approvals.read(provenance.requestId);
          if (current === null || current.state !== "pending") {
            phase = "terminal";
            if (open) postUnavailableAndClose(correlationId, false);
            return;
          }
        } catch {
          // Durable cancellation below is the fail-closed fallback.
        } finally {
          clearRecord(current);
        }
        if (open) postUnavailableAndClose(correlationId, true);
      } finally {
        clearRecord(terminal);
      }
    };

    const onMessage = (message: unknown): void => {
      if (!open) return;
      if (busy || phase === "terminal") {
        close(true, true);
        return;
      }
      let request;
      try {
        request = parseApprovalUiRequest(message);
      } catch {
        close(true, true);
        return;
      }
      if (
        request.params.requestId !== provenance.requestId ||
        correlations.has(request.correlationId)
      ) {
        close(true, true);
        return;
      }
      correlations.add(request.correlationId);
      if (phase === "awaiting-review" && request.method === "approval:getReview") {
        busy = true;
        void handleReview(request.correlationId);
        return;
      }
      if (phase === "review-visible" && request.method === "approval:reject") {
        busy = true;
        void handleReject(request.correlationId);
        return;
      }
      close(true, true);
    };

    const onDisconnect = (): void => close(false, true);

    try {
      port.onDisconnect.addListener(onDisconnect);
      port.onMessage.addListener(onMessage);
      active.add(close);
      activeRequests.set(provenance.requestId, close);
      activeDocuments.set(provenance.documentId, close);
    } catch {
      close(true, true);
    }
  };

  runtime.onConnect.addListener(onConnect);

  return Object.freeze({
    dispose(): void {
      if (disposed) return;
      disposed = true;
      try {
        runtime.onConnect.removeListener(onConnect);
      } finally {
        // The parent closes the repository immediately after disposing this
        // synchronous boundary, so starting an unawaited cancellation here
        // would race a closed owner and could falsely report a fatal. Ports are
        // made unreachable now; the mandatory next-start invalidation owns any
        // abandoned pending record. Ordinary document disconnects still cancel.
        for (const close of [...active]) close(true, false);
      }
    },
  });
}
