//! Audit finding X-2: per-(origin, documentId) shares beneath the global
//! approval-path caps.
//!
//! Every approval-path pool used to be a single flat global counter, so one
//! hostile http(s) origin could hold all of it and every other site received a
//! generic capacity refusal until the hostile origin's entries drained. The
//! journal made that worse: a failed row is only swept on a later `claim()`,
//! after a ten-minute retention, so the starvation outlived the attack.
//!
//! The shares below sit *beneath* the existing global caps, never above them:
//! the global cap is still checked first and still refuses with its own error,
//! and the per-origin share only ever refuses earlier. A refusal that is
//! origin-scoped is reported with a distinct error so a caller — and an
//! operator reading a report — can tell "this site has used its share" apart
//! from "the extension is globally out of room".
//!
//! The numbers are owner-tunable policy, not derived constants. They were
//! picked so that a single document cannot hold more than one approval window
//! at a time (an approval window is a modal decision; two at once from one
//! document is never a legitimate flow), and so that no single origin can hold
//! more than a quarter of any global pool — four independent hostile origins
//! are still needed to exhaust a global cap, and each of them must first pass
//! the browser's own same-origin boundary.

/** At most one open approval window per (origin, documentId). */
export const MAX_APPROVAL_WINDOWS_PER_DOCUMENT = 1;
/** Beneath MAX_ACTIVE_APPROVAL_WINDOWS (16). */
export const MAX_APPROVAL_WINDOWS_PER_ORIGIN = 4;
/** Beneath MAX_ACTIVE_PROVIDER_SIGNED_RESULT_FLOWS (32). */
export const MAX_PROVIDER_SIGNED_RESULT_FLOWS_PER_ORIGIN = 4;
/** Beneath MAX_ACTIVE_PROVIDER_APPROVAL_REQUESTS (32). */
export const MAX_PROVIDER_APPROVAL_REQUESTS_PER_ORIGIN = 4;
/** Beneath MAX_TOTAL_PROVIDER_OPERATIONS (128). */
export const MAX_PROVIDER_OPERATIONS_PER_ORIGIN = 16;

/**
 * The subject of a per-origin quota. `documentId` is `null` for a pool that is
 * shared across a whole origin rather than pinned to one document.
 */
export interface ProviderCapacityScope {
  readonly origin: string;
  readonly documentId: string | null;
}

/**
 * Marker carried by every origin-scoped refusal, including the IndexedDB
 * store's sibling class, which must extend that module's own error base and so
 * cannot extend `ProviderOriginCapacityError` directly.
 */
export interface ProviderOriginCapacityRefusal {
  readonly providerOriginCapacity: true;
  readonly origin: string;
  readonly documentId: string | null;
  readonly limit: number;
}

export class ProviderOriginCapacityError extends Error
  implements ProviderOriginCapacityRefusal {
  readonly providerOriginCapacity = true as const;
  readonly origin: string;
  readonly documentId: string | null;
  readonly limit: number;

  constructor(pool: string, scope: ProviderCapacityScope, limit: number) {
    super(providerOriginCapacityMessage(pool, scope, limit));
    this.name = "ProviderOriginCapacityError";
    this.origin = scope.origin;
    this.documentId = scope.documentId;
    this.limit = limit;
  }
}

/**
 * The refusal text never echoes anything the page chose beyond its own already
 * browser-authenticated origin and document id, and never names another site.
 */
export function providerOriginCapacityMessage(
  pool: string,
  scope: ProviderCapacityScope,
  limit: number,
): string {
  const subject = scope.documentId === null
    ? `origin ${scope.origin}`
    : `document ${scope.documentId} of origin ${scope.origin}`;
  return `provider origin capacity: ${subject} may hold at most ${limit} ${pool}`;
}

export function isProviderOriginCapacityRefusal(
  value: unknown,
): value is Error & ProviderOriginCapacityRefusal {
  return value instanceof Error &&
    (value as Partial<ProviderOriginCapacityRefusal>).providerOriginCapacity === true;
}

/**
 * Read a caller-supplied quota subject. Returns `null` only when the caller
 * supplied none — a route with no page principal, such as the privileged UI or
 * a harness. A malformed scope is a programming error and throws, because
 * silently degrading to "global cap only" is exactly the failure X-2 describes.
 */
export function readProviderCapacityScope(
  value: unknown,
  malformed: (message: string) => never,
): ProviderCapacityScope | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    malformed("capacity scope must be an object");
  }
  const scope = value as Partial<ProviderCapacityScope>;
  if (typeof scope.origin !== "string" || scope.origin.length === 0) {
    malformed("capacity scope origin must be a non-empty string");
  }
  if (
    scope.documentId !== null &&
    (typeof scope.documentId !== "string" || scope.documentId.length === 0)
  ) {
    malformed("capacity scope documentId must be a non-empty string or null");
  }
  return Object.freeze({
    origin: scope.origin,
    documentId: scope.documentId ?? null,
  });
}
