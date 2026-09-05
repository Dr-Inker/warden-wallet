/**
 * Fail-closed arming guard for the approval window's "Approve and sign" control.
 *
 * Audit finding A-1 (2026-09-02): the control was armed synchronously with the
 * review response (`approveButton.disabled = !canApprove`) and the click handler
 * accepted any `click` event. A page that primes rapid clicks or keypresses at
 * the coordinates where the fixed-size approval window appears could therefore
 * land the user's next input on the button before the user had read — or even
 * seen — the request. That is the click-race / clickjacking class.
 *
 * This module owns the decision and nothing else. It has no DOM handle, no
 * timer, and no clock of its own: every rule is expressed over timestamps the
 * caller passes in, so the whole guard is unit-testable without DOM timing.
 *
 * All timestamps MUST come from one monotonic clock. The approval page passes
 * `performance.now()`; mixing that with `Date.now()` would make the dwell
 * meaningless, and a backward wall-clock jump could arm the control early.
 *
 * Nothing here is a substitute for the background trust boundary: this guard
 * governs only when the page is willing to *send* an approve request. The
 * background still owns the record, the digest, and the single atomic winner.
 */

/**
 * Continuous-focus dwell AFTER the review is rendered, before approval arms.
 * 600 ms is the midpoint of the audit's 500-700 ms band. This is an input-race
 * mitigation, not proof the user has read or understood the request.
 */
export const APPROVAL_ARM_DWELL_MS = 600;

/** Keys the browser turns into a synthetic `click` on a focused <button>. */
const ACTIVATION_KEYS: ReadonlySet<string> = new Set(["Enter", " "]);

function finite(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export class ApprovalArmGuard {
  /** When the decoded review became visible; nothing arms before this exists. */
  #reviewAt: number | undefined;
  /** Start of the CURRENT uninterrupted focus run; cleared on any loss. */
  #focusSince: number | undefined;
  /** First trusted pointer move in the current focus run, at/after the review. */
  #pointerMoveAt: number | undefined;
  #pointerDownAt: number | undefined;
  #pointerUpAt: number | undefined;
  #keyActivationAt: number | undefined;

  /**
   * A focus or visibility loss invalidates every accumulated fact, not just the
   * dwell: the pointer move, the primed pointer pair, and a pending keyboard
   * activation all belong to a window state the user has since left. This is
   * also what makes "the last visibility/focus loss did not occur within the
   * dwell" hold by construction — the dwell can only be measured from a focus
   * gain that is itself later than the last loss.
   */
  #resetToUnfocused(): void {
    this.#focusSince = undefined;
    this.#pointerMoveAt = undefined;
    this.#pointerDownAt = undefined;
    this.#pointerUpAt = undefined;
    this.#keyActivationAt = undefined;
  }

  noteReviewVisible(at: number): void {
    const stamp = finite(at);
    if (stamp === undefined) {
      this.#reviewAt = undefined;
      return;
    }
    this.#reviewAt = stamp;
    // A pointer move that preceded the rendered review proves nothing about
    // this request; only motion after it counts.
    this.#pointerMoveAt = undefined;
    this.#pointerDownAt = undefined;
    this.#pointerUpAt = undefined;
    this.#keyActivationAt = undefined;
  }

  noteFocus(at: number): void {
    const stamp = finite(at);
    if (stamp === undefined) {
      this.#resetToUnfocused();
      return;
    }
    // A repeated focus event must not extend an already-running dwell, and must
    // not restart one either.
    if (this.#focusSince === undefined) this.#focusSince = stamp;
  }

  noteFocusLoss(at: number): void {
    void finite(at);
    this.#resetToUnfocused();
  }

  /** `document.visibilityState !== "visible"` is treated exactly like blur. */
  noteVisibilityLoss(at: number): void {
    this.noteFocusLoss(at);
  }

  notePointerMove(at: number, isTrusted: boolean): void {
    if (isTrusted !== true) return;
    const stamp = finite(at);
    if (stamp === undefined) return;
    if (this.#reviewAt === undefined || stamp < this.#reviewAt) return;
    if (this.#focusSince === undefined) return;
    if (this.#pointerMoveAt === undefined) this.#pointerMoveAt = stamp;
  }

  notePointerDown(at: number, isTrusted: boolean): void {
    if (isTrusted !== true) return;
    const stamp = finite(at);
    if (stamp === undefined) return;
    this.#pointerDownAt = stamp;
    // A new press invalidates the previous release, so a stale up can never be
    // paired with a fresh down.
    this.#pointerUpAt = undefined;
  }

  notePointerUp(at: number, isTrusted: boolean): void {
    if (isTrusted !== true) return;
    const stamp = finite(at);
    if (stamp === undefined) return;
    this.#pointerUpAt = stamp;
  }

  noteKeyActivation(at: number, isTrusted: boolean, key: string, repeat = false): void {
    if (isTrusted !== true || !ACTIVATION_KEYS.has(key)) return;
    // A held key must not turn into fresh consent when auto-repeat crosses the
    // dwell. A keyboard activation also cannot borrow a prior pointer pair.
    this.#pointerDownAt = undefined;
    this.#pointerUpAt = undefined;
    this.#keyActivationAt = undefined;
    if (repeat) return;
    const stamp = finite(at);
    if (stamp === undefined) return;
    this.#keyActivationAt = stamp;
  }

  /**
   * The instant every arming condition is (or becomes) satisfied, or `undefined`
   * when at least one condition is still outstanding regardless of elapsed time.
   */
  armedAt(): number | undefined {
    if (this.#reviewAt === undefined) return undefined;
    if (this.#focusSince === undefined) return undefined;
    if (this.#pointerMoveAt === undefined) return undefined;
    return Math.max(
      Math.max(this.#reviewAt, this.#focusSince) + APPROVAL_ARM_DWELL_MS,
      this.#pointerMoveAt,
    );
  }

  isArmed(now: number): boolean {
    const armAt = this.armedAt();
    const stamp = finite(now);
    return armAt !== undefined && stamp !== undefined && stamp >= armAt;
  }

  /**
   * Milliseconds until arming, `0` when already armed, `undefined` when arming
   * is blocked on something other than time (no review, no focus, no trusted
   * pointer move). The page uses this to schedule exactly one re-check instead
   * of polling.
   */
  msUntilArmed(now: number): number | undefined {
    const armAt = this.armedAt();
    const stamp = finite(now);
    if (armAt === undefined || stamp === undefined) return undefined;
    return Math.max(0, armAt - stamp);
  }

  /**
   * Whether a `click` may be turned into an approve request.
   *
   * Requires the event itself to be trusted, the control to be armed, and the
   * activation behind the click to be evidence the browser generated after the
   * arm time: either a complete trusted pointerdown/pointerup pair, or a trusted
   * Enter/Space keydown on the focused control. Everything else is refused
   * silently — the caller sends nothing and leaves the request pending.
   *
   * Both pointer timestamps are compared at-or-after the arm time rather than
   * strictly after it: a trusted pointermove and the pointerdown that follows it
   * can share a millisecond, and the security property is the dwell, which the
   * comparison does not touch.
   */
  acceptsActivation(now: number, isTrusted: boolean): boolean {
    if (isTrusted !== true) return false;
    if (!this.isArmed(now)) return false;
    const armAt = this.armedAt()!;
    const down = this.#pointerDownAt;
    const up = this.#pointerUpAt;
    const pointerActivated =
      down !== undefined && up !== undefined && down >= armAt && up >= armAt && up >= down;
    const keyActivated =
      this.#keyActivationAt !== undefined && this.#keyActivationAt >= armAt;
    return pointerActivated || keyActivated;
  }
}
