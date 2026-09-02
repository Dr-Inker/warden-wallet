import { describe, expect, it } from "vitest";

import {
  APPROVAL_ARM_DWELL_MS,
  ApprovalArmGuard,
} from "../src/approval/approval-arm.js";

const T0 = 10_000;
const DWELL = APPROVAL_ARM_DWELL_MS;

/** Focused, review rendered, one trusted move: the minimal arming precondition. */
function armed(reviewAt = T0): { guard: ApprovalArmGuard; armAt: number } {
  const guard = new ApprovalArmGuard();
  guard.noteFocus(reviewAt - 10);
  guard.noteReviewVisible(reviewAt);
  guard.notePointerMove(reviewAt + 5, true);
  return { guard, armAt: reviewAt - 10 + DWELL };
}

describe("approval arming dwell (audit A-1: click-race / clickjacking)", () => {
  it("keeps the dwell inside the reviewed 500-700 ms band", () => {
    expect(APPROVAL_ARM_DWELL_MS).toBeGreaterThanOrEqual(500);
    expect(APPROVAL_ARM_DWELL_MS).toBeLessThanOrEqual(700);
  });

  it("never arms before the review response lands", () => {
    const guard = new ApprovalArmGuard();
    guard.noteFocus(T0);
    guard.notePointerMove(T0 + 5, true);
    expect(guard.isArmed(T0 + DWELL * 10)).toBe(false);
    expect(guard.armedAt()).toBeUndefined();
  });

  it("never arms without focus, however long the page waits", () => {
    const guard = new ApprovalArmGuard();
    guard.noteReviewVisible(T0);
    guard.notePointerMove(T0 + 5, true);
    expect(guard.isArmed(T0 + DWELL * 10)).toBe(false);
  });

  it("arms only once an uninterrupted focus dwell and one trusted pointer move are both complete", () => {
    const { guard, armAt } = armed();
    expect(guard.isArmed(armAt - 1)).toBe(false);
    expect(guard.isArmed(armAt)).toBe(true);
    expect(guard.armedAt()).toBe(armAt);
  });

  it("does not accept an untrusted pointer move as the required human motion", () => {
    const guard = new ApprovalArmGuard();
    guard.noteFocus(T0);
    guard.noteReviewVisible(T0);
    guard.notePointerMove(T0 + 5, false);
    expect(guard.isArmed(T0 + DWELL * 10)).toBe(false);
    guard.notePointerMove(T0 + 10, true);
    expect(guard.isArmed(T0 + DWELL * 10)).toBe(true);
  });

  it("does not count a pointer move that happened before the review response", () => {
    const guard = new ApprovalArmGuard();
    guard.noteFocus(T0);
    guard.notePointerMove(T0 + 5, true);
    guard.noteReviewVisible(T0 + 10);
    expect(guard.isArmed(T0 + DWELL * 10)).toBe(false);
  });

  it("arms no earlier than the trusted pointer move when the move is the last condition", () => {
    const guard = new ApprovalArmGuard();
    guard.noteFocus(T0);
    guard.noteReviewVisible(T0);
    const moveAt = T0 + DWELL + 250;
    guard.notePointerMove(moveAt, true);
    expect(guard.armedAt()).toBe(moveAt);
    expect(guard.isArmed(moveAt - 1)).toBe(false);
    expect(guard.isArmed(moveAt)).toBe(true);
  });

  it("restarts the whole dwell on focus loss and requires a fresh pointer move", () => {
    const { guard, armAt } = armed();
    expect(guard.isArmed(armAt)).toBe(true);
    guard.noteFocusLoss(armAt + 1);
    expect(guard.isArmed(armAt + 2)).toBe(false);
    const refocusAt = armAt + 100;
    guard.noteFocus(refocusAt);
    // The dwell restarts AND the pre-loss pointer move no longer counts.
    expect(guard.isArmed(refocusAt + DWELL)).toBe(false);
    guard.notePointerMove(refocusAt + 5, true);
    expect(guard.isArmed(refocusAt + DWELL - 1)).toBe(false);
    expect(guard.isArmed(refocusAt + DWELL)).toBe(true);
  });

  it("restarts the dwell when the document is hidden mid-dwell", () => {
    const guard = new ApprovalArmGuard();
    guard.noteFocus(T0);
    guard.noteReviewVisible(T0);
    guard.notePointerMove(T0 + 5, true);
    guard.noteVisibilityLoss(T0 + 100);
    expect(guard.isArmed(T0 + DWELL)).toBe(false);
    guard.noteFocus(T0 + 200);
    guard.notePointerMove(T0 + 205, true);
    expect(guard.isArmed(T0 + 200 + DWELL - 1)).toBe(false);
    expect(guard.isArmed(T0 + 200 + DWELL)).toBe(true);
  });

  it("accepts a trusted click whose pointerdown and pointerup both follow the arm time", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt + 5, true);
    guard.notePointerUp(armAt + 9, true);
    expect(guard.acceptsActivation(armAt + 10, true)).toBe(true);
  });

  it("refuses an untrusted click even with a fully armed control", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt + 5, true);
    guard.notePointerUp(armAt + 9, true);
    expect(guard.acceptsActivation(armAt + 10, false)).toBe(false);
  });

  it("refuses a click with no pointer or key activation behind it", () => {
    const { guard, armAt } = armed();
    expect(guard.acceptsActivation(armAt + 10, true)).toBe(false);
  });

  it("refuses a click whose pointerdown was primed before the arm time", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt - 5, true);
    guard.notePointerUp(armAt + 5, true);
    expect(guard.acceptsActivation(armAt + 10, true)).toBe(false);
  });

  it("does not record an untrusted pointerdown or pointerup as activation evidence", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt + 5, false);
    guard.notePointerUp(armAt + 9, false);
    expect(guard.acceptsActivation(armAt + 10, true)).toBe(false);
  });

  it("refuses a pointer pair whose up precedes its down", () => {
    const { guard, armAt } = armed();
    guard.notePointerUp(armAt + 9, true);
    guard.notePointerDown(armAt + 12, true);
    expect(guard.acceptsActivation(armAt + 13, true)).toBe(false);
  });

  it("accepts a trusted Enter or Space activation only after the arm time", () => {
    for (const key of ["Enter", " "]) {
      const { guard, armAt } = armed();
      guard.noteKeyActivation(armAt - 1, true, key);
      expect(guard.acceptsActivation(armAt + 1, true)).toBe(false);
      guard.noteKeyActivation(armAt + 2, true, key);
      expect(guard.acceptsActivation(armAt + 3, true)).toBe(true);
    }
  });

  it("refuses an untrusted or non-activation key", () => {
    const { guard, armAt } = armed();
    guard.noteKeyActivation(armAt + 2, false, "Enter");
    expect(guard.acceptsActivation(armAt + 3, true)).toBe(false);
    guard.noteKeyActivation(armAt + 4, true, "a");
    expect(guard.acceptsActivation(armAt + 5, true)).toBe(false);
  });

  it("refuses an already-evidenced click when focus is lost before it arrives", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt + 5, true);
    guard.notePointerUp(armAt + 9, true);
    guard.noteFocusLoss(armAt + 10);
    expect(guard.acceptsActivation(armAt + 11, true)).toBe(false);
  });

  it("reports the remaining dwell so the page can re-check without polling", () => {
    const { guard, armAt } = armed();
    expect(guard.msUntilArmed(armAt - 120)).toBe(120);
    expect(guard.msUntilArmed(armAt)).toBe(0);
    const blocked = new ApprovalArmGuard();
    blocked.noteFocus(T0);
    blocked.noteReviewVisible(T0);
    // No trusted pointer move yet: arming is not merely pending on time.
    expect(blocked.msUntilArmed(T0 + DWELL * 10)).toBeUndefined();
  });

  it("stays closed on a non-finite timestamp from any source", () => {
    const { guard, armAt } = armed();
    guard.notePointerDown(armAt + 5, true);
    guard.notePointerUp(armAt + 9, true);
    expect(guard.acceptsActivation(Number.NaN, true)).toBe(false);

    const broken = new ApprovalArmGuard();
    broken.noteFocus(Number.NaN);
    broken.noteReviewVisible(T0);
    broken.notePointerMove(T0 + 5, true);
    expect(broken.isArmed(T0 + DWELL * 10)).toBe(false);

    const brokenMove = new ApprovalArmGuard();
    brokenMove.noteFocus(T0);
    brokenMove.noteReviewVisible(T0);
    brokenMove.notePointerMove(Number.POSITIVE_INFINITY, true);
    expect(brokenMove.isArmed(T0 + DWELL * 10)).toBe(false);
  });
});
