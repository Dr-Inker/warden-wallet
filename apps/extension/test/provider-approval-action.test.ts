import { describe, expect, it } from "vitest";

import {
  MAX_ACTIVE_PROVIDER_APPROVAL_ACTIONS,
  ProviderApprovalActionOwner,
  ProviderApprovalActionStateError,
  type ProviderApprovalActionRegistration,
} from "../src/background/provider-approval-action.js";

const APPROVAL_ID = `req_${"ab".repeat(16)}`;
const DIGEST = new Uint8Array(32).fill(0x11);

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolveValue, rejectValue) => {
    resolve = resolveValue;
    reject = rejectValue;
  });
  return { promise, resolve, reject };
}

function registration(
  overrides: Partial<ProviderApprovalActionRegistration> = {},
): ProviderApprovalActionRegistration & {
  readonly controller: AbortController;
  readonly events: string[];
} {
  const controller = new AbortController();
  const events: string[] = [];
  return {
    id: APPROVAL_ID,
    messageDigest: DIGEST.slice(),
    signal: controller.signal,
    async approve(): Promise<boolean> {
      events.push("approve");
      return true;
    },
    async settle(): Promise<boolean> {
      events.push("settle");
      return true;
    },
    controller,
    events,
    ...overrides,
  };
}

describe("provider approval action ownership", () => {
  it("copy-binds one exact digest and shares one approval attempt until settlement", async () => {
    const owner = new ProviderApprovalActionOwner();
    const action = registration();
    owner.register(action);
    action.messageDigest.fill(0xff);

    expect(owner.activeCount).toBe(1);
    expect(owner.canApprove(APPROVAL_ID, DIGEST)).toBe(true);
    expect(owner.canApprove(APPROVAL_ID, new Uint8Array(32).fill(0x12))).toBe(false);

    const first = owner.approve(APPROVAL_ID);
    const concurrent = owner.approve(APPROVAL_ID);
    expect(concurrent).toBe(first);
    await expect(first).resolves.toBe(true);
    expect(action.events).toEqual(["approve"]);
    expect(owner.activeCount).toBe(1);
    expect(owner.canApprove(APPROVAL_ID, DIGEST)).toBe(false);

    const firstSettlement = owner.settle(APPROVAL_ID);
    const concurrentSettlement = owner.settle(APPROVAL_ID);
    expect(concurrentSettlement).toBe(firstSettlement);
    await expect(firstSettlement).resolves.toBe(true);
    expect(action.events).toEqual(["approve", "settle"]);
    expect(owner.activeCount).toBe(0);
    await expect(owner.settle(APPROVAL_ID)).resolves.toBe(false);
  });

  it("suppresses a late approval result after the provider lifetime aborts", async () => {
    const owner = new ProviderApprovalActionOwner();
    const gate = deferred<boolean>();
    const action = registration({ approve: () => gate.promise });
    owner.register(action);

    const approving = owner.approve(APPROVAL_ID);
    action.controller.abort();
    expect(owner.activeCount).toBe(0);
    gate.resolve(true);

    await expect(approving).rejects.toThrow("lifetime ended during approval");
    await expect(owner.settle(APPROVAL_ID)).resolves.toBe(false);
  });

  it("rejects a false capability verdict without inventing signed success", async () => {
    const owner = new ProviderApprovalActionOwner();
    const action = registration({ approve: async () => false });
    owner.register(action);

    await expect(owner.approve(APPROVAL_ID)).rejects.toThrow(
      "approval capability returned no durable signing proof",
    );
    expect(owner.activeCount).toBe(1);
    await expect(owner.settle(APPROVAL_ID)).resolves.toBe(true);
  });

  it("reserves duplicate ids and the hard action cap before invoking a capability", () => {
    const owner = new ProviderApprovalActionOwner();
    const actions = Array.from(
      { length: 32 },
      (_, index) => registration({
        id: `req_${index.toString(16).padStart(32, "0")}`,
      }),
    );
    for (const action of actions) owner.register(action);

    expect(MAX_ACTIVE_PROVIDER_APPROVAL_ACTIONS).toBe(32);
    expect(owner.activeCount).toBe(32);
    expect(() => owner.register(actions[0]!)).toThrow("already registered");
    expect(() => owner.register(registration({
      id: `req_${"ff".repeat(16)}`,
    }))).toThrow("capacity exhausted");
    expect(actions.every((action) => action.events.length === 0)).toBe(true);
  });

  it("rolls back a partial signal-listener failure and permits the exact id again", () => {
    const owner = new ProviderApprovalActionOwner();
    let removed = 0;
    const hostileSignal = {
      aborted: false,
      addEventListener(): void {
        throw new Error("listener installation failed");
      },
      removeEventListener(): void {
        removed++;
      },
    } as unknown as AbortSignal;

    expect(() => owner.register(registration({ signal: hostileSignal }))).toThrow(
      "lifetime listener registration failed",
    );
    expect(removed).toBe(1);
    expect(owner.activeCount).toBe(0);
    expect(() => owner.register(registration())).not.toThrow();
  });

  it("does not reserve an id when a bound capability is malformed", () => {
    const owner = new ProviderApprovalActionOwner();
    const malformed = {
      ...registration(),
      approve: undefined,
    } as unknown as ProviderApprovalActionRegistration;

    expect(() => owner.register(malformed)).toThrow(
      "approval action approve must be a function",
    );
    expect(owner.activeCount).toBe(0);
    expect(() => owner.register(registration())).not.toThrow();
  });

  it("disposes synchronously, drops volatile capabilities, and refuses new work", async () => {
    const owner = new ProviderApprovalActionOwner();
    owner.register(registration());

    owner.dispose();
    expect(owner.activeCount).toBe(0);
    expect(owner.canApprove(APPROVAL_ID, DIGEST)).toBe(false);
    await expect(owner.approve(APPROVAL_ID)).rejects.toBeInstanceOf(
      ProviderApprovalActionStateError,
    );
    expect(() => owner.register(registration())).toThrow("owner is disposed");
  });
});
