import { describe, expect, it } from "vitest";

import type { OwnedProviderRequest } from "../src/background/provider-port.js";
import {
  MAX_ACTIVE_PROVIDER_SIGNED_RESULT_FLOWS,
  ProviderSignedResultFlowOwner,
  ProviderSignedResultFlowStateError,
} from "../src/background/provider-signed-result-flow.js";
import type { ProviderTerminalResponse } from "../src/background/provider-terminal-protocol.js";

const EXTENSION_ID = "a".repeat(32);

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolveValue, rejectValue) => {
    resolve = resolveValue;
    reject = rejectValue;
  });
  return { promise, resolve, reject };
}

function owned(): OwnedProviderRequest {
  return Object.freeze({
    id: `req_${"11".repeat(16)}`,
    provenance: Object.freeze({
      kind: "provider" as const,
      extensionId: EXTENSION_ID,
      documentId: "document-0123456789",
      origin: "https://dapp.example",
      tabId: 9,
      frameId: 2,
    }),
    request: Object.freeze({
      version: 1 as const,
      type: "request" as const,
      correlationId: "request_0123456789abcdef",
      method: "solana:signTransaction" as const,
      params: Object.freeze({
        requestedAccountAddress:
          "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2",
        transaction: Object.freeze([1, 2, 3]),
        chain: "solana:devnet" as const,
        options: Object.freeze({
          preflightCommitment: "confirmed" as const,
          minContextSlot: 7,
        }),
      }),
    }),
    createdAt: 1_000,
    expiresAt: 61_000,
    signal: new AbortController().signal,
  });
}

function lease(value = owned()) {
  let active = true;
  const posts: ProviderTerminalResponse[] = [];
  return {
    value,
    posts,
    lease: Object.freeze({
      owned: value,
      assertActive(): void {
        if (!active || value.signal.aborted) throw new Error("inactive request");
      },
      postMessage(message: ProviderTerminalResponse): void {
        posts.push(message);
      },
      finish(): boolean {
        if (!active) return false;
        active = false;
        return true;
      },
    }),
  };
}

describe("C18/C19 provider terminal result composition", () => {
  it("waits for byte-free durable approval proof, then delivers once through one shared Promise", async () => {
    const current = lease();
    const terminal = deferred<boolean>();
    let launches = 0;
    let deliveries = 0;
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          launches++;
          return Object.freeze({
            kind: "opened" as const,
            approval: Object.freeze({}),
            terminal: terminal.promise,
          });
        },
      },
      results: {
        async deliver(received) {
          deliveries++;
          expect(received.owned).toBe(current.value);
          return true;
        },
      },
    });

    const first = owner.deliver(current.lease);
    const repeated = owner.deliver(current.lease);
    expect(repeated).toBe(first);
    await Promise.resolve();
    expect(launches).toBe(1);
    expect(deliveries).toBe(0);

    terminal.resolve(true);
    await expect(first).resolves.toEqual({ kind: "delivered", replayed: false });
    expect(deliveries).toBe(1);
    expect(owner.activeCount).toBe(0);
  });

  it("uses C14 directly for a retained operation and never prepares another approval", async () => {
    const current = lease();
    let launches = 0;
    let deliveries = 0;
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          launches++;
          return Object.freeze({ kind: "replay-required" as const });
        },
      },
      results: {
        async deliver() {
          deliveries++;
          return true;
        },
      },
    });

    await expect(owner.deliver(current.lease)).resolves.toEqual({
      kind: "delivered",
      replayed: true,
    });
    expect(launches).toBe(1);
    expect(deliveries).toBe(1);
  });

  it("lets C19 recover only exact durable terminal state after C15 throws", async () => {
    const current = lease();
    const launchFailure = new Error("operation previously failed as worker-restarted");
    let deliveries = 0;
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          throw launchFailure;
        },
      },
      results: {
        async deliver(received) {
          deliveries++;
          expect(received.owned).toBe(current.value);
          return true;
        },
      },
    });

    await expect(owner.deliver(current.lease)).resolves.toEqual({
      kind: "delivered",
      replayed: true,
    });
    expect(deliveries).toBe(1);
  });

  it("does not translate a launch exception when durable terminal recovery is unproven", async () => {
    const current = lease();
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          throw new Error("preparation failed");
        },
      },
      results: {
        async deliver() {
          throw new Error("durable operation is absent");
        },
      },
    });

    await expect(owner.deliver(current.lease)).rejects.toThrow(
      "approval launch failed and terminal recovery is unproven",
    );
  });

  it("delegates a proven false terminal to C19 instead of guessing its outcome", async () => {
    const current = lease();
    let deliveries = 0;
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          return Object.freeze({
            kind: "opened" as const,
            approval: Object.freeze({}),
            terminal: Promise.resolve(false),
          });
        },
      },
      results: {
        async deliver() {
          deliveries++;
          return true;
        },
      },
    });

    await expect(owner.deliver(current.lease)).resolves.toEqual({
      kind: "delivered",
      replayed: false,
    });
    expect(deliveries).toBe(1);
  });

  it("rejects malformed completion and delivery proofs without guessing success", async () => {
    const current = lease();
    let malformedDeliveries = 0;
    const malformedTerminal = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          return {
            kind: "opened" as const,
            approval: Object.freeze({}),
            terminal: Promise.resolve("yes"),
          } as never;
        },
      },
      results: {
        async deliver() {
          malformedDeliveries++;
          return true;
        },
      },
    });
    await expect(malformedTerminal.deliver(current.lease)).rejects.toThrow(
      ProviderSignedResultFlowStateError,
    );
    expect(malformedDeliveries).toBe(0);

    const replay = lease(owned());
    const malformedDelivery = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          return Object.freeze({ kind: "replay-required" as const });
        },
      },
      results: { deliver: async () => false },
    });
    await expect(malformedDelivery.deliver(replay.lease)).rejects.toThrow(
      "terminal delivery returned no proof",
    );
  });

  it("caps unresolved flows at 32 exact owned requests and releases capacity after failure", async () => {
    const terminal = deferred<boolean>();
    const owner = new ProviderSignedResultFlowOwner({
      approvals: {
        async launch() {
          return Object.freeze({
            kind: "opened" as const,
            approval: Object.freeze({}),
            terminal: terminal.promise,
          });
        },
      },
      results: {
        async deliver() {
          throw new Error("false terminal must not reach delivery");
        },
      },
    });
    const active = Array.from(
      { length: MAX_ACTIVE_PROVIDER_SIGNED_RESULT_FLOWS },
      () => owner.deliver(lease(owned()).lease),
    );

    expect(owner.activeCount).toBe(32);
    await expect(owner.deliver(lease(owned()).lease)).rejects.toThrow(
      "active flow capacity exhausted",
    );

    terminal.resolve(false);
    const outcomes = await Promise.allSettled(active);
    expect(outcomes.every((outcome) => outcome.status === "rejected")).toBe(true);
    expect(owner.activeCount).toBe(0);
  });
});
