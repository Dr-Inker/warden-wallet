import { describe, expect, it } from "vitest";

import {
  CommittedProviderApprovalSelectionResolver,
  type CommittedProviderApprovalSelectionResolverOptions,
} from "../src/background/provider-approval-selection.js";

describe("committed provider selection with the shipped release registry", () => {
  it("refuses the empty registry before Connection, keyring, approval, or page-selector access", async () => {
    const reads = {
      releaseName: 0,
      connectionFactory: 0,
      approvals: 0,
      keyring: 0,
      readNow: 0,
      approvalTtlMs: 0,
      requestedAccountAddress: 0,
      requestedChain: 0,
    };
    const options = {
      get releaseName() {
        reads.releaseName++;
        return "mainnet-r1";
      },
      get connectionFactory() {
        reads.connectionFactory++;
        throw new Error("must not construct or inspect a Connection");
      },
      get approvals() {
        reads.approvals++;
        throw new Error("must not inspect the approval repository");
      },
      get keyring() {
        reads.keyring++;
        throw new Error("must not inspect or open the keyring");
      },
      get readNow() {
        reads.readNow++;
        throw new Error("must not inspect runtime clocks");
      },
      get approvalTtlMs() {
        reads.approvalTtlMs++;
        throw new Error("must not inspect runtime approval configuration");
      },
    } as unknown as CommittedProviderApprovalSelectionResolverOptions;
    const input = {
      method: "solana:signTransaction" as const,
      get requestedAccountAddress(): string {
        reads.requestedAccountAddress++;
        throw new Error("page account must not select a release");
      },
      get requestedChain(): "solana:devnet" {
        reads.requestedChain++;
        throw new Error("page chain must not select a release");
      },
      signal: new AbortController().signal,
    };
    const resolver = new CommittedProviderApprovalSelectionResolver(options);

    await expect(resolver.resolve(input)).rejects.toMatchObject({
      name: "SessionReleaseError",
      code: "UNKNOWN_RELEASE",
    });
    expect(reads).toEqual({
      releaseName: 1,
      connectionFactory: 0,
      approvals: 0,
      keyring: 0,
      readNow: 0,
      approvalTtlMs: 0,
      requestedAccountAddress: 0,
      requestedChain: 0,
    });
  });
});
