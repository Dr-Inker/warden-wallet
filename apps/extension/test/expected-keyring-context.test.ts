import { PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
// Deliberately a relative path, not a `@warden/core/...` alias: the background
// bundle must stay unable to reach this core module (`scripts/build.mjs` forbids
// it), and adding an alias would hand src an import it is not allowed to use.
import {
  SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES,
  SESSION_AUTHORITY_WARDEN_PROGRAM_ID,
} from "../../../packages/core/src/transaction/session-authority-resolver.js";

import {
  EXTENSION_PINNED_CHAIN,
  shippedExpectedKeyringContext,
} from "../src/background/expected-keyring-context.js";

/**
 * `scripts/build.mjs` forbids the core session-authority/RPC tree from the
 * background bundle, so the shipped pin is duplicated as byte literals. This
 * suite is the drift guard: it imports the core constants (tests are not
 * bundled) and fails if the two ever disagree.
 */
describe("shipped expected keyring context", () => {
  it("equals the core public genesis pin for the chain it names", () => {
    const expected = new PublicKey(
      SESSION_AUTHORITY_PUBLIC_GENESIS_HASHES[EXTENSION_PINNED_CHAIN],
    ).toBytes();
    expect(Array.from(shippedExpectedKeyringContext().genesisHash)).toEqual(
      Array.from(expected),
    );
  });

  it("equals the core shipped Warden program literal", () => {
    const expected = new PublicKey(SESSION_AUTHORITY_WARDEN_PROGRAM_ID).toBytes();
    expect(Array.from(shippedExpectedKeyringContext().programId)).toEqual(
      Array.from(expected),
    );
  });

  it("hands out an isolated copy so a consumer cannot widen the pin", () => {
    const first = shippedExpectedKeyringContext();
    first.genesisHash.fill(0);
    first.programId.fill(0);
    const second = shippedExpectedKeyringContext();
    expect(Array.from(second.genesisHash)).not.toEqual(new Array(32).fill(0));
    expect(Array.from(second.programId)).not.toEqual(new Array(32).fill(0));
  });
});
