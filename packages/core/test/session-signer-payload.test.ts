import { describe, expect, it } from "vitest";

import {
  KeyringFormatError,
  SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION,
  SESSION_SIGNER_SEED_BYTES,
  decodeSessionSignerPayload,
  encodeSessionSignerPayload,
} from "../src/index.js";

describe("session-signer plaintext payload", () => {
  it("pins schema v1 to the exact 32-byte Ed25519 seed", () => {
    const seed = Uint8Array.from({ length: 32 }, (_unused, index) => index);
    const expected = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    const encoded = encodeSessionSignerPayload(seed);

    expect(SESSION_SIGNER_PAYLOAD_SCHEMA_VERSION).toBe(1);
    expect(SESSION_SIGNER_SEED_BYTES).toBe(32);
    seed.fill(0xff);
    expect(Array.from(encoded)).toEqual(expected);

    const decoded = decodeSessionSignerPayload(encoded);
    encoded.fill(0xee);
    expect(Array.from(decoded)).toEqual(expected);
  });

  it.each([
    ["non-bytes", [1, 2, 3]],
    ["empty", new Uint8Array(0)],
    ["31 bytes", new Uint8Array(31)],
    ["33 bytes", new Uint8Array(33)],
  ])("rejects a %s payload without truncation or padding", (_label, value) => {
    expect(() => decodeSessionSignerPayload(value as Uint8Array)).toThrow(
      KeyringFormatError,
    );
    expect(() => encodeSessionSignerPayload(value as Uint8Array)).toThrow(
      KeyringFormatError,
    );
  });
});
