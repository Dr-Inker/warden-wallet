import { describe, it, expect } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import { p256 } from "@noble/curves/nist";
import {
  assertionToCompact,
  parseDerEcdsaSig,
  AssertionFormatError,
  isLowS,
  P256_N,
  P256_HALF_N,
} from "../src/webauthn/assertion.js";

// Strict-DER parse + mandatory low-S normalization (WRD-SIG-01), the ONLY assertion
// conversion the root/create ceremonies may consume. Verified end to end against a REAL,
// recorded high-S Chrome assertion (Phase 0 spike 02-webauthn) — data, not spike code.

const hexToBytes = (h: string): Uint8Array => Uint8Array.from((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const bytesToHex = (b: Uint8Array): string => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const b64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "base64"));

// --- The recorded real Chrome assertion (spike 02-webauthn/out/assertion.json) ----------
// Chrome emitted a HIGH-S signature here — exactly the case that bricks a ceremony without
// client-side normalization.
const CHROME = {
  signatureDer: "3046022100c583d03246235be3b1a79e84ddb910498baeca3652aa58706903078a34c4676a022100b59b3fe3d519d08b824de29f95796962d8282213e8dd74e50e4bfdeb1d208466",
  authenticatorDataB64: "vlxK98up2TYOCUeXAktaOj3Z9DeqmFIpFlbntbXZ2jQFAAAAAg==",
  clientDataJSONB64: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiV1Bnb0htYzZLZUFGNHlZUktNcWw4bFYwLWh3OEdhNGJWNU5pYlJfN3RfUSIsIm9yaWdpbiI6ImNocm9tZS1leHRlbnNpb246Ly9tYWlrYWRwYW9iYmprbWFvbW5wbmhqZ2xwYWJsbGFvaSIsImNyb3NzT3JpZ2luIjpmYWxzZX0=",
  pubkeyUncompressed: "0426d5d6e77c6252de67b9d9a1d17f3219f0b7f1010890851c3c45e518237da23ebd29fc5de9e856fdcf1ec4aaed048b83d0187eac846f1f9a6cbfbb42f4007234",
  r: "c583d03246235be3b1a79e84ddb910498baeca3652aa58706903078a34c4676a",
  sOriginalHigh: "b59b3fe3d519d08b824de29f95796962d8282213e8dd74e50e4bfdeb1d208466",
  sNormalizedLow: "4a64c01b2ae62f757db21d606a86969ce4bed899be3a299fe56dccd7df42a0eb",
};

// Minimal DER INTEGER encoder (for building valid test signatures from raw scalars).
function derInteger(x: bigint): number[] {
  let bytes: number[] = [];
  if (x === 0n) bytes = [0];
  else { let v = x; while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; } }
  if (bytes[0]! & 0x80) bytes.unshift(0x00); // sign byte for unsigned values
  return [0x02, bytes.length, ...bytes];
}
function derSig(r: bigint, s: bigint): Uint8Array {
  const body = [...derInteger(r), ...derInteger(s)];
  return Uint8Array.from([0x30, body.length, ...body]);
}

describe("assertionToCompact — golden real Chrome high-S vector (WRD-SIG-01)", () => {
  it("normalizes the recorded high-S Chrome assertion to a low-S 64-byte compact signature", () => {
    const compact = assertionToCompact(hexToBytes(CHROME.signatureDer));
    expect(compact.length).toBe(64);
    expect(bytesToHex(compact.subarray(0, 32))).toBe(CHROME.r); // r unchanged
    expect(bytesToHex(compact.subarray(32, 64))).toBe(CHROME.sNormalizedLow); // s flipped to low-S
    // The recorded sample really was high-S (proving the normalization is not decorative).
    const sOrig = BigInt("0x" + CHROME.sOriginalHigh);
    expect(sOrig > P256_HALF_N).toBe(true);
    expect(isLowS(BigInt("0x" + CHROME.sNormalizedLow))).toBe(true);
    expect((P256_N - sOrig)).toBe(BigInt("0x" + CHROME.sNormalizedLow));
  });

  it("PROVES the normalization is load-bearing: the precompile-equivalent (lowS) verifier rejects the raw high-S signature but accepts the normalized one", () => {
    const authData = b64(CHROME.authenticatorDataB64);
    const clientData = b64(CHROME.clientDataJSONB64);
    // WebAuthn signs sha256(authenticatorData ‖ sha256(clientDataJSON)).
    const msgHash = sha256(Uint8Array.from([...authData, ...sha256(clientData)]));
    const pub = hexToBytes(CHROME.pubkeyUncompressed);
    const rawHigh = Uint8Array.from([...hexToBytes(CHROME.r), ...hexToBytes(CHROME.sOriginalHigh)]);
    const normalized = assertionToCompact(hexToBytes(CHROME.signatureDer));

    // The signature IS mathematically valid (accepted when high-S is tolerated)…
    expect(p256.verify(rawHigh, msgHash, pub, { lowS: false })).toBe(true);
    // …but the precompile enforces low-S — so the RAW high-S form is REJECTED…
    expect(p256.verify(rawHigh, msgHash, pub, { lowS: true })).toBe(false);
    // …and the normalized form is ACCEPTED. Without assertionToCompact, the ceremony fails.
    expect(p256.verify(normalized, msgHash, pub, { lowS: true })).toBe(true);
  });
});

describe("parseDerEcdsaSig — strict DER, typed errors not panics", () => {
  const good = hexToBytes(CHROME.signatureDer);
  const cases: [string, Uint8Array][] = [
    ["truncated", good.subarray(0, good.length - 4)],
    ["trailing garbage", Uint8Array.from([...good, 0x00, 0x01])],
    ["not a SEQUENCE", Uint8Array.from([0x02, ...good.subarray(1)])],
    ["indefinite length", Uint8Array.from([0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])],
    ["non-minimal length (long form for short)", Uint8Array.from([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])],
    ["zero-length INTEGER", Uint8Array.from([0x30, 0x04, 0x02, 0x00, 0x02, 0x01, 0x01])],
    ["negative INTEGER (high bit set, no 0x00)", Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])],
    ["non-minimal INTEGER (superfluous 0x00)", Uint8Array.from([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])],
  ];
  for (const [name, bytes] of cases) {
    it(`rejects: ${name}`, () => {
      expect(() => parseDerEcdsaSig(bytes)).toThrow(AssertionFormatError);
    });
  }
  it("rejects r = 0, s = 0, and s = n (out of [1, n-1])", () => {
    expect(() => parseDerEcdsaSig(derSig(0n, 1n))).toThrow(/r is zero/);
    expect(() => parseDerEcdsaSig(derSig(1n, 0n))).toThrow(/s is zero/);
    expect(() => parseDerEcdsaSig(derSig(1n, P256_N))).toThrow(/s >= n/);
    expect(() => parseDerEcdsaSig(derSig(P256_N, 1n))).toThrow(/r >= n/);
  });
});

describe("normalization properties", () => {
  it("output is ALWAYS low-S, and normalize is idempotent (normalize∘normalize = normalize)", () => {
    for (let k = 0; k < 500; k++) {
      const r = (BigInt("0x" + bytesToHex(randomBytes(32))) % (P256_N - 1n)) + 1n;
      const s = (BigInt("0x" + bytesToHex(randomBytes(32))) % (P256_N - 1n)) + 1n;
      const c1 = assertionToCompact(derSig(r, s));
      const s1 = BigInt("0x" + bytesToHex(c1.subarray(32)));
      expect(isLowS(s1)).toBe(true); // always low-S
      // re-encode and normalize again → unchanged (idempotent)
      const c2 = assertionToCompact(derSig(BigInt("0x" + bytesToHex(c1.subarray(0, 32))), s1));
      expect(bytesToHex(c2)).toBe(bytesToHex(c1));
    }
  });
});

describe("fuzz — bounded random inputs never panic", () => {
  it("returns a 64-byte signature or throws AssertionFormatError (never a raw exception)", () => {
    for (let k = 0; k < 3000; k++) {
      const len = Math.floor(Math.random() * 80);
      const bytes = Uint8Array.from({ length: len }, () => Math.floor(Math.random() * 256));
      try {
        const out = assertionToCompact(bytes);
        expect(out.length).toBe(64);
      } catch (e) {
        expect(e, `unexpected non-AssertionFormatError for ${bytesToHex(bytes)}`).toBeInstanceOf(AssertionFormatError);
      }
    }
  });
});
