//! WebAuthn ECDSA-P256 assertion → the fixed 64-byte compact signature the Solana
//! secp256r1 precompile verifies. Two jobs, both security-critical (invariant WRD-SIG-01):
//!
//!   1. STRICT DER parsing of the `Ecdsa-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`)
//!      the authenticator emits — reject trailing bytes, non-minimal / long-form-when-short
//!      lengths, negative or non-minimally-encoded INTEGERs, and any `r`/`s` outside
//!      `[1, n-1]`. A lax parser is a real attack surface (signature malleability, smuggled
//!      bytes), so every deviation is a typed `AssertionFormatError`, never a raw panic.
//!   2. MANDATORY low-S normalization (`s > n/2 ⇒ s = n − s`). This is not optional: the
//!      on-chain secp256r1 precompile REJECTS high-S signatures (the SEC1 malleability
//!      guard), and Chrome emitted a high-S signature on the very first real sample — so a
//!      real root ceremony fails end-to-end unless the client normalizes here.
//!
//! Dependency-free by design: the conversion is pure ASN.1 + bigint arithmetic and needs no
//! elliptic-curve library (verification is the precompile's job), keeping the client's
//! supply-chain surface minimal — the same discipline the deploy gate follows.

/** secp256r1 / NIST P-256 group order `n`. */
export const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
/** The low-S threshold: `floor(n/2)`. A signature is low-S iff `s <= P256_HALF_N`. */
export const P256_HALF_N = P256_N >> 1n;

/** Thrown for any malformed / out-of-range DER signature. Never leaks a raw exception. */
export class AssertionFormatError extends Error {
  constructor(message: string) {
    super(`assertion: ${message}`);
    this.name = "AssertionFormatError";
  }
}

/** A cursor over the DER bytes with strict, bounds-checked reads. */
class DerReader {
  private i = 0;
  constructor(private readonly d: Uint8Array) {}
  private need(n: number): void {
    if (this.i + n > this.d.length) throw new AssertionFormatError("truncated: read past end");
  }
  byte(): number {
    this.need(1);
    return this.d[this.i++]!;
  }
  /** Definite-form length, minimally encoded (long form is rejected when short would do,
   *  and long-form leading-zero / oversized length bytes are rejected). */
  length(): number {
    const first = this.byte();
    if (first < 0x80) return first; // short form
    const numBytes = first & 0x7f;
    if (numBytes === 0) throw new AssertionFormatError("indefinite length is not DER");
    if (numBytes > 4) throw new AssertionFormatError("length too large");
    this.need(numBytes);
    let len = 0;
    for (let k = 0; k < numBytes; k++) len = (len << 8) | this.byte();
    if (len < 0x80) throw new AssertionFormatError("non-minimal length (long form for a short value)");
    if ((first === 0x81 && len < 0x80) || len === 0) throw new AssertionFormatError("non-minimal length");
    return len;
  }
  /** Read a DER INTEGER (tag 0x02) as a non-negative bigint, enforcing minimal encoding. */
  integer(): bigint {
    if (this.byte() !== 0x02) throw new AssertionFormatError("expected INTEGER");
    const len = this.length();
    if (len === 0) throw new AssertionFormatError("zero-length INTEGER");
    this.need(len);
    const start = this.i;
    const bytes = this.d.subarray(start, start + len);
    this.i += len;
    // Sign & minimality: the high bit of the first byte marks a negative two's-complement
    // INTEGER (forbidden here — ECDSA r/s are unsigned), and a leading 0x00 is legal ONLY
    // when the next byte's high bit is set (otherwise it is non-minimal padding).
    if (bytes[0]! & 0x80) throw new AssertionFormatError("negative INTEGER");
    if (bytes.length > 1 && bytes[0] === 0x00 && !(bytes[1]! & 0x80)) {
      throw new AssertionFormatError("non-minimal INTEGER (superfluous leading zero)");
    }
    // A P-256 scalar is <= 32 bytes; with the optional sign byte the encoding is <= 33.
    if (bytes.length > 33 || (bytes.length === 33 && bytes[0] !== 0x00)) {
      throw new AssertionFormatError("INTEGER too large for a P-256 scalar");
    }
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v;
  }
  atEnd(): boolean {
    return this.i === this.d.length;
  }
  get pos(): number {
    return this.i;
  }
}

/** Strictly parse a DER `Ecdsa-Sig-Value` into `{ r, s }`, each validated in `[1, n-1]`. */
export function parseDerEcdsaSig(der: Uint8Array): { r: bigint; s: bigint } {
  const rd = new DerReader(der);
  if (rd.byte() !== 0x30) throw new AssertionFormatError("expected SEQUENCE");
  const seqLen = rd.length();
  const contentStart = rd.pos;
  if (contentStart + seqLen !== der.length) {
    throw new AssertionFormatError("SEQUENCE length does not span the whole input (trailing or truncated bytes)");
  }
  const r = rd.integer();
  const s = rd.integer();
  if (!rd.atEnd()) throw new AssertionFormatError("extra bytes inside SEQUENCE");
  for (const [name, v] of [["r", r], ["s", s]] as const) {
    if (v < 1n) throw new AssertionFormatError(`${name} is zero`);
    if (v >= P256_N) throw new AssertionFormatError(`${name} >= n (out of range)`);
  }
  return { r, s };
}

/** A non-negative bigint (< 2^256) as a fixed 32-byte big-endian array. */
function to32(x: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let k = 31; k >= 0; k--) {
    out[k] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new AssertionFormatError("scalar exceeds 32 bytes");
  return out;
}

/**
 * Parse a DER ECDSA-P256 signature (as WebAuthn emits) STRICTLY and return the fixed
 * 64-byte compact form (`r ‖ s`, 32 bytes each, big-endian) with `s` UNCONDITIONALLY
 * low-S normalized (`s > n/2 ⇒ n − s`). Throws `AssertionFormatError` on any malformed or
 * out-of-range input — never a raw panic. This is the ONLY conversion the root ceremony
 * and the create ceremony are permitted to consume (WRD-SIG-01).
 */
export function assertionToCompact(signatureDer: Uint8Array): Uint8Array {
  const { r, s } = parseDerEcdsaSig(signatureDer);
  const sLow = s > P256_HALF_N ? P256_N - s : s;
  const out = new Uint8Array(64);
  out.set(to32(r), 0);
  out.set(to32(sLow), 32);
  return out;
}

/** True iff `s` is already low-S (`s <= n/2`). */
export function isLowS(s: bigint): boolean {
  return s <= P256_HALF_N;
}
