//! `ExecutePayload` — the TS half of the wire format warden's `execute` (and,
//! via the same logical-account model, `swap`) parses on-chain. It MUST be
//! byte-for-byte what the Rust `payload::parse_payload` reads, and its
//! `accountsHash` MUST equal the Rust `payload::compute_accounts_hash` over the
//! same logical list — both are pinned by cross-language fixtures/tests.
//!
//! ## Wire format (spec §5.2, fixed — mirror of `programs/warden/src/payload.rs`)
//!
//! ```text
//! ExecutePayload := n_ixs: u8, InnerIx * n_ixs
//! InnerIx        := program_idx: u8,
//!                   n_accts: u8,
//!                   (idx: u8, flags: u8) * n_accts,
//!                   data_len: u16 LE,
//!                   data: u8 * data_len
//! ```
//!
//! `flags`: bit 0 = signer, bit 1 = writable; any other bit is invalid.
//!
//! ## Logical account indices (Global Constraints ABI)
//!
//! Every `idx` names a slot of the LOGICAL account list the handler builds:
//! `logical[0] = smart_account`, `logical[1] = signer`, `logical[2 + k] =
//! remaining_accounts[k]`. The client builds and hashes the SAME list; it never
//! indexes a physical account slice.

import { keccak_256 } from "@noble/hashes/sha3";

/** `flags` bit 0 — the account signs the inner instruction. */
export const FLAG_SIGNER = 1 << 0;
/** `flags` bit 1 — the account is writable in the inner instruction. */
export const FLAG_WRITABLE = 1 << 1;
const FLAG_KNOWN = FLAG_SIGNER | FLAG_WRITABLE;

/** The logical index of the SmartAccount PDA. */
export const LOGICAL_SMART_ACCOUNT = 0;
/** The logical index of the session/root signer. */
export const LOGICAL_SIGNER = 1;

/** One `(logicalIndex, flags)` account reference of an inner instruction. */
export interface InnerAccount {
  index: number;
  flags: number;
}

/** One decoded inner instruction. */
export interface InnerIx {
  programIndex: number;
  accounts: InnerAccount[];
  data: Uint8Array;
}

/** A fully-decoded execute payload. */
export interface ExecutePayload {
  ixs: InnerIx[];
}

/** One entry of the logical account list, as `accountsHash` sees it. */
export interface LogicalAccount {
  /** 32-byte pubkey. */
  key: Uint8Array;
  isSigner: boolean;
  isWritable: boolean;
}

function u8(n: number, name: string): number {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new Error(`${name} must be a u8 (0..255), got ${n}`);
  return n;
}

/**
 * Encode an `ExecutePayload` to the exact bytes `parse_payload` reads. Enforces
 * the SAME structural rules as the Rust decoder so a client cannot build a
 * payload the program will reject: known flag bits only, the PDA (index 0)
 * never writable, a signer flag only on index 0/1. (Index-range and the
 * deny-list are the handler's job — they need the accounts.)
 */
export function encodeExecutePayload(payload: ExecutePayload): Uint8Array {
  const out: number[] = [];
  out.push(u8(payload.ixs.length, "n_ixs"));
  for (const ix of payload.ixs) {
    out.push(u8(ix.programIndex, "program_idx"));
    out.push(u8(ix.accounts.length, "n_accts"));
    for (const a of ix.accounts) {
      u8(a.index, "account idx");
      u8(a.flags, "account flags");
      if ((a.flags & ~FLAG_KNOWN) !== 0) throw new Error(`unknown flag bit set: ${a.flags}`);
      if (a.index === LOGICAL_SMART_ACCOUNT && (a.flags & FLAG_WRITABLE) !== 0) {
        throw new Error("the SmartAccount PDA (index 0) may not be writable to a CPI");
      }
      if ((a.flags & FLAG_SIGNER) !== 0 && a.index !== LOGICAL_SMART_ACCOUNT && a.index !== LOGICAL_SIGNER) {
        throw new Error(`a signer flag is only valid on index 0 or 1, got ${a.index}`);
      }
      out.push(a.index, a.flags);
    }
    const len = ix.data.length;
    if (len > 0xffff) throw new Error(`inner instruction data length ${len} exceeds u16`);
    out.push(len & 0xff, (len >> 8) & 0xff); // u16 LE
    for (const b of ix.data) out.push(b);
  }
  return Uint8Array.from(out);
}

/**
 * Decode bytes to an `ExecutePayload`, enforcing the same structural rules and
 * the strict trailing-bytes reject (`parse_payload`'s `Cursor::done`). Throws
 * on any malformed input, never returns a partial result.
 */
export function decodeExecutePayload(bytes: Uint8Array): ExecutePayload {
  let pos = 0;
  const need = (n: number) => {
    if (pos + n > bytes.length) throw new Error("payload truncated");
  };
  const readU8 = (): number => {
    need(1);
    return bytes[pos++]!;
  };
  const readU16 = () => {
    const lo = readU8();
    const hi = readU8();
    return lo | (hi << 8);
  };
  const nIxs = readU8();
  const ixs: InnerIx[] = [];
  for (let i = 0; i < nIxs; i++) {
    const programIndex = readU8();
    const nAccts = readU8();
    const accounts: InnerAccount[] = [];
    for (let j = 0; j < nAccts; j++) {
      const index = readU8();
      const flags = readU8();
      if ((flags & ~FLAG_KNOWN) !== 0) throw new Error(`unknown flag bit set: ${flags}`);
      if (index === LOGICAL_SMART_ACCOUNT && (flags & FLAG_WRITABLE) !== 0) {
        throw new Error("the SmartAccount PDA (index 0) may not be writable to a CPI");
      }
      if ((flags & FLAG_SIGNER) !== 0 && index !== LOGICAL_SMART_ACCOUNT && index !== LOGICAL_SIGNER) {
        throw new Error(`a signer flag is only valid on index 0 or 1, got ${index}`);
      }
      accounts.push({ index, flags });
    }
    const dataLen = readU16();
    need(dataLen);
    const data = bytes.slice(pos, pos + dataLen);
    pos += dataLen;
    ixs.push({ programIndex, accounts, data });
  }
  if (pos !== bytes.length) throw new Error("trailing bytes after the last inner instruction");
  return { ixs };
}

/**
 * `Keccak256` over the logical account list in logical order — for each entry,
 * `pubkey ‖ (isSigner as u8) ‖ (isWritable as u8)` — matching the Rust
 * `compute_accounts_hash`. The root ceremony binds this via `ExecuteBody` /
 * `SwapBody`, so the SDK must build the list EXACTLY as the handler will
 * (`[smart_account, signer] ++ remaining_accounts`, in logical order) and this
 * must equal the on-chain value byte-for-byte.
 */
export function computeAccountsHash(logical: LogicalAccount[]): Uint8Array {
  const buf = new Uint8Array(logical.length * 34);
  let o = 0;
  for (const a of logical) {
    if (a.key.length !== 32) throw new Error("logical account key must be 32 bytes");
    buf.set(a.key, o);
    o += 32;
    buf[o++] = a.isSigner ? 1 : 0;
    buf[o++] = a.isWritable ? 1 : 0;
  }
  return keccak_256(buf);
}

/**
 * Split staged payload bytes into `stage_chunk`-sized slices for upload
 * (`ceil(len / cap)`), using the measured `STAGE_CHUNK_PAYLOAD_CAP` (Task 4).
 * Each returned entry is `{ offset, bytes }` in the order `stage_chunk` requires
 * (strictly sequential, `offset === written`). An empty payload yields no
 * chunks (there is nothing to stage — `stage_open` rejects `len == 0`).
 */
export function splitForStage(payload: Uint8Array, capBytes: number): Array<{ offset: number; bytes: Uint8Array }> {
  if (!Number.isInteger(capBytes) || capBytes <= 0) throw new Error("capBytes must be a positive integer");
  const chunks: Array<{ offset: number; bytes: Uint8Array }> = [];
  for (let offset = 0; offset < payload.length; offset += capBytes) {
    chunks.push({ offset, bytes: payload.slice(offset, Math.min(offset + capBytes, payload.length)) });
  }
  return chunks;
}
