import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  encodeExecutePayload,
  decodeExecutePayload,
  computeAccountsHash,
  splitForStage,
  FLAG_SIGNER,
  FLAG_WRITABLE,
  type ExecutePayload,
  type LogicalAccount,
} from "../src/index.js";
import {
  FIXTURES_DIR,
  PAYLOAD_VECTOR,
  PAYLOAD_VECTOR_LOGICAL,
  CLOSE_PAYLOAD,
} from "../scripts/gen-fixtures.js";

const hex = (b: Uint8Array): string =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
const fill = (n: number, byte: number): Uint8Array => new Uint8Array(n).fill(byte);

describe("encodeExecutePayload / decodeExecutePayload", () => {
  it("round-trips a two-instruction payload", () => {
    const p: ExecutePayload = {
      ixs: [
        {
          programIndex: 2,
          accounts: [
            { index: 0, flags: FLAG_SIGNER },
            { index: 3, flags: FLAG_WRITABLE },
          ],
          data: Uint8Array.from([9, 9, 9]),
        },
        {
          programIndex: 4,
          accounts: [
            { index: 1, flags: FLAG_SIGNER },
            { index: 5, flags: 0 },
          ],
          data: Uint8Array.from([]),
        },
      ],
    };
    const bytes = encodeExecutePayload(p);
    expect(decodeExecutePayload(bytes)).toEqual(p);
  });

  it("encodes the empty payload as a single zero byte", () => {
    expect(hex(encodeExecutePayload({ ixs: [] }))).toBe("00");
    expect(decodeExecutePayload(Uint8Array.from([0]))).toEqual({ ixs: [] });
  });

  it("rejects a duplicate index within one ix at neither layer (allowed — see payload.rs)", () => {
    // The per-inner-ix duplicate rule was relaxed (a vault-sweep close names the
    // PDA twice); encode/decode must accept it.
    const p: ExecutePayload = {
      ixs: [{ programIndex: 9, accounts: [{ index: 0, flags: 0 }, { index: 0, flags: FLAG_SIGNER }], data: Uint8Array.from([]) }],
    };
    expect(decodeExecutePayload(encodeExecutePayload(p))).toEqual(p);
  });

  it("rejects unknown flag bits and out-of-slot signers on ENCODE", () => {
    expect(() => encodeExecutePayload({ ixs: [{ programIndex: 2, accounts: [{ index: 3, flags: 0b100 }], data: new Uint8Array() }] })).toThrow();
    expect(() => encodeExecutePayload({ ixs: [{ programIndex: 9, accounts: [{ index: 2, flags: FLAG_SIGNER }], data: new Uint8Array() }] })).toThrow();
  });

  it("accepts a writable index-0 structurally (parity with parse_payload)", () => {
    // The pure codec no longer rejects a writable PDA — that rule needs the
    // accounts + deny-list and lives in the handler's `enforce_pda_writable`.
    // The sanctioned CloseAccount rent-destination shape must round-trip.
    const p: ExecutePayload = {
      ixs: [{ programIndex: 9, accounts: [{ index: 0, flags: FLAG_WRITABLE }], data: Uint8Array.from([9]) }],
    };
    expect(decodeExecutePayload(encodeExecutePayload(p))).toEqual(p);
  });

  it("rejects the same shapes on DECODE, plus trailing bytes and truncation", () => {
    // n_ixs=1 but no ix bytes.
    expect(() => decodeExecutePayload(Uint8Array.from([1]))).toThrow();
    // trailing byte after a complete payload.
    const ok = encodeExecutePayload({ ixs: [{ programIndex: 2, accounts: [{ index: 0, flags: FLAG_SIGNER }], data: new Uint8Array() }] });
    expect(() => decodeExecutePayload(Uint8Array.from([...ok, 0xff]))).toThrow();
    // data_len past the end: n_ixs=1, program=2, n_accts=0, data_len=5, 2 bytes.
    expect(() => decodeExecutePayload(Uint8Array.from([1, 2, 0, 5, 0, 0xaa, 0xbb]))).toThrow();
    // out-of-slot signer in the bytes: idx 2 with FLAG_SIGNER.
    expect(() => decodeExecutePayload(Uint8Array.from([1, 2, 1, 2, FLAG_SIGNER, 0, 0]))).toThrow();
    // a writable PDA in the bytes now DECODES (handler-gated, not codec-gated).
    expect(decodeExecutePayload(Uint8Array.from([1, 2, 1, 0, FLAG_WRITABLE, 0, 0]))).toEqual({
      ixs: [{ programIndex: 2, accounts: [{ index: 0, flags: FLAG_WRITABLE }], data: new Uint8Array() }],
    });
  });
});

describe("computeAccountsHash", () => {
  it("is order- and flag-sensitive and reproducible", () => {
    const a = fill(32, 0xa1);
    const b = fill(32, 0xb2);
    const base: LogicalAccount[] = [
      { key: a, isSigner: true, isWritable: false },
      { key: b, isSigner: false, isWritable: true },
    ];
    const h = hex(computeAccountsHash(base));
    expect(hex(computeAccountsHash([base[1]!, base[0]!]))).not.toBe(h); // reorder
    expect(hex(computeAccountsHash([{ ...base[0]!, isWritable: true }, base[1]!]))).not.toBe(h); // flag flip
    expect(hex(computeAccountsHash(base))).toBe(h); // reproducible
  });
});

describe("splitForStage", () => {
  it("splits into ceil(len/cap) sequential chunks", () => {
    const payload = fill(2500, 7);
    const chunks = splitForStage(payload, 977);
    expect(chunks.length).toBe(Math.ceil(2500 / 977)); // 3
    expect(chunks[0]!.offset).toBe(0);
    expect(chunks[1]!.offset).toBe(977);
    expect(chunks[2]!.offset).toBe(1954);
    expect(chunks[2]!.bytes.length).toBe(2500 - 1954);
    // reassembly is byte-identical
    const joined = new Uint8Array(2500);
    for (const c of chunks) joined.set(c.bytes, c.offset);
    expect(hex(joined)).toBe(hex(payload));
  });
  it("yields no chunks for an empty payload", () => {
    expect(splitForStage(new Uint8Array(), 977)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Cross-language GOLDEN fixtures. These files are READ-ONLY golden vectors,
// written only by `scripts/gen-fixtures.ts`; the Rust tests
// (`payload::tests::ts_payload_vector_round_trips`,
// `ts_writable_pda_close_vector_parses`) read the SAME committed bytes. Here we
// assert the TS encoder reproduces the committed golden byte-for-byte — a
// wrapper/encoder regression fails this AND the gate's `git diff` guard, rather
// than silently rewriting the fixture (WRDF-0081).
// ---------------------------------------------------------------------------
const golden = (name: string): Uint8Array => new Uint8Array(readFileSync(resolve(FIXTURES_DIR, name)));

describe("cross-language golden fixtures", () => {
  it("payload_vector.bin matches the committed golden (independently pinned)", () => {
    // Independently pin the structure the Rust decoder asserts, so this is not a
    // tautology against the encoder's own output.
    expect(PAYLOAD_VECTOR.ixs.length).toBe(2);
    expect(PAYLOAD_VECTOR.ixs[0]!.programIndex).toBe(4);
    expect(PAYLOAD_VECTOR.ixs[0]!.accounts.map((a) => [a.index, a.flags])).toEqual([[2, FLAG_WRITABLE], [3, FLAG_WRITABLE], [0, FLAG_SIGNER], [4, 0]]);
    expect(PAYLOAD_VECTOR.ixs[1]!.programIndex).toBe(5);

    expect(hex(encodeExecutePayload(PAYLOAD_VECTOR))).toBe(hex(golden("payload_vector.bin")));
    expect(decodeExecutePayload(golden("payload_vector.bin"))).toEqual(PAYLOAD_VECTOR);
  });

  it("payload_accounts_hash.hex matches the committed golden", () => {
    const committed = readFileSync(resolve(FIXTURES_DIR, "payload_accounts_hash.hex"), "utf8").trim();
    expect(hex(computeAccountsHash(PAYLOAD_VECTOR_LOGICAL))).toBe(committed);
    // Independent structural pin of the hashed list.
    expect(PAYLOAD_VECTOR_LOGICAL.map((a) => [a.isSigner, a.isWritable])).toEqual([[true, false], [true, false], [false, true], [false, true], [false, false], [false, false]]);
  });

  it("payload_writable_pda_close.bin matches the committed golden (WRDF-0073)", () => {
    // The sanctioned vault-sweep CloseAccount: the PDA appears twice, once
    // WRITABLE (rent destination) once SIGNER (owner).
    expect(CLOSE_PAYLOAD.ixs[0]!.accounts.map((a) => [a.index, a.flags])).toEqual([[2, FLAG_WRITABLE], [0, FLAG_WRITABLE], [0, FLAG_SIGNER]]);
    expect(hex(encodeExecutePayload(CLOSE_PAYLOAD))).toBe(hex(golden("payload_writable_pda_close.bin")));
    expect(decodeExecutePayload(golden("payload_writable_pda_close.bin"))).toEqual(CLOSE_PAYLOAD);
  });
});
