import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { Connection, Keypair, PublicKey, Transaction, SystemProgram } from "@solana/web3.js";
import { checkDevnet, DEVNET_GENESIS, DEVNET_PROGRAM, DEVNET_RPC, hex, inspectTestReceipt, parseTestAmount, prepareCeremony,
  readRootState, rootInstructions, sendTestTransaction, unhex, validateWallet, verifyProgramBytes, type WalletMetadata } from "../src/devnet.js";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/devnet-root.json", import.meta.url), "utf8"));
const wallet = fixture.wallet as WalletMetadata;
const payer = new PublicKey(fixture.payer);
const destination = new PublicKey(fixture.destination);
const digest = (data: Uint8Array) => createHash("sha256").update(data).digest();
function inputs(operation: "create" | "transfer") {
  const ceremony = prepareCeremony(wallet, { generation: 0n, nonce: operation === "create" ? 0n : 1n, policyVersion: 1 }, operation,
    fixture.slot, fixture.now, destination, 1_000_000n);
  const source = fixture[operation].assertion;
  const assertion = { authenticatorData: unhex(source.authenticatorData), clientDataJSON: unhex(source.clientDataJSON), signature: unhex(source.signature) };
  return { ceremony, assertion };
}
describe("devnet root client", () => {
  for (const operation of ["create", "transfer"] as const) it(`${operation} matches the committed OpenSSL/Rust execution fixture and fits a packet`, () => {
    const { ceremony, assertion } = inputs(operation);
    expect(hex(ceremony.challenge)).toBe(fixture[operation].challenge);
    const instructions = rootInstructions(wallet, payer, ceremony, assertion, operation, destination, 1_000_000n);
    expect(instructions.map(ix => ({ programId: ix.programId.toBase58(), keys: ix.keys.map(m => ({ pubkey: m.pubkey.toBase58(), isSigner: m.isSigner, isWritable: m.isWritable })), data: hex(ix.data) }))).toEqual(fixture[operation].instructions);
    const tx = new Transaction({ feePayer: payer, recentBlockhash: SystemProgram.programId.toBase58() }).add(...instructions);
    expect(tx.serialize({ requireAllSignatures: false, verifySignatures: false }).length).toBeLessThanOrEqual(1232);
  });
  it("binds recipient, amount, network and generation into the passkey challenge", () => {
    const state = { generation: 0n, nonce: 1n, policyVersion: 1 };
    const original = inputs("transfer").ceremony.challenge;
    for (const [dest, amount, generation] of [[payer, 1_000_000n, 0n], [destination, 2_000_000n, 0n], [destination, 1_000_000n, 1n]] as const) {
      expect(prepareCeremony(wallet, { ...state, generation }, "transfer", fixture.slot, fixture.now, dest, amount).challenge).not.toEqual(original);
    }
  });
  for (const field of ["authenticatorData", "clientDataJSON", "signature"] as const) it(`rejects a changed ${field}`, () => {
    const { ceremony, assertion } = inputs("transfer");
    assertion[field][10] = assertion[field][10]! ^ 1;
    expect(() => rootInstructions(wallet, payer, ceremony, assertion, "transfer", destination, 1_000_000n)).toThrow();
  });
  it("rejects absent user verification", () => {
    const { ceremony, assertion } = inputs("transfer"); assertion.authenticatorData[32] = 1;
    expect(() => rootInstructions(wallet, payer, ceremony, assertion, "transfer", destination, 1n)).toThrow(/verification/);
  });
  it("validates stored public metadata and origin instead of trusting a saved address", () => {
    expect(validateWallet(wallet, wallet.origin)).toEqual(wallet);
    expect(() => validateWallet({ ...wallet, address: payer.toBase58() }, wallet.origin)).toThrow(/address/);
    expect(() => validateWallet(wallet, `chrome-extension://${"b".repeat(32)}`)).toThrow();
    expect(() => validateWallet({ ...wallet, publicKey: "02" + "ff".repeat(32) }, wallet.origin)).toThrow();
  });
  for (const value of ["0", "-1", "1e-3", "0.0000000001", "0.010000001", "0.1", "NaN", " 0.001", "00.001"]) it(`rejects amount ${value}`, () => {
    expect(() => parseTestAmount(value)).toThrow();
  });
  it("keeps lamports exact", () => {
    expect(parseTestAmount("0.000000001")).toBe(1n);
    expect(parseTestAmount("0.01")).toBe(10_000_000n);
  });
  it("refuses malformed on-chain account containers", () => {
    expect(() => readRootState(new Uint8Array(4120), new PublicKey(DEVNET_PROGRAM), false, wallet)).toThrow();
    expect(() => readRootState(new Uint8Array(4120), SystemProgram.programId, false, wallet)).toThrow();
  });
});

describe("devnet trust and submission boundaries", () => {
  const binary = Uint8Array.of(127, 69, 76, 70, 1, 2, 3);
  const pin = { sha256: hex(digest(binary)), bytes: binary.length };
  function programData() { const bytes = new Uint8Array(45 + binary.length + 4); bytes[0] = 3; bytes.set(binary, 45); return bytes; }
  it("accepts only the pinned ELF and zero allocation padding", () => {
    expect(() => verifyProgramBytes(programData(), pin)).not.toThrow();
    const changed = programData(); changed[49] = 5;
    expect(() => verifyProgramBytes(changed, pin)).toThrow(/binary/);
    const padding = programData(); padding[padding.length - 1] = 1;
    expect(() => verifyProgramBytes(padding, pin)).toThrow(/binary/);
  });
  it("refuses a mainnet endpoint before RPC", async () => {
    const getGenesisHash = vi.fn();
    await expect(checkDevnet({ rpcEndpoint: "https://api.mainnet-beta.solana.com", getGenesisHash } as unknown as Connection, pin)).rejects.toThrow(/other than/);
    expect(getGenesisHash).not.toHaveBeenCalled();
  });
  it("refuses a wrong genesis before reading a program", async () => {
    const getAccountInfo = vi.fn();
    await expect(checkDevnet({ rpcEndpoint: DEVNET_RPC, getGenesisHash: async () => "mainnet", getAccountInfo } as unknown as Connection, pin)).rejects.toThrow(/other than/);
    expect(getAccountInfo).not.toHaveBeenCalled();
  });
  it("reports an absent deployment without signing or submission", async () => {
    const getLatestBlockhash = vi.fn(); const sendRawTransaction = vi.fn();
    const connection = { rpcEndpoint: DEVNET_RPC, getGenesisHash: async () => DEVNET_GENESIS, getAccountInfo: async () => null, getLatestBlockhash, sendRawTransaction } as unknown as Connection;
    await expect(sendTestTransaction(connection, pin, Keypair.generate(), [], () => {})).rejects.toThrow(/not deployed/);
    expect(getLatestBlockhash).not.toHaveBeenCalled(); expect(sendRawTransaction).not.toHaveBeenCalled();
  });
  function rpc() {
    const loader = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
    const address = PublicKey.findProgramAddressSync([new PublicKey(DEVNET_PROGRAM).toBytes()], loader)[0];
    const program = Buffer.alloc(36); program[0] = 2; program.set(address.toBytes(), 4);
    return { rpcEndpoint: DEVNET_RPC, getGenesisHash: async () => DEVNET_GENESIS,
      getAccountInfo: async (key: PublicKey) => ({ owner: loader, executable: key.toBase58() === DEVNET_PROGRAM, data: key.toBase58() === DEVNET_PROGRAM ? program : programData() }),
      getLatestBlockhash: async () => ({ blockhash: "11111111111111111111111111111111", lastValidBlockHeight: 700 }),
      sendRawTransaction: vi.fn(async () => { throw new Error("RPC timed out"); }) };
  }
  it("saves the local signature and expiry before a possibly ambiguous send", async () => {
    const connection = rpc(); const fee = Keypair.generate(); const saved = vi.fn(async (signature, expiry) => {
      expect(signature).toMatch(/^[1-9A-HJ-NP-Za-km-z]{64,88}$/); expect(expiry).toBe(700);
      expect(connection.sendRawTransaction).not.toHaveBeenCalled();
    });
    await expect(sendTestTransaction(connection as unknown as Connection, pin, fee, [SystemProgram.transfer({ fromPubkey: fee.publicKey, toPubkey: destination, lamports: 1 })], saved)).rejects.toThrow(/timed out/);
    expect(saved).toHaveBeenCalledOnce(); expect(connection.sendRawTransaction).toHaveBeenCalledOnce();
  });
  it("does not send if receipt persistence or request liveness fails", async () => {
    const connection = rpc(); const fee = Keypair.generate();
    await expect(sendTestTransaction(connection as unknown as Connection, pin, fee, [SystemProgram.transfer({ fromPubkey: fee.publicKey, toPubkey: destination, lamports: 1 })], () => { throw new Error("request closed"); })).rejects.toThrow(/closed/);
    expect(connection.sendRawTransaction).not.toHaveBeenCalled();
  });
  it("checks absence after finalized expiry, preserving a receipt that landed between reads", async () => {
    const calls: string[] = [];
    const connection = { getBlockHeight: async () => { calls.push("height"); return 701; },
      getSignatureStatuses: async () => { calls.push("status"); return { value: [{ err: null, confirmationStatus: "confirmed" }] }; } } as unknown as Connection;
    expect(await inspectTestReceipt(connection, "test-signature", 700)).toEqual({ state: "confirmed" });
    expect(calls).toEqual(["height", "status"]);
  });
  it("does not expire a processed transaction or absence at the last valid height", async () => {
    const getSignatureStatuses = vi.fn().mockResolvedValue({ value: [null] });
    const getBlockHeight = vi.fn().mockResolvedValue(700);
    const connection = { getBlockHeight, getSignatureStatuses } as unknown as Connection;
    expect(await inspectTestReceipt(connection, "test-signature", 700)).toEqual({ state: "pending" });
    getBlockHeight.mockResolvedValue(701);
    getSignatureStatuses.mockResolvedValue({ value: [{ err: null, confirmationStatus: "processed" }] });
    expect(await inspectTestReceipt(connection, "test-signature", 700)).toEqual({ state: "pending" });
    getSignatureStatuses.mockResolvedValue({ value: [null] });
    expect(await inspectTestReceipt(connection, "test-signature", 700)).toEqual({ state: "expired" });
  });
});
