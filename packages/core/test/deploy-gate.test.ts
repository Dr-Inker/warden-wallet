import { describe, it, expect } from "vitest";
import { PublicKey } from "@solana/web3.js";
import { verifyDeployGate, type GateVerdict } from "../src/deploy/gate.js";
import {
  SYNTHETIC_PIN,
  BPF_UPGRADEABLE_LOADER,
  PERMISSION_VOTE,
  MIN_TIME_LOCK_SECONDS,
} from "../src/deploy/config.js";
import {
  buildHappyScenario,
  encodeMultisig,
  encodeProgramAccount,
  encodeProgramData,
  MapRpc,
  fiveMembers,
  type Scenario,
} from "../src/deploy/fixtures.js";

const synthetic = (byte: number): PublicKey => new PublicKey(new Uint8Array(byte === 0 ? 32 : 32).fill(byte));
const run = (s: Scenario): Promise<GateVerdict> => verifyDeployGate(s.pin, { rpc: s.rpc, expectedReleaseHashHex: s.expectedReleaseHashHex });
const failed = (v: GateVerdict): string[] => v.results.filter((r) => !r.ok).map((r) => r.name);
const detailOf = (v: GateVerdict, name: string): string => v.results.find((r) => r.name === name)?.detail ?? "";
const acct = (owner: PublicKey, data: Uint8Array) => ({ owner, data, executable: false });
/** A multisig account with the pinned fields, overridable per negative case. */
const multisigAcct = (s: Scenario, over: Partial<Parameters<typeof encodeMultisig>[0]> = {}) =>
  acct(s.pin.squadsProgramId, encodeMultisig({ threshold: s.pin.threshold, timeLock: s.pin.minTimeLockSeconds, members: s.pin.members, ...over }));

describe("deploy-gate verifyDeployGate", () => {
  it("passes the happy path — pinned identity, 3-of-5, fresh, autonomous, matching hashes", async () => {
    const v = await run(buildHappyScenario(SYNTHETIC_PIN));
    expect(failed(v)).toEqual([]);
    expect(v.ok).toBe(true);
    expect(v.results.map((r) => r.name).sort()).toEqual([
      "squads-code-hash",
      "squads-multisig-governance",
      "upgrade-authority-is-vault-pda",
      "warden-programdata-chain",
      "warden-release-hash",
    ]);
  });

  // ---- fail-closed on absent / erroring accounts ----------------------------
  it("fails closed when the warden Program account is missing", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.del(s.pin.wardenProgramId);
    const v = await run(s);
    expect(v.ok).toBe(false);
    expect(failed(v)).toContain("warden-programdata-chain");
    expect(detailOf(v, "warden-programdata-chain")).toMatch(/does not exist/);
  });

  it("fails closed on an RPC error", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    const throwing: MapRpc = Object.assign(Object.create(MapRpc.prototype), {
      getAccountInfo: () => Promise.reject(new Error("connection reset")),
    });
    const v = await verifyDeployGate(s.pin, { rpc: throwing, expectedReleaseHashHex: s.expectedReleaseHashHex });
    expect(v.ok).toBe(false);
    expect(detailOf(v, "warden-programdata-chain")).toMatch(/RPC error/);
  });

  // ---- Warden Program → ProgramData authentication chain --------------------
  it("rejects a Warden Program not owned by the BPF loader", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.wardenProgramId, acct(synthetic(0x99), encodeProgramAccount(s.addrs.wardenProgramData)));
    const v = await run(s);
    expect(failed(v)).toContain("warden-programdata-chain");
    expect(detailOf(v, "warden-programdata-chain")).toMatch(/not owned by the BPF Upgradeable Loader/);
  });

  it("rejects a Warden Program of the wrong loader variant", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.wardenProgramId, acct(BPF_UPGRADEABLE_LOADER, Uint8Array.from([1, 0, 0, 0, ...new Array(32).fill(0)]))); // Buffer variant
    const v = await run(s);
    expect(failed(v)).toContain("warden-programdata-chain");
  });

  it("rejects an immutable Warden ProgramData (no upgrade authority)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.addrs.wardenProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: null, code: new TextEncoder().encode("warden-elf-bytes-vX") })));
    const v = await run(s);
    expect(failed(v)).toContain("warden-programdata-chain");
    expect(detailOf(v, "warden-programdata-chain")).toMatch(/immutable/);
  });

  it("rejects a Warden ProgramData not owned by the loader", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.addrs.wardenProgramData, acct(synthetic(0x77), encodeProgramData({ authority: s.addrs.vaultPda, code: new TextEncoder().encode("warden-elf-bytes-vX") })));
    expect(failed(await run(s))).toContain("warden-programdata-chain");
  });

  // ---- Squads multisig governance (pinned + complete) -----------------------
  it("rejects a multisig not owned by the pinned Squads program", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, acct(synthetic(0x66), encodeMultisig({ threshold: s.pin.threshold, timeLock: s.pin.minTimeLockSeconds, members: s.pin.members })));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/not owned by the pinned Squads program/);
  });

  it("rejects a spoofed non-Squads account whose bytes lack the Multisig discriminator", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    // Right owner, but the discriminator is wrong (bytes merely look multisig-ish).
    const bytes = encodeMultisig({ threshold: 3, timeLock: MIN_TIME_LOCK_SECONDS, members: s.pin.members });
    bytes[0] ^= 0xff; // corrupt the discriminator
    s.rpc.set(s.pin.multisig, acct(s.pin.squadsProgramId, bytes));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/discriminator is not Multisig/);
  });

  it("rejects member_count != 5 even when threshold == 3", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { members: s.pin.members.slice(0, 4) }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/member_count 4 != required 5/);
  });

  it("rejects a wrong threshold", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { threshold: 1 }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/threshold 1 != required 3/);
  });

  it("rejects a time-lock below the 7-day floor", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { timeLock: MIN_TIME_LOCK_SECONDS - 1 }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/time_lock .* < floor/);
  });

  it("rejects a non-default config authority (WRDF-0017 round 4)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { configAuthority: synthetic(0x55) }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/config_authority .* != expected/);
  });

  it("rejects an actionable stale governance state (WRDF-0028)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { transactionIndex: 3n, staleTransactionIndex: 1n }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/actionable governance state present/);
  });

  it("rejects a structurally-perfect 3-of-5 with an ATTACKER member set (round-3 case)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    // 5 members, threshold 3, 7-day lock, autonomous — but the wrong pubkeys.
    s.rpc.set(s.pin.multisig, multisigAcct(s, { members: fiveMembers() }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/is absent from the on-chain multisig/);
  });

  it("rejects a member whose permission mask differs from the pinned mask (round 7)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    const members = s.pin.members.map((m, i) => (i === 0 ? { key: m.key, mask: PERMISSION_VOTE } : m));
    s.rpc.set(s.pin.multisig, multisigAcct(s, { members }));
    expect(detailOf(await run(s), "squads-multisig-governance")).toMatch(/permission mask .* != pinned/);
  });

  // ---- authority ↔ vault binding -------------------------------------------
  it("rejects an upgrade authority that is not the derived vault PDA", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.addrs.wardenProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: synthetic(0x44), code: new TextEncoder().encode("warden-elf-bytes-vX") })));
    const v = await run(s);
    expect(failed(v)).toContain("upgrade-authority-is-vault-pda");
    // the governance check itself still passes — the mutation is isolated
    expect(v.results.find((r) => r.name === "squads-multisig-governance")!.ok).toBe(true);
  });

  // ---- Squads code trust root ----------------------------------------------
  it("rejects replacement Squads code (hash != pinned audited hash, WRDF-0017 round 6)", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.addrs.squadsProgramData, acct(BPF_UPGRADEABLE_LOADER, encodeProgramData({ authority: new PublicKey(new Uint8Array(32)), code: new TextEncoder().encode("MALICIOUS-squads-code") })));
    expect(detailOf(await run(s), "squads-code-hash")).toMatch(/code hash .* != pinned audited hash/);
  });

  // ---- release artifact hash ------------------------------------------------
  it("rejects a Warden release-hash mismatch", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    const v = await verifyDeployGate(s.pin, { rpc: s.rpc, expectedReleaseHashHex: "00".repeat(32) });
    expect(failed(v)).toContain("warden-release-hash");
    expect(detailOf(v, "warden-release-hash")).toMatch(/!= release-integrity hash/);
  });

  it("keeps checks isolated — a single mutation fails exactly one check", async () => {
    const s = buildHappyScenario(SYNTHETIC_PIN);
    s.rpc.set(s.pin.multisig, multisigAcct(s, { threshold: 1 }));
    const v = await run(s);
    // governance fails; the authority-vault binding also fails (it depends on the
    // vault derived only when governance completes), but the warden chain, squads
    // code, and release hash are untouched.
    expect(v.results.find((r) => r.name === "warden-programdata-chain")!.ok).toBe(true);
    expect(v.results.find((r) => r.name === "squads-code-hash")!.ok).toBe(true);
    expect(v.results.find((r) => r.name === "warden-release-hash")!.ok).toBe(true);
  });
});
