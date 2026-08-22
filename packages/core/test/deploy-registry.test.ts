import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PublicKey } from "@solana/web3.js";
import {
  decodeRegistry,
  anchorInstructionSighash,
  REGISTRY_DISCRIMINATOR,
  REGISTRY_DATA_LEN,
} from "../src/deploy/accounts.js";
import {
  expectedRegistryConfig,
  diffRegistry,
  EXPECTED_ADAPTERS,
  hexOf,
} from "../src/deploy/registry-config.js";
import { encodeRegistry, defaultRegistryEntries, namedScenario } from "../src/deploy/fixtures.js";
import { verifyDeployGate } from "../src/deploy/gate.js";
import { SYNTHETIC_PIN } from "../src/deploy/config.js";

// WRD-DEP-02 (deploy-gate check 3): the on-chain adapter Registry is authenticated and its
// COMPLETE config — every source-re-derived selector, role_rules, list membership, version,
// and the treasury — is diffed against the pinned expectation, rejecting any deviation.

const TREASURY = SYNTHETIC_PIN.registryTreasury;
const opts = { expectedVersion: 1, expectedTreasuryB58: TREASURY.toBase58() };
const happyRegistry = () => decodeRegistry(encodeRegistry({ version: 1, treasury: TREASURY, entries: defaultRegistryEntries() }));

describe("Registry decoder (accounts.ts)", () => {
  it("round-trips encodeRegistry → decodeRegistry with the pinned discriminator, treasury, and 11 default entries", () => {
    const reg = happyRegistry();
    expect(reg.version).toBe(1);
    expect(reg.treasury.equals(TREASURY)).toBe(true);
    expect(reg.nEntries).toBe(11);
    expect(reg.entries).toHaveLength(11);
    // First entry is SPL Transfer tag [3], disc_len 1, role 3, list 1.
    expect(hexOf(reg.entries[0]!.selector.slice(0, reg.entries[0]!.discLen))).toBe("03");
    expect(reg.entries[0]!.roleRules).toBe(3);
  });

  it("rejects a wrong discriminator, a short account, and an out-of-range n_entries", () => {
    const good = encodeRegistry({ treasury: TREASURY, entries: defaultRegistryEntries() });
    const bad = Uint8Array.from(good); bad[0] = bad[0]! ^ 0xff;
    expect(() => decodeRegistry(bad)).toThrow(/discriminator is not Registry/);
    expect(() => decodeRegistry(good.slice(0, 100))).toThrow(/too short/);
    const nBad = Uint8Array.from(good); nBad[80] = 0xff; nBad[81] = 0xff; // n_entries = 65535
    expect(() => decodeRegistry(nBad)).toThrow(/n_entries .* exceeds/);
  });

  it("REGISTRY_DISCRIMINATOR is the Anchor account discriminator and REGISTRY_DATA_LEN is 3488", () => {
    expect(hexOf(REGISTRY_DISCRIMINATOR)).toBe("2fae6ef6b8b6fcda"); // sha256("account:Registry")[..8]
    expect(REGISTRY_DATA_LEN).toBe(3488);
  });
});

describe("selector re-derivation (registry-config.ts)", () => {
  it("re-derives Anchor sighashes from the instruction name (sha256('global:route'))", () => {
    // Jupiter `route` sighash, independently pinned in registry-default.rs / constants.rs.
    expect(Array.from(anchorInstructionSighash("route"))).toEqual([229, 23, 203, 151, 122, 227, 173, 42]);
    expect(Array.from(anchorInstructionSighash("shared_accounts_route"))).toEqual([193, 32, 155, 51, 65, 214, 156, 129]);
  });

  it("the expected config matches the parity-locked registry-default.json (no drift from Rust source)", () => {
    const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const json = JSON.parse(readFileSync(join(REPO, "packages/core/src/registry-default.json"), "utf8"));
    const expected = expectedRegistryConfig();
    expect(expected).toHaveLength(json.adapters.length);
    json.adapters.forEach((a: { program_id: string; selector: number[]; disc_len: number; role_rules: number; lists: number[] }, i: number) => {
      const e = expected[i]!;
      expect(e.program, `entry ${i} program`).toBe(a.program_id);
      expect(e.selectorHex, `entry ${i} selector`).toBe(hexOf(a.selector));
      expect(e.discLen, `entry ${i} disc_len`).toBe(a.disc_len);
      expect(e.roleRules, `entry ${i} role_rules`).toBe(a.role_rules);
      expect(e.lists, `entry ${i} lists`).toEqual([...a.lists].sort((x, y) => x - y));
    });
  });

  it("EXPECTED_ADAPTERS covers all 11 default adapters", () => {
    expect(EXPECTED_ADAPTERS).toHaveLength(11);
  });
});

describe("diffRegistry (registry-config.ts)", () => {
  it("passes the happy registry with no violations", () => {
    expect(diffRegistry(happyRegistry(), opts)).toEqual([]);
  });

  const mutant = (over: Parameters<typeof encodeRegistry>[0]) => decodeRegistry(encodeRegistry(over));

  it("rejects a wrong version", () => {
    const v = diffRegistry(mutant({ version: 2, treasury: TREASURY, entries: defaultRegistryEntries() }), opts);
    expect(v.join()).toMatch(/version 2 != expected 1/);
  });
  it("rejects a wrong treasury", () => {
    const v = diffRegistry(mutant({ treasury: new PublicKey(new Uint8Array(32).fill(0x99)), entries: defaultRegistryEntries() }), opts);
    expect(v.join()).toMatch(/treasury .* != pinned/);
  });
  it("rejects a tampered selector (Jupiter route sighash swapped) as unexpected + missing", () => {
    const e = defaultRegistryEntries(); e[5] = { ...e[5]!, selector: Uint8Array.from([9, 9, 9, 9, 9, 9, 9, 9]) };
    const v = diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join();
    expect(v).toMatch(/unexpected entry/);
    expect(v).toMatch(/missing expected entry/);
  });
  it("rejects an extra entry", () => {
    const e = defaultRegistryEntries(); e.push({ program: new PublicKey(new Uint8Array(32).fill(0x55)), selector: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]), discLen: 8, roleRules: 0, lists: [1] });
    expect(diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join()).toMatch(/unexpected entry/);
  });
  it("rejects a missing entry", () => {
    const e = defaultRegistryEntries(); e.splice(6, 1);
    expect(diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join()).toMatch(/missing expected entry/);
  });
  it("rejects a role_rules mismatch", () => {
    const e = defaultRegistryEntries(); e[0] = { ...e[0]!, roleRules: 0 };
    expect(diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join()).toMatch(/role_rules 0 != expected 3/);
  });
  it("rejects a list-membership mismatch", () => {
    const e = defaultRegistryEntries(); e[0] = { ...e[0]!, lists: [2] };
    expect(diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join()).toMatch(/lists \[2\] != expected \[1\]/);
  });
  it("rejects a duplicate entry", () => {
    const e = defaultRegistryEntries(); e.push({ ...e[0]! });
    expect(diffRegistry(mutant({ treasury: TREASURY, entries: e }), opts).join()).toMatch(/duplicate entry/);
  });
  it("rejects a list bitmask bit set past n_entries", () => {
    const buf = encodeRegistry({ treasury: TREASURY, entries: defaultRegistryEntries() });
    // list 1 mask is at offset 3160; set bit 40 (>> 11 entries) by writing byte 5.
    buf[3160 + 5] = buf[3160 + 5]! | 0x01; // bit 40
    expect(diffRegistry(decodeRegistry(buf), opts).join()).toMatch(/bit set for non-existent entry index 40/);
  });
});

describe("deploy gate check-3 wiring (gate.ts)", () => {
  it("the happy scenario passes registry-config", async () => {
    const s = namedScenario("happy")!;
    const v = await verifyDeployGate(s.pin, { rpc: s.rpc, expectedReleaseHashHex: s.expectedReleaseHashHex });
    const reg = v.results.find((r) => r.name === "registry-config")!;
    expect(reg.ok, reg.detail).toBe(true);
  });

  for (const name of ["registry-wrong-owner", "registry-bad-discriminator", "registry-wrong-treasury", "registry-wrong-version", "registry-wrong-selector", "registry-extra-entry", "registry-wrong-role", "registry-missing-entry", "registry-wrong-list"]) {
    it(`fixture ${name} fails specifically on registry-config`, async () => {
      const s = namedScenario(name)!;
      const v = await verifyDeployGate(s.pin, { rpc: s.rpc, expectedReleaseHashHex: s.expectedReleaseHashHex });
      expect(v.ok).toBe(false);
      const reg = v.results.find((r) => r.name === "registry-config")!;
      expect(reg.ok, `expected registry-config to fail for ${name}`).toBe(false);
    });
  }
});
