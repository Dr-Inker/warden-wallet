import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const gatePath = resolve("../../.claude/test-gate.sh");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("the local gate's Cargo.lock boundary", () => {
  it("checks the tracked lock before any project Cargo command", () => {
    const commands = readFileSync(gatePath, "utf8")
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#"));

    const firstCargoCommand = commands.find((line) => /^(?:nice -n 10 )?cargo(?:\s|$)/u.test(line));
    expect(firstCargoCommand).toBe("cargo metadata --locked --format-version 1 >/dev/null");

    for (const prefix of ["cargo tree", "cargo test", "cargo clippy"]) {
      const command = commands.find((line) => line.includes(prefix));
      expect(command, `${prefix} must exist in the local gate`).toBeDefined();
      expect(command, `${prefix} must refuse lockfile resolution drift`).toMatch(/(?:^|\s)--locked(?:\s|$)/u);
    }

    const anchorSbf = commands.find((line) => line.includes("anchor build"));
    expect(anchorSbf).toBe("nice -n 10 anchor build --no-idl -- --features test-jup -- --locked");
    const anchorIdl = commands.find((line) => line.includes("anchor idl build"));
    expect(anchorIdl).toBe(
      "nice -n 10 anchor idl build -p warden -o target/idl/warden.json -- --features test-jup --locked",
    );

    for (const command of commands.filter((line) => line.includes("cargo-build-sbf --manifest-path"))) {
      expect(command, "the direct SBF fallback must lock Cargo resolution").toMatch(/ -- --locked$/u);
    }
  });

  it("proves Cargo's locked preflight refuses a stale graph without rewriting the lock", () => {
    const directory = mkdtempSync(join(tmpdir(), "warden-cargo-lock-preflight-"));
    temporaryDirectories.push(directory);
    mkdirSync(join(directory, "src"));
    writeFileSync(
      join(directory, "Cargo.toml"),
      '[package]\nname = "lock-preflight-fixture"\nversion = "0.1.0"\nedition = "2021"\n',
    );
    writeFileSync(join(directory, "src/lib.rs"), "pub fn fixture() {}\n");
    execFileSync("cargo", ["generate-lockfile"], { cwd: directory, stdio: "pipe" });
    const lockBefore = readFileSync(join(directory, "Cargo.lock"));

    mkdirSync(join(directory, "helper", "src"), { recursive: true });
    writeFileSync(
      join(directory, "helper", "Cargo.toml"),
      '[package]\nname = "helper"\nversion = "0.1.0"\nedition = "2021"\n',
    );
    writeFileSync(join(directory, "helper", "src/lib.rs"), "pub fn helper() {}\n");
    writeFileSync(
      join(directory, "Cargo.toml"),
      '[package]\nname = "lock-preflight-fixture"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nhelper = { path = "helper" }\n',
    );

    const result = spawnSync("cargo", ["metadata", "--locked", "--format-version", "1"], {
      cwd: directory,
      encoding: "utf8",
    });

    expect(result.status).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain("the lock file");
    expect(readFileSync(join(directory, "Cargo.lock"))).toEqual(lockBefore);
  });
});
