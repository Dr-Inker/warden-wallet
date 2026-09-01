import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const execFile = promisify(execFileCallback);
const verifierPath = fileURLToPath(
  new URL("../scripts/verify-release.mjs", import.meta.url),
);
const temporaryDirectories = [];

async function rejectedOutput(args) {
  try {
    await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
  throw new Error("release verifier unexpectedly succeeded");
}

async function settledOutput(args) {
  try {
    const result = await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
    return `${result.stdout ?? ""}${result.stderr ?? ""}`;
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("deterministic upload verifier CLI", () => {
  it("accepts the documented pnpm argument separator before reading the candidate", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const candidatePath = join(directory, "missing-candidate.zip");
    const explicitArguments = [
      candidatePath,
      join(directory, "missing.artifact.json"),
      join(directory, "missing.sbom.json"),
      join(directory, "missing.bundle-inputs.json"),
      join(directory, "missing.static-inputs.json"),
      join(directory, "missing.recipe-inputs.json"),
    ];

    for (const optionalUnpacked of [[], [join(directory, "missing-unpacked")]]) {
      for (const separator of [[], ["--"]]) {
        const output = await rejectedOutput([
          ...separator,
          ...explicitArguments,
          ...optionalUnpacked,
        ]);
        expect(output).toContain(candidatePath);
        expect(output).not.toMatch(/usage: verify-release/);
      }
    }
  });

  it("preserves the zero-argument default with or without one package separator", async () => {
    const outputs = [];
    for (const args of [[], ["--"]]) {
      const output = await settledOutput(args);
      expect(output).not.toMatch(/usage: verify-release/);
      outputs.push(output);
    }
    expect(outputs[1]).toBe(outputs[0]);
  });

  it("enforces exact zero, six, or seven semantic arguments", async () => {
    for (const argumentCount of [1, 2, 3, 4, 5, 8]) {
      const arguments_ = Array.from(
        { length: argumentCount },
        (_, index) => `missing-${index}`,
      );
      for (const separator of [[], ["--"]]) {
        const output = await rejectedOutput([...separator, ...arguments_]);
        expect(output).toMatch(/usage: verify-release/);
      }
    }
  });

  it("removes only one leading package separator", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const candidatePath = join(directory, "missing-candidate.zip");
    const output = await rejectedOutput([
      "--",
      "--",
      candidatePath,
      join(directory, "missing.artifact.json"),
      join(directory, "missing.sbom.json"),
      join(directory, "missing.bundle-inputs.json"),
      join(directory, "missing.static-inputs.json"),
      join(directory, "missing.recipe-inputs.json"),
    ]);

    expect(output).toMatch(/open '.*\/--'/);
    expect(output).not.toContain(candidatePath);
    expect(output).not.toMatch(/usage: verify-release/);
  });
});
