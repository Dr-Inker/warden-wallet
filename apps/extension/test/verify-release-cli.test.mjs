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

    for (const separator of [[], ["--"]]) {
      const output = await rejectedOutput([...separator, ...explicitArguments]);
      expect(output).toContain(candidatePath);
      expect(output).not.toMatch(/usage: verify-release/);
    }
  });
});
