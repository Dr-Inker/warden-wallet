import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const execFile = promisify(execFileCallback);
const verifierPath = fileURLToPath(
  new URL("../scripts/verify-release-source-tag.mjs", import.meta.url),
);
const temporaryDirectories = [];
const MAX_ARTIFACT_MANIFEST_BYTES = 8 * 1024 * 1024;

async function rejectedOutput(args) {
  try {
    await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
  throw new Error("release source verifier unexpectedly succeeded");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("release-source CLI external files", () => {
  it("requires an independent exact artifact digest before parsing or GnuPG", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-source-cli-test-"));
    temporaryDirectories.push(directory);
    const artifactPath = join(directory, "reviewed.artifact.json");
    await writeFile(artifactPath, Buffer.from("{}\n"));

    const output = await rejectedOutput([
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
      artifactPath,
      "0".repeat(64),
    ]);
    expect(output).toMatch(
      /reviewed artifact manifest differs from the independently supplied SHA-256/,
    );
    expect(output).not.toMatch(/usage: verify-release-source-tag/);
    expect(output).not.toMatch(/artifact manifest is not valid JSON/);
    expect(output).not.toMatch(/GNUPGHOME/);
  });

  it("rejects an oversized artifact manifest before reading and parsing it", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-source-cli-test-"));
    temporaryDirectories.push(directory);
    const artifactPath = join(directory, "oversized.artifact.json");
    await writeFile(artifactPath, Buffer.alloc(MAX_ARTIFACT_MANIFEST_BYTES + 1, 0x20));

    const output = await rejectedOutput([
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
      artifactPath,
    ]);
    expect(output).toMatch(
      /reviewed artifact manifest must be a nonempty regular file no larger than 8388608 bytes/,
    );
    expect(output).not.toMatch(/artifact manifest is not valid JSON/);

    const emptyPath = join(directory, "empty.artifact.json");
    await writeFile(emptyPath, Buffer.alloc(0));
    const emptyOutput = await rejectedOutput([
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
      emptyPath,
    ]);
    expect(emptyOutput).toMatch(/reviewed artifact manifest must be a nonempty regular file/);

    const targetPath = join(directory, "target.artifact.json");
    const symlinkPath = join(directory, "symlink.artifact.json");
    await writeFile(targetPath, Buffer.from("{}\n"));
    await symlink(targetPath, symlinkPath);
    const symlinkOutput = await rejectedOutput([
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
      symlinkPath,
    ]);
    expect(symlinkOutput).toMatch(/could not be opened as a non-symlink regular file/);
  });
});
