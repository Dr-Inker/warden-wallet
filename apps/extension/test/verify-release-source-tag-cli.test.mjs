import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
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
  it("accepts the documented pnpm argument separator before semantic validation", async () => {
    for (const separator of [[], ["--"]]) {
      const output = await rejectedOutput([
        ...separator,
        "release-test",
        "a".repeat(40),
        "A".repeat(40),
        "B".repeat(40),
        "missing.artifact.json",
        "C".repeat(64),
      ]);

      expect(output).toMatch(
        /expected artifact manifest SHA-256 must be a lowercase digest/,
      );
      expect(output).not.toMatch(/usage: verify-release-source-tag/);
    }
  });

  it("requires an independent digest for the auto-selected local artifact", async () => {
    const sourceArguments = [
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
    ];

    const missingOutput = await rejectedOutput(sourceArguments);
    expect(missingOutput).toMatch(/usage: verify-release-source-tag/);

    const malformedOutput = await rejectedOutput([
      ...sourceArguments,
      "A".repeat(64),
    ]);
    expect(malformedOutput).toMatch(
      /expected artifact manifest SHA-256 must be a lowercase digest/,
    );
    expect(malformedOutput).not.toMatch(/usage: verify-release-source-tag/);
  });

  it("requires an independent exact artifact digest before parsing or GnuPG", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-source-cli-test-"));
    temporaryDirectories.push(directory);
    const artifactPath = join(directory, "reviewed.artifact.json");
    const artifactBytes = Buffer.from("{}\n");
    await writeFile(artifactPath, artifactBytes);

    const baseArguments = [
      "release-test",
      "a".repeat(40),
      "A".repeat(40),
      "B".repeat(40),
      artifactPath,
      "0".repeat(64),
    ];
    const tierTails = [
      [],
      ["missing-report.json", "1".repeat(64)],
      [
        "missing-report.json",
        "1".repeat(64),
        "missing-signature",
        "2".repeat(64),
        "C".repeat(40),
        "D".repeat(40),
      ],
      [
        "missing-report.json",
        "1".repeat(64),
        "missing-signature",
        "2".repeat(64),
        "C".repeat(40),
        "D".repeat(40),
        "missing-store.crx",
        "3".repeat(64),
        "a".repeat(32),
        "missing-upload.zip",
      ],
    ];
    for (const tail of tierTails) {
      const output = await rejectedOutput([...baseArguments, ...tail]);
      expect(output).toMatch(
        /reviewed artifact manifest differs from the independently supplied SHA-256/,
      );
      expect(output).not.toMatch(/usage: verify-release-source-tag/);
      expect(output).not.toMatch(/artifact manifest is not valid JSON/);
      expect(output).not.toMatch(/GNUPGHOME/);
    }

    const uppercaseOutput = await rejectedOutput([
      ...baseArguments.slice(0, -1),
      "A".repeat(64),
    ]);
    expect(uppercaseOutput).toMatch(
      /expected artifact manifest SHA-256 must be a lowercase digest/,
    );

    const missingOutput = await rejectedOutput(baseArguments.slice(0, -1));
    expect(missingOutput).toMatch(
      /expected artifact manifest SHA-256 must be a lowercase digest/,
    );

    const exactOutput = await rejectedOutput([
      ...baseArguments.slice(0, -1),
      createHash("sha256").update(artifactBytes).digest("hex"),
    ]);
    expect(exactOutput).toMatch(/artifact manifest/);
    expect(exactOutput).not.toMatch(/independently supplied SHA-256/);
    expect(exactOutput).not.toMatch(/usage: verify-release-source-tag/);
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
      "0".repeat(64),
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
      "0".repeat(64),
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
      "0".repeat(64),
    ]);
    expect(symlinkOutput).toMatch(/could not be opened as a non-symlink regular file/);
  });
});
