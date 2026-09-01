import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";
import * as releaseSourceTag from "../scripts/release-source-tag.mjs";

const execFile = promisify(execFileCallback);
const printerPath = fileURLToPath(
  new URL("../scripts/print-release-source-tag-message.mjs", import.meta.url),
);
const temporaryDirectories = [];
const MAX_ARTIFACT_MANIFEST_BYTES = 8 * 1024 * 1024;

const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden release tag message fixture",
  version: "1.2.3",
  permissions: ["storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function expectedMessage(artifactManifestSha256) {
  return [
    "warden.extension-release-tag.v1",
    `artifact-manifest-sha256 ${artifactManifestSha256}`,
    "",
  ].join("\n");
}

async function fixture() {
  const directory = await mkdtemp(
    join(tmpdir(), "warden-release-tag-message-cli-test-"),
  );
  temporaryDirectories.push(directory);
  const entries = [
    { path: "background.js", data: Buffer.from("globalThis.booted = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`) },
  ];
  const archiveBytes = createCanonicalZip(entries);
  const attachment = (suffix) => ({
    file: `warden-extension-1.2.3.${suffix}.json`,
    bytes: Buffer.from(`${suffix} fixture\n`),
  });
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: { gitCommit: "a".repeat(40), lockfileSha256: "b".repeat(64) },
    toolchain: { node: "22.23.2", pnpm: "11.12.0", esbuild: "0.28.2" },
    dependencyEvidence: attachment("sbom"),
    bundleInputEvidence: attachment("bundle-inputs"),
    staticInputEvidence: attachment("static-inputs"),
    releaseRecipeInputEvidence: attachment("recipe-inputs"),
  });
  const artifactManifestBytes = Buffer.from(
    serializeArtifactManifest(artifactManifest),
    "utf8",
  );
  const artifactManifestPath = join(directory, "reviewed.artifact.json");
  await writeFile(artifactManifestPath, artifactManifestBytes);
  return { artifactManifestBytes, artifactManifestPath, directory };
}

async function rejectedOutput(args) {
  try {
    await execFile(process.execPath, [printerPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
  throw new Error("release tag message printer unexpectedly succeeded");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("canonical release source-tag message", () => {
  it("formats the exact authenticated artifact identity for an operator", () => {
    const artifactManifestSha256 = "a".repeat(64);

    expect(releaseSourceTag.formatReleaseTagMessage).toBeTypeOf("function");
    expect(releaseSourceTag.formatReleaseTagMessage(artifactManifestSha256)).toBe(
      expectedMessage(artifactManifestSha256),
    );
    for (const invalid of [undefined, "", "A".repeat(64), "a".repeat(63)]) {
      expect(() => releaseSourceTag.formatReleaseTagMessage(invalid)).toThrow(
        /artifact manifest SHA-256 must be a lowercase digest/,
      );
    }
  });

  it("prints only the canonical message for exact stable artifact bytes", async () => {
    const created = await fixture();
    const artifactManifestSha256 = sha256(created.artifactManifestBytes);
    for (const separator of [[], ["--"]]) {
      const result = await execFile(
        process.execPath,
        [printerPath, ...separator, created.artifactManifestPath, artifactManifestSha256],
        { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 },
      );

      expect(result.stdout).toBe(expectedMessage(artifactManifestSha256));
      expect(result.stderr).toBe("");
    }
  });

  it("requires exactly one path and one independent lowercase digest", async () => {
    const created = await fixture();
    const artifactManifestSha256 = sha256(created.artifactManifestBytes);

    expect(await rejectedOutput([])).toMatch(/usage: print-release-source-tag-message/);
    expect(await rejectedOutput([created.artifactManifestPath])).toMatch(
      /usage: print-release-source-tag-message/,
    );
    expect(await rejectedOutput([
      created.artifactManifestPath,
      artifactManifestSha256,
      "extra",
    ])).toMatch(/usage: print-release-source-tag-message/);
    expect(await rejectedOutput([
      created.artifactManifestPath,
      artifactManifestSha256.toUpperCase(),
    ])).toMatch(/expected artifact manifest SHA-256 must be a lowercase digest/);
    expect(await rejectedOutput([
      created.artifactManifestPath,
      "0".repeat(64),
    ])).toMatch(/differs from the independently supplied SHA-256/);
  });

  it("refuses noncanonical, empty, oversized, or symlink artifact input", async () => {
    const created = await fixture();
    const noncanonicalBytes = Buffer.concat([
      created.artifactManifestBytes,
      Buffer.from(" "),
    ]);
    const noncanonicalPath = join(created.directory, "noncanonical.artifact.json");
    await writeFile(noncanonicalPath, noncanonicalBytes);
    expect(await rejectedOutput([noncanonicalPath, sha256(noncanonicalBytes)])).toMatch(
      /canonical generated JSON serialization/,
    );

    const emptyPath = join(created.directory, "empty.artifact.json");
    await writeFile(emptyPath, Buffer.alloc(0));
    expect(await rejectedOutput([emptyPath, "0".repeat(64)])).toMatch(
      /must be a nonempty regular file/,
    );

    const oversizedPath = join(created.directory, "oversized.artifact.json");
    await writeFile(
      oversizedPath,
      Buffer.alloc(MAX_ARTIFACT_MANIFEST_BYTES + 1, 0x20),
    );
    expect(await rejectedOutput([oversizedPath, "0".repeat(64)])).toMatch(
      /no larger than 8388608 bytes/,
    );

    const symlinkPath = join(created.directory, "artifact-link.json");
    await symlink(created.artifactManifestPath, symlinkPath);
    expect(await rejectedOutput([symlinkPath, sha256(created.artifactManifestBytes)])).toMatch(
      /could not be opened as a non-symlink regular file/,
    );
  });
});
