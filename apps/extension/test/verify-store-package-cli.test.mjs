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

const execFile = promisify(execFileCallback);
const verifierPath = fileURLToPath(new URL("../scripts/verify-store-package.mjs", import.meta.url));
const temporaryDirectories = [];

const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden store CLI fixture",
  version: "1.2.3",
  permissions: ["storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

const SOURCE = Object.freeze({
  gitCommit: "a".repeat(40),
  lockfileSha256: "b".repeat(64),
});

const TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function payloadEntries() {
  return [
    { path: "background.js", data: Buffer.from("globalThis.booted = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`) },
  ];
}

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "warden-store-package-cli-test-"));
  temporaryDirectories.push(directory);
  const candidateBytes = Buffer.from("not a CRX3 package\n");
  const candidatePath = join(directory, "candidate.crx");
  const reviewedArchivePath = join(directory, "reviewed.zip");
  const artifactManifestPath = join(directory, "reviewed.artifact.json");
  const entries = payloadEntries();
  const archiveBytes = createCanonicalZip(entries);
  const attachment = (suffix) => ({
    file: `warden-extension-1.2.3.${suffix}.json`,
    bytes: Buffer.from(`${suffix} fixture\n`),
  });
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: SOURCE,
    toolchain: TOOLCHAIN,
    dependencyEvidence: attachment("sbom"),
    bundleInputEvidence: attachment("bundle-inputs"),
    staticInputEvidence: attachment("static-inputs"),
    releaseRecipeInputEvidence: attachment("recipe-inputs"),
  });
  const artifactManifestBytes = serializeArtifactManifest(artifactManifest);
  await Promise.all([
    writeFile(candidatePath, candidateBytes),
    writeFile(reviewedArchivePath, archiveBytes),
    writeFile(artifactManifestPath, artifactManifestBytes),
  ]);
  return {
    artifactManifestBytes,
    artifactManifestPath,
    candidateBytes,
    candidatePath,
    directory,
    reviewedArchivePath,
  };
}

async function rejectedOutput(args) {
  try {
    await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
  throw new Error("store verifier unexpectedly succeeded");
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("standalone store-package CLI", () => {
  it("accepts the documented pnpm argument separator before semantic validation", async () => {
    const created = await fixture();
    for (const separator of [[], ["--"]]) {
      const output = await rejectedOutput([
        ...separator,
        created.candidatePath,
        "A".repeat(64),
        "a".repeat(32),
        sha256(created.artifactManifestBytes),
      ]);

      expect(output).toMatch(/expected package SHA-256 must be a lowercase digest/);
      expect(output).not.toMatch(/usage: verify-store-package/);
    }
  });

  it("requires an independent exact artifact-manifest digest before CRX handling", async () => {
    const created = await fixture();
    const commonArgs = [
      created.candidatePath,
      sha256(created.candidateBytes),
      "a".repeat(32),
    ];
    const wrongDigest = await rejectedOutput([
      ...commonArgs,
      "0".repeat(64),
      created.reviewedArchivePath,
      created.artifactManifestPath,
    ]);
    expect(wrongDigest).toMatch(
      /reviewed artifact manifest differs from the independently supplied SHA-256/,
    );
    expect(wrongDigest).not.toMatch(/CRX3 magic/);

    const uppercaseDigest = await rejectedOutput([
      ...commonArgs,
      sha256(created.artifactManifestBytes).toUpperCase(),
      created.reviewedArchivePath,
      created.artifactManifestPath,
    ]);
    expect(uppercaseDigest).toMatch(
      /expected artifact manifest SHA-256 must be a lowercase digest/,
    );
    expect(uppercaseDigest).not.toMatch(/CRX3 magic/);

    const exactDigest = await rejectedOutput([
      ...commonArgs,
      sha256(created.artifactManifestBytes),
      created.reviewedArchivePath,
      created.artifactManifestPath,
    ]);
    expect(exactDigest).toMatch(/CRX3 magic must be Cr24/);

    const missingDigest = await rejectedOutput([
      created.candidatePath,
      sha256(created.candidateBytes),
      "a".repeat(32),
    ]);
    expect(missingDigest).toMatch(
      /expected-artifact-manifest-sha256/,
    );
  });

  it("rejects a final candidate symlink before digest or CRX handling", async () => {
    const created = await fixture();
    const candidateSymlinkPath = join(created.directory, "candidate-link.crx");
    await symlink(created.candidatePath, candidateSymlinkPath);

    const output = await rejectedOutput([
      candidateSymlinkPath,
      sha256(created.candidateBytes),
      "a".repeat(32),
      sha256(created.artifactManifestBytes),
      created.reviewedArchivePath,
      created.artifactManifestPath,
    ]);
    expect(output).toMatch(/could not be opened as a non-symlink regular file/);
    expect(output).not.toMatch(/CRX3 magic/);
  });

  it("requires and checks an independent exact CRX digest before parsing", async () => {
    const created = await fixture();
    const commonArgs = [
      "a".repeat(32),
      sha256(created.artifactManifestBytes),
      created.reviewedArchivePath,
      created.artifactManifestPath,
    ];

    const wrongDigest = await rejectedOutput([
      created.candidatePath,
      "0".repeat(64),
      ...commonArgs,
    ]);
    expect(wrongDigest).toMatch(/store package differs from the independently supplied SHA-256/);
    expect(wrongDigest).not.toMatch(/CRX3 magic/);

    const uppercaseDigest = await rejectedOutput([
      created.candidatePath,
      sha256(created.candidateBytes).toUpperCase(),
      ...commonArgs,
    ]);
    expect(uppercaseDigest).toMatch(/expected package SHA-256 must be a lowercase digest/);

    const exactDigest = await rejectedOutput([
      created.candidatePath,
      sha256(created.candidateBytes),
      ...commonArgs,
    ]);
    expect(exactDigest).toMatch(/CRX3 magic must be Cr24/);

    const missingDigest = await rejectedOutput([
      created.candidatePath,
      "a".repeat(32),
    ]);
    expect(missingDigest).toMatch(
      /candidate\.crx expected-package-sha256 expected-extension-id/,
    );
  });
});
