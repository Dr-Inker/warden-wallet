import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
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
  await Promise.all([
    writeFile(candidatePath, candidateBytes),
    writeFile(reviewedArchivePath, archiveBytes),
    writeFile(artifactManifestPath, serializeArtifactManifest(artifactManifest)),
  ]);
  return {
    artifactManifestPath,
    candidateBytes,
    candidatePath,
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
  it("requires and checks an independent exact CRX digest before parsing", async () => {
    const created = await fixture();
    const commonArgs = [
      "a".repeat(32),
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

    const exactDigest = await rejectedOutput([
      created.candidatePath,
      sha256(created.candidateBytes),
      ...commonArgs,
    ]);
    expect(exactDigest).toMatch(/CRX3 magic must be Cr24/);
  });
});
