import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  parseArtifactManifest,
  verifyArtifactArchive,
} from "./release-artifact.mjs";
import {
  MAX_CRX3_PACKAGE_BYTES,
  verifyStorePackage,
} from "./store-package.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const releaseDirectory = join(appDirectory, "release");
const execFile = promisify(execFileCallback);

function fail(message) {
  throw new Error(`extension store package verify: ${message}`);
}

async function main() {
  const sourceManifest = JSON.parse(await readFile(join(appDirectory, "manifest.json"), "utf8"));
  const version = sourceManifest.version;
  if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
    fail(`invalid source manifest version: ${String(version)}`);
  }
  const args = process.argv.slice(2);
  if (![3, 5].includes(args.length)) {
    fail("usage: verify-store-package.mjs candidate.crx expected-package-sha256 expected-extension-id [reviewed-upload.zip reviewed-artifact.json]");
  }
  const candidatePath = resolve(args[0]);
  const expectedPackageSha256 = args[1];
  if (!/^[0-9a-f]{64}$/.test(expectedPackageSha256)) {
    fail("expected package SHA-256 must be a lowercase digest");
  }
  const expectedExtensionId = args[2];
  const reviewedArchivePath = resolve(
    args[3] ?? join(releaseDirectory, `warden-extension-${version}.zip`),
  );
  const artifactManifestPath = resolve(
    args[4] ?? join(releaseDirectory, `warden-extension-${version}.artifact.json`),
  );
  const candidateStat = await stat(candidatePath);
  if (!candidateStat.isFile() || candidateStat.size <= 0 || candidateStat.size > MAX_CRX3_PACKAGE_BYTES) {
    fail(`candidate must be a nonempty regular file no larger than ${MAX_CRX3_PACKAGE_BYTES} bytes`);
  }
  const crxBytes = await readFile(candidatePath);
  const actualPackageSha256 = createHash("sha256").update(crxBytes).digest("hex");
  if (actualPackageSha256 !== expectedPackageSha256) {
    fail("store package differs from the independently supplied SHA-256");
  }
  const reviewedArchiveBytes = await readFile(reviewedArchivePath);
  const artifactManifest = parseArtifactManifest(await readFile(artifactManifestPath));
  const approved = verifyArtifactArchive({
    archiveBytes: reviewedArchiveBytes,
    artifactManifest,
  });
  const verified = verifyStorePackage({ crxBytes, artifactManifest, expectedExtensionId });
  if (verified.packageSha256 !== expectedPackageSha256) {
    fail("store package verifier returned a different package digest");
  }

  const temporaryDirectory = await mkdtemp(join(tmpdir(), "warden-store-package-verify-"));
  try {
    const embeddedArchivePath = join(temporaryDirectory, "embedded.zip");
    await writeFile(embeddedArchivePath, verified.archiveBytes, { flag: "wx", mode: 0o600 });
    try {
      await execFile("unzip", ["-t", embeddedArchivePath], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
      });
    } catch (error) {
      fail(`independent unzip -t validation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }

  if (verified.treeSha256 !== approved.treeSha256 || verified.files !== approved.files) {
    fail("store-package and reviewed-upload verification disagree");
  }
  console.log(`verified store package ${candidatePath}`);
  console.log(`against reviewed upload ${reviewedArchivePath}`);
  console.log(`against artifact manifest ${artifactManifestPath}`);
  console.log(`source ${artifactManifest.source.gitCommit}`);
  console.log(`CRX3 package bytes ${verified.packageBytes}`);
  console.log(`CRX3 package sha256 ${verified.packageSha256}`);
  console.log(`CRX3 header bytes ${verified.headerBytes}`);
  console.log(`CRX3 header sha256 ${verified.headerSha256}`);
  console.log(`CRX3 extension id ${verified.extensionId}`);
  console.log(`CRX3 publisher key sha256 ${verified.publisherKeySha256}`);
  console.log(`embedded ZIP bytes ${verified.archiveBytes.length}`);
  console.log(`embedded ZIP sha256 ${verified.archiveSha256}`);
  console.log(`reviewed upload ZIP sha256 ${approved.archiveSha256}`);
  console.log(`files ${verified.files}`);
  console.log(`payload tree sha256 ${verified.treeSha256}`);
  console.log("independent embedded ZIP reader unzip -t passed");
}

await main();
