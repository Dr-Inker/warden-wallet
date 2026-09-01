import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { mkdtemp, open, readFile, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  parseArtifactManifest,
  verifyArtifactArchive,
} from "./release-artifact.mjs";
import { normalizeReleaseCliArguments } from "./release-cli-arguments.mjs";
import { readBoundedRegularFile } from "./release-input-file.mjs";
import {
  MAX_CRX3_PACKAGE_BYTES,
  verifyStorePackage,
} from "./store-package.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const releaseDirectory = join(appDirectory, "release");
const execFile = promisify(execFileCallback);
const MAX_ARTIFACT_MANIFEST_BYTES = 8 * 1024 * 1024;
const TEMPORARY_ARCHIVE_COMPARE_CHUNK_BYTES = 64 * 1024;
const TEMPORARY_ARCHIVE_CHANGED_MESSAGE =
  "temporary embedded archive bytes changed during independent unzip -t validation";

function fail(message) {
  throw new Error(`extension store package verify: ${message}`);
}

async function assertTemporaryArchiveUnchanged(
  temporaryArchiveHandle,
  archiveBytes,
) {
  const current = await temporaryArchiveHandle.stat({ bigint: true });
  if (!current.isFile() || current.size !== BigInt(archiveBytes.length)) {
    throw new Error(TEMPORARY_ARCHIVE_CHANGED_MESSAGE);
  }
  const comparisonBuffer = Buffer.allocUnsafe(
    Math.min(TEMPORARY_ARCHIVE_COMPARE_CHUNK_BYTES, archiveBytes.length),
  );
  for (let offset = 0; offset < archiveBytes.length;) {
    const length = Math.min(comparisonBuffer.length, archiveBytes.length - offset);
    let bytesRead = 0;
    while (bytesRead < length) {
      const result = await temporaryArchiveHandle.read(
        comparisonBuffer,
        bytesRead,
        length - bytesRead,
        offset + bytesRead,
      );
      if (result.bytesRead === 0) {
        throw new Error(TEMPORARY_ARCHIVE_CHANGED_MESSAGE);
      }
      bytesRead += result.bytesRead;
    }
    if (!comparisonBuffer
      .subarray(0, length)
      .equals(archiveBytes.subarray(offset, offset + length))) {
      throw new Error(TEMPORARY_ARCHIVE_CHANGED_MESSAGE);
    }
    offset += length;
  }
}

export async function verifyEmbeddedArchiveWithInfoZip(archiveBytes) {
  let temporaryDirectory;
  let temporaryArchiveReadHandle;
  let temporaryArchiveWriteHandle;
  let validationError;
  try {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "warden-store-package-verify-"));
    const temporaryArchivePath = join(temporaryDirectory, "embedded.zip");
    temporaryArchiveWriteHandle = await open(
      temporaryArchivePath,
      fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        fsConstants.O_RDWR |
        fsConstants.O_NOFOLLOW,
      0o600,
    );
    await temporaryArchiveWriteHandle.writeFile(archiveBytes);
    const written = await temporaryArchiveWriteHandle.stat({ bigint: true });
    if (!written.isFile() || written.size !== BigInt(archiveBytes.length)) {
      throw new Error("temporary embedded archive byte count differs from the verified archive");
    }
    await temporaryArchiveWriteHandle.sync();
    temporaryArchiveReadHandle = await open(
      temporaryArchivePath,
      fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
    );
    const readable = await temporaryArchiveReadHandle.stat({ bigint: true });
    if (
      !readable.isFile() ||
      readable.dev !== written.dev ||
      readable.ino !== written.ino ||
      readable.size !== written.size
    ) {
      throw new Error("temporary embedded archive read handle differs from the synced writer");
    }
    await temporaryArchiveWriteHandle.close();
    temporaryArchiveWriteHandle = undefined;
    await temporaryArchiveReadHandle.chmod(0o400);
    const sealed = await temporaryArchiveReadHandle.stat({ bigint: true });
    if (
      !sealed.isFile() ||
      sealed.dev !== readable.dev ||
      sealed.ino !== readable.ino ||
      sealed.size !== readable.size ||
      Number(sealed.mode & 0o777n) !== 0o400
    ) {
      throw new Error("temporary embedded archive read-only seal differs from the synced archive");
    }
    await unlink(temporaryArchivePath);
    const descriptorPath = `/proc/${process.pid}/fd/${temporaryArchiveReadHandle.fd}`;
    await execFile("unzip", ["-t", descriptorPath], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
    await assertTemporaryArchiveUnchanged(temporaryArchiveReadHandle, archiveBytes);
  } catch (error) {
    validationError = error;
  }
  let cleanupError;
  if (temporaryArchiveReadHandle !== undefined) {
    try {
      await temporaryArchiveReadHandle.close();
    } catch (error) {
      cleanupError = error;
    }
  }
  if (temporaryArchiveWriteHandle !== undefined) {
    try {
      await temporaryArchiveWriteHandle.close();
    } catch (error) {
      cleanupError ??= error;
    }
  }
  if (temporaryDirectory !== undefined) {
    try {
      await rm(temporaryDirectory, { recursive: true, force: true });
    } catch (error) {
      cleanupError ??= error;
    }
  }
  if (cleanupError !== undefined) {
    fail(`independent unzip -t temporary archive cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
  }
  if (validationError !== undefined) {
    fail(`independent unzip -t validation failed: ${validationError instanceof Error ? validationError.message : String(validationError)}`);
  }
}

async function main() {
  const sourceManifest = JSON.parse(await readFile(join(appDirectory, "manifest.json"), "utf8"));
  const version = sourceManifest.version;
  if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
    fail(`invalid source manifest version: ${String(version)}`);
  }
  const args = normalizeReleaseCliArguments(process.argv.slice(2));
  if (![4, 6].includes(args.length)) {
    fail("usage: verify-store-package.mjs candidate.crx expected-package-sha256 expected-extension-id expected-artifact-manifest-sha256 [reviewed-upload.zip reviewed-artifact.json]");
  }
  const candidatePath = resolve(args[0]);
  const expectedPackageSha256 = args[1];
  if (!/^[0-9a-f]{64}$/.test(expectedPackageSha256)) {
    fail("expected package SHA-256 must be a lowercase digest");
  }
  const expectedExtensionId = args[2];
  const expectedArtifactManifestSha256 = args[3];
  if (!/^[0-9a-f]{64}$/.test(expectedArtifactManifestSha256)) {
    fail("expected artifact manifest SHA-256 must be a lowercase digest");
  }
  const reviewedArchivePath = resolve(
    args[4] ?? join(releaseDirectory, `warden-extension-${version}.zip`),
  );
  const artifactManifestPath = resolve(
    args[5] ?? join(releaseDirectory, `warden-extension-${version}.artifact.json`),
  );
  const crxBytes = await readBoundedRegularFile(
    candidatePath,
    MAX_CRX3_PACKAGE_BYTES,
    "store package",
  );
  const actualPackageSha256 = createHash("sha256").update(crxBytes).digest("hex");
  if (actualPackageSha256 !== expectedPackageSha256) {
    fail("store package differs from the independently supplied SHA-256");
  }
  const reviewedArchiveBytes = await readBoundedRegularFile(
    reviewedArchivePath,
    MAX_CRX3_PACKAGE_BYTES,
    "reviewed upload archive",
  );
  const artifactManifestBytes = await readBoundedRegularFile(
    artifactManifestPath,
    MAX_ARTIFACT_MANIFEST_BYTES,
    "reviewed artifact manifest",
  );
  const artifactManifestSha256 = createHash("sha256")
    .update(artifactManifestBytes)
    .digest("hex");
  if (artifactManifestSha256 !== expectedArtifactManifestSha256) {
    fail("reviewed artifact manifest differs from the independently supplied SHA-256");
  }
  const artifactManifest = parseArtifactManifest(artifactManifestBytes);
  const approved = verifyArtifactArchive({
    archiveBytes: reviewedArchiveBytes,
    artifactManifest,
  });
  const verified = verifyStorePackage({ crxBytes, artifactManifest, expectedExtensionId });
  if (verified.packageSha256 !== expectedPackageSha256) {
    fail("store package verifier returned a different package digest");
  }

  await verifyEmbeddedArchiveWithInfoZip(verified.archiveBytes);

  if (verified.treeSha256 !== approved.treeSha256 || verified.files !== approved.files) {
    fail("store-package and reviewed-upload verification disagree");
  }
  console.log(`verified store package ${candidatePath}`);
  console.log(`against reviewed upload ${reviewedArchivePath}`);
  console.log(`against artifact manifest ${artifactManifestPath}`);
  console.log(`artifact manifest sha256 ${artifactManifestSha256}`);
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

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
