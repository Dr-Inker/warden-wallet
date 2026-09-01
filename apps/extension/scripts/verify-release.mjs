import { execFile as execFileCallback } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { mkdtemp, open, readFile, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { verifyJavaScriptBundleInputEvidenceAttachment } from "./bundle-input-evidence.mjs";
import { verifyProductionDependencyEvidenceAttachment } from "./production-dependency-evidence.mjs";
import {
  parseArtifactManifest,
  verifyArtifactArchive,
  verifyCanonicalUnpacked,
} from "./release-artifact.mjs";
import { normalizeReleaseCliArguments } from "./release-cli-arguments.mjs";
import { readBoundedRegularFile } from "./release-input-file.mjs";
import { verifyReleaseRecipeInputEvidenceAttachment } from "./release-recipe-input-evidence.mjs";
import { verifyStaticInputEvidenceAttachment } from "./static-input-evidence.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(appDirectory, "../..");
const releaseDirectory = join(appDirectory, "release");
const execFile = promisify(execFileCallback);
const MAX_UPLOAD_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_UPLOAD_ARTIFACT_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_UPLOAD_EVIDENCE_BYTES = 256 * 1024 * 1024;
const TEMPORARY_ARCHIVE_COMPARE_CHUNK_BYTES = 64 * 1024;
const TEMPORARY_ARCHIVE_CHANGED_MESSAGE =
  "temporary archive bytes changed during independent unzip -t validation";
const INFO_ZIP_ENVIRONMENT = Object.freeze({
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
});

function fail(message) {
  throw new Error(`extension release verify: ${message}`);
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

async function verifyArchiveWithInfoZip(archiveBytes) {
  let temporaryDirectory;
  let temporaryArchiveReadHandle;
  let temporaryArchiveWriteHandle;
  let validationError;
  try {
    temporaryDirectory = await mkdtemp(join(tmpdir(), "warden-release-unzip-"));
    const temporaryArchivePath = join(temporaryDirectory, "archive.zip");
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
      throw new Error("temporary archive byte count differs from the stable archive");
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
      throw new Error("temporary archive read handle differs from the synced writer");
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
      throw new Error("temporary archive read-only seal differs from the synced archive");
    }
    await unlink(temporaryArchivePath);
    const descriptorPath = `/proc/${process.pid}/fd/${temporaryArchiveReadHandle.fd}`;
    await execFile("unzip", ["-t", descriptorPath], {
      cwd: temporaryDirectory,
      encoding: "utf8",
      env: INFO_ZIP_ENVIRONMENT,
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

  const defaultArchive = join(releaseDirectory, `warden-extension-${version}.zip`);
  const defaultArtifactManifest = join(releaseDirectory, `warden-extension-${version}.artifact.json`);
  const defaultDependencyEvidence = join(releaseDirectory, `warden-extension-${version}.sbom.json`);
  const defaultBundleInputEvidence = join(releaseDirectory, `warden-extension-${version}.bundle-inputs.json`);
  const defaultStaticInputEvidence = join(releaseDirectory, `warden-extension-${version}.static-inputs.json`);
  const defaultReleaseRecipeInputEvidence = join(releaseDirectory, `warden-extension-${version}.recipe-inputs.json`);
  const args = normalizeReleaseCliArguments(process.argv.slice(2));
  if (![0, 6, 7].includes(args.length)) {
    fail("usage: verify-release.mjs [candidate.zip artifact.json dependency-evidence.json bundle-input-evidence.json static-input-evidence.json recipe-input-evidence.json [unpacked-directory]]");
  }
  const archivePath = resolve(args[0] ?? defaultArchive);
  const artifactManifestPath = resolve(args[1] ?? defaultArtifactManifest);
  const dependencyEvidencePath = resolve(args[2] ?? defaultDependencyEvidence);
  const bundleInputEvidencePath = resolve(args[3] ?? defaultBundleInputEvidence);
  const staticInputEvidencePath = resolve(args[4] ?? defaultStaticInputEvidence);
  const releaseRecipeInputEvidencePath = resolve(args[5] ?? defaultReleaseRecipeInputEvidence);
  const unpackedPath = args[6] === undefined
    ? (args.length === 0 ? join(releaseDirectory, "unpacked") : undefined)
    : resolve(args[6]);

  const archiveBytes = await readBoundedRegularFile(
    archivePath,
    MAX_UPLOAD_ARCHIVE_BYTES,
    "upload archive",
  );
  const artifactManifest = parseArtifactManifest(await readBoundedRegularFile(
    artifactManifestPath,
    MAX_UPLOAD_ARTIFACT_MANIFEST_BYTES,
    "artifact manifest",
  ));
  const dependencyEvidenceBytes = await readBoundedRegularFile(
    dependencyEvidencePath,
    MAX_UPLOAD_EVIDENCE_BYTES,
    "dependency evidence",
  );
  const bundleInputEvidenceBytes = await readBoundedRegularFile(
    bundleInputEvidencePath,
    MAX_UPLOAD_EVIDENCE_BYTES,
    "bundle input evidence",
  );
  const staticInputEvidenceBytes = await readBoundedRegularFile(
    staticInputEvidencePath,
    MAX_UPLOAD_EVIDENCE_BYTES,
    "static input evidence",
  );
  const releaseRecipeInputEvidenceBytes = await readBoundedRegularFile(
    releaseRecipeInputEvidencePath,
    MAX_UPLOAD_EVIDENCE_BYTES,
    "release recipe input evidence",
  );
  const verified = verifyArtifactArchive({ archiveBytes, artifactManifest });
  const dependencyEvidence = verifyProductionDependencyEvidenceAttachment({
    evidenceBytes: dependencyEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  const bundleInputEvidence = verifyJavaScriptBundleInputEvidenceAttachment({
    evidenceBytes: bundleInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  const staticInputEvidence = verifyStaticInputEvidenceAttachment({
    evidenceBytes: staticInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  const releaseRecipeInputEvidence = await verifyReleaseRecipeInputEvidenceAttachment({
    evidenceBytes: releaseRecipeInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
    repositoryRoot,
  });
  await verifyArchiveWithInfoZip(archiveBytes);
  if (unpackedPath !== undefined) {
    const unpacked = await verifyCanonicalUnpacked({
      rootDirectory: unpackedPath,
      artifactManifest,
    });
    if (
      unpacked.archiveSha256 !== verified.archiveSha256 ||
      unpacked.treeSha256 !== verified.treeSha256 ||
      unpacked.files !== verified.files
    ) {
      fail("canonical unpacked verification disagrees with archive verification");
    }
  }

  console.log(`verified ${archivePath}`);
  console.log(`against ${artifactManifestPath}`);
  console.log(`dependency evidence ${dependencyEvidencePath}`);
  console.log(`bundle input evidence ${bundleInputEvidencePath}`);
  console.log(`static input evidence ${staticInputEvidencePath}`);
  console.log(`release recipe input evidence ${releaseRecipeInputEvidencePath}`);
  console.log(`source ${artifactManifest.source.gitCommit}`);
  console.log(`files ${verified.files}`);
  console.log(`payload tree sha256 ${verified.treeSha256}`);
  console.log(`archive sha256 ${verified.archiveSha256}`);
  console.log(`production dependency components ${dependencyEvidence.components}`);
  console.log(`JavaScript bundles ${bundleInputEvidence.bundles}`);
  console.log(`JavaScript bundle inputs ${bundleInputEvidence.inputs}`);
  console.log(`static input files ${staticInputEvidence.files}`);
  console.log(`release recipe input files ${releaseRecipeInputEvidence.inputs}`);
  console.log("independent ZIP reader unzip -t passed");
  console.log(unpackedPath === undefined ? "unpacked tree not requested" : `unpacked ${unpackedPath}`);
}

await main();
