import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { parseLocalDualReleaseReport } from "../../../scripts/local-dual-extension-release.mjs";
import {
  parseArtifactManifest,
  verifyArtifactArchive,
} from "./release-artifact.mjs";
import { verifyStorePackage } from "./store-package.mjs";

const GIT_EXECUTABLE = "/usr/bin/git";
const GPG_LAUNCHER_PREFIX = "warden-release-source-gpg-launcher-";
export const RELEASE_TAG_MESSAGE_SCHEMA = "warden.extension-release-tag.v1";
const OPENPGP_SIGNATURE_BEGIN = "-----BEGIN PGP SIGNATURE-----\n";
const OPENPGP_SIGNATURE_END = "-----END PGP SIGNATURE-----\n";
export const GIT_GPG_LAUNCHER_MODE = 0o700;
export const GIT_GPG_LAUNCHER_TEXT = [
  "#!/bin/sh",
  "set -eu",
  "exec /usr/bin/gpg \\",
  "  --no-options \\",
  "  --homedir \"$GNUPGHOME\" \\",
  "  --batch \\",
  "  --no-tty \\",
  "  --no-auto-key-import \\",
  "  --no-auto-key-retrieve \\",
  "  --auto-key-locate clear \\",
  "  \"$@\"",
  "",
].join("\n");
const MAX_TAG_OBJECT_BYTES = 1024 * 1024;
export const MAX_DUAL_RELEASE_REPORT_BYTES = 1024 * 1024;
export const MAX_ARTIFACT_MANIFEST_BYTES = 8 * 1024 * 1024;
export const MAX_ARTIFACT_REVIEW_SIGNATURE_BYTES = 1024 * 1024;
const MAX_OPENPGP_TIME_VALUE = 0xffff_ffff;
const FULL_SHA1_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}(?:[0-9A-F]{24})?$/;
export const OPENPGP_RELEASE_SIGNATURE_POLICY = Object.freeze({
  signatureVersions: Object.freeze([4, 6]),
  publicKeyAlgorithms: Object.freeze([1, 19, 22, 27, 28]),
  hashAlgorithms: Object.freeze([8, 9, 10]),
  signatureClass: "00",
});
const ALLOWED_PUBLIC_KEY_ALGORITHMS = new Set(
  OPENPGP_RELEASE_SIGNATURE_POLICY.publicKeyAlgorithms,
);
const ALLOWED_HASH_ALGORITHMS = new Set(
  OPENPGP_RELEASE_SIGNATURE_POLICY.hashAlgorithms,
);
const ALLOWED_SIGNATURE_VERSIONS = new Set(
  OPENPGP_RELEASE_SIGNATURE_POLICY.signatureVersions,
);
const TERMINAL_SIGNATURE_STATUSES = new Set([
  "GOODSIG",
  "BADSIG",
  "EXPSIG",
  "EXPKEYSIG",
  "REVKEYSIG",
  "ERRSIG",
]);
const REFUSAL_STATUSES = new Set([
  "BADSIG",
  "EXPSIG",
  "EXPKEYSIG",
  "REVKEYSIG",
  "ERRSIG",
  "NO_PUBKEY",
  "NODATA",
  "BADARMOR",
  "FAILURE",
  "ERROR",
]);

function fail(message) {
  throw new Error(`extension release source tag: ${message}`);
}

function openPgpFail(message) {
  throw new Error(`OpenPGP verification: ${message}`);
}

export function normalizeOpenPgpFingerprint(value, label) {
  if (typeof value !== "string" || value !== value.trim()) {
    openPgpFail(`${label} must be an unspaced full OpenPGP fingerprint`);
  }
  const normalized = value.toUpperCase();
  if (!FINGERPRINT_PATTERN.test(normalized)) {
    openPgpFail(`${label} must be a 40- or 64-character full OpenPGP fingerprint`);
  }
  return normalized;
}

function assertFullSha1(value, label) {
  if (typeof value !== "string" || !FULL_SHA1_PATTERN.test(value)) {
    fail(`${label} must be a full lowercase 40-character Git object SHA`);
  }
}

async function verifyExpectedArtifactReview({
  artifactManifestBytes,
  dualReleaseReportBytes,
  expectedDualReleaseReportSha256,
  artifactReviewSignatureBytes,
  expectedArtifactReviewSignatureSha256,
  expectedArtifactReviewPrimaryFingerprint,
  expectedArtifactReviewSigningFingerprint,
  environment,
}) {
  const suppliedValues = [
    artifactReviewSignatureBytes,
    expectedArtifactReviewSignatureSha256,
    expectedArtifactReviewPrimaryFingerprint,
    expectedArtifactReviewSigningFingerprint,
  ];
  const suppliedCount = suppliedValues.filter((value) => value !== undefined).length;
  if (suppliedCount === 0) {
    return null;
  }
  if (suppliedCount !== suppliedValues.length) {
    fail("artifact review signature bytes, SHA-256, and primary/signing fingerprints must be provided together");
  }
  if (
    dualReleaseReportBytes === undefined ||
    expectedDualReleaseReportSha256 === undefined
  ) {
    fail("artifact review signature requires the exact dual release report binding");
  }
  if (!(artifactManifestBytes instanceof Uint8Array)) {
    fail("exact artifact manifest bytes are required with an artifact review signature");
  }
  if (!(artifactReviewSignatureBytes instanceof Uint8Array)) {
    fail("artifact review signature must be byte data");
  }
  const signatureBytes = Buffer.from(artifactReviewSignatureBytes);
  if (
    signatureBytes.length === 0 ||
    signatureBytes.length > MAX_ARTIFACT_REVIEW_SIGNATURE_BYTES
  ) {
    fail(
      `artifact review signature must be between 1 and ${MAX_ARTIFACT_REVIEW_SIGNATURE_BYTES} bytes`,
    );
  }
  if (
    typeof expectedArtifactReviewSignatureSha256 !== "string" ||
    !SHA256_PATTERN.test(expectedArtifactReviewSignatureSha256)
  ) {
    fail("expected artifact review signature SHA-256 must be a lowercase digest");
  }
  const actualSignatureSha256 = createHash("sha256")
    .update(signatureBytes)
    .digest("hex");
  if (actualSignatureSha256 !== expectedArtifactReviewSignatureSha256) {
    fail("artifact review signature differs from the independently supplied SHA-256");
  }
  const { verifyReviewedArtifactSignature } = await import(
    "./reviewed-artifact-signature.mjs"
  );
  const verified = await verifyReviewedArtifactSignature({
    artifactBytes: artifactManifestBytes,
    signatureBytes,
    expectedPrimaryFingerprint: expectedArtifactReviewPrimaryFingerprint,
    expectedSigningFingerprint: expectedArtifactReviewSigningFingerprint,
    environment,
  });
  if (verified.signatureSha256 !== expectedArtifactReviewSignatureSha256) {
    fail("artifact review verifier returned a different signature digest");
  }
  return verified;
}

function verifyExpectedStorePackage({
  artifactManifestBytes,
  artifactReview,
  reviewedUploadArchiveBytes,
  storePackageBytes,
  expectedStorePackageSha256,
  expectedStoreExtensionId,
  requiredStorePublisherKeySha256,
}) {
  const suppliedValues = [
    reviewedUploadArchiveBytes,
    storePackageBytes,
    expectedStorePackageSha256,
    expectedStoreExtensionId,
  ];
  const suppliedCount = suppliedValues.filter((value) => value !== undefined).length;
  if (suppliedCount === 0 && requiredStorePublisherKeySha256 === undefined) {
    return null;
  }
  if (suppliedCount !== suppliedValues.length) {
    fail("reviewed upload archive, store package, SHA-256, and expected extension id must be provided together");
  }
  if (artifactReview === null) {
    fail("store package verification requires the exact artifact review binding");
  }
  if (!(artifactManifestBytes instanceof Uint8Array)) {
    fail("exact artifact manifest bytes are required with a store package");
  }
  if (!(reviewedUploadArchiveBytes instanceof Uint8Array)) {
    fail("reviewed upload archive must be byte data");
  }
  if (!(storePackageBytes instanceof Uint8Array)) {
    fail("store package must be byte data");
  }
  if (
    typeof expectedStorePackageSha256 !== "string" ||
    !SHA256_PATTERN.test(expectedStorePackageSha256)
  ) {
    fail("expected store package SHA-256 must be a lowercase digest");
  }
  const actualStorePackageSha256 = createHash("sha256")
    .update(storePackageBytes)
    .digest("hex");
  if (actualStorePackageSha256 !== expectedStorePackageSha256) {
    fail("store package differs from the independently supplied SHA-256");
  }

  const exactArtifactManifest = parseArtifactManifest(artifactManifestBytes);
  let approved;
  try {
    approved = verifyArtifactArchive({
      archiveBytes: reviewedUploadArchiveBytes,
      artifactManifest: exactArtifactManifest,
    });
  } catch (error) {
    fail(
      `reviewed upload archive verification failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  let verified;
  try {
    verified = verifyStorePackage({
      crxBytes: storePackageBytes,
      artifactManifest: exactArtifactManifest,
      expectedExtensionId: expectedStoreExtensionId,
      requiredPublisherKeySha256: requiredStorePublisherKeySha256,
    });
  } catch (error) {
    fail(
      `store package verification failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (verified.treeSha256 !== approved.treeSha256 || verified.files !== approved.files) {
    fail("store package and reviewed upload verification disagree");
  }
  if (verified.packageSha256 !== expectedStorePackageSha256) {
    fail("store package verifier returned a different package digest");
  }
  return {
    artifactManifestSha256: artifactReview.artifactSha256,
    reviewedUploadArchiveSha256: approved.archiveSha256,
    packageBytes: verified.packageBytes,
    packageSha256: verified.packageSha256,
    headerBytes: verified.headerBytes,
    headerSha256: verified.headerSha256,
    embeddedArchiveBytes: verified.archiveBytes.length,
    embeddedArchiveSha256: verified.archiveSha256,
    extensionId: verified.extensionId,
    publisherKeySha256: verified.publisherKeySha256,
    files: verified.files,
    treeSha256: verified.treeSha256,
  };
}

function verifyExpectedDualReleaseReport({
  dualReleaseReportBytes,
  expectedDualReleaseReportSha256,
  artifactManifest,
  artifactManifestBytes,
}) {
  const reportSupplied = dualReleaseReportBytes !== undefined;
  const digestSupplied = expectedDualReleaseReportSha256 !== undefined;
  if (reportSupplied !== digestSupplied) {
    fail("dual release report bytes and independently supplied SHA-256 must be provided together");
  }
  if (!reportSupplied) {
    return null;
  }
  if (!(artifactManifestBytes instanceof Uint8Array)) {
    fail("exact artifact manifest bytes are required with a dual release report");
  }
  if (!(dualReleaseReportBytes instanceof Uint8Array)) {
    fail("dual release report must be byte data");
  }
  const reportBytes = Buffer.from(dualReleaseReportBytes);
  if (
    reportBytes.length === 0 ||
    reportBytes.length > MAX_DUAL_RELEASE_REPORT_BYTES
  ) {
    fail(
      `dual release report must be between 1 and ${MAX_DUAL_RELEASE_REPORT_BYTES} bytes`,
    );
  }
  if (
    typeof expectedDualReleaseReportSha256 !== "string" ||
    !SHA256_PATTERN.test(expectedDualReleaseReportSha256)
  ) {
    fail("expected dual release report SHA-256 must be a lowercase digest");
  }
  const actualSha256 = createHash("sha256").update(reportBytes).digest("hex");
  if (actualSha256 !== expectedDualReleaseReportSha256) {
    fail("dual release report differs from the independently supplied SHA-256");
  }

  const report = parseLocalDualReleaseReport(reportBytes);
  const exactArtifactBytes = Buffer.from(artifactManifestBytes);
  if (
    exactArtifactBytes.length === 0 ||
    exactArtifactBytes.length > MAX_ARTIFACT_MANIFEST_BYTES
  ) {
    fail(
      `artifact manifest must be between 1 and ${MAX_ARTIFACT_MANIFEST_BYTES} bytes`,
    );
  }
  const exactArtifactManifest = parseArtifactManifest(exactArtifactBytes);
  if (exactArtifactManifest.source.gitCommit !== artifactManifest?.source?.gitCommit) {
    fail("exact artifact manifest bytes differ from the supplied artifact source commit");
  }
  if (report.source.gitCommit !== exactArtifactManifest.source.gitCommit) {
    fail("dual release report source differs from the artifact source commit");
  }
  const artifactVersion = exactArtifactManifest.extension.version;
  if (report.source.extensionVersion !== artifactVersion) {
    fail("dual release report extension version differs from the artifact extension version");
  }

  const attachmentClaims = [
    ["dependency evidence", exactArtifactManifest.dependencyEvidence],
    ["bundle input evidence", exactArtifactManifest.bundleInputEvidence],
    ["static input evidence", exactArtifactManifest.staticInputEvidence],
    ["release recipe input evidence", exactArtifactManifest.releaseRecipeInputEvidence],
  ];
  const artifactManifestSha256 = createHash("sha256")
    .update(exactArtifactBytes)
    .digest("hex");
  const expectedFiles = [
    {
      label: "artifact manifest",
      path: `release/warden-extension-${artifactVersion}.artifact.json`,
      bytes: exactArtifactBytes.length,
      sha256: artifactManifestSha256,
    },
    {
      label: "archive",
      path: `release/${exactArtifactManifest.archive.file}`,
      bytes: exactArtifactManifest.archive.bytes,
      sha256: exactArtifactManifest.archive.sha256,
    },
    ...attachmentClaims.map(([label, attachment]) => ({
      label,
      path: `release/${attachment.file}`,
      bytes: attachment.bytes,
      sha256: attachment.sha256,
    })),
    ...exactArtifactManifest.payload.files.map((file) => ({
      label: `unpacked payload ${file.path}`,
      path: `release/unpacked/${file.path}`,
      bytes: file.bytes,
      sha256: file.sha256,
    })),
  ].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  if (expectedFiles.length !== 14) {
    fail("artifact manifest does not declare the reviewed fourteen-file release set");
  }
  for (let index = 0; index < expectedFiles.length; index += 1) {
    const expected = expectedFiles[index];
    const actual = report.comparison.files[index];
    if (
      actual.path !== expected.path ||
      actual.bytes !== expected.bytes ||
      actual.sha256 !== expected.sha256
    ) {
      fail(`dual release report ${expected.label} record differs from the exact artifact manifest`);
    }
  }
  return {
    sha256: actualSha256,
    sourceCommit: report.source.gitCommit,
    extensionVersion: report.source.extensionVersion,
    comparisonFileCount: report.comparison.fileCount,
    artifactManifestSha256,
    boundReleaseFileCount: expectedFiles.length,
    scope: { ...report.scope },
  };
}

function countStatus(statuses, keyword) {
  return statuses.filter((status) => status.keyword === keyword).length;
}

function parseCanonicalOpenPgpOctet(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,2})$/.test(value)) {
    openPgpFail(`${label} must be a canonical decimal octet`);
  }
  const parsed = Number(value);
  if (parsed > 255) {
    openPgpFail(`${label} must be a canonical decimal octet`);
  }
  return parsed;
}

function utcTimestampFromParts(parts, label, maximum) {
  const [year, month, day, hour, minute, second] = parts.map(Number);
  const milliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(milliseconds);
  const timestamp = milliseconds / 1000;
  if (
    !Number.isInteger(timestamp) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    timestamp < 0 ||
    timestamp > maximum
  ) {
    openPgpFail(`${label} must be a valid UTC time in the allowed OpenPGP range`);
  }
  return timestamp;
}

function parseOpenPgpStatusTimestamp(value, label, maximum) {
  if (typeof value !== "string") {
    openPgpFail(
      `${label} must be canonical decimal epoch seconds or a basic ISO 8601 UTC time`,
    );
  }
  if (/^(?:0|[1-9][0-9]{0,9})$/.test(value)) {
    const timestamp = Number(value);
    if (timestamp <= maximum) {
      return timestamp;
    }
    openPgpFail(`${label} is outside the allowed OpenPGP range`);
  }
  const basicIso = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})$/.exec(value);
  if (!basicIso) {
    openPgpFail(
      `${label} must be canonical decimal epoch seconds or a basic ISO 8601 UTC time`,
    );
  }
  return utcTimestampFromParts(basicIso.slice(1), label, maximum);
}

function parseOpenPgpCreationDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) {
    openPgpFail("VALIDSIG creation date must be a canonical UTC YYYY-MM-DD date");
  }
  utcTimestampFromParts(
    [...match.slice(1), "0", "0", "0"],
    "VALIDSIG creation date",
    MAX_OPENPGP_TIME_VALUE,
  );
  return value;
}

function openPgpUtcDate(timestamp) {
  return new Date(timestamp * 1000).toISOString().slice(0, 10);
}

function goodSignatureIdentityMatches(signingFingerprint, value) {
  if (typeof value !== "string") {
    return false;
  }
  const identity = value.toUpperCase();
  if (identity === signingFingerprint) {
    return true;
  }
  if (!/^[0-9A-F]{16}$/.test(identity)) {
    return false;
  }
  return signingFingerprint.length === 40
    ? signingFingerprint.endsWith(identity)
    : signingFingerprint.startsWith(identity);
}

export function parseSingleOpenPgpSignatureStatus(
  statusText,
  expectedPrimaryFingerprintValue,
  expectedSigningFingerprintValue,
) {
  if (typeof statusText !== "string") {
    openPgpFail("machine status must be text");
  }
  const expectedPrimaryFingerprint = normalizeOpenPgpFingerprint(
    expectedPrimaryFingerprintValue,
    "expected primary fingerprint",
  );
  const expectedSigningFingerprint = normalizeOpenPgpFingerprint(
    expectedSigningFingerprintValue,
    "expected signing fingerprint",
  );
  const statuses = [];
  for (const line of statusText.split("\n")) {
    if (line.length === 0) {
      continue;
    }
    const prefix = "[GNUPG:] ";
    if (!line.startsWith(prefix)) {
      openPgpFail("machine-status channel emitted non-status output");
    }
    const status = line.slice(prefix.length);
    const separator = status.indexOf(" ");
    const keyword = separator === -1 ? status : status.slice(0, separator);
    const argumentsText = separator === -1 ? "" : status.slice(separator + 1);
    if (!/^[A-Z][A-Z0-9_]*$/.test(keyword)) {
      openPgpFail("GnuPG emitted an invalid status keyword");
    }
    statuses.push({ keyword, argumentsText });
  }
  if (statuses.length === 0) {
    openPgpFail("GnuPG emitted no machine status");
  }
  const refused = statuses.find((status) => REFUSAL_STATUSES.has(status.keyword));
  if (refused) {
    openPgpFail(`GnuPG refused the signature with ${refused.keyword}`);
  }
  if (countStatus(statuses, "NEWSIG") !== 1) {
    openPgpFail("GnuPG status must describe exactly one signature");
  }
  const terminalStatuses = statuses.filter((status) =>
    TERMINAL_SIGNATURE_STATUSES.has(status.keyword));
  if (terminalStatuses.length !== 1 || terminalStatuses[0].keyword !== "GOODSIG") {
    openPgpFail("GnuPG status must contain exactly one successful signature result");
  }
  const validSignatures = statuses.filter((status) => status.keyword === "VALIDSIG");
  if (validSignatures.length !== 1) {
    openPgpFail("GnuPG status must contain exactly one cryptographic VALIDSIG result");
  }
  const validArguments = validSignatures[0].argumentsText.split(" ").filter(Boolean);
  if (validArguments.length !== 10) {
    openPgpFail("GnuPG OpenPGP VALIDSIG status must contain exactly ten arguments");
  }
  const signingFingerprint = normalizeOpenPgpFingerprint(
    validArguments[0],
    "VALIDSIG signing fingerprint",
  );
  if (signingFingerprint !== expectedSigningFingerprint) {
    openPgpFail(
      "VALIDSIG signing fingerprint differs from the independently supplied signing key",
    );
  }
  const signatureCreationDate = parseOpenPgpCreationDate(validArguments[1]);
  const signatureTimestamp = parseOpenPgpStatusTimestamp(
    validArguments[2],
    "VALIDSIG creation timestamp",
    MAX_OPENPGP_TIME_VALUE,
  );
  if (signatureCreationDate !== openPgpUtcDate(signatureTimestamp)) {
    openPgpFail("VALIDSIG creation date differs from its UTC creation timestamp");
  }
  const parsedExpirationTimestamp = parseOpenPgpStatusTimestamp(
    validArguments[3],
    "VALIDSIG expiration timestamp",
    signatureTimestamp + MAX_OPENPGP_TIME_VALUE,
  );
  const signatureExpirationTimestamp = parsedExpirationTimestamp === 0
    ? null
    : parsedExpirationTimestamp;
  if (
    signatureExpirationTimestamp !== null &&
    signatureExpirationTimestamp <= signatureTimestamp
  ) {
    openPgpFail("VALIDSIG expiration timestamp must be after its creation timestamp");
  }
  const signatureVersion = parseCanonicalOpenPgpOctet(
    validArguments[4],
    "VALIDSIG signature version",
  );
  if (!ALLOWED_SIGNATURE_VERSIONS.has(signatureVersion)) {
    openPgpFail(`VALIDSIG signature version ${signatureVersion} is not allowed`);
  }
  if (validArguments[5] !== "0") {
    openPgpFail("VALIDSIG reserved field must be zero");
  }
  const publicKeyAlgorithm = parseCanonicalOpenPgpOctet(
    validArguments[6],
    "VALIDSIG public-key algorithm",
  );
  if (!ALLOWED_PUBLIC_KEY_ALGORITHMS.has(publicKeyAlgorithm)) {
    openPgpFail(`VALIDSIG public-key algorithm ${publicKeyAlgorithm} is not allowed`);
  }
  const hashAlgorithm = parseCanonicalOpenPgpOctet(
    validArguments[7],
    "VALIDSIG hash algorithm",
  );
  if (!ALLOWED_HASH_ALGORITHMS.has(hashAlgorithm)) {
    openPgpFail(`VALIDSIG hash algorithm ${hashAlgorithm} is not allowed`);
  }
  const signatureClass = validArguments[8].toUpperCase();
  if (!/^[0-9A-F]{2}$/.test(signatureClass)) {
    openPgpFail("VALIDSIG signature class must be exactly one hexadecimal octet");
  }
  if (signatureClass !== OPENPGP_RELEASE_SIGNATURE_POLICY.signatureClass) {
    openPgpFail(`VALIDSIG signature class ${signatureClass} is not allowed`);
  }
  const primaryFingerprint = normalizeOpenPgpFingerprint(
    validArguments[9],
    "VALIDSIG primary fingerprint",
  );
  if (primaryFingerprint !== expectedPrimaryFingerprint) {
    openPgpFail(
      "VALIDSIG primary fingerprint differs from the independently supplied primary key",
    );
  }
  const goodSignatureIdentity = terminalStatuses[0].argumentsText.split(" ")[0];
  if (!goodSignatureIdentityMatches(signingFingerprint, goodSignatureIdentity)) {
    openPgpFail("GOODSIG identity differs from the VALIDSIG signing fingerprint");
  }
  return {
    signingFingerprint,
    primaryFingerprint,
    signatureCreationDate,
    signatureTimestamp,
    signatureExpirationTimestamp,
    signatureVersion,
    publicKeyAlgorithm,
    hashAlgorithm,
    signatureClass,
  };
}

function executeGit(arguments_, { repositoryRoot, environment, allowFailure = false }) {
  return new Promise((resolve, reject) => {
    execFileCallback(
      GIT_EXECUTABLE,
      arguments_,
      {
        cwd: repositoryRoot,
        env: environment,
        encoding: "utf8",
        maxBuffer: MAX_TAG_OBJECT_BYTES + 64 * 1024,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const numericExitCode = typeof error?.code === "number" ? error.code : null;
        if (error && numericExitCode === null) {
          reject(error);
          return;
        }
        if (error && !allowFailure) {
          reject(error);
          return;
        }
        resolve({
          exitCode: numericExitCode ?? 0,
          stdout,
          stderr,
        });
      },
    );
  });
}

function verificationEnvironment(gnupgHome) {
  const sanitized = {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
  };
  sanitized.GNUPGHOME = gnupgHome;
  return sanitized;
}

async function createPrivateGitGpgLauncher() {
  const directory = await mkdtemp(join(tmpdir(), GPG_LAUNCHER_PREFIX));
  const path = join(directory, "gpg");
  try {
    await chmod(directory, GIT_GPG_LAUNCHER_MODE);
    await writeFile(path, GIT_GPG_LAUNCHER_TEXT, {
      flag: "wx",
      mode: GIT_GPG_LAUNCHER_MODE,
    });
    await chmod(path, GIT_GPG_LAUNCHER_MODE);
    const [directoryMetadata, launcherMetadata] = await Promise.all([
      stat(directory),
      stat(path),
    ]);
    if (
      !directoryMetadata.isDirectory() ||
      (directoryMetadata.mode & 0o777) !== GIT_GPG_LAUNCHER_MODE ||
      !launcherMetadata.isFile() ||
      (launcherMetadata.mode & 0o777) !== GIT_GPG_LAUNCHER_MODE
    ) {
      fail("private GnuPG launcher permissions differ from mode 0700");
    }
    return { directory, path };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

export async function requireExplicitGnuPgHome(environment) {
  const gnupgHome = (environment ?? process.env).GNUPGHOME;
  if (
    typeof gnupgHome !== "string" ||
    gnupgHome.length === 0 ||
    gnupgHome !== gnupgHome.trim() ||
    !isAbsolute(gnupgHome)
  ) {
    openPgpFail("GNUPGHOME must explicitly select an existing absolute verification keyring directory");
  }
  let metadata;
  let canonicalHome;
  try {
    [metadata, canonicalHome] = await Promise.all([stat(gnupgHome), realpath(gnupgHome)]);
  } catch (error) {
    openPgpFail(`GNUPGHOME is unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!metadata.isDirectory()) {
    openPgpFail("GNUPGHOME must select a directory");
  }
  return canonicalHome;
}

async function requireGitSuccess(arguments_, options, label) {
  try {
    return await executeGit(arguments_, options);
  } catch (error) {
    fail(`${label} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function parseAnnotatedTagObject(
  tagObjectText,
  expectedTagName,
  expectedArtifactManifestSha256,
) {
  const headerEnd = tagObjectText.indexOf("\n\n");
  if (headerEnd === -1) {
    fail("annotated tag object has no message boundary");
  }
  const headers = tagObjectText.slice(0, headerEnd).split("\n");
  const parsed = new Map();
  for (const header of headers) {
    const separator = header.indexOf(" ");
    if (separator <= 0) {
      fail("annotated tag object contains a malformed header");
    }
    const name = header.slice(0, separator);
    if (parsed.has(name)) {
      fail(`annotated tag object contains duplicate ${name} headers`);
    }
    parsed.set(name, header.slice(separator + 1));
  }
  if (
    parsed.size !== 4 ||
    !parsed.has("object") ||
    !parsed.has("type") ||
    !parsed.has("tag") ||
    !parsed.has("tagger")
  ) {
    fail("annotated tag object must contain exactly object/type/tag/tagger headers");
  }
  const targetCommit = parsed.get("object");
  assertFullSha1(targetCommit, "annotated tag target");
  if (parsed.get("type") !== "commit") {
    fail("annotated release tag must point directly to a commit");
  }
  if (parsed.get("tag") !== expectedTagName) {
    fail("annotated tag object's name differs from the exact selected tag ref");
  }
  if (parsed.get("tagger").length === 0) {
    fail("annotated tag object has an empty tagger");
  }
  const body = tagObjectText.slice(headerEnd + 2);
  const signatureOffset = body.indexOf(OPENPGP_SIGNATURE_BEGIN);
  if (
    signatureOffset <= 0 ||
    body.indexOf(OPENPGP_SIGNATURE_BEGIN, signatureOffset + 1) !== -1 ||
    !body.endsWith(OPENPGP_SIGNATURE_END) ||
    body.indexOf(OPENPGP_SIGNATURE_END) !==
      body.length - OPENPGP_SIGNATURE_END.length
  ) {
    fail("annotated tag message must bind the exact artifact manifest SHA-256");
  }
  const messageLines = body.slice(0, signatureOffset).split("\n");
  if (
    messageLines.length !== 3 ||
    messageLines[0] !== RELEASE_TAG_MESSAGE_SCHEMA ||
    messageLines[2] !== "" ||
    !messageLines[1].startsWith("artifact-manifest-sha256 ")
  ) {
    fail("annotated tag message must bind the exact artifact manifest SHA-256");
  }
  const signedArtifactManifestSha256 = messageLines[1].slice(
    "artifact-manifest-sha256 ".length,
  );
  if (!SHA256_PATTERN.test(signedArtifactManifestSha256)) {
    fail("annotated tag message must bind the exact artifact manifest SHA-256");
  }
  if (signedArtifactManifestSha256 !== expectedArtifactManifestSha256) {
    fail("annotated tag message artifact manifest SHA-256 differs from the exact artifact");
  }
  return { targetCommit, signedArtifactManifestSha256 };
}

async function resolveExactTagRef(tagName, options) {
  const ref = `refs/tags/${tagName}`;
  const checked = await executeGit(["check-ref-format", ref], {
    ...options,
    allowFailure: true,
  });
  if (checked.exitCode !== 0 || checked.stdout !== "" || checked.stderr !== "") {
    fail("selected tag name is not an exact valid Git tag ref");
  }
  const resolved = await executeGit(["show-ref", "--verify", "--hash", ref], {
    ...options,
    allowFailure: true,
  });
  if (resolved.exitCode !== 0 || resolved.stderr !== "") {
    fail("selected tag ref does not exist exactly once");
  }
  const lines = resolved.stdout.trimEnd().split("\n");
  if (lines.length !== 1 || !FULL_SHA1_PATTERN.test(lines[0])) {
    fail("selected tag ref resolved ambiguously or not to a full SHA-1 object id");
  }
  return { ref, objectSha: lines[0] };
}

export async function verifyReleaseSourceTag({
  repositoryRoot,
  tagName,
  expectedTagObject,
  expectedPrimaryFingerprint,
  expectedSigningFingerprint,
  artifactManifest,
  artifactManifestBytes,
  expectedArtifactManifestSha256,
  dualReleaseReportBytes,
  expectedDualReleaseReportSha256,
  artifactReviewSignatureBytes,
  expectedArtifactReviewSignatureSha256,
  expectedArtifactReviewPrimaryFingerprint,
  expectedArtifactReviewSigningFingerprint,
  reviewedUploadArchiveBytes,
  storePackageBytes,
  expectedStorePackageSha256,
  expectedStoreExtensionId,
  requiredStorePublisherKeySha256,
  environment,
}) {
  if (typeof repositoryRoot !== "string" || repositoryRoot.length === 0) {
    fail("repository root is required");
  }
  if (
    typeof tagName !== "string" ||
    tagName.length === 0 ||
    tagName.length > 256 ||
    tagName !== tagName.trim() ||
    /[\0-\x20\x7f]/.test(tagName)
  ) {
    fail("selected tag name is invalid");
  }
  assertFullSha1(expectedTagObject, "expected tag object");
  const normalizedExpectedPrimaryFingerprint = normalizeOpenPgpFingerprint(
    expectedPrimaryFingerprint,
    "expected primary fingerprint",
  );
  const normalizedExpectedSigningFingerprint = normalizeOpenPgpFingerprint(
    expectedSigningFingerprint,
    "expected signing fingerprint",
  );
  if (
    !(artifactManifestBytes instanceof Uint8Array) ||
    expectedArtifactManifestSha256 === undefined
  ) {
    fail(
      "exact artifact manifest bytes and independently supplied SHA-256 are required",
    );
  }
  if (
    typeof expectedArtifactManifestSha256 !== "string" ||
    !SHA256_PATTERN.test(expectedArtifactManifestSha256)
  ) {
    fail("expected artifact manifest SHA-256 must be a lowercase digest");
  }
  const exactArtifactManifestBytes = Buffer.from(artifactManifestBytes);
  if (
    exactArtifactManifestBytes.length === 0 ||
    exactArtifactManifestBytes.length > MAX_ARTIFACT_MANIFEST_BYTES
  ) {
    fail(
      `artifact manifest must be between 1 and ${MAX_ARTIFACT_MANIFEST_BYTES} bytes`,
    );
  }
  const artifactManifestSha256 = createHash("sha256")
    .update(exactArtifactManifestBytes)
    .digest("hex");
  if (artifactManifestSha256 !== expectedArtifactManifestSha256) {
    fail("artifact manifest differs from the independently supplied SHA-256");
  }
  const exactArtifactManifest = parseArtifactManifest(exactArtifactManifestBytes);
  if (!isDeepStrictEqual(artifactManifest, exactArtifactManifest)) {
    fail("supplied artifact manifest differs from the exact artifact manifest bytes");
  }
  const artifactCommit = exactArtifactManifest.source.gitCommit;
  assertFullSha1(artifactCommit, "artifact source commit");
  const artifactReview = await verifyExpectedArtifactReview({
    artifactManifestBytes: exactArtifactManifestBytes,
    dualReleaseReportBytes,
    expectedDualReleaseReportSha256,
    artifactReviewSignatureBytes,
    expectedArtifactReviewSignatureSha256,
    expectedArtifactReviewPrimaryFingerprint,
    expectedArtifactReviewSigningFingerprint,
    environment,
  });
  const dualReleaseReport = verifyExpectedDualReleaseReport({
    dualReleaseReportBytes,
    expectedDualReleaseReportSha256,
    artifactManifest: exactArtifactManifest,
    artifactManifestBytes: exactArtifactManifestBytes,
  });
  if (
    artifactReview !== null &&
    artifactReview.artifactSha256 !== dualReleaseReport?.artifactManifestSha256
  ) {
    fail("artifact review and dual release report authenticated different manifest bytes");
  }
  const storePackage = verifyExpectedStorePackage({
    artifactManifestBytes: exactArtifactManifestBytes,
    artifactReview,
    reviewedUploadArchiveBytes,
    storePackageBytes,
    expectedStorePackageSha256,
    expectedStoreExtensionId,
    requiredStorePublisherKeySha256,
  });
  const gnupgHome = await requireExplicitGnuPgHome(environment);
  const gitOptions = {
    repositoryRoot,
    environment: verificationEnvironment(gnupgHome),
  };

  const initial = await resolveExactTagRef(tagName, gitOptions);
  if (initial.objectSha !== expectedTagObject) {
    fail("selected tag ref was moved or differs from the independently supplied tag object");
  }
  const objectType = await requireGitSuccess(
    ["cat-file", "-t", expectedTagObject],
    gitOptions,
    "reading selected tag object type",
  );
  if (objectType.stderr !== "" || objectType.stdout !== "tag\n") {
    fail("selected release ref must resolve to an annotated tag object, not a lightweight tag");
  }
  const objectSize = await requireGitSuccess(
    ["cat-file", "-s", expectedTagObject],
    gitOptions,
    "reading selected tag object size",
  );
  const parsedSize = Number(objectSize.stdout.trim());
  if (
    objectSize.stderr !== "" ||
    !Number.isSafeInteger(parsedSize) ||
    parsedSize <= 0 ||
    parsedSize > MAX_TAG_OBJECT_BYTES
  ) {
    fail(`annotated tag object must be between 1 and ${MAX_TAG_OBJECT_BYTES} bytes`);
  }
  const object = await requireGitSuccess(
    ["cat-file", "tag", expectedTagObject],
    gitOptions,
    "reading selected annotated tag object",
  );
  if (object.stderr !== "" || Buffer.byteLength(object.stdout) !== parsedSize) {
    fail("annotated tag object bytes differ from Git's declared object size");
  }
  const { targetCommit, signedArtifactManifestSha256 } = parseAnnotatedTagObject(
    object.stdout,
    tagName,
    artifactManifestSha256,
  );
  if (targetCommit !== artifactCommit) {
    fail("annotated tag target differs from the artifact source commit");
  }

  const launcher = await createPrivateGitGpgLauncher();
  let verification;
  try {
    verification = await executeGit(
      [
        "-c",
        "gpg.format=openpgp",
        "-c",
        `gpg.program=${launcher.path}`,
        "-c",
        `gpg.openpgp.program=${launcher.path}`,
        "verify-tag",
        "--raw",
        expectedTagObject,
      ],
      { ...gitOptions, allowFailure: true },
    );
  } finally {
    await rm(launcher.directory, { recursive: true, force: true });
  }
  if (verification.stdout !== "") {
    fail("git verify-tag --raw unexpectedly emitted stdout");
  }
  const signature = parseSingleOpenPgpSignatureStatus(
    verification.stderr,
    normalizedExpectedPrimaryFingerprint,
    normalizedExpectedSigningFingerprint,
  );
  if (verification.exitCode !== 0) {
    fail(`git verify-tag exited ${verification.exitCode} despite parsed status`);
  }

  const final = await resolveExactTagRef(tagName, gitOptions);
  if (final.objectSha !== expectedTagObject) {
    fail("selected tag ref moved during signature verification");
  }
  const result = {
    tagName,
    tagRef: initial.ref,
    tagObject: expectedTagObject,
    sourceCommit: targetCommit,
    artifactManifestSha256,
    signedArtifactManifestSha256,
    signingFingerprint: signature.signingFingerprint,
    primaryFingerprint: signature.primaryFingerprint,
    signatureCreationDate: signature.signatureCreationDate,
    signatureTimestamp: signature.signatureTimestamp,
    signatureExpirationTimestamp: signature.signatureExpirationTimestamp,
    signatureVersion: signature.signatureVersion,
    publicKeyAlgorithm: signature.publicKeyAlgorithm,
    hashAlgorithm: signature.hashAlgorithm,
    signatureClass: signature.signatureClass,
  };
  if (dualReleaseReport !== null) {
    result.dualReleaseReport = dualReleaseReport;
  }
  if (artifactReview !== null) {
    result.artifactReview = artifactReview;
  }
  if (storePackage !== null) {
    result.storePackage = storePackage;
  }
  return result;
}
