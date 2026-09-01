import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArtifactManifest } from "./release-artifact.mjs";
import { readBoundedRegularFile } from "./release-input-file.mjs";
import {
  MAX_ARTIFACT_MANIFEST_BYTES,
  MAX_ARTIFACT_REVIEW_SIGNATURE_BYTES,
  MAX_DUAL_RELEASE_REPORT_BYTES,
  verifyReleaseSourceTag,
} from "./release-source-tag.mjs";
import { MAX_CRX3_PACKAGE_BYTES } from "./store-package.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(appDirectory, "../..");
const releaseDirectory = join(appDirectory, "release");

function fail(message) {
  throw new Error(`extension release source tag verify: ${message}`);
}

async function main() {
  const args = process.argv.slice(2);
  if (![5, 6, 8, 12, 16].includes(args.length)) {
    fail("usage: verify-release-source-tag.mjs tag expected-tag-object expected-primary-fingerprint expected-signing-fingerprint expected-default-artifact-manifest-sha256 | verify-release-source-tag.mjs tag expected-tag-object expected-primary-fingerprint expected-signing-fingerprint reviewed-artifact.json expected-artifact-manifest-sha256 [dual-local-report.json expected-dual-report-sha256 [artifact-review-signature expected-artifact-review-signature-sha256 expected-artifact-review-primary-fingerprint expected-artifact-review-signing-fingerprint [store-returned.crx expected-store-package-sha256 expected-store-extension-id reviewed-upload.zip]]]");
  }
  const [
    tagName,
    expectedTagObject,
    expectedPrimaryFingerprint,
    expectedSigningFingerprint,
  ] = args;
  let artifactManifestPath;
  let expectedArtifactManifestSha256 = args[4];
  if (args.length >= 6) {
    artifactManifestPath = resolve(args[4]);
    expectedArtifactManifestSha256 = args[5];
  } else {
    const sourceManifest = JSON.parse(await readFile(join(appDirectory, "manifest.json"), "utf8"));
    const version = sourceManifest.version;
    if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
      fail(`invalid source manifest version: ${String(version)}`);
    }
    artifactManifestPath = join(
      releaseDirectory,
      `warden-extension-${version}.artifact.json`,
    );
  }
  if (!/^[0-9a-f]{64}$/.test(expectedArtifactManifestSha256)) {
    fail("expected artifact manifest SHA-256 must be a lowercase digest");
  }
  const artifactManifestBytes = await readBoundedRegularFile(
    artifactManifestPath,
    MAX_ARTIFACT_MANIFEST_BYTES,
    "reviewed artifact manifest",
  );
  const artifactManifestSha256 = createHash("sha256")
    .update(artifactManifestBytes)
    .digest("hex");
  if (
    expectedArtifactManifestSha256 !== undefined &&
    artifactManifestSha256 !== expectedArtifactManifestSha256
  ) {
    fail("reviewed artifact manifest differs from the independently supplied SHA-256");
  }
  const artifactManifest = parseArtifactManifest(artifactManifestBytes);
  let dualReleaseReportPath;
  let dualReleaseReportBytes;
  let expectedDualReleaseReportSha256;
  if (args.length >= 8) {
    dualReleaseReportPath = resolve(args[6]);
    dualReleaseReportBytes = await readBoundedRegularFile(
      dualReleaseReportPath,
      MAX_DUAL_RELEASE_REPORT_BYTES,
      "dual release report",
    );
    expectedDualReleaseReportSha256 = args[7];
  }
  let artifactReviewSignaturePath;
  let artifactReviewSignatureBytes;
  let expectedArtifactReviewSignatureSha256;
  let expectedArtifactReviewPrimaryFingerprint;
  let expectedArtifactReviewSigningFingerprint;
  if (args.length >= 12) {
    artifactReviewSignaturePath = resolve(args[8]);
    artifactReviewSignatureBytes = await readBoundedRegularFile(
      artifactReviewSignaturePath,
      MAX_ARTIFACT_REVIEW_SIGNATURE_BYTES,
      "artifact review signature",
    );
    expectedArtifactReviewSignatureSha256 = args[9];
    expectedArtifactReviewPrimaryFingerprint = args[10];
    expectedArtifactReviewSigningFingerprint = args[11];
  }
  let storePackagePath;
  let storePackageBytes;
  let expectedStorePackageSha256;
  let expectedStoreExtensionId;
  let reviewedUploadArchivePath;
  let reviewedUploadArchiveBytes;
  if (args.length === 16) {
    storePackagePath = resolve(args[12]);
    storePackageBytes = await readBoundedRegularFile(
      storePackagePath,
      MAX_CRX3_PACKAGE_BYTES,
      "store package",
    );
    expectedStorePackageSha256 = args[13];
    expectedStoreExtensionId = args[14];
    reviewedUploadArchivePath = resolve(args[15]);
    reviewedUploadArchiveBytes = await readBoundedRegularFile(
      reviewedUploadArchivePath,
      MAX_CRX3_PACKAGE_BYTES,
      "reviewed upload archive",
    );
  }
  const result = await verifyReleaseSourceTag({
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
  });
  if (result.artifactManifestSha256 !== artifactManifestSha256) {
    fail("source tag verifier returned a different artifact manifest digest");
  }
  if (result.signedArtifactManifestSha256 !== artifactManifestSha256) {
    fail("source tag signed a different artifact manifest digest");
  }
  console.log(`verified release tag ${result.tagRef}`);
  console.log(`tag object ${result.tagObject}`);
  console.log(`artifact source commit ${result.sourceCommit}`);
  console.log(`OpenPGP signing fingerprint ${result.signingFingerprint}`);
  console.log(`OpenPGP primary fingerprint ${result.primaryFingerprint}`);
  console.log(`OpenPGP signature creation date ${result.signatureCreationDate}`);
  console.log(`OpenPGP signature timestamp ${result.signatureTimestamp}`);
  console.log(
    `OpenPGP signature expiration ${result.signatureExpirationTimestamp ?? "never"}`,
  );
  console.log(`OpenPGP signature version ${result.signatureVersion}`);
  console.log(`OpenPGP public-key algorithm ${result.publicKeyAlgorithm}`);
  console.log(`OpenPGP hash algorithm ${result.hashAlgorithm}`);
  console.log(`OpenPGP signature class ${result.signatureClass}`);
  console.log(`reviewed artifact ${artifactManifestPath}`);
  console.log(`reviewed artifact manifest sha256 ${result.artifactManifestSha256}`);
  console.log(`signed artifact manifest sha256 ${result.signedArtifactManifestSha256}`);
  if (result.dualReleaseReport) {
    console.log(`verified local dual report ${dualReleaseReportPath}`);
    console.log(`dual report sha256 ${result.dualReleaseReport.sha256}`);
    console.log(`dual report source commit ${result.dualReleaseReport.sourceCommit}`);
    console.log(`dual report extension version ${result.dualReleaseReport.extensionVersion}`);
    console.log(`dual report compared files ${result.dualReleaseReport.comparisonFileCount}`);
    console.log(`bound artifact manifest sha256 ${result.dualReleaseReport.artifactManifestSha256}`);
    console.log(`bound release files ${result.dualReleaseReport.boundReleaseFileCount}`);
    console.log("dual report scope same-host sequential shared-store; independent builders not asserted");
  }
  if (result.artifactReview) {
    console.log(`verified artifact review signature ${artifactReviewSignaturePath}`);
    console.log(`artifact review signature sha256 ${result.artifactReview.signatureSha256}`);
    console.log(`artifact review manifest sha256 ${result.artifactReview.artifactSha256}`);
    console.log(
      `artifact review signing fingerprint ${result.artifactReview.signingFingerprint}`,
    );
    console.log(
      `artifact review primary fingerprint ${result.artifactReview.primaryFingerprint}`,
    );
    console.log(
      `artifact review signature creation date ${result.artifactReview.signatureCreationDate}`,
    );
    console.log(
      `artifact review signature expiration ${result.artifactReview.signatureExpirationTimestamp ?? "never"}`,
    );
  }
  if (result.storePackage) {
    console.log(`verified store-returned package ${storePackagePath}`);
    console.log(`against reviewed upload ${reviewedUploadArchivePath}`);
    console.log(`store package bytes ${result.storePackage.packageBytes}`);
    console.log(`store package sha256 ${result.storePackage.packageSha256}`);
    console.log(`store extension id ${result.storePackage.extensionId}`);
    console.log(`store publisher key sha256 ${result.storePackage.publisherKeySha256}`);
    console.log(
      `store embedded archive sha256 ${result.storePackage.embeddedArchiveSha256}`,
    );
    console.log(
      `reviewed upload archive sha256 ${result.storePackage.reviewedUploadArchiveSha256}`,
    );
    console.log(`store payload files ${result.storePackage.files}`);
    console.log(`store payload tree sha256 ${result.storePackage.treeSha256}`);
  }
}

await main();
