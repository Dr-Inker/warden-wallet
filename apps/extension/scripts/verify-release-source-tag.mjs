import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArtifactManifest } from "./release-artifact.mjs";
import { verifyReleaseSourceTag } from "./release-source-tag.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(appDirectory, "../..");
const releaseDirectory = join(appDirectory, "release");

function fail(message) {
  throw new Error(`extension release source tag verify: ${message}`);
}

async function main() {
  const args = process.argv.slice(2);
  if (![4, 5, 7, 11].includes(args.length)) {
    fail("usage: verify-release-source-tag.mjs tag expected-tag-object expected-primary-fingerprint expected-signing-fingerprint [reviewed-artifact.json [dual-local-report.json expected-dual-report-sha256 [artifact-review-signature expected-artifact-review-signature-sha256 expected-artifact-review-primary-fingerprint expected-artifact-review-signing-fingerprint]]]");
  }
  const [
    tagName,
    expectedTagObject,
    expectedPrimaryFingerprint,
    expectedSigningFingerprint,
  ] = args;
  let artifactManifestPath;
  if (args[4]) {
    artifactManifestPath = resolve(args[4]);
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
  const artifactManifestBytes = await readFile(artifactManifestPath);
  const artifactManifest = parseArtifactManifest(artifactManifestBytes);
  let dualReleaseReportPath;
  let dualReleaseReportBytes;
  let expectedDualReleaseReportSha256;
  if (args.length >= 7) {
    dualReleaseReportPath = resolve(args[5]);
    dualReleaseReportBytes = await readFile(dualReleaseReportPath);
    expectedDualReleaseReportSha256 = args[6];
  }
  let artifactReviewSignaturePath;
  let artifactReviewSignatureBytes;
  let expectedArtifactReviewSignatureSha256;
  let expectedArtifactReviewPrimaryFingerprint;
  let expectedArtifactReviewSigningFingerprint;
  if (args.length === 11) {
    artifactReviewSignaturePath = resolve(args[7]);
    artifactReviewSignatureBytes = await readFile(artifactReviewSignaturePath);
    expectedArtifactReviewSignatureSha256 = args[8];
    expectedArtifactReviewPrimaryFingerprint = args[9];
    expectedArtifactReviewSigningFingerprint = args[10];
  }
  const result = await verifyReleaseSourceTag({
    repositoryRoot,
    tagName,
    expectedTagObject,
    expectedPrimaryFingerprint,
    expectedSigningFingerprint,
    artifactManifest,
    artifactManifestBytes: args.length >= 7 ? artifactManifestBytes : undefined,
    dualReleaseReportBytes,
    expectedDualReleaseReportSha256,
    artifactReviewSignatureBytes,
    expectedArtifactReviewSignatureSha256,
    expectedArtifactReviewPrimaryFingerprint,
    expectedArtifactReviewSigningFingerprint,
  });
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
}

await main();
