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
  if (![4, 5, 7].includes(args.length)) {
    fail("usage: verify-release-source-tag.mjs tag expected-tag-object expected-primary-fingerprint expected-signing-fingerprint [reviewed-artifact.json [dual-local-report.json expected-dual-report-sha256]]");
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
  const artifactManifest = parseArtifactManifest(await readFile(artifactManifestPath));
  let dualReleaseReportPath;
  let dualReleaseReportBytes;
  let expectedDualReleaseReportSha256;
  if (args.length === 7) {
    dualReleaseReportPath = resolve(args[5]);
    dualReleaseReportBytes = await readFile(dualReleaseReportPath);
    expectedDualReleaseReportSha256 = args[6];
  }
  const result = await verifyReleaseSourceTag({
    repositoryRoot,
    tagName,
    expectedTagObject,
    expectedPrimaryFingerprint,
    expectedSigningFingerprint,
    artifactManifest,
    dualReleaseReportBytes,
    expectedDualReleaseReportSha256,
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
    console.log("dual report scope same-host sequential shared-store; independent builders not asserted");
  }
}

await main();
