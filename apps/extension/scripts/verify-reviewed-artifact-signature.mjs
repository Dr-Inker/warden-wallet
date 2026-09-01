import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { parseArtifactManifest } from "./release-artifact.mjs";
import {
  MAX_DETACHED_SIGNATURE_BYTES,
  MAX_REVIEWED_ARTIFACT_BYTES,
  verifyReviewedArtifactSignature,
} from "./reviewed-artifact-signature.mjs";

function fail(message) {
  throw new Error(`reviewed extension artifact signature verify: ${message}`);
}

async function readBoundedRegularFile(path, maximumBytes, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > maximumBytes) {
    fail(`${label} must be a nonempty regular file no larger than ${maximumBytes} bytes`);
  }
  const bytes = await readFile(path);
  if (bytes.length !== metadata.size) {
    fail(`${label} changed while it was being read`);
  }
  return bytes;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 3) {
    fail("usage: verify-reviewed-artifact-signature.mjs reviewed-artifact.json detached-signature expected-primary-fingerprint");
  }
  const artifactPath = resolve(args[0]);
  const signaturePath = resolve(args[1]);
  const [artifactBytes, signatureBytes] = await Promise.all([
    readBoundedRegularFile(
      artifactPath,
      MAX_REVIEWED_ARTIFACT_BYTES,
      "reviewed artifact manifest",
    ),
    readBoundedRegularFile(
      signaturePath,
      MAX_DETACHED_SIGNATURE_BYTES,
      "detached signature",
    ),
  ]);
  const verified = await verifyReviewedArtifactSignature({
    artifactBytes,
    signatureBytes,
    expectedSignerFingerprint: args[2],
  });
  const artifactManifest = parseArtifactManifest(artifactBytes);
  console.log(`verified reviewed artifact ${artifactPath}`);
  console.log(`detached signature ${signaturePath}`);
  console.log(`artifact bytes ${verified.artifactBytes}`);
  console.log(`artifact sha256 ${verified.artifactSha256}`);
  console.log(`signature bytes ${verified.signatureBytes}`);
  console.log(`signature sha256 ${verified.signatureSha256}`);
  console.log(`OpenPGP signing fingerprint ${verified.signingFingerprint}`);
  console.log(`OpenPGP primary fingerprint ${verified.primaryFingerprint}`);
  console.log(`OpenPGP signature version ${verified.signatureVersion}`);
  console.log(`OpenPGP public-key algorithm ${verified.publicKeyAlgorithm}`);
  console.log(`OpenPGP hash algorithm ${verified.hashAlgorithm}`);
  console.log(`OpenPGP signature class ${verified.signatureClass}`);
  console.log(`artifact source commit ${artifactManifest.source.gitCommit}`);
  console.log(`artifact archive sha256 ${artifactManifest.archive.sha256}`);
}

await main();
