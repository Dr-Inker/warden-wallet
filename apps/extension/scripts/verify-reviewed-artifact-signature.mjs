import { createHash } from "node:crypto";
import { resolve } from "node:path";

import { parseArtifactManifest } from "./release-artifact.mjs";
import { readBoundedRegularFile } from "./release-input-file.mjs";
import {
  MAX_DETACHED_SIGNATURE_BYTES,
  MAX_REVIEWED_ARTIFACT_BYTES,
  verifyReviewedArtifactSignature,
} from "./reviewed-artifact-signature.mjs";

function fail(message) {
  throw new Error(`reviewed extension artifact signature verify: ${message}`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length !== 6) {
    fail("usage: verify-reviewed-artifact-signature.mjs reviewed-artifact.json detached-signature expected-artifact-manifest-sha256 expected-detached-signature-sha256 expected-primary-fingerprint expected-signing-fingerprint");
  }
  const artifactPath = resolve(args[0]);
  const signaturePath = resolve(args[1]);
  const expectedArtifactSha256 = args[2];
  if (!/^[0-9a-f]{64}$/.test(expectedArtifactSha256)) {
    fail("expected artifact manifest SHA-256 must be a lowercase digest");
  }
  const expectedSignatureSha256 = args[3];
  if (!/^[0-9a-f]{64}$/.test(expectedSignatureSha256)) {
    fail("expected detached-signature SHA-256 must be a lowercase digest");
  }
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
  const artifactSha256 = createHash("sha256").update(artifactBytes).digest("hex");
  if (artifactSha256 !== expectedArtifactSha256) {
    fail("reviewed artifact manifest differs from the independently supplied SHA-256");
  }
  const signatureSha256 = createHash("sha256").update(signatureBytes).digest("hex");
  if (signatureSha256 !== expectedSignatureSha256) {
    fail("detached signature differs from the independently supplied SHA-256");
  }
  const verified = await verifyReviewedArtifactSignature({
    artifactBytes,
    signatureBytes,
    expectedPrimaryFingerprint: args[4],
    expectedSigningFingerprint: args[5],
  });
  if (verified.artifactSha256 !== expectedArtifactSha256) {
    fail("artifact signature verifier returned a different artifact digest");
  }
  if (verified.signatureSha256 !== expectedSignatureSha256) {
    fail("artifact signature verifier returned a different detached-signature digest");
  }
  const artifactManifest = parseArtifactManifest(artifactBytes);
  console.log(`verified reviewed artifact ${artifactPath}`);
  console.log(`detached signature ${signaturePath}`);
  console.log(`artifact bytes ${verified.artifactBytes}`);
  console.log(`artifact sha256 ${verified.artifactSha256}`);
  console.log(`signature bytes ${verified.signatureBytes}`);
  console.log(`signature sha256 ${verified.signatureSha256}`);
  console.log(`OpenPGP signing fingerprint ${verified.signingFingerprint}`);
  console.log(`OpenPGP primary fingerprint ${verified.primaryFingerprint}`);
  console.log(`OpenPGP signature creation date ${verified.signatureCreationDate}`);
  console.log(`OpenPGP signature timestamp ${verified.signatureTimestamp}`);
  console.log(
    `OpenPGP signature expiration ${verified.signatureExpirationTimestamp ?? "never"}`,
  );
  console.log(`OpenPGP signature version ${verified.signatureVersion}`);
  console.log(`OpenPGP public-key algorithm ${verified.publicKeyAlgorithm}`);
  console.log(`OpenPGP hash algorithm ${verified.hashAlgorithm}`);
  console.log(`OpenPGP signature class ${verified.signatureClass}`);
  console.log(`artifact source commit ${artifactManifest.source.gitCommit}`);
  console.log(`artifact archive sha256 ${artifactManifest.archive.sha256}`);
}

await main();
