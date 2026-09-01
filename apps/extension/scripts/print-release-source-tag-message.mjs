import { createHash } from "node:crypto";

import { parseArtifactManifest } from "./release-artifact.mjs";
import { normalizeReleaseCliArguments } from "./release-cli-arguments.mjs";
import { readBoundedRegularFile } from "./release-input-file.mjs";
import {
  MAX_ARTIFACT_MANIFEST_BYTES,
  formatReleaseTagMessage,
} from "./release-source-tag.mjs";

function fail(message) {
  throw new Error(`extension release source tag message: ${message}`);
}

async function main() {
  const args = normalizeReleaseCliArguments(process.argv.slice(2));
  if (args.length !== 2) {
    fail(
      "usage: print-release-source-tag-message.mjs reviewed-artifact.json expected-artifact-manifest-sha256",
    );
  }
  const [artifactManifestPath, expectedArtifactManifestSha256] = args;
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
  if (artifactManifestSha256 !== expectedArtifactManifestSha256) {
    fail("reviewed artifact manifest differs from the independently supplied SHA-256");
  }
  parseArtifactManifest(artifactManifestBytes);
  process.stdout.write(formatReleaseTagMessage(artifactManifestSha256));
}

await main();
