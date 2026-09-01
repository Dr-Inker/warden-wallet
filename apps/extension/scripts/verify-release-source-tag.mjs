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
  if (![3, 4].includes(args.length)) {
    fail("usage: verify-release-source-tag.mjs tag expected-tag-object expected-primary-fingerprint [reviewed-artifact.json]");
  }
  const [tagName, expectedTagObject, expectedSignerFingerprint] = args;
  let artifactManifestPath;
  if (args[3]) {
    artifactManifestPath = resolve(args[3]);
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
  const result = await verifyReleaseSourceTag({
    repositoryRoot,
    tagName,
    expectedTagObject,
    expectedSignerFingerprint,
    artifactManifest,
  });
  console.log(`verified release tag ${result.tagRef}`);
  console.log(`tag object ${result.tagObject}`);
  console.log(`artifact source commit ${result.sourceCommit}`);
  console.log(`OpenPGP signing fingerprint ${result.signingFingerprint}`);
  console.log(`OpenPGP primary fingerprint ${result.primaryFingerprint}`);
  console.log(`reviewed artifact ${artifactManifestPath}`);
}

await main();
