import { execFile as execFileCallback } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  parseArtifactManifest,
  verifyArtifactArchive,
  verifyCanonicalUnpacked,
} from "./release-artifact.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const releaseDirectory = join(appDirectory, "release");
const execFile = promisify(execFileCallback);

function fail(message) {
  throw new Error(`extension release verify: ${message}`);
}

async function main() {
  const sourceManifest = JSON.parse(await readFile(join(appDirectory, "manifest.json"), "utf8"));
  const version = sourceManifest.version;
  if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
    fail(`invalid source manifest version: ${String(version)}`);
  }

  const defaultArchive = join(releaseDirectory, `warden-extension-${version}.zip`);
  const defaultArtifactManifest = join(releaseDirectory, `warden-extension-${version}.artifact.json`);
  const args = process.argv.slice(2);
  if (args.length > 3) {
    fail("usage: verify-release.mjs [candidate.zip] [artifact.json] [unpacked-directory]");
  }
  const archivePath = resolve(args[0] ?? defaultArchive);
  const artifactManifestPath = resolve(args[1] ?? defaultArtifactManifest);
  const unpackedPath = args[2] === undefined
    ? (args.length === 0 ? join(releaseDirectory, "unpacked") : undefined)
    : resolve(args[2]);

  const archiveBytes = await readFile(archivePath);
  const artifactManifest = parseArtifactManifest(await readFile(artifactManifestPath));
  const verified = verifyArtifactArchive({ archiveBytes, artifactManifest });
  try {
    await execFile("unzip", ["-t", archivePath], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    fail(`independent unzip -t validation failed: ${error instanceof Error ? error.message : String(error)}`);
  }
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
  console.log(`source ${artifactManifest.source.gitCommit}`);
  console.log(`files ${verified.files}`);
  console.log(`payload tree sha256 ${verified.treeSha256}`);
  console.log(`archive sha256 ${verified.archiveSha256}`);
  console.log("independent ZIP reader unzip -t passed");
  console.log(unpackedPath === undefined ? "unpacked tree not requested" : `unpacked ${unpackedPath}`);
}

await main();
