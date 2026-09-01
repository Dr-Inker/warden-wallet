import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { version as esbuildVersion } from "esbuild";

import { buildExtension } from "./build.mjs";
import {
  createJavaScriptBundleInputEvidence,
  serializeJavaScriptBundleInputEvidence,
  verifyJavaScriptBundleInputEvidenceAttachment,
} from "./bundle-input-evidence.mjs";
import {
  collectInstalledProductionDependencyReports,
  createProductionDependencyEvidence,
  serializeProductionDependencyEvidence,
  verifyProductionDependencyEvidenceAttachment,
} from "./production-dependency-evidence.mjs";
import {
  CANONICAL_TIMESTAMP,
  collectCanonicalPayload,
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
  stageCanonicalUnpacked,
  verifyArtifactArchive,
  verifyCanonicalUnpacked,
} from "./release-artifact.mjs";
import {
  RELEASE_RECIPE_INPUT_PATHS,
  createReleaseRecipeInputEvidence,
  serializeReleaseRecipeInputEvidence,
  verifyReleaseRecipeInputEvidenceAttachment,
} from "./release-recipe-input-evidence.mjs";
import {
  createStaticInputEvidence,
  serializeStaticInputEvidence,
  verifyStaticInputEvidenceAttachment,
} from "./static-input-evidence.mjs";

const execFile = promisify(execFileCallback);
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(appDirectory, "../..");
const distributionDirectory = join(appDirectory, "dist");
const releaseDirectory = join(appDirectory, "release");
const canonicalDate = new Date(CANONICAL_TIMESTAMP);

const EXPECTED_PAYLOAD_FILES = Object.freeze([
  "approval.css",
  "approval.html",
  "approval.js",
  "background.js",
  "content.js",
  "manifest.json",
  "popup.html",
  "popup.js",
]);

function fail(message) {
  throw new Error(`extension release package: ${message}`);
}

async function readJson(path, label) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    fail(`${label} is not readable JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function run(command, args, cwd = repositoryRoot) {
  try {
    return await execFile(command, args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const stdout = typeof error?.stdout === "string" ? error.stdout.trim() : "";
    const stderr = typeof error?.stderr === "string" ? error.stderr.trim() : "";
    fail(`${command} ${args.join(" ")} failed: ${[detail, stdout, stderr].filter(Boolean).join(" | ")}`);
  }
}

async function assertReleaseEnvironment() {
  const rootPackage = await readJson(join(repositoryRoot, "package.json"), "root package.json");
  const extensionPackage = await readJson(join(appDirectory, "package.json"), "extension package.json");
  const expectedNode = rootPackage.engines?.node;
  const expectedPnpm = rootPackage.engines?.pnpm;
  if (typeof expectedNode !== "string" || !/^\d+\.\d+\.\d+$/.test(expectedNode)) {
    fail("root engines.node must be an exact semantic version");
  }
  if (typeof expectedPnpm !== "string" || !/^\d+\.\d+\.\d+$/.test(expectedPnpm)) {
    fail("root engines.pnpm must be an exact semantic version");
  }
  if (rootPackage.packageManager !== `pnpm@${expectedPnpm}`) {
    fail("root packageManager must exactly match engines.pnpm");
  }
  if (process.versions.node !== expectedNode) {
    fail(`Node mismatch: expected ${expectedNode}, got ${process.versions.node}`);
  }
  const { stdout: pnpmOutput } = await run("pnpm", ["--version"]);
  const actualPnpm = pnpmOutput.trim();
  if (actualPnpm !== expectedPnpm) {
    fail(`pnpm mismatch: expected ${expectedPnpm}, got ${actualPnpm}`);
  }
  const expectedEsbuild = extensionPackage.devDependencies?.esbuild;
  if (typeof expectedEsbuild !== "string" || !/^\d+\.\d+\.\d+$/.test(expectedEsbuild)) {
    fail("extension devDependencies.esbuild must be an exact semantic version");
  }
  if (esbuildVersion !== expectedEsbuild) {
    fail(`esbuild mismatch: expected ${expectedEsbuild}, got ${esbuildVersion}`);
  }

  const { stdout: gitRootOutput } = await run("git", ["rev-parse", "--show-toplevel"]);
  const gitRoot = await realpath(gitRootOutput.trim());
  if (gitRoot !== await realpath(repositoryRoot)) {
    fail(`unexpected git root: ${gitRoot}`);
  }
  const { stdout: statusOutput } = await run("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (statusOutput !== "") {
    fail(`release packaging requires a clean source tree:\n${statusOutput.trimEnd()}`);
  }
  const { stdout: gitCommitOutput } = await run("git", ["rev-parse", "HEAD"]);
  const gitCommit = gitCommitOutput.trim();
  if (!/^[0-9a-f]{40}$/.test(gitCommit)) {
    fail(`git did not return a full commit SHA: ${gitCommit}`);
  }
  await run("git", ["check-ignore", "--quiet", "--no-index", "apps/extension/release/probe"]);

  const lockfileBytes = await readFile(join(repositoryRoot, "pnpm-lock.yaml"));
  return {
    source: {
      gitCommit,
      lockfileSha256: createHash("sha256").update(lockfileBytes).digest("hex"),
    },
    toolchain: {
      node: expectedNode,
      pnpm: expectedPnpm,
      esbuild: expectedEsbuild,
    },
  };
}

function assertExpectedPayload(entries) {
  const actual = entries.map((entry) => entry.path);
  if (JSON.stringify(actual) !== JSON.stringify(EXPECTED_PAYLOAD_FILES)) {
    fail(`payload file set changed: expected ${EXPECTED_PAYLOAD_FILES.join(",")}, got ${actual.join(",")}`);
  }
}

function assertNoObviousRuntimeNetworkOrSecret(entries) {
  const networkPatterns = [
    [/(?:^|[^A-Za-z0-9_$])fetch\s*\(/m, "fetch()"],
    [/(?:^|[^A-Za-z0-9_$])WebSocket\s*\(/m, "WebSocket()"],
    [/(?:^|[^A-Za-z0-9_$])XMLHttpRequest\s*\(/m, "XMLHttpRequest()"],
    [/(?:^|[^A-Za-z0-9_$])EventSource\s*\(/m, "EventSource()"],
    [/\.sendBeacon\s*\(/m, "sendBeacon()"],
    [/chrome\.(?:sockets|proxy)\b/m, "Chrome network API"],
  ];
  const secretPatterns = [
    [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/m, "private-key PEM"],
    [/\bAKIA[0-9A-Z]{16}\b/m, "AWS access key"],
    [/\bgh[pousr]_[A-Za-z0-9]{20,}\b/m, "GitHub token"],
    [/\bAIza[0-9A-Za-z_-]{35}\b/m, "Google API key"],
  ];
  for (const entry of entries) {
    const text = entry.data.toString("utf8");
    if (entry.path.endsWith(".js")) {
      for (const [pattern, label] of networkPatterns) {
        if (pattern.test(text)) {
          fail(`${entry.path} contains a direct runtime network primitive (${label})`);
        }
      }
    }
    for (const [pattern, label] of secretPatterns) {
      if (pattern.test(text)) {
        fail(`${entry.path} contains secret-like material (${label})`);
      }
    }
  }
}

async function ensureReleaseDirectory() {
  try {
    const existing = await lstat(releaseDirectory);
    if (!existing.isDirectory() || existing.isSymbolicLink()) {
      fail("apps/extension/release must be a real directory, not a symlink");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
    await mkdir(releaseDirectory, { mode: 0o755 });
  }
}

async function removeGeneratedTarget(target, expectedKind) {
  if (dirname(target) !== releaseDirectory) {
    fail(`refusing to replace a path outside the release directory: ${target}`);
  }
  try {
    const existing = await lstat(target);
    if (existing.isSymbolicLink()) {
      fail(`refusing to replace a symlinked release target: ${target}`);
    }
    if (expectedKind === "directory" ? !existing.isDirectory() : !existing.isFile()) {
      fail(`refusing to replace an unexpected release target type: ${target}`);
    }
    await rm(target, { recursive: expectedKind === "directory", force: false });
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

async function writeCanonicalFile(path, bytes) {
  await writeFile(path, bytes, { flag: "wx", mode: 0o644 });
  await chmod(path, 0o644);
  await utimes(path, canonicalDate, canonicalDate);
}

async function main() {
  const releaseEnvironment = await assertReleaseEnvironment();
  const buildOutput = await buildExtension();
  if (!Array.isArray(buildOutput?.bundleResults) || !Array.isArray(buildOutput?.staticResults)) {
    fail("extension build did not return bundle metafiles and static transformations");
  }
  const { stdout: postBuildStatus } = await run("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (postBuildStatus !== "") {
    fail(`build changed the source tree:\n${postBuildStatus.trimEnd()}`);
  }

  const entries = await collectCanonicalPayload(distributionDirectory);
  assertExpectedPayload(entries);
  assertNoObviousRuntimeNetworkOrSecret(entries);
  const sourceManifest = await readJson(join(appDirectory, "manifest.json"), "extension manifest.json");
  const version = sourceManifest.version;
  if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
    fail(`invalid extension version: ${String(version)}`);
  }
  const archiveFileName = `warden-extension-${version}.zip`;
  const artifactManifestFileName = `warden-extension-${version}.artifact.json`;
  const dependencyEvidenceFileName = `warden-extension-${version}.sbom.json`;
  const bundleInputEvidenceFileName = `warden-extension-${version}.bundle-inputs.json`;
  const staticInputEvidenceFileName = `warden-extension-${version}.static-inputs.json`;
  const releaseRecipeInputEvidenceFileName = `warden-extension-${version}.recipe-inputs.json`;
  const archiveBytes = createCanonicalZip(entries);
  const bundleInputEvidence = await createJavaScriptBundleInputEvidence({
    buildResults: buildOutput.bundleResults,
    entries,
    appDirectory,
    repositoryRoot,
    source: releaseEnvironment.source,
    archiveFileName,
    archiveBytes,
  });
  const bundleInputEvidenceBytes = Buffer.from(
    serializeJavaScriptBundleInputEvidence(bundleInputEvidence),
    "utf8",
  );
  const staticInputEvidence = await createStaticInputEvidence({
    staticResults: buildOutput.staticResults,
    entries,
    appDirectory,
    repositoryRoot,
    source: releaseEnvironment.source,
    archiveFileName,
    archiveBytes,
  });
  const staticInputEvidenceBytes = Buffer.from(
    serializeStaticInputEvidence(staticInputEvidence),
    "utf8",
  );
  const { dependencyReport, licenseReport } =
    await collectInstalledProductionDependencyReports({
      rootDirectory: appDirectory,
      repositoryRoot,
    });
  const { stdout: postInventoryStatus } = await run("git", [
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
  ]);
  if (postInventoryStatus !== "") {
    fail(`dependency inventory changed the source tree:\n${postInventoryStatus.trimEnd()}`);
  }
  const dependencyEvidence = createProductionDependencyEvidence({
    dependencyReport,
    licenseReport,
    rootPackage: { name: "@warden/extension", version },
    source: releaseEnvironment.source,
    archiveFileName,
    archiveBytes,
  });
  const dependencyEvidenceBytes = Buffer.from(
    serializeProductionDependencyEvidence(dependencyEvidence),
    "utf8",
  );
  const releaseRecipeInputEvidence = await createReleaseRecipeInputEvidence({
    repositoryRoot,
    inputPaths: RELEASE_RECIPE_INPUT_PATHS,
    source: releaseEnvironment.source,
    archiveFileName,
    archiveBytes,
  });
  const releaseRecipeInputEvidenceBytes = Buffer.from(
    serializeReleaseRecipeInputEvidence(releaseRecipeInputEvidence),
    "utf8",
  );
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: archiveFileName,
    ...releaseEnvironment,
    dependencyEvidence: {
      file: dependencyEvidenceFileName,
      bytes: dependencyEvidenceBytes,
    },
    bundleInputEvidence: {
      file: bundleInputEvidenceFileName,
      bytes: bundleInputEvidenceBytes,
    },
    staticInputEvidence: {
      file: staticInputEvidenceFileName,
      bytes: staticInputEvidenceBytes,
    },
    releaseRecipeInputEvidence: {
      file: releaseRecipeInputEvidenceFileName,
      bytes: releaseRecipeInputEvidenceBytes,
    },
  });
  verifyArtifactArchive({ archiveBytes, artifactManifest });
  verifyProductionDependencyEvidenceAttachment({
    evidenceBytes: dependencyEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  verifyJavaScriptBundleInputEvidenceAttachment({
    evidenceBytes: bundleInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  verifyStaticInputEvidenceAttachment({
    evidenceBytes: staticInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
  });
  await verifyReleaseRecipeInputEvidenceAttachment({
    evidenceBytes: releaseRecipeInputEvidenceBytes,
    artifactManifest,
    archiveBytes,
    repositoryRoot,
  });

  await ensureReleaseDirectory();
  const stagingDirectory = await mkdtemp(join(releaseDirectory, ".staging-"));
  const stagedUnpacked = join(stagingDirectory, "unpacked");
  const stagedArchive = join(stagingDirectory, archiveFileName);
  const stagedArtifactManifest = join(stagingDirectory, artifactManifestFileName);
  const stagedDependencyEvidence = join(stagingDirectory, dependencyEvidenceFileName);
  const stagedBundleInputEvidence = join(stagingDirectory, bundleInputEvidenceFileName);
  const stagedStaticInputEvidence = join(stagingDirectory, staticInputEvidenceFileName);
  const stagedReleaseRecipeInputEvidence = join(
    stagingDirectory,
    releaseRecipeInputEvidenceFileName,
  );
  try {
    await stageCanonicalUnpacked(entries, stagedUnpacked);
    await writeCanonicalFile(stagedArchive, archiveBytes);
    await writeCanonicalFile(
      stagedArtifactManifest,
      Buffer.from(serializeArtifactManifest(artifactManifest), "utf8"),
    );
    await writeCanonicalFile(stagedDependencyEvidence, dependencyEvidenceBytes);
    await writeCanonicalFile(stagedBundleInputEvidence, bundleInputEvidenceBytes);
    await writeCanonicalFile(stagedStaticInputEvidence, staticInputEvidenceBytes);
    await writeCanonicalFile(stagedReleaseRecipeInputEvidence, releaseRecipeInputEvidenceBytes);
    await verifyCanonicalUnpacked({
      rootDirectory: stagedUnpacked,
      artifactManifest,
    });

    const unpackedTarget = join(releaseDirectory, "unpacked");
    const archiveTarget = join(releaseDirectory, archiveFileName);
    const artifactManifestTarget = join(releaseDirectory, artifactManifestFileName);
    const dependencyEvidenceTarget = join(releaseDirectory, dependencyEvidenceFileName);
    const bundleInputEvidenceTarget = join(releaseDirectory, bundleInputEvidenceFileName);
    const staticInputEvidenceTarget = join(releaseDirectory, staticInputEvidenceFileName);
    const releaseRecipeInputEvidenceTarget = join(
      releaseDirectory,
      releaseRecipeInputEvidenceFileName,
    );
    await removeGeneratedTarget(unpackedTarget, "directory");
    await removeGeneratedTarget(archiveTarget, "file");
    await removeGeneratedTarget(artifactManifestTarget, "file");
    await removeGeneratedTarget(dependencyEvidenceTarget, "file");
    await removeGeneratedTarget(bundleInputEvidenceTarget, "file");
    await removeGeneratedTarget(staticInputEvidenceTarget, "file");
    await removeGeneratedTarget(releaseRecipeInputEvidenceTarget, "file");
    await rename(stagedUnpacked, unpackedTarget);
    await rename(stagedArchive, archiveTarget);
    await rename(stagedArtifactManifest, artifactManifestTarget);
    await rename(stagedDependencyEvidence, dependencyEvidenceTarget);
    await rename(stagedBundleInputEvidence, bundleInputEvidenceTarget);
    await rename(stagedStaticInputEvidence, staticInputEvidenceTarget);
    await rename(stagedReleaseRecipeInputEvidence, releaseRecipeInputEvidenceTarget);
  } finally {
    await rm(stagingDirectory, { recursive: true, force: true });
  }

  const relativeArchive = relative(repositoryRoot, join(releaseDirectory, archiveFileName));
  const relativeManifest = relative(repositoryRoot, join(releaseDirectory, artifactManifestFileName));
  const relativeDependencyEvidence = relative(
    repositoryRoot,
    join(releaseDirectory, dependencyEvidenceFileName),
  );
  const relativeBundleInputEvidence = relative(
    repositoryRoot,
    join(releaseDirectory, bundleInputEvidenceFileName),
  );
  const relativeStaticInputEvidence = relative(
    repositoryRoot,
    join(releaseDirectory, staticInputEvidenceFileName),
  );
  const relativeReleaseRecipeInputEvidence = relative(
    repositoryRoot,
    join(releaseDirectory, releaseRecipeInputEvidenceFileName),
  );
  console.log(`packaged ${relativeArchive}`);
  console.log(`attestation ${relativeManifest}`);
  console.log(`dependency evidence ${relativeDependencyEvidence}`);
  console.log(`bundle input evidence ${relativeBundleInputEvidence}`);
  console.log(`static input evidence ${relativeStaticInputEvidence}`);
  console.log(`release recipe input evidence ${relativeReleaseRecipeInputEvidence}`);
  console.log(`source ${artifactManifest.source.gitCommit}`);
  console.log(`payload tree sha256 ${artifactManifest.payload.treeSha256}`);
  console.log(`archive sha256 ${artifactManifest.archive.sha256}`);
  console.log(`production dependency components ${dependencyEvidence.components.length}`);
  console.log(`JavaScript bundle inputs ${bundleInputEvidence.bundles.reduce((total, bundle) => total + bundle.inputCount, 0)}`);
  console.log(`static input files ${staticInputEvidence.files.length}`);
  console.log(`release recipe input files ${releaseRecipeInputEvidence.inputs.length}`);
}

await main();
