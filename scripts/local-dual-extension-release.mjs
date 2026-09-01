import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

export const LOCAL_DUAL_RELEASE_SCHEMA =
  "warden.extension-local-dual-release-rehearsal.v1";

const execFile = promisify(execFileCallback);
const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), "..");
const extensionDirectory = join(repositoryRoot, "apps", "extension");
const releaseDirectory = join(extensionDirectory, "release");

const PAYLOAD_PATHS = Object.freeze([
  "approval.css",
  "approval.html",
  "approval.js",
  "background.js",
  "content.js",
  "manifest.json",
  "popup.html",
  "popup.js",
]);

const SCOPE = Object.freeze({
  checkoutModel: "same-host-sequential-local-shared-object-clones",
  dependencyStoreModel: "shared-pnpm-content-addressed-store",
  independentBuilderClaim: "not-asserted",
  signedTagClaim: "not-asserted",
});

const COMMANDS = Object.freeze({
  materialize: "git clone --shared --no-checkout <repository> <temporary-checkout> && git checkout --detach <source-sha>",
  install: "pnpm install --frozen-lockfile --offline",
  release: "pnpm --filter @warden/extension release:gate",
});

function fail(message) {
  throw new Error(`local dual extension release: ${message}`);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, keys, label) {
  if (!isPlainObject(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields differ: expected ${expected.join(",")}, got ${actual.join(",")}`);
  }
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertHash(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertSemver(value, label) {
  if (typeof value !== "string" || !/^\d+\.\d+\.\d+$/.test(value)) {
    fail(`${label} must be an exact semantic version`);
  }
}

function releaseFileNames(version) {
  if (typeof version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(version)) {
    fail("extension version is invalid");
  }
  return Object.freeze([
    `warden-extension-${version}.artifact.json`,
    `warden-extension-${version}.bundle-inputs.json`,
    `warden-extension-${version}.recipe-inputs.json`,
    `warden-extension-${version}.sbom.json`,
    `warden-extension-${version}.static-inputs.json`,
    `warden-extension-${version}.zip`,
  ]);
}

export function releaseComparisonPaths(version) {
  return [
    ...releaseFileNames(version).map((file) => `release/${file}`),
    ...PAYLOAD_PATHS.map((file) => `release/unpacked/${file}`),
  ].sort(compareUtf8);
}

function normalizeBuilderFiles(files, version, label) {
  if (!Array.isArray(files)) {
    fail(`${label} files are required`);
  }
  const normalized = files.map((file) => {
    assertExactKeys(file, ["path", "data"], `${label} file`);
    if (
      typeof file.path !== "string" ||
      file.path.includes("\\") ||
      file.path.startsWith("/") ||
      file.path.split("/").some((part) => part === "" || part === "." || part === "..") ||
      !(file.data instanceof Uint8Array)
    ) {
      fail(`${label} contains an invalid release file`);
    }
    return { path: file.path, data: Buffer.from(file.data) };
  }).sort((left, right) => compareUtf8(left.path, right.path));
  if (new Set(normalized.map((file) => file.path)).size !== normalized.length) {
    fail(`${label} contains duplicate release files`);
  }
  const actualPaths = normalized.map((file) => file.path);
  const expectedPaths = releaseComparisonPaths(version);
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail(`${label} release file set differs from the reviewed fourteen-file comparison set`);
  }
  return normalized;
}

function assertReportShape(report) {
  assertExactKeys(
    report,
    ["schema", "scope", "source", "toolchain", "orchestrator", "commands", "builders", "comparison"],
    "local dual release report",
  );
  if (report.schema !== LOCAL_DUAL_RELEASE_SCHEMA) {
    fail(`unsupported report schema: ${String(report.schema)}`);
  }
  assertExactKeys(
    report.scope,
    ["checkoutModel", "dependencyStoreModel", "independentBuilderClaim", "signedTagClaim"],
    "report scope",
  );
  if (JSON.stringify(report.scope) !== JSON.stringify(SCOPE)) {
    fail("report scope differs from the reviewed local rehearsal scope");
  }
  assertExactKeys(report.source, ["gitCommit", "extensionVersion"], "report source");
  if (
    typeof report.source.gitCommit !== "string" ||
    !/^[0-9a-f]{40}$/.test(report.source.gitCommit) ||
    typeof report.source.extensionVersion !== "string" ||
    !/^\d+(?:\.\d+){0,3}$/.test(report.source.extensionVersion)
  ) {
    fail("report source gitCommit must be a full lowercase commit SHA");
  }
  assertExactKeys(report.toolchain, ["node", "pnpm", "esbuild"], "report toolchain");
  for (const name of ["node", "pnpm", "esbuild"]) {
    assertSemver(report.toolchain[name], `report toolchain ${name}`);
  }
  assertExactKeys(report.orchestrator, ["path", "bytes", "sha256"], "report orchestrator");
  if (
    report.orchestrator.path !== "repo:scripts/local-dual-extension-release.mjs" ||
    !Number.isSafeInteger(report.orchestrator.bytes) ||
    report.orchestrator.bytes <= 0
  ) {
    fail("report orchestrator metadata is invalid");
  }
  assertHash(report.orchestrator.sha256, "report orchestrator sha256");
  assertExactKeys(report.commands, ["materialize", "install", "release"], "report commands");
  if (JSON.stringify(report.commands) !== JSON.stringify(COMMANDS)) {
    fail("report commands differ from the reviewed local rehearsal commands");
  }
  if (!Array.isArray(report.builders) || report.builders.length !== 2) {
    fail("report must contain exactly two local builders");
  }
  for (let index = 0; index < report.builders.length; index += 1) {
    const builder = report.builders[index];
    assertExactKeys(builder, ["id", "sourceGitCommit"], "report builder");
    if (
      builder.id !== `local-${index === 0 ? "a" : "b"}` ||
      builder.sourceGitCommit !== report.source.gitCommit
    ) {
      fail("report builder identity or source differs");
    }
  }
  assertExactKeys(report.comparison, ["fileCount", "files"], "report comparison");
  if (!Array.isArray(report.comparison.files) || report.comparison.fileCount !== 14) {
    fail("report comparison must contain exactly fourteen files");
  }
  let previousPath;
  for (const file of report.comparison.files) {
    assertExactKeys(file, ["path", "bytes", "sha256"], "report comparison file");
    if (
      typeof file.path !== "string" ||
      (previousPath !== undefined && compareUtf8(previousPath, file.path) >= 0) ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes <= 0
    ) {
      fail("report comparison file metadata is invalid or not canonically sorted");
    }
    previousPath = file.path;
    assertHash(file.sha256, `report comparison hash for ${file.path}`);
  }
  if (
    JSON.stringify(report.comparison.files.map((file) => file.path)) !==
    JSON.stringify(releaseComparisonPaths(report.source.extensionVersion))
  ) {
    fail("report comparison paths differ from the reviewed fourteen-file set");
  }
}

export function createLocalDualReleaseReport({
  sourceGitCommit,
  toolchain,
  orchestrator,
  extensionVersion,
  firstFiles,
  secondFiles,
}) {
  const first = normalizeBuilderFiles(firstFiles, extensionVersion, "first builder");
  const second = normalizeBuilderFiles(secondFiles, extensionVersion, "second builder");
  for (let index = 0; index < first.length; index += 1) {
    if (first[index].path !== second[index].path || !first[index].data.equals(second[index].data)) {
      fail(`builder release bytes differ for ${first[index].path}`);
    }
  }
  const report = {
    schema: LOCAL_DUAL_RELEASE_SCHEMA,
    scope: { ...SCOPE },
    source: { gitCommit: sourceGitCommit, extensionVersion },
    toolchain: {
      node: toolchain?.node,
      pnpm: toolchain?.pnpm,
      esbuild: toolchain?.esbuild,
    },
    orchestrator: {
      path: orchestrator?.path,
      bytes: orchestrator?.bytes,
      sha256: orchestrator?.sha256,
    },
    commands: { ...COMMANDS },
    builders: [
      { id: "local-a", sourceGitCommit },
      { id: "local-b", sourceGitCommit },
    ],
    comparison: {
      fileCount: first.length,
      files: first.map((file) => ({
        path: file.path,
        bytes: file.data.length,
        sha256: sha256(file.data),
      })),
    },
  };
  assertReportShape(report);
  return report;
}

export function serializeLocalDualReleaseReport(report) {
  assertReportShape(report);
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function parseLocalDualReleaseReport(bytes) {
  const reportBytes = Buffer.from(bytes);
  const text = reportBytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(reportBytes)) {
    fail("report is not canonical UTF-8");
  }
  let report;
  try {
    report = JSON.parse(text);
  } catch (error) {
    fail(`report is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertReportShape(report);
  if (text !== serializeLocalDualReleaseReport(report)) {
    fail("report must use the canonical generated JSON serialization");
  }
  return report;
}

async function run(command, args, cwd = repositoryRoot) {
  try {
    return await execFile(command, args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, npm_config_cache: "/tmp/warden-npm-cache" },
    });
  } catch (error) {
    const stdout = typeof error?.stdout === "string" ? error.stdout.trim() : "";
    const stderr = typeof error?.stderr === "string" ? error.stderr.trim() : "";
    fail(`${command} ${args.join(" ")} failed: ${[error?.message, stdout, stderr].filter(Boolean).join(" | ")}`);
  }
}

async function assertRegularFile(path, label) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular file`);
  }
}

async function collectBuilderRelease(checkout, version, sourceGitCommit, expectedToolchain) {
  const checkoutRelease = join(checkout, "apps", "extension", "release");
  const rootEntries = await readdir(checkoutRelease, { withFileTypes: true });
  const expectedRoot = ["unpacked", ...releaseFileNames(version)].sort(compareUtf8);
  const actualRoot = rootEntries.map((entry) => entry.name).sort(compareUtf8);
  if (JSON.stringify(actualRoot) !== JSON.stringify(expectedRoot)) {
    fail("builder release root differs from the reviewed artifact set");
  }
  const artifactPath = join(
    checkoutRelease,
    `warden-extension-${version}.artifact.json`,
  );
  await assertRegularFile(artifactPath, "builder artifact manifest");
  const artifactManifest = JSON.parse(await readFile(artifactPath, "utf8"));
  if (
    artifactManifest?.source?.gitCommit !== sourceGitCommit ||
    JSON.stringify(artifactManifest?.toolchain) !== JSON.stringify(expectedToolchain) ||
    JSON.stringify(artifactManifest?.payload?.files?.map((file) => file.path)) !==
      JSON.stringify(PAYLOAD_PATHS)
  ) {
    fail("builder artifact source, toolchain, or payload set differs");
  }
  const unpacked = join(checkoutRelease, "unpacked");
  const unpackedEntries = await readdir(unpacked, { withFileTypes: true });
  if (
    unpackedEntries.some((entry) => !entry.isFile() || entry.isSymbolicLink()) ||
    JSON.stringify(unpackedEntries.map((entry) => entry.name).sort(compareUtf8)) !==
      JSON.stringify(PAYLOAD_PATHS)
  ) {
    fail("builder unpacked tree differs from the reviewed payload set");
  }
  const files = [];
  for (const file of releaseFileNames(version)) {
    const path = join(checkoutRelease, file);
    await assertRegularFile(path, `builder release file ${file}`);
    files.push({ path: `release/${file}`, data: await readFile(path) });
  }
  for (const file of PAYLOAD_PATHS) {
    const path = join(unpacked, file);
    await assertRegularFile(path, `builder unpacked file ${file}`);
    files.push({ path: `release/unpacked/${file}`, data: await readFile(path) });
  }
  return files;
}

async function materializeAndBuild({ temporaryRoot, id, sourceGitCommit, version, toolchain }) {
  const checkout = join(temporaryRoot, id);
  try {
    await run("git", ["clone", "--quiet", "--shared", "--no-checkout", repositoryRoot, checkout]);
    await run("git", ["checkout", "--quiet", "--detach", sourceGitCommit], checkout);
    const { stdout: initialStatus } = await run(
      "git",
      ["status", "--porcelain=v1", "--untracked-files=all"],
      checkout,
    );
    if (initialStatus !== "") {
      fail(`${id} is not clean before install`);
    }
    await run("pnpm", ["install", "--frozen-lockfile", "--offline"], checkout);
    await run("pnpm", ["--filter", "@warden/extension", "release:gate"], checkout);
    const { stdout: finalStatus } = await run(
      "git",
      ["status", "--porcelain=v1", "--untracked-files=all"],
      checkout,
    );
    if (finalStatus !== "") {
      fail(`${id} source tree changed during install or release`);
    }
    return await collectBuilderRelease(checkout, version, sourceGitCommit, toolchain);
  } finally {
    await rm(checkout, { recursive: true, force: true });
  }
}

async function writeReport(path, bytes) {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  try {
    const existing = await lstat(path);
    if (!existing.isFile() || existing.isSymbolicLink()) {
      fail("refusing to replace a non-file or symlinked dual-release report");
    }
    await unlink(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
  const staging = `${path}.staging-${process.pid}`;
  try {
    await writeFile(staging, bytes, { flag: "wx", mode: 0o644 });
    await chmod(staging, 0o644);
    await rename(staging, path);
  } finally {
    await rm(staging, { force: true });
  }
}

async function main() {
  const canonicalRoot = await realpath(repositoryRoot);
  const { stdout: gitRootOutput } = await run("git", ["rev-parse", "--show-toplevel"]);
  if (await realpath(gitRootOutput.trim()) !== canonicalRoot) {
    fail("script is not running from its repository");
  }
  const { stdout: status } = await run("git", ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") {
    fail(`source tree must be clean before the local dual release:\n${status.trimEnd()}`);
  }
  const { stdout: commitOutput } = await run("git", ["rev-parse", "HEAD"]);
  const sourceGitCommit = commitOutput.trim();
  if (!/^[0-9a-f]{40}$/.test(sourceGitCommit)) {
    fail("git did not return a full source SHA");
  }
  const sourceManifest = JSON.parse(
    await readFile(join(extensionDirectory, "manifest.json"), "utf8"),
  );
  const extensionVersion = sourceManifest.version;
  releaseFileNames(extensionVersion);
  const rootPackage = JSON.parse(await readFile(join(repositoryRoot, "package.json"), "utf8"));
  const extensionPackage = JSON.parse(
    await readFile(join(extensionDirectory, "package.json"), "utf8"),
  );
  const { stdout: pnpmOutput } = await run("pnpm", ["--version"]);
  const toolchain = {
    node: process.versions.node,
    pnpm: pnpmOutput.trim(),
    esbuild: extensionPackage.devDependencies?.esbuild,
  };
  if (
    rootPackage.engines?.node !== toolchain.node ||
    rootPackage.engines?.pnpm !== toolchain.pnpm
  ) {
    fail("observed Node or pnpm differs from the exact root package pins");
  }
  const orchestratorBytes = await readFile(scriptPath);
  const orchestrator = {
    path: "repo:scripts/local-dual-extension-release.mjs",
    bytes: orchestratorBytes.length,
    sha256: sha256(orchestratorBytes),
  };
  const temporaryRoot = await mkdtemp(join(tmpdir(), "warden-extension-dual-release-"));
  let firstFiles;
  let secondFiles;
  try {
    firstFiles = await materializeAndBuild({
      temporaryRoot,
      id: "local-a",
      sourceGitCommit,
      version: extensionVersion,
      toolchain,
    });
    secondFiles = await materializeAndBuild({
      temporaryRoot,
      id: "local-b",
      sourceGitCommit,
      version: extensionVersion,
      toolchain,
    });
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
  const report = createLocalDualReleaseReport({
    sourceGitCommit,
    toolchain,
    orchestrator,
    extensionVersion,
    firstFiles,
    secondFiles,
  });
  const reportBytes = Buffer.from(serializeLocalDualReleaseReport(report), "utf8");
  const reportPath = join(
    releaseDirectory,
    `warden-extension-${extensionVersion}.dual-local.json`,
  );
  await writeReport(reportPath, reportBytes);
  console.log(`local dual release report ${relative(repositoryRoot, reportPath).split(sep).join("/")}`);
  console.log(`source ${sourceGitCommit}`);
  console.log(`compared files ${report.comparison.fileCount}`);
  console.log(`report sha256 ${sha256(reportBytes)}`);
  console.log("scope same-host sequential clones with a shared pnpm store; independent builders not asserted");
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
