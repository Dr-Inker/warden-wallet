import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";

export const RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA =
  "warden.extension-release-recipe-input-evidence.v1";

export const RELEASE_RECIPE_INPUT_PATHS = Object.freeze([
  ".node-version",
  ".npmrc",
  "apps/extension/package.json",
  "apps/extension/scripts/build.mjs",
  "apps/extension/scripts/bundle-input-evidence.mjs",
  "apps/extension/scripts/package-release.mjs",
  "apps/extension/scripts/production-dependency-evidence.mjs",
  "apps/extension/scripts/release-artifact.mjs",
  "apps/extension/scripts/release-recipe-input-evidence.mjs",
  "apps/extension/scripts/release-source-tag.mjs",
  "apps/extension/scripts/reviewed-artifact-signature.mjs",
  "apps/extension/scripts/static-input-evidence.mjs",
  "apps/extension/scripts/store-package.mjs",
  "apps/extension/scripts/verify-release-source-tag.mjs",
  "apps/extension/scripts/verify-release.mjs",
  "apps/extension/scripts/verify-reviewed-artifact-signature.mjs",
  "apps/extension/scripts/verify-store-package.mjs",
  "package.json",
  "packages/core/package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
]);

const SCOPE = Object.freeze({
  type: "extension-release-recipe-repository-inputs",
  inputCoverage: "twenty-one-reviewed-non-payload-files-only",
  executableCoverage: "not-asserted",
  runtimeEnvironmentCoverage: "not-asserted",
});

function fail(message) {
  throw new Error(`extension release recipe input evidence: ${message}`);
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

function assertSource(source) {
  assertExactKeys(source, ["gitCommit", "lockfileSha256"], "evidence source");
  if (typeof source.gitCommit !== "string" || !/^[0-9a-f]{40}$/.test(source.gitCommit)) {
    fail("evidence source gitCommit must be a full lowercase commit SHA");
  }
  assertHash(source.lockfileSha256, "evidence source lockfileSha256");
}

function portableRelative(parent, candidate) {
  return relative(parent, candidate).split(sep).join("/");
}

function normalizeInputPaths(inputPaths) {
  if (!Array.isArray(inputPaths) || inputPaths.some((path) => typeof path !== "string")) {
    fail("reviewed input paths are required");
  }
  const normalized = [...inputPaths].sort(compareUtf8);
  if (JSON.stringify(normalized) !== JSON.stringify(RELEASE_RECIPE_INPUT_PATHS)) {
    fail("input paths must contain exactly the twenty-one reviewed release recipe files");
  }
  return normalized;
}

function assertEvidenceShape(evidence) {
  assertExactKeys(
    evidence,
    ["schema", "scope", "source", "artifact", "inputs"],
    "release recipe input evidence",
  );
  if (evidence.schema !== RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA) {
    fail(`unsupported evidence schema: ${String(evidence.schema)}`);
  }
  assertExactKeys(
    evidence.scope,
    ["type", "inputCoverage", "executableCoverage", "runtimeEnvironmentCoverage"],
    "evidence scope",
  );
  if (
    evidence.scope.type !== SCOPE.type ||
    evidence.scope.inputCoverage !== SCOPE.inputCoverage ||
    evidence.scope.executableCoverage !== SCOPE.executableCoverage ||
    evidence.scope.runtimeEnvironmentCoverage !== SCOPE.runtimeEnvironmentCoverage
  ) {
    fail("evidence scope differs from the reviewed release recipe scope");
  }
  assertSource(evidence.source);
  assertExactKeys(evidence.artifact, ["archiveFile", "archiveSha256"], "evidence artifact");
  if (
    typeof evidence.artifact.archiveFile !== "string" ||
    !/^[A-Za-z0-9._-]+\.zip$/.test(evidence.artifact.archiveFile)
  ) {
    fail("evidence archive file is invalid");
  }
  assertHash(evidence.artifact.archiveSha256, "evidence archiveSha256");
  if (!Array.isArray(evidence.inputs) || evidence.inputs.length !== RELEASE_RECIPE_INPUT_PATHS.length) {
    fail("evidence must contain exactly twenty-one release recipe inputs");
  }
  for (let index = 0; index < RELEASE_RECIPE_INPUT_PATHS.length; index += 1) {
    const input = evidence.inputs[index];
    const expectedPath = `repo:${RELEASE_RECIPE_INPUT_PATHS[index]}`;
    assertExactKeys(input, ["path", "bytes", "sha256"], `recipe input ${String(input?.path)}`);
    if (
      input.path !== expectedPath ||
      !Number.isSafeInteger(input.bytes) ||
      input.bytes <= 0
    ) {
      fail(`recipe input identity or byte metadata is invalid for ${expectedPath}`);
    }
    assertHash(input.sha256, `recipe input hash for ${expectedPath}`);
  }
  const lockfile = evidence.inputs.find((input) => input.path === "repo:pnpm-lock.yaml");
  if (lockfile?.sha256 !== evidence.source.lockfileSha256) {
    fail("recipe lockfile hash differs from the evidence source lockfile hash");
  }
}

async function readReviewedInputs(repositoryRoot, inputPaths) {
  const canonicalRepositoryRoot = await realpath(repositoryRoot);
  const inputs = [];
  for (const expectedPath of normalizeInputPaths(inputPaths)) {
    let canonicalPath;
    try {
      canonicalPath = await realpath(join(canonicalRepositoryRoot, ...expectedPath.split("/")));
    } catch (error) {
      fail(`reviewed input is unreadable: ${expectedPath} (${error instanceof Error ? error.message : String(error)})`);
    }
    if (portableRelative(canonicalRepositoryRoot, canonicalPath) !== expectedPath) {
      fail(`reviewed input path moved or escapes the repository: ${expectedPath}`);
    }
    const bytes = await readFile(canonicalPath);
    if (bytes.length === 0) {
      fail(`reviewed input is empty: ${expectedPath}`);
    }
    inputs.push({
      path: `repo:${expectedPath}`,
      bytes: bytes.length,
      sha256: sha256(bytes),
    });
  }
  return inputs;
}

export async function createReleaseRecipeInputEvidence({
  repositoryRoot,
  inputPaths,
  source,
  archiveFileName,
  archiveBytes,
}) {
  if (!(archiveBytes instanceof Uint8Array)) {
    fail("archive bytes are required");
  }
  const evidence = {
    schema: RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA,
    scope: { ...SCOPE },
    source: {
      gitCommit: source?.gitCommit,
      lockfileSha256: source?.lockfileSha256,
    },
    artifact: {
      archiveFile: archiveFileName,
      archiveSha256: sha256(archiveBytes),
    },
    inputs: await readReviewedInputs(repositoryRoot, inputPaths),
  };
  assertEvidenceShape(evidence);
  return evidence;
}

export function serializeReleaseRecipeInputEvidence(evidence) {
  assertEvidenceShape(evidence);
  return `${JSON.stringify(evidence, null, 2)}\n`;
}

export function parseReleaseRecipeInputEvidence(bytes) {
  const evidenceBytes = Buffer.from(bytes);
  const text = evidenceBytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(evidenceBytes)) {
    fail("evidence is not canonical UTF-8");
  }
  let evidence;
  try {
    evidence = JSON.parse(text);
  } catch (error) {
    fail(`evidence is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertEvidenceShape(evidence);
  if (text !== serializeReleaseRecipeInputEvidence(evidence)) {
    fail("evidence must use the canonical generated JSON serialization");
  }
  return evidence;
}

export async function verifyReleaseRecipeInputEvidenceAttachment({
  evidenceBytes,
  artifactManifest,
  archiveBytes,
  repositoryRoot,
}) {
  const attachment = artifactManifest?.releaseRecipeInputEvidence;
  assertExactKeys(
    attachment,
    ["file", "schema", "bytes", "sha256"],
    "artifact release recipe input evidence attachment",
  );
  if (
    typeof attachment.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.recipe-inputs\.json$/.test(attachment.file) ||
    attachment.schema !== RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(attachment.bytes) ||
    attachment.bytes <= 0 ||
    attachment.bytes !== evidenceBytes.length ||
    attachment.sha256 !== sha256(evidenceBytes)
  ) {
    fail("artifact attachment metadata or evidence bytes differ");
  }
  const evidence = parseReleaseRecipeInputEvidence(evidenceBytes);
  if (JSON.stringify(evidence.source) !== JSON.stringify(artifactManifest.source)) {
    fail("evidence source differs from the artifact manifest");
  }
  if (
    evidence.artifact.archiveFile !== artifactManifest.archive.file ||
    evidence.artifact.archiveSha256 !== artifactManifest.archive.sha256 ||
    evidence.artifact.archiveSha256 !== sha256(archiveBytes)
  ) {
    fail("evidence archive bytes differ from the artifact manifest");
  }
  const actualInputs = await readReviewedInputs(repositoryRoot, RELEASE_RECIPE_INPUT_PATHS);
  if (JSON.stringify(actualInputs) !== JSON.stringify(evidence.inputs)) {
    fail("evidence inputs differ from the current reviewed repository files");
  }
  return { inputs: evidence.inputs.length };
}
