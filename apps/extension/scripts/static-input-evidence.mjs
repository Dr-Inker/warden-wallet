import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";

export const STATIC_INPUT_EVIDENCE_SCHEMA =
  "warden.extension-static-input-evidence.v1";

const EXPECTED_FILES = Object.freeze([
  { outputFile: "approval.css", sourceFile: "approval.css", transformation: "byte-copy" },
  { outputFile: "approval.html", sourceFile: "approval.html", transformation: "byte-copy" },
  {
    outputFile: "manifest.json",
    sourceFile: "manifest.json",
    transformation: "json-parse-stringify-two-space-newline",
  },
  { outputFile: "popup.html", sourceFile: "popup.html", transformation: "byte-copy" },
]);
const SCOPE = Object.freeze({
  type: "extension-non-javascript-payload-source-map",
  outputCoverage: "four-emitted-non-javascript-files-only",
  absentAssetCoverage: "not-asserted",
});

function fail(message) {
  throw new Error(`extension static input evidence: ${message}`);
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

function isWithin(parent, candidate) {
  const path = relative(parent, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function portableRelative(parent, candidate) {
  return relative(parent, candidate).split(sep).join("/");
}

function canonicalJsonBytes(sourceBytes, sourceFile) {
  const text = sourceBytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(sourceBytes)) {
    fail(`${sourceFile} is not canonical UTF-8`);
  }
  try {
    return Buffer.from(`${JSON.stringify(JSON.parse(text), null, 2)}\n`, "utf8");
  } catch (error) {
    fail(`${sourceFile} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function assertEvidenceShape(evidence) {
  assertExactKeys(evidence, ["schema", "scope", "source", "artifact", "files"], "static input evidence");
  if (evidence.schema !== STATIC_INPUT_EVIDENCE_SCHEMA) {
    fail(`unsupported evidence schema: ${String(evidence.schema)}`);
  }
  assertExactKeys(evidence.scope, ["type", "outputCoverage", "absentAssetCoverage"], "evidence scope");
  if (
    evidence.scope.type !== SCOPE.type ||
    evidence.scope.outputCoverage !== SCOPE.outputCoverage ||
    evidence.scope.absentAssetCoverage !== SCOPE.absentAssetCoverage
  ) {
    fail("evidence scope differs from the reviewed static-file scope");
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
  if (!Array.isArray(evidence.files) || evidence.files.length !== EXPECTED_FILES.length) {
    fail("evidence must contain exactly four static files");
  }
  for (let index = 0; index < EXPECTED_FILES.length; index += 1) {
    const file = evidence.files[index];
    const expected = EXPECTED_FILES[index];
    assertExactKeys(
      file,
      ["output", "source", "transformation", "sourceBytes", "sourceSha256", "outputBytes", "outputSha256"],
      `static file ${String(file?.output)}`,
    );
    if (
      file.output !== expected.outputFile ||
      file.source !== `repo:apps/extension/${expected.sourceFile}` ||
      file.transformation !== expected.transformation ||
      !Number.isSafeInteger(file.sourceBytes) ||
      file.sourceBytes <= 0 ||
      !Number.isSafeInteger(file.outputBytes) ||
      file.outputBytes <= 0
    ) {
      fail(`static file identity or byte metadata is invalid for ${expected.outputFile}`);
    }
    assertHash(file.sourceSha256, `source hash for ${file.output}`);
    assertHash(file.outputSha256, `output hash for ${file.output}`);
    if (
      file.transformation === "byte-copy" &&
      (file.sourceBytes !== file.outputBytes || file.sourceSha256 !== file.outputSha256)
    ) {
      fail(`byte-copy evidence differs for ${file.output}`);
    }
  }
}

export async function createStaticInputEvidence({
  staticResults,
  entries,
  appDirectory,
  repositoryRoot,
  source,
  archiveFileName,
  archiveBytes,
}) {
  const canonicalRepositoryRoot = await realpath(repositoryRoot);
  const canonicalAppDirectory = await realpath(appDirectory);
  if (!isWithin(canonicalRepositoryRoot, canonicalAppDirectory)) {
    fail("extension directory must be inside the repository");
  }
  if (
    portableRelative(canonicalRepositoryRoot, canonicalAppDirectory) !== "apps/extension" ||
    !Array.isArray(staticResults) ||
    !Array.isArray(entries) ||
    !(archiveBytes instanceof Uint8Array)
  ) {
    fail("reviewed extension paths, build results, payload entries, and archive bytes are required");
  }
  const normalizedResults = staticResults.map((result) => {
    assertExactKeys(result, ["outputFile", "sourceFile", "transformation"], "static build result");
    return result;
  }).sort((left, right) => Buffer.compare(
    Buffer.from(left.outputFile, "utf8"),
    Buffer.from(right.outputFile, "utf8"),
  ));
  if (JSON.stringify(normalizedResults) !== JSON.stringify(EXPECTED_FILES)) {
    fail("build results must contain exactly the four reviewed static transformations");
  }
  const payload = new Map(entries.map((entry) => [entry.path, Buffer.from(entry.data)]));
  const files = [];
  for (const expected of EXPECTED_FILES) {
    const sourcePath = await realpath(join(canonicalAppDirectory, expected.sourceFile));
    if (!isWithin(canonicalAppDirectory, sourcePath)) {
      fail(`static source escapes the extension directory: ${expected.sourceFile}`);
    }
    const sourceBytes = await readFile(sourcePath);
    const outputBytes = payload.get(expected.outputFile);
    if (outputBytes === undefined) {
      fail(`static output is missing from the release payload: ${expected.outputFile}`);
    }
    const transformed = expected.transformation === "byte-copy"
      ? sourceBytes
      : canonicalJsonBytes(sourceBytes, expected.sourceFile);
    if (!transformed.equals(outputBytes)) {
      fail(`reviewed transformation differs from the release payload for ${expected.outputFile}`);
    }
    files.push({
      output: expected.outputFile,
      source: `repo:${portableRelative(canonicalRepositoryRoot, sourcePath)}`,
      transformation: expected.transformation,
      sourceBytes: sourceBytes.length,
      sourceSha256: sha256(sourceBytes),
      outputBytes: outputBytes.length,
      outputSha256: sha256(outputBytes),
    });
  }
  const evidence = {
    schema: STATIC_INPUT_EVIDENCE_SCHEMA,
    scope: { ...SCOPE },
    source: {
      gitCommit: source?.gitCommit,
      lockfileSha256: source?.lockfileSha256,
    },
    artifact: {
      archiveFile: archiveFileName,
      archiveSha256: sha256(archiveBytes),
    },
    files,
  };
  assertEvidenceShape(evidence);
  return evidence;
}

export function serializeStaticInputEvidence(evidence) {
  assertEvidenceShape(evidence);
  return `${JSON.stringify(evidence, null, 2)}\n`;
}

export function parseStaticInputEvidence(bytes) {
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
  if (text !== serializeStaticInputEvidence(evidence)) {
    fail("evidence must use the canonical generated JSON serialization");
  }
  return evidence;
}

export function verifyStaticInputEvidenceAttachment({
  evidenceBytes,
  artifactManifest,
  archiveBytes,
}) {
  const attachment = artifactManifest?.staticInputEvidence;
  assertExactKeys(attachment, ["file", "schema", "bytes", "sha256"], "artifact static input evidence attachment");
  if (
    typeof attachment.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.static-inputs\.json$/.test(attachment.file) ||
    attachment.schema !== STATIC_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(attachment.bytes) ||
    attachment.bytes <= 0 ||
    attachment.bytes !== evidenceBytes.length ||
    attachment.sha256 !== sha256(evidenceBytes)
  ) {
    fail("artifact attachment metadata or evidence bytes differ");
  }
  const evidence = parseStaticInputEvidence(evidenceBytes);
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
  const payloadFiles = new Map(artifactManifest.payload.files.map((file) => [file.path, file]));
  for (const file of evidence.files) {
    const payloadFile = payloadFiles.get(file.output);
    if (
      payloadFile === undefined ||
      payloadFile.bytes !== file.outputBytes ||
      payloadFile.sha256 !== file.outputSha256
    ) {
      fail(`evidence output differs from artifact payload: ${file.output}`);
    }
  }
  return { files: evidence.files.length };
}
