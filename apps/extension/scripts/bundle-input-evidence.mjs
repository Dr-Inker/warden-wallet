import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

export const JS_BUNDLE_INPUT_EVIDENCE_SCHEMA =
  "warden.extension-js-bundle-input-evidence.v1";

const EXPECTED_BUNDLES = Object.freeze([
  "approval.js",
  "background.js",
  "content.js",
  "popup.js",
]);
const SCOPE = Object.freeze({
  type: "esbuild-metafile-positive-output-inputs",
  outputCoverage: "four-emitted-javascript-bundles-only",
  staticAssetCoverage: "not-asserted",
  attributionMeaning: "esbuild-bytesInOutput-estimate-not-byte-partition",
});

function fail(message) {
  throw new Error(`extension bundle input evidence: ${message}`);
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

function isWithin(parent, candidate) {
  const path = relative(parent, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function portableRelative(parent, candidate) {
  return relative(parent, candidate).split(sep).join("/");
}

async function normalizeFileInput({
  rawInput,
  expectedSourceBytes,
  canonicalAppDirectory,
  canonicalRepositoryRoot,
}) {
  if (
    typeof rawInput !== "string" ||
    rawInput.length === 0 ||
    rawInput.includes("\0") ||
    rawInput.includes("\\")
  ) {
    fail(`unsupported esbuild input path: ${String(rawInput)}`);
  }
  const candidate = resolve(canonicalAppDirectory, rawInput);
  let canonicalPath;
  try {
    canonicalPath = await realpath(candidate);
  } catch (error) {
    fail(`esbuild input is not a readable file (${rawInput}): ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isWithin(canonicalRepositoryRoot, canonicalPath)) {
    fail(`esbuild input escapes the repository: ${rawInput}`);
  }
  const bytes = await readFile(canonicalPath);
  if (
    expectedSourceBytes !== undefined &&
    (!Number.isSafeInteger(expectedSourceBytes) || expectedSourceBytes < 0 || expectedSourceBytes !== bytes.length)
  ) {
    fail(`esbuild source byte count disagrees for ${rawInput}`);
  }

  const repositoryParts = portableRelative(canonicalRepositoryRoot, canonicalPath).split("/");
  const nodeModulesIndex = repositoryParts.lastIndexOf("node_modules");
  if (nodeModulesIndex >= 0) {
    const packageStart = nodeModulesIndex + 1;
    const scoped = repositoryParts[packageStart]?.startsWith("@");
    const packageParts = repositoryParts.slice(
      packageStart,
      packageStart + (scoped ? 2 : 1),
    );
    if (
      packageParts.length !== (scoped ? 2 : 1) ||
      packageParts.some((part) => part.length === 0)
    ) {
      fail(`cannot identify installed package for ${rawInput}`);
    }
    const packageRoot = join(
      canonicalRepositoryRoot,
      ...repositoryParts.slice(0, packageStart),
      ...packageParts,
    );
    let packageJson;
    try {
      packageJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
    } catch (error) {
      fail(`installed input package.json is unreadable for ${rawInput}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const packageName = packageParts.join("/");
    if (
      packageJson.name !== packageName ||
      typeof packageJson.version !== "string" ||
      !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(packageJson.version)
    ) {
      fail(`installed input package identity is invalid for ${rawInput}`);
    }
    const packagePath = portableRelative(packageRoot, canonicalPath);
    if (packagePath === "" || packagePath.startsWith("../")) {
      fail(`installed input path is not below its package root: ${rawInput}`);
    }
    return {
      id: `npm:${packageName}@${packageJson.version}/${packagePath}`,
      kind: "registry",
      sourceBytes: bytes.length,
      sourceSha256: sha256(bytes),
    };
  }

  const repositoryPath = portableRelative(canonicalRepositoryRoot, canonicalPath);
  if (repositoryPath === "" || repositoryPath.startsWith("../")) {
    fail(`repository input path is invalid: ${rawInput}`);
  }
  return {
    id: `repo:${repositoryPath}`,
    kind: "repository",
    sourceBytes: bytes.length,
    sourceSha256: sha256(bytes),
  };
}

async function normalizeOutputInput({
  rawInput,
  inputMetadata,
  bytesInOutput,
  canonicalAppDirectory,
  canonicalRepositoryRoot,
}) {
  if (!Number.isSafeInteger(bytesInOutput) || bytesInOutput <= 0) {
    fail(`positive esbuild bytesInOutput is required for ${rawInput}`);
  }
  if (rawInput.startsWith("(disabled):")) {
    const source = await normalizeFileInput({
      rawInput: rawInput.slice("(disabled):".length),
      expectedSourceBytes: undefined,
      canonicalAppDirectory,
      canonicalRepositoryRoot,
    });
    return {
      id: `esbuild-disabled:${source.id}`,
      kind: "esbuild-virtual",
      sourceBytes: null,
      sourceSha256: null,
      bytesInOutput,
    };
  }
  if (rawInput.startsWith("(") || rawInput.startsWith("<")) {
    fail(`unsupported esbuild virtual input: ${rawInput}`);
  }
  const source = await normalizeFileInput({
    rawInput,
    expectedSourceBytes: inputMetadata?.bytes,
    canonicalAppDirectory,
    canonicalRepositoryRoot,
  });
  return { ...source, bytesInOutput };
}

function assertEvidenceShape(evidence) {
  assertExactKeys(evidence, ["schema", "scope", "source", "artifact", "bundles"], "bundle input evidence");
  if (evidence.schema !== JS_BUNDLE_INPUT_EVIDENCE_SCHEMA) {
    fail(`unsupported evidence schema: ${String(evidence.schema)}`);
  }
  assertExactKeys(
    evidence.scope,
    ["type", "outputCoverage", "staticAssetCoverage", "attributionMeaning"],
    "evidence scope",
  );
  if (
    evidence.scope.type !== SCOPE.type ||
    evidence.scope.outputCoverage !== SCOPE.outputCoverage ||
    evidence.scope.staticAssetCoverage !== SCOPE.staticAssetCoverage ||
    evidence.scope.attributionMeaning !== SCOPE.attributionMeaning
  ) {
    fail("evidence scope differs from the reviewed JavaScript-only scope");
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
  if (!Array.isArray(evidence.bundles)) {
    fail("evidence bundles must be an array");
  }
  if (JSON.stringify(evidence.bundles.map((bundle) => bundle.output)) !== JSON.stringify(EXPECTED_BUNDLES)) {
    fail("evidence must contain the four canonically sorted JavaScript bundles");
  }
  for (const bundle of evidence.bundles) {
    assertExactKeys(
      bundle,
      ["output", "bytes", "sha256", "inputCount", "zeroByteInputCount", "attributedBytes", "unattributedBytes", "inputs"],
      `bundle ${String(bundle?.output)}`,
    );
    if (
      !Number.isSafeInteger(bundle.bytes) ||
      bundle.bytes <= 0 ||
      !Number.isSafeInteger(bundle.inputCount) ||
      bundle.inputCount <= 0 ||
      !Number.isSafeInteger(bundle.zeroByteInputCount) ||
      bundle.zeroByteInputCount < 0 ||
      !Number.isSafeInteger(bundle.attributedBytes) ||
      bundle.attributedBytes <= 0 ||
      !Number.isSafeInteger(bundle.unattributedBytes) ||
      bundle.unattributedBytes < 0 ||
      bundle.attributedBytes + bundle.unattributedBytes !== bundle.bytes ||
      !Array.isArray(bundle.inputs) ||
      bundle.inputs.length !== bundle.inputCount
    ) {
      fail(`bundle byte accounting is invalid for ${bundle.output}`);
    }
    assertHash(bundle.sha256, `bundle hash for ${bundle.output}`);
    let previousId;
    let attributedBytes = 0;
    for (const input of bundle.inputs) {
      assertExactKeys(
        input,
        ["id", "kind", "sourceBytes", "sourceSha256", "bytesInOutput"],
        `bundle input for ${bundle.output}`,
      );
      if (
        typeof input.id !== "string" ||
        input.id.length === 0 ||
        input.id.includes("\0") ||
        input.id.includes("\\") ||
        (input.kind !== "repository" && input.kind !== "registry" && input.kind !== "esbuild-virtual") ||
        !Number.isSafeInteger(input.bytesInOutput) ||
        input.bytesInOutput <= 0
      ) {
        fail(`bundle input identity is invalid for ${bundle.output}`);
      }
      if (previousId !== undefined && compareUtf8(previousId, input.id) >= 0) {
        fail(`bundle inputs are not unique and canonically sorted for ${bundle.output}`);
      }
      previousId = input.id;
      if (input.kind === "esbuild-virtual") {
        if (
          !input.id.startsWith("esbuild-disabled:") ||
          input.sourceBytes !== null ||
          input.sourceSha256 !== null
        ) {
          fail(`virtual input metadata is invalid for ${bundle.output}`);
        }
      } else {
        if (
          !Number.isSafeInteger(input.sourceBytes) ||
          input.sourceBytes < 0 ||
          (input.kind === "repository" && !input.id.startsWith("repo:")) ||
          (input.kind === "registry" && !input.id.startsWith("npm:"))
        ) {
          fail(`source input metadata is invalid for ${bundle.output}`);
        }
        assertHash(input.sourceSha256, `source input hash for ${input.id}`);
      }
      attributedBytes += input.bytesInOutput;
    }
    if (attributedBytes !== bundle.attributedBytes) {
      fail(`bundle attributed byte total disagrees for ${bundle.output}`);
    }
  }
}

export async function createJavaScriptBundleInputEvidence({
  buildResults,
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
  if (!Array.isArray(buildResults) || !Array.isArray(entries) || !(archiveBytes instanceof Uint8Array)) {
    fail("build results, payload entries, and archive bytes are required");
  }
  const payload = new Map(entries.map((entry) => [entry.path, Buffer.from(entry.data)]));
  const byOutput = new Map();
  for (const result of buildResults) {
    assertExactKeys(result, ["outputFile", "metafile"], "build result");
    if (byOutput.has(result.outputFile)) {
      fail(`duplicate build result for ${result.outputFile}`);
    }
    byOutput.set(result.outputFile, result.metafile);
  }
  if (JSON.stringify([...byOutput.keys()].sort(compareUtf8)) !== JSON.stringify(EXPECTED_BUNDLES)) {
    fail("build results must contain exactly the four reviewed JavaScript bundles");
  }

  const bundles = [];
  for (const outputFile of EXPECTED_BUNDLES) {
    const metafile = byOutput.get(outputFile);
    if (!isPlainObject(metafile?.inputs) || !isPlainObject(metafile?.outputs)) {
      fail(`esbuild metafile is invalid for ${outputFile}`);
    }
    const outputRecords = Object.entries(metafile.outputs);
    const matchingOutputs = outputRecords.filter(([path]) => path.replaceAll("\\", "/").endsWith(`/dist/${outputFile}`) || path === `dist/${outputFile}`);
    if (outputRecords.length !== 1 || matchingOutputs.length !== 1) {
      fail(`esbuild metafile must contain exactly output dist/${outputFile}`);
    }
    const outputMetadata = matchingOutputs[0][1];
    if (!isPlainObject(outputMetadata?.inputs) || !Number.isSafeInteger(outputMetadata.bytes)) {
      fail(`esbuild output metadata is invalid for ${outputFile}`);
    }
    const outputBytes = payload.get(outputFile);
    if (outputBytes === undefined || outputMetadata.bytes !== outputBytes.length) {
      fail(`esbuild output bytes disagree with the release payload for ${outputFile}`);
    }
    const inputs = [];
    let zeroByteInputCount = 0;
    for (const [rawInput, attribution] of Object.entries(outputMetadata.inputs)) {
      if (!isPlainObject(attribution) || !Number.isSafeInteger(attribution.bytesInOutput) || attribution.bytesInOutput < 0) {
        fail(`esbuild output attribution is invalid for ${rawInput}`);
      }
      if (!Object.hasOwn(metafile.inputs, rawInput)) {
        fail(`esbuild output input is absent from the metafile input table: ${rawInput}`);
      }
      if (attribution.bytesInOutput === 0) {
        zeroByteInputCount += 1;
        continue;
      }
      inputs.push(await normalizeOutputInput({
        rawInput,
        inputMetadata: metafile.inputs[rawInput],
        bytesInOutput: attribution.bytesInOutput,
        canonicalAppDirectory,
        canonicalRepositoryRoot,
      }));
    }
    inputs.sort((left, right) => compareUtf8(left.id, right.id));
    if (inputs.some((input, index) => index > 0 && input.id === inputs[index - 1].id)) {
      fail(`esbuild inputs collapse to a duplicate canonical identity for ${outputFile}`);
    }
    const attributedBytes = inputs.reduce((total, input) => total + input.bytesInOutput, 0);
    if (inputs.length === 0 || attributedBytes > outputBytes.length) {
      fail(`esbuild input accounting is invalid for ${outputFile}`);
    }
    bundles.push({
      output: outputFile,
      bytes: outputBytes.length,
      sha256: sha256(outputBytes),
      inputCount: inputs.length,
      zeroByteInputCount,
      attributedBytes,
      unattributedBytes: outputBytes.length - attributedBytes,
      inputs,
    });
  }

  const evidence = {
    schema: JS_BUNDLE_INPUT_EVIDENCE_SCHEMA,
    scope: { ...SCOPE },
    source: {
      gitCommit: source?.gitCommit,
      lockfileSha256: source?.lockfileSha256,
    },
    artifact: {
      archiveFile: archiveFileName,
      archiveSha256: sha256(archiveBytes),
    },
    bundles,
  };
  assertEvidenceShape(evidence);
  return evidence;
}

export function serializeJavaScriptBundleInputEvidence(evidence) {
  assertEvidenceShape(evidence);
  return `${JSON.stringify(evidence, null, 2)}\n`;
}

export function parseJavaScriptBundleInputEvidence(bytes) {
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
  if (text !== serializeJavaScriptBundleInputEvidence(evidence)) {
    fail("evidence must use the canonical generated JSON serialization");
  }
  return evidence;
}

export function verifyJavaScriptBundleInputEvidenceAttachment({
  evidenceBytes,
  artifactManifest,
  archiveBytes,
}) {
  const attachment = artifactManifest?.bundleInputEvidence;
  assertExactKeys(attachment, ["file", "schema", "bytes", "sha256"], "artifact bundle input evidence attachment");
  if (
    typeof attachment.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.bundle-inputs\.json$/.test(attachment.file) ||
    attachment.schema !== JS_BUNDLE_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(attachment.bytes) ||
    attachment.bytes <= 0 ||
    attachment.bytes !== evidenceBytes.length ||
    attachment.sha256 !== sha256(evidenceBytes)
  ) {
    fail("artifact attachment metadata or evidence bytes differ");
  }
  const evidence = parseJavaScriptBundleInputEvidence(evidenceBytes);
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
  const payloadFiles = new Map(
    artifactManifest.payload.files.map((file) => [file.path, file]),
  );
  for (const bundle of evidence.bundles) {
    const payloadFile = payloadFiles.get(bundle.output);
    if (
      payloadFile === undefined ||
      payloadFile.bytes !== bundle.bytes ||
      payloadFile.sha256 !== bundle.sha256
    ) {
      fail(`evidence bundle differs from artifact payload: ${bundle.output}`);
    }
  }
  return {
    bundles: evidence.bundles.length,
    inputs: evidence.bundles.reduce((total, bundle) => total + bundle.inputCount, 0),
  };
}
