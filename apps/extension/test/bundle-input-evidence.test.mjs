import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  JS_BUNDLE_INPUT_EVIDENCE_SCHEMA,
  createJavaScriptBundleInputEvidence,
  parseJavaScriptBundleInputEvidence,
  serializeJavaScriptBundleInputEvidence,
  verifyJavaScriptBundleInputEvidenceAttachment,
} from "../scripts/bundle-input-evidence.mjs";
import {
  createArtifactManifest,
  createCanonicalZip,
} from "../scripts/release-artifact.mjs";

const temporaryDirectories = [];
const SOURCE = Object.freeze({
  gitCommit: "a".repeat(40),
  lockfileSha256: "b".repeat(64),
});
const TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});
const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden bundle evidence fixture",
  version: "1.2.3",
  permissions: ["alarms", "storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function payloadEntries() {
  return [
    { path: "approval.js", data: Buffer.alloc(64, "a") },
    { path: "background.js", data: Buffer.alloc(64, "b") },
    { path: "content.js", data: Buffer.alloc(64, "c") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`) },
    { path: "popup.js", data: Buffer.alloc(64, "p") },
  ];
}

async function fixture() {
  const repositoryRoot = await mkdtemp(join(tmpdir(), "warden-bundle-evidence-test-"));
  temporaryDirectories.push(repositoryRoot);
  const appDirectory = join(repositoryRoot, "apps", "extension");
  const sourceDirectory = join(appDirectory, "src");
  const packageDirectory = join(
    repositoryRoot,
    "node_modules",
    ".pnpm",
    "fixture-package@1.2.3",
    "node_modules",
    "fixture-package",
  );
  await mkdir(sourceDirectory, { recursive: true });
  await mkdir(packageDirectory, { recursive: true });
  const sourceFiles = {
    approval: Buffer.from("export const approval = true;\n"),
    background: Buffer.from("export const background = true;\n"),
    content: Buffer.from("export const content = true;\n"),
    popup: Buffer.from("export const popup = true;\n"),
    zero: Buffer.from("export const zero = true;\n"),
    registry: Buffer.from("module.exports = 'fixture';\n"),
  };
  await Promise.all([
    ...["approval", "background", "content", "popup", "zero"].map((name) =>
      writeFile(join(sourceDirectory, `${name}.ts`), sourceFiles[name]),
    ),
    writeFile(join(packageDirectory, "index.js"), sourceFiles.registry),
    writeFile(
      join(packageDirectory, "package.json"),
      `${JSON.stringify({ name: "fixture-package", version: "1.2.3" }, null, 2)}\n`,
    ),
  ]);

  const rawRegistry = "../../node_modules/.pnpm/fixture-package@1.2.3/node_modules/fixture-package/index.js";
  function result(outputFile, records, reverse = false) {
    const ordered = reverse ? [...records].reverse() : records;
    return {
      outputFile,
      metafile: {
        inputs: Object.fromEntries(ordered.map((record) => [
          record.path,
          { bytes: record.sourceBytes },
        ])),
        outputs: {
          [`dist/${outputFile}`]: {
            bytes: 64,
            inputs: Object.fromEntries(ordered.map((record) => [
              record.path,
              { bytesInOutput: record.bytesInOutput },
            ])),
          },
        },
      },
    };
  }
  function buildResults(reverse = false) {
    const results = [
      result("approval.js", [
        { path: "src/approval.ts", sourceBytes: sourceFiles.approval.length, bytesInOutput: 20 },
      ], reverse),
      result("background.js", [
        { path: "src/background.ts", sourceBytes: sourceFiles.background.length, bytesInOutput: 18 },
        { path: rawRegistry, sourceBytes: sourceFiles.registry.length, bytesInOutput: 16 },
        { path: `(disabled):${rawRegistry}`, sourceBytes: 0, bytesInOutput: 3 },
        { path: "src/zero.ts", sourceBytes: sourceFiles.zero.length, bytesInOutput: 0 },
      ], reverse),
      result("content.js", [
        { path: "src/content.ts", sourceBytes: sourceFiles.content.length, bytesInOutput: 20 },
      ], reverse),
      result("popup.js", [
        { path: "src/popup.ts", sourceBytes: sourceFiles.popup.length, bytesInOutput: 18 },
      ], reverse),
    ];
    return reverse ? results.reverse() : results;
  }
  const entries = payloadEntries();
  const archiveBytes = createCanonicalZip(entries);
  async function evidence(reverse = false) {
    return createJavaScriptBundleInputEvidence({
      buildResults: buildResults(reverse),
      entries,
      appDirectory,
      repositoryRoot,
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes,
    });
  }
  return {
    repositoryRoot,
    appDirectory,
    sourceFiles,
    entries,
    archiveBytes,
    buildResults,
    evidence,
  };
}

describe("JavaScript bundle input evidence", () => {
  it("canonically records repository, registry, and virtual positive-byte inputs", async () => {
    const context = await fixture();
    const forward = await context.evidence(false);
    const reverse = await context.evidence(true);
    expect(serializeJavaScriptBundleInputEvidence(reverse)).toBe(
      serializeJavaScriptBundleInputEvidence(forward),
    );
    expect(forward.schema).toBe(JS_BUNDLE_INPUT_EVIDENCE_SCHEMA);
    expect(forward.scope).toEqual({
      type: "esbuild-metafile-positive-output-inputs",
      outputCoverage: "four-emitted-javascript-bundles-only",
      staticAssetCoverage: "not-asserted",
      attributionMeaning: "esbuild-bytesInOutput-estimate-not-byte-partition",
    });
    const background = forward.bundles.find((bundle) => bundle.output === "background.js");
    expect(background).toMatchObject({
      bytes: 64,
      inputCount: 3,
      zeroByteInputCount: 1,
      attributedBytes: 37,
      unattributedBytes: 27,
    });
    expect(background.inputs.map((input) => [input.kind, input.id])).toEqual([
      ["esbuild-virtual", "esbuild-disabled:npm:fixture-package@1.2.3/index.js"],
      ["registry", "npm:fixture-package@1.2.3/index.js"],
      ["repository", "repo:apps/extension/src/background.ts"],
    ]);
    expect(background.inputs.find((input) => input.kind === "registry")).toMatchObject({
      sourceBytes: context.sourceFiles.registry.length,
      sourceSha256: sha256(context.sourceFiles.registry),
    });
    expect(serializeJavaScriptBundleInputEvidence(forward)).not.toContain(context.repositoryRoot);
  });

  it("is hash-bound to the artifact manifest, archive, and four payload bundles", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const evidenceBytes = Buffer.from(serializeJavaScriptBundleInputEvidence(evidence));
    const artifactManifest = createArtifactManifest({
      entries: context.entries,
      archiveBytes: context.archiveBytes,
      artifactFileName: "warden-extension-1.2.3.zip",
      source: SOURCE,
      toolchain: TOOLCHAIN,
      dependencyEvidence: {
        file: "warden-extension-1.2.3.sbom.json",
        bytes: Buffer.from("canonical dependency evidence fixture\n"),
      },
      bundleInputEvidence: {
        file: "warden-extension-1.2.3.bundle-inputs.json",
        bytes: evidenceBytes,
      },
      staticInputEvidence: {
        file: "warden-extension-1.2.3.static-inputs.json",
        bytes: Buffer.from("canonical static input evidence fixture\n"),
      },
      releaseRecipeInputEvidence: {
        file: "warden-extension-1.2.3.recipe-inputs.json",
        bytes: Buffer.from("canonical release recipe input evidence fixture\n"),
      },
    });
    expect(artifactManifest.bundleInputEvidence.sha256).toBe(sha256(evidenceBytes));
    expect(verifyJavaScriptBundleInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes: context.archiveBytes,
    })).toEqual({ bundles: 4, inputs: 6 });

    const tamperedEvidence = Buffer.from(
      evidenceBytes.toString("utf8").replace('"bytesInOutput": 20', '"bytesInOutput": 21'),
    );
    expect(() => verifyJavaScriptBundleInputEvidenceAttachment({
      evidenceBytes: tamperedEvidence,
      artifactManifest,
      archiveBytes: context.archiveBytes,
    })).toThrow(/evidence bytes differ/);
    expect(() => verifyJavaScriptBundleInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes: Buffer.concat([context.archiveBytes, Buffer.from([0])]),
    })).toThrow(/archive bytes differ/);
  });

  it("fails closed on missing or extra bundles and mismatched source bytes", async () => {
    const context = await fixture();
    await expect(createJavaScriptBundleInputEvidence({
      buildResults: context.buildResults().slice(1),
      entries: context.entries,
      appDirectory: context.appDirectory,
      repositoryRoot: context.repositoryRoot,
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: context.archiveBytes,
    })).rejects.toThrow(/exactly the four reviewed/);

    const extra = structuredClone(context.buildResults());
    extra.push(structuredClone(extra[0]));
    extra[extra.length - 1].outputFile = "surprise.js";
    await expect(createJavaScriptBundleInputEvidence({
      buildResults: extra,
      entries: context.entries,
      appDirectory: context.appDirectory,
      repositoryRoot: context.repositoryRoot,
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: context.archiveBytes,
    })).rejects.toThrow(/exactly the four reviewed/);

    const wrongBytes = structuredClone(context.buildResults());
    wrongBytes[0].metafile.inputs["src/approval.ts"].bytes += 1;
    await expect(createJavaScriptBundleInputEvidence({
      buildResults: wrongBytes,
      entries: context.entries,
      appDirectory: context.appDirectory,
      repositoryRoot: context.repositoryRoot,
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: context.archiveBytes,
    })).rejects.toThrow(/source byte count disagrees/);
  });

  it("rejects duplicate-key and noncanonical evidence JSON", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const serialized = serializeJavaScriptBundleInputEvidence(evidence);
    expect(parseJavaScriptBundleInputEvidence(Buffer.from(serialized))).toEqual(evidence);
    const ambiguous = serialized.replace(
      `  "schema": "${JS_BUNDLE_INPUT_EVIDENCE_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${JS_BUNDLE_INPUT_EVIDENCE_SCHEMA}",`,
    );
    expect(() => parseJavaScriptBundleInputEvidence(Buffer.from(ambiguous)))
      .toThrow(/canonical generated JSON/);
  });
});
