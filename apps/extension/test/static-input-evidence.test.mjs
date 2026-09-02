import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  STATIC_INPUT_EVIDENCE_SCHEMA,
  createStaticInputEvidence,
  parseStaticInputEvidence,
  serializeStaticInputEvidence,
  verifyStaticInputEvidenceAttachment,
} from "../scripts/static-input-evidence.mjs";
import { createArtifactManifest, createCanonicalZip } from "../scripts/release-artifact.mjs";

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
  name: "Warden static evidence fixture",
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

async function fixture() {
  const repositoryRoot = await mkdtemp(join(tmpdir(), "warden-static-evidence-test-"));
  temporaryDirectories.push(repositoryRoot);
  const appDirectory = join(repositoryRoot, "apps", "extension");
  await mkdir(appDirectory, { recursive: true });
  const sources = {
    "approval.css": Buffer.from("body { color: #fff; }\n"),
    "approval.html": Buffer.from("<!doctype html><title>Approve</title>\n"),
    "manifest.json": Buffer.from(`${JSON.stringify(MANIFEST)}\n`),
    "popup.html": Buffer.from("<!doctype html><title>Popup</title>\n"),
  };
  await Promise.all(Object.entries(sources).map(([file, bytes]) =>
    writeFile(join(appDirectory, file), bytes),
  ));
  const manifestOutput = Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`);
  const entries = [
    { path: "approval.css", data: sources["approval.css"] },
    { path: "approval.html", data: sources["approval.html"] },
    { path: "approval.js", data: Buffer.from("globalThis.approval = true;\n") },
    { path: "background.js", data: Buffer.from("globalThis.background = true;\n") },
    { path: "content.js", data: Buffer.from("globalThis.content = true;\n") },
    { path: "manifest.json", data: manifestOutput },
    { path: "popup.html", data: sources["popup.html"] },
    { path: "popup.js", data: Buffer.from("globalThis.popup = true;\n") },
  ];
  const canonicalResults = [
    { outputFile: "approval.css", sourceFile: "approval.css", transformation: "byte-copy" },
    { outputFile: "approval.html", sourceFile: "approval.html", transformation: "byte-copy" },
    {
      outputFile: "manifest.json",
      sourceFile: "manifest.json",
      transformation: "json-parse-stringify-two-space-newline",
    },
    { outputFile: "popup.html", sourceFile: "popup.html", transformation: "byte-copy" },
  ];
  const archiveBytes = createCanonicalZip(entries);
  async function evidence(reverse = false) {
    return createStaticInputEvidence({
      staticResults: reverse ? [...canonicalResults].reverse() : canonicalResults,
      entries: reverse ? [...entries].reverse() : entries,
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
    sources,
    entries,
    canonicalResults,
    archiveBytes,
    evidence,
  };
}

describe("static payload source evidence", () => {
  it("canonically records three byte copies and one JSON transformation", async () => {
    const context = await fixture();
    const forward = await context.evidence();
    const reverse = await context.evidence(true);
    expect(serializeStaticInputEvidence(reverse)).toBe(serializeStaticInputEvidence(forward));
    expect(forward.schema).toBe(STATIC_INPUT_EVIDENCE_SCHEMA);
    expect(forward.scope).toEqual({
      type: "extension-non-javascript-payload-source-map",
      outputCoverage: "four-emitted-non-javascript-files-only",
      absentAssetCoverage: "not-asserted",
    });
    expect(forward.files.map((file) => [file.output, file.transformation])).toEqual([
      ["approval.css", "byte-copy"],
      ["approval.html", "byte-copy"],
      ["manifest.json", "json-parse-stringify-two-space-newline"],
      ["popup.html", "byte-copy"],
    ]);
    const approvalCss = forward.files[0];
    expect(approvalCss).toMatchObject({
      sourceBytes: context.sources["approval.css"].length,
      sourceSha256: sha256(context.sources["approval.css"]),
      outputBytes: context.sources["approval.css"].length,
      outputSha256: sha256(context.sources["approval.css"]),
    });
    const manifest = forward.files[2];
    expect(manifest.sourceBytes).not.toBe(manifest.outputBytes);
    expect(manifest.sourceSha256).not.toBe(manifest.outputSha256);
    expect(serializeStaticInputEvidence(forward)).not.toContain(context.repositoryRoot);
  });

  it("is hash-bound to the artifact manifest, archive, and four static outputs", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const evidenceBytes = Buffer.from(serializeStaticInputEvidence(evidence));
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
        bytes: Buffer.from("canonical bundle input evidence fixture\n"),
      },
      staticInputEvidence: {
        file: "warden-extension-1.2.3.static-inputs.json",
        bytes: evidenceBytes,
      },
      releaseRecipeInputEvidence: {
        file: "warden-extension-1.2.3.recipe-inputs.json",
        bytes: Buffer.from("canonical release recipe input evidence fixture\n"),
      },
    });
    expect(artifactManifest.staticInputEvidence.sha256).toBe(sha256(evidenceBytes));
    expect(verifyStaticInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes: context.archiveBytes,
    })).toEqual({ files: 4 });

    const tamperedEvidence = Buffer.from(
      evidenceBytes.toString("utf8").replace('"sourceBytes": 22', '"sourceBytes": 23'),
    );
    expect(() => verifyStaticInputEvidenceAttachment({
      evidenceBytes: tamperedEvidence,
      artifactManifest,
      archiveBytes: context.archiveBytes,
    })).toThrow(/evidence bytes differ/);
    expect(() => verifyStaticInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes: Buffer.concat([context.archiveBytes, Buffer.from([0])]),
    })).toThrow(/archive bytes differ/);
  });

  it("fails closed on missing/extra mappings and transformation drift", async () => {
    const context = await fixture();
    const create = (staticResults) => createStaticInputEvidence({
      staticResults,
      entries: context.entries,
      appDirectory: context.appDirectory,
      repositoryRoot: context.repositoryRoot,
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: context.archiveBytes,
    });
    await expect(create(context.canonicalResults.slice(1))).rejects.toThrow(/exactly the four reviewed/);
    await expect(create([
      ...context.canonicalResults,
      { outputFile: "icon.png", sourceFile: "icon.png", transformation: "byte-copy" },
    ])).rejects.toThrow(/exactly the four reviewed/);

    await writeFile(join(context.appDirectory, "approval.css"), "body { color: red; }\n");
    await expect(create(context.canonicalResults)).rejects.toThrow(/transformation differs/);
  });

  it("rejects duplicate-key and noncanonical evidence JSON", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const serialized = serializeStaticInputEvidence(evidence);
    expect(parseStaticInputEvidence(Buffer.from(serialized))).toEqual(evidence);
    const ambiguous = serialized.replace(
      `  "schema": "${STATIC_INPUT_EVIDENCE_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${STATIC_INPUT_EVIDENCE_SCHEMA}",`,
    );
    expect(() => parseStaticInputEvidence(Buffer.from(ambiguous)))
      .toThrow(/canonical generated JSON/);
  });
});
