import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA,
  RELEASE_RECIPE_INPUT_PATHS,
  createReleaseRecipeInputEvidence,
  parseReleaseRecipeInputEvidence,
  serializeReleaseRecipeInputEvidence,
  verifyReleaseRecipeInputEvidenceAttachment,
} from "../scripts/release-recipe-input-evidence.mjs";
import { createArtifactManifest, createCanonicalZip } from "../scripts/release-artifact.mjs";

const temporaryDirectories = [];
const TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});
const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden recipe evidence fixture",
  version: "1.2.3",
  permissions: ["storage"],
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
  const repositoryRoot = await mkdtemp(join(tmpdir(), "warden-recipe-evidence-test-"));
  temporaryDirectories.push(repositoryRoot);
  const inputBytes = new Map();
  for (const path of RELEASE_RECIPE_INPUT_PATHS) {
    const bytes = Buffer.from(`fixture bytes for ${path}\n`);
    const target = join(repositoryRoot, ...path.split("/"));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
    inputBytes.set(path, bytes);
  }
  const source = {
    gitCommit: "a".repeat(40),
    lockfileSha256: sha256(inputBytes.get("pnpm-lock.yaml")),
  };
  const entries = [
    { path: "background.js", data: Buffer.from("globalThis.background = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`) },
  ];
  const archiveBytes = createCanonicalZip(entries);
  async function evidence(inputPaths = RELEASE_RECIPE_INPUT_PATHS) {
    return createReleaseRecipeInputEvidence({
      repositoryRoot,
      inputPaths,
      source,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes,
    });
  }
  return { repositoryRoot, inputBytes, source, entries, archiveBytes, evidence };
}

function artifactManifest(context, evidenceBytes) {
  return createArtifactManifest({
    entries: context.entries,
    archiveBytes: context.archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: context.source,
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
      bytes: Buffer.from("canonical static input evidence fixture\n"),
    },
    releaseRecipeInputEvidence: {
      file: "warden-extension-1.2.3.recipe-inputs.json",
      bytes: evidenceBytes,
    },
  });
}

describe("release recipe repository input evidence", () => {
  it("canonically records the exact twenty-six reviewed non-payload inputs", async () => {
    const context = await fixture();
    const forward = await context.evidence();
    const reverse = await context.evidence([...RELEASE_RECIPE_INPUT_PATHS].reverse());
    expect(serializeReleaseRecipeInputEvidence(reverse))
      .toBe(serializeReleaseRecipeInputEvidence(forward));
    expect(forward.schema).toBe(RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA);
    expect(forward.scope).toEqual({
      type: "extension-release-recipe-repository-inputs",
      inputCoverage: "twenty-six-reviewed-non-payload-files-only",
      executableCoverage: "not-asserted",
      runtimeEnvironmentCoverage: "not-asserted",
    });
    expect(forward.inputs.map((input) => input.path))
      .toEqual(RELEASE_RECIPE_INPUT_PATHS.map((path) => `repo:${path}`));
    expect(forward.inputs[0]).toEqual({
      path: `repo:${RELEASE_RECIPE_INPUT_PATHS[0]}`,
      bytes: context.inputBytes.get(RELEASE_RECIPE_INPUT_PATHS[0]).length,
      sha256: sha256(context.inputBytes.get(RELEASE_RECIPE_INPUT_PATHS[0])),
    });
    expect(forward.inputs.find((input) => input.path === "repo:pnpm-lock.yaml")?.sha256)
      .toBe(context.source.lockfileSha256);
    expect(serializeReleaseRecipeInputEvidence(forward)).not.toContain(context.repositoryRoot);
  });

  it("binds the artifact and rejects sidecar, archive, or repository-byte drift", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const evidenceBytes = Buffer.from(serializeReleaseRecipeInputEvidence(evidence));
    const manifest = artifactManifest(context, evidenceBytes);
    expect(manifest.releaseRecipeInputEvidence.sha256).toBe(sha256(evidenceBytes));
    await expect(verifyReleaseRecipeInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest: manifest,
      archiveBytes: context.archiveBytes,
      repositoryRoot: context.repositoryRoot,
    })).resolves.toEqual({ inputs: 26 });
    await expect(verifyReleaseRecipeInputEvidenceAttachment({
      evidenceBytes: Buffer.concat([evidenceBytes, Buffer.from(" ")]),
      artifactManifest: manifest,
      archiveBytes: context.archiveBytes,
      repositoryRoot: context.repositoryRoot,
    })).rejects.toThrow(/evidence bytes differ/);
    await expect(verifyReleaseRecipeInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest: manifest,
      archiveBytes: Buffer.concat([context.archiveBytes, Buffer.from([0])]),
      repositoryRoot: context.repositoryRoot,
    })).rejects.toThrow(/archive bytes differ/);
    await writeFile(join(context.repositoryRoot, "package.json"), "tampered package recipe\n");
    await expect(verifyReleaseRecipeInputEvidenceAttachment({
      evidenceBytes,
      artifactManifest: manifest,
      archiveBytes: context.archiveBytes,
      repositoryRoot: context.repositoryRoot,
    })).rejects.toThrow(/current reviewed repository files/);
  });

  it("fails closed on a missing, extra, or moved reviewed path", async () => {
    const context = await fixture();
    await expect(context.evidence(RELEASE_RECIPE_INPUT_PATHS.slice(1)))
      .rejects.toThrow(/exactly the twenty-six reviewed/);
    await expect(context.evidence([...RELEASE_RECIPE_INPUT_PATHS, "extra-release-config.json"]))
      .rejects.toThrow(/exactly the twenty-six reviewed/);
    await rename(
      join(context.repositoryRoot, ".node-version"),
      join(context.repositoryRoot, "moved-node-version"),
    );
    await expect(context.evidence()).rejects.toThrow(/reviewed input is unreadable/);
  });

  it("rejects duplicate-key and noncanonical evidence JSON", async () => {
    const context = await fixture();
    const evidence = await context.evidence();
    const serialized = serializeReleaseRecipeInputEvidence(evidence);
    expect(parseReleaseRecipeInputEvidence(Buffer.from(serialized))).toEqual(evidence);
    const ambiguous = serialized.replace(
      `  "schema": "${RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA}",`,
    );
    expect(() => parseReleaseRecipeInputEvidence(Buffer.from(ambiguous)))
      .toThrow(/canonical generated JSON/);
  });
});
