import { chmod, lstat, mkdir, mkdtemp, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  ARTIFACT_SCHEMA,
  CANONICAL_TIMESTAMP,
  collectCanonicalPayload,
  createArtifactManifest,
  createCanonicalZip,
  parseArtifactManifest,
  parseCanonicalZip,
  serializeArtifactManifest,
  stageCanonicalUnpacked,
  verifyArtifactArchive,
  verifyCanonicalUnpacked,
} from "../scripts/release-artifact.mjs";

const temporaryDirectories = [];

const BASE_MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden release fixture",
  version: "1.2.3",
  permissions: ["alarms", "storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

const RELEASE_SOURCE = Object.freeze({
  gitCommit: "a".repeat(40),
  lockfileSha256: "b".repeat(64),
});

const RELEASE_TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});

const DEPENDENCY_EVIDENCE = Object.freeze({
  file: "warden-extension-1.2.3.sbom.json",
  bytes: Buffer.from("canonical dependency evidence fixture\n"),
});

const BUNDLE_INPUT_EVIDENCE = Object.freeze({
  file: "warden-extension-1.2.3.bundle-inputs.json",
  bytes: Buffer.from("canonical bundle input evidence fixture\n"),
});

const STATIC_INPUT_EVIDENCE = Object.freeze({
  file: "warden-extension-1.2.3.static-inputs.json",
  bytes: Buffer.from("canonical static input evidence fixture\n"),
});

const RELEASE_RECIPE_INPUT_EVIDENCE = Object.freeze({
  file: "warden-extension-1.2.3.recipe-inputs.json",
  bytes: Buffer.from("canonical release recipe input evidence fixture\n"),
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeTemporaryDirectory() {
  const directory = await mkdtemp(join(tmpdir(), "warden-extension-artifact-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function payloadEntries(manifest = BASE_MANIFEST) {
  return [
    { path: "approval.js", data: Buffer.from("globalThis.approve = () => false;\n") },
    { path: "assets/icon.txt", data: Buffer.from("not-a-real-icon\n") },
    { path: "background.js", data: Buffer.from("globalThis.booted = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    { path: "popup.js", data: Buffer.from("globalThis.popup = 1;\n") },
  ];
}

function baselineArtifact(entries = payloadEntries()) {
  const archiveBytes = createCanonicalZip(entries);
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: RELEASE_SOURCE,
    toolchain: RELEASE_TOOLCHAIN,
    dependencyEvidence: DEPENDENCY_EVIDENCE,
    bundleInputEvidence: BUNDLE_INPUT_EVIDENCE,
    staticInputEvidence: STATIC_INPUT_EVIDENCE,
    releaseRecipeInputEvidence: RELEASE_RECIPE_INPUT_EVIDENCE,
  });
  return { archiveBytes, artifactManifest };
}

function replaceEntry(entries, path, data) {
  return entries.map((entry) =>
    entry.path === path ? { path, data: Buffer.from(data) } : entry,
  );
}

function replaceManifest(entries, mutate) {
  const manifest = structuredClone(BASE_MANIFEST);
  mutate(manifest);
  return replaceEntry(entries, "manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
}

describe("canonical Web Store upload ZIP", () => {
  it("is byte-identical for differently ordered inputs and parses in sorted root-relative order", () => {
    const entries = payloadEntries();
    const forward = createCanonicalZip(entries);
    const reverse = createCanonicalZip([...entries].reverse());

    expect(reverse.equals(forward)).toBe(true);
    expect(parseCanonicalZip(forward).map((entry) => entry.path)).toEqual([
      "approval.js",
      "assets/icon.txt",
      "background.js",
      "manifest.json",
      "popup.js",
    ]);
  });

  it("normalizes source mtimes and modes in both the archive and unpacked tree", async () => {
    const firstRoot = await makeTemporaryDirectory();
    const secondRoot = await makeTemporaryDirectory();
    for (const root of [firstRoot, secondRoot]) {
      await mkdir(join(root, "assets"));
      for (const entry of payloadEntries()) {
        const target = join(root, ...entry.path.split("/"));
        await writeFile(target, entry.data);
      }
    }
    await chmod(join(firstRoot, "background.js"), 0o600);
    await chmod(join(secondRoot, "background.js"), 0o755);
    await utimes(join(firstRoot, "background.js"), new Date("2024-01-02T03:04:05Z"), new Date("2024-01-02T03:04:05Z"));
    await utimes(join(secondRoot, "background.js"), new Date("2026-08-31T12:34:56Z"), new Date("2026-08-31T12:34:56Z"));

    const first = await collectCanonicalPayload(firstRoot);
    const second = await collectCanonicalPayload(secondRoot);
    expect(createCanonicalZip(first).equals(createCanonicalZip(second))).toBe(true);

    const unpacked = join(await makeTemporaryDirectory(), "unpacked");
    await stageCanonicalUnpacked(first, unpacked);
    const fileStat = await lstat(join(unpacked, "background.js"));
    const directoryStat = await lstat(join(unpacked, "assets"));
    expect(fileStat.mode & 0o777).toBe(0o644);
    expect(directoryStat.mode & 0o777).toBe(0o755);
    expect(fileStat.mtime.toISOString()).toBe(CANONICAL_TIMESTAMP);
    expect(directoryStat.mtime.toISOString()).toBe(CANONICAL_TIMESTAMP);

    const { artifactManifest } = baselineArtifact(first);
    await expect(verifyCanonicalUnpacked({
      rootDirectory: unpacked,
      artifactManifest,
    })).resolves.toMatchObject({ files: first.length });
    await chmod(join(unpacked, "background.js"), 0o600);
    await expect(verifyCanonicalUnpacked({
      rootDirectory: unpacked,
      artifactManifest,
    })).rejects.toThrow(/canonical mode 0644/);
  });

  it("refuses unsafe paths, duplicate paths, symlinks, and non-canonical archive modes", async () => {
    expect(() => createCanonicalZip([
      { path: "manifest.json", data: Buffer.from("{}") },
      { path: "../escape.js", data: Buffer.from("bad") },
    ])).toThrow(/unsafe artifact path/);
    expect(() => createCanonicalZip([
      { path: "manifest.json", data: Buffer.from("{}") },
      { path: "manifest.json", data: Buffer.from("{}") },
    ])).toThrow(/duplicate artifact path/);

    const root = await makeTemporaryDirectory();
    await writeFile(join(root, "manifest.json"), "{}\n");
    await symlink(join(root, "manifest.json"), join(root, "linked.json"));
    await expect(collectCanonicalPayload(root)).rejects.toThrow(/symlink/);

    const archive = createCanonicalZip(payloadEntries());
    const centralHeader = archive.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    expect(centralHeader).toBeGreaterThan(0);
    archive.writeUInt32LE((0o100600 << 16) >>> 0, centralHeader + 38);
    expect(() => parseCanonicalZip(archive)).toThrow(/canonical file mode/);
  });
});

describe("reviewed artifact manifest and fail-closed verifier", () => {
  it("records the complete payload and verifies the exact canonical archive", () => {
    const { archiveBytes, artifactManifest } = baselineArtifact();

    expect(artifactManifest.schema).toBe(ARTIFACT_SCHEMA);
    expect(artifactManifest.source).toEqual(RELEASE_SOURCE);
    expect(artifactManifest.toolchain).toEqual(RELEASE_TOOLCHAIN);
    expect(artifactManifest.payload.files.map((entry) => entry.path)).toEqual(
      payloadEntries().map((entry) => entry.path),
    );
    expect(artifactManifest.extension.permissions).toEqual(["alarms", "storage"]);
    expect(artifactManifest.extension.background).toEqual({
      service_worker: "background.js",
      type: "module",
    });
    expect(artifactManifest.extension.action).toBeNull();
    expect(artifactManifest.extension.contentScripts).toEqual([]);
    expect(artifactManifest.extension.contentSecurityPolicy).toEqual(
      BASE_MANIFEST.content_security_policy,
    );
    expect(artifactManifest.extension.updateUrl).toBeNull();
    expect(() => verifyArtifactArchive({ archiveBytes, artifactManifest })).not.toThrow();
  });

  it("refuses duplicate-key or noncanonical manifest and attestation JSON", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const serialized = serializeArtifactManifest(artifactManifest);
    expect(parseArtifactManifest(Buffer.from(serialized))).toEqual(artifactManifest);

    const ambiguousArtifact = serialized.replace(
      `  "schema": "${ARTIFACT_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${ARTIFACT_SCHEMA}",`,
    );
    expect(() => parseArtifactManifest(Buffer.from(ambiguousArtifact))).toThrow(/canonical generated JSON/);

    const canonicalManifest = `${JSON.stringify(BASE_MANIFEST, null, 2)}\n`;
    const ambiguousManifest = canonicalManifest.replace(
      '  "permissions": [',
      '  "permissions": ["tabs"],\n  "permissions": [',
    );
    const ambiguousEntries = replaceEntry(entries, "manifest.json", ambiguousManifest);
    const ambiguousArchive = createCanonicalZip(ambiguousEntries);
    expect(() => createArtifactManifest({
      entries: ambiguousEntries,
      archiveBytes: ambiguousArchive,
      artifactFileName: "warden-extension-1.2.3.zip",
      source: RELEASE_SOURCE,
      toolchain: RELEASE_TOOLCHAIN,
      dependencyEvidence: DEPENDENCY_EVIDENCE,
      bundleInputEvidence: BUNDLE_INPUT_EVIDENCE,
      staticInputEvidence: STATIC_INPUT_EVIDENCE,
      releaseRecipeInputEvidence: RELEASE_RECIPE_INPUT_EVIDENCE,
    })).toThrow(/canonical two-space JSON/);
  });

  it("rejects a recomputed canonical ZIP after one JavaScript byte changes", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const tampered = replaceEntry(entries, "popup.js", "globalThis.popup = 2;\n");
    const originalBytes = entries.find((entry) => entry.path === "popup.js").data;
    const tamperedBytes = tampered.find((entry) => entry.path === "popup.js").data;
    expect(tamperedBytes).toHaveLength(originalBytes.length);
    expect([...originalBytes].filter((byte, index) => byte !== tamperedBytes[index])).toHaveLength(1);

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(tampered),
      artifactManifest,
    })).toThrow(/popup\.js/);
  });

  it("rejects a recomputed canonical ZIP after a manifest permission changes", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const tampered = replaceManifest(entries, (manifest) => {
      manifest.permissions.push("tabs");
    });

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(tampered),
      artifactManifest,
    })).toThrow(/permissions/);
  });

  it("WRDF-0131 rejects manifest capabilities outside the exact reviewed policy", () => {
    for (const [field, value] of [
      ["host_permissions", ["https://example.invalid/*"]],
      ["optional_permissions", ["tabs"]],
      ["optional_host_permissions", ["https://example.invalid/*"]],
      ["externally_connectable", { matches: ["https://example.invalid/*"] }],
      ["web_accessible_resources", [{ resources: ["background.js"], matches: ["<all_urls>"] }]],
    ]) {
      const entries = replaceManifest(payloadEntries(), (manifest) => {
        manifest[field] = value;
      });
      const archiveBytes = createCanonicalZip(entries);
      expect(() => createArtifactManifest({
        entries,
        archiveBytes,
        artifactFileName: "warden-extension-1.2.3.zip",
        source: RELEASE_SOURCE,
        toolchain: RELEASE_TOOLCHAIN,
        dependencyEvidence: DEPENDENCY_EVIDENCE,
        bundleInputEvidence: BUNDLE_INPUT_EVIDENCE,
        staticInputEvidence: STATIC_INPUT_EVIDENCE,
        releaseRecipeInputEvidence: RELEASE_RECIPE_INPUT_EVIDENCE,
      }), field).toThrow(/manifest|capability|policy/);
    }
  });

  it("rejects a recomputed canonical ZIP after CSP is relaxed", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const tampered = replaceManifest(entries, (manifest) => {
      manifest.content_security_policy.extension_pages = "script-src 'self' 'unsafe-eval'; object-src 'self';";
    });

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(tampered),
      artifactManifest,
    })).toThrow(/content security policy/);
  });

  it("rejects a recomputed canonical ZIP after an update URL is introduced", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const tampered = replaceManifest(entries, (manifest) => {
      manifest.update_url = "https://attacker.invalid/update.xml";
    });

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(tampered),
      artifactManifest,
    })).toThrow(/update URL/);
  });

  it("rejects a recomputed canonical ZIP after a dependency-produced asset changes", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const tampered = replaceEntry(entries, "background.js", "globalThis.booted = false;\n");

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(tampered),
      artifactManifest,
    })).toThrow(/background\.js/);
  });

  it("rejects missing and extra files even when each candidate ZIP is canonical", () => {
    const entries = payloadEntries();
    const { artifactManifest } = baselineArtifact(entries);
    const missing = entries.filter((entry) => entry.path !== "approval.js");
    const extra = [...entries, { path: "surprise.js", data: Buffer.from("surprise\n") }];

    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(missing),
      artifactManifest,
    })).toThrow(/payload path set/);
    expect(() => verifyArtifactArchive({
      archiveBytes: createCanonicalZip(extra),
      artifactManifest,
    })).toThrow(/payload path set/);
  });
});
