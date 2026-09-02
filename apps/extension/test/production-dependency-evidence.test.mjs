import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA,
  collectInstalledProductionDependencyReports,
  createProductionDependencyEvidence,
  parseProductionDependencyEvidence,
  serializeProductionDependencyEvidence,
  verifyProductionDependencyEvidenceAttachment,
} from "../scripts/production-dependency-evidence.mjs";
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

const EXTENSION_MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden release fixture",
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

async function writePackage(directory, packageJson) {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, "package.json"), `${JSON.stringify(packageJson, null, 2)}\n`);
}

function payloadEntries() {
  return [
    { path: "background.js", data: Buffer.from("globalThis.booted = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(EXTENSION_MANIFEST, null, 2)}\n`) },
  ];
}

function dependencyReport(reverse = false) {
  const extensionDependencies = reverse
    ? {
      "@solana/web3.js": {
        from: "@solana/web3.js",
        version: "1.98.4",
        resolved: "https://registry.npmjs.org/@solana/web3.js/-/web3.js-1.98.4.tgz",
        dependencies: {
          "@noble/hashes": {
            from: "@noble/hashes",
            version: "1.8.0",
            resolved: "https://registry.npmjs.org/@noble/hashes/-/hashes-1.8.0.tgz",
          },
        },
      },
      "@warden/core": {
        from: "@warden/core",
        version: "link:../../packages/core",
        dependencies: {
          "@noble/hashes": {
            from: "@noble/hashes",
            version: "2.4.0",
            resolved: "https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz",
          },
        },
      },
    }
    : {
      "@warden/core": {
        from: "@warden/core",
        version: "link:../../packages/core",
        dependencies: {
          "@noble/hashes": {
            from: "@noble/hashes",
            version: "2.4.0",
            resolved: "https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz",
          },
        },
      },
      "@solana/web3.js": {
        from: "@solana/web3.js",
        version: "1.98.4",
        resolved: "https://registry.npmjs.org/@solana/web3.js/-/web3.js-1.98.4.tgz",
        dependencies: {
          "@noble/hashes": {
            from: "@noble/hashes",
            version: "1.8.0",
            resolved: "https://registry.npmjs.org/@noble/hashes/-/hashes-1.8.0.tgz",
          },
        },
      },
    };
  const workspaces = [
    {
      name: "@warden/extension",
      version: "1.2.3",
      path: "/different/hosts/must/not/affect/evidence",
      private: true,
      dependencies: extensionDependencies,
      unsavedDependencies: {
        vitest: { version: "link:../../node_modules/vitest" },
      },
    },
    {
      name: "@warden/core",
      version: "0.0.1",
      path: "/different/hosts/must/not/affect/evidence/core",
      dependencies: {},
    },
  ];
  return reverse ? workspaces.reverse() : workspaces;
}

function licenseReport(reverse = false) {
  const report = {
    MIT: [
      {
        name: "@noble/hashes",
        versions: reverse ? ["2.4.0", "1.8.0"] : ["1.8.0", "2.4.0"],
        paths: ["/host/path/ignored"],
        license: "MIT",
      },
    ],
    Unknown: [
      {
        name: "@solana/web3.js",
        versions: ["1.98.4"],
        paths: ["/host/path/also-ignored"],
        license: "Unknown",
      },
    ],
  };
  return reverse ? { Unknown: report.Unknown, MIT: report.MIT } : report;
}

function makeEvidence(reverse = false, archiveBytes = Buffer.from("canonical zip fixture")) {
  return createProductionDependencyEvidence({
    dependencyReport: dependencyReport(reverse),
    licenseReport: licenseReport(reverse),
    rootPackage: { name: "@warden/extension", version: "1.2.3" },
    source: SOURCE,
    archiveFileName: "warden-extension-1.2.3.zip",
    archiveBytes,
  });
}

describe("canonical production dependency evidence", () => {
  it("walks only installed production package.json dependencies and preserves missing licenses as Unknown", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "warden-installed-closure-test-"));
    temporaryDirectories.push(repositoryRoot);
    await writePackage(repositoryRoot, {
      name: "@warden/extension",
      version: "1.2.3",
      dependencies: { runtime: "1.0.0" },
      devDependencies: { "dev-only": "1.0.0" },
    });
    await writePackage(join(repositoryRoot, "node_modules", "runtime"), {
      name: "runtime",
      version: "1.0.0",
      license: "MIT",
      dependencies: { nested: "2.0.0" },
      peerDependencies: { "peer-runtime": "3.0.0" },
    });
    await writePackage(join(repositoryRoot, "node_modules", "nested"), {
      name: "nested",
      version: "2.0.0",
    });
    await writePackage(join(repositoryRoot, "node_modules", "dev-only"), {
      name: "dev-only",
      version: "1.0.0",
      license: "ISC",
    });
    await writePackage(join(repositoryRoot, "node_modules", "peer-runtime"), {
      name: "peer-runtime",
      version: "3.0.0",
      license: "Apache-2.0",
    });

    const reports = await collectInstalledProductionDependencyReports({
      rootDirectory: repositoryRoot,
      repositoryRoot,
    });
    const evidence = createProductionDependencyEvidence({
      ...reports,
      rootPackage: { name: "@warden/extension", version: "1.2.3" },
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: Buffer.from("canonical zip fixture"),
    });

    expect(evidence.components.map((component) => component.id)).toEqual([
      "npm:nested@2.0.0",
      "npm:peer-runtime@3.0.0",
      "npm:runtime@1.0.0",
      "workspace:@warden/extension@1.2.3",
    ]);
    expect(evidence.components.find((component) => component.name === "nested")?.declaredLicense)
      .toBe("Unknown");
    expect(serializeProductionDependencyEvidence(evidence)).not.toContain("dev-only");
  });

  it("is host-path independent, canonically ordered, and explicitly disclaims bundle coverage", () => {
    const forward = makeEvidence(false);
    const reverse = makeEvidence(true);

    expect(serializeProductionDependencyEvidence(reverse)).toBe(
      serializeProductionDependencyEvidence(forward),
    );
    expect(forward.schema).toBe(PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA);
    expect(forward.scope).toEqual({
      type: "pnpm-installed-production-closure",
      rootComponent: "workspace:@warden/extension@1.2.3",
      bundleCoverage: "not-asserted",
      licenseMeaning: "package-declared-metadata-not-legal-conclusion",
    });
    expect(forward.components.map((component) => component.id)).toEqual([
      "npm:@noble/hashes@1.8.0",
      "npm:@noble/hashes@2.4.0",
      "npm:@solana/web3.js@1.98.4",
      "workspace:@warden/core@0.0.1",
      "workspace:@warden/extension@1.2.3",
    ]);
    expect(forward.components.find((component) => component.name === "@solana/web3.js")?.declaredLicense)
      .toBe("Unknown");
    expect(serializeProductionDependencyEvidence(forward)).not.toMatch(/\/different\/hosts|\/host\/path/);
  });

  it("is hash-bound by the artifact manifest and rejects evidence or archive tampering", () => {
    const archiveBytes = createCanonicalZip(payloadEntries());
    const evidence = makeEvidence(false, archiveBytes);
    const evidenceBytes = Buffer.from(serializeProductionDependencyEvidence(evidence));
    const artifactManifest = createArtifactManifest({
      entries: payloadEntries(),
      archiveBytes,
      artifactFileName: "warden-extension-1.2.3.zip",
      source: SOURCE,
      toolchain: TOOLCHAIN,
      dependencyEvidence: {
        file: "warden-extension-1.2.3.sbom.json",
        bytes: evidenceBytes,
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
        bytes: Buffer.from("canonical release recipe input evidence fixture\n"),
      },
    });

    expect(artifactManifest.dependencyEvidence.sha256).toBe(
      createHash("sha256").update(evidenceBytes).digest("hex"),
    );
    expect(verifyProductionDependencyEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes,
    })).toEqual({ components: 5 });

    const tamperedEvidence = Buffer.from(evidenceBytes.toString("utf8").replace('"MIT"', '"ISC"'));
    expect(() => verifyProductionDependencyEvidenceAttachment({
      evidenceBytes: tamperedEvidence,
      artifactManifest,
      archiveBytes,
    })).toThrow(/evidence bytes differ/);
    expect(() => verifyProductionDependencyEvidenceAttachment({
      evidenceBytes,
      artifactManifest,
      archiveBytes: Buffer.concat([archiveBytes, Buffer.from([0])]),
    })).toThrow(/archive bytes differ/);
  });

  it("fails closed on missing or extraneous declared-license metadata", () => {
    const incompleteLicenses = licenseReport();
    delete incompleteLicenses.Unknown;
    expect(() => createProductionDependencyEvidence({
      dependencyReport: dependencyReport(),
      licenseReport: incompleteLicenses,
      rootPackage: { name: "@warden/extension", version: "1.2.3" },
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: Buffer.from("canonical zip fixture"),
    })).toThrow(/missing declared-license metadata.*@solana\/web3\.js@1\.98\.4/);

    const extraneousLicenses = licenseReport();
    extraneousLicenses.MIT.push({
      name: "not-in-production-closure",
      versions: ["9.9.9"],
      license: "MIT",
    });
    expect(() => createProductionDependencyEvidence({
      dependencyReport: dependencyReport(),
      licenseReport: extraneousLicenses,
      rootPackage: { name: "@warden/extension", version: "1.2.3" },
      source: SOURCE,
      archiveFileName: "warden-extension-1.2.3.zip",
      archiveBytes: Buffer.from("canonical zip fixture"),
    })).toThrow(/declared-license metadata is outside the production closure.*not-in-production-closure@9\.9\.9/);
  });

  it("rejects duplicate-key and noncanonical evidence JSON", () => {
    const evidence = makeEvidence();
    const serialized = serializeProductionDependencyEvidence(evidence);
    expect(parseProductionDependencyEvidence(Buffer.from(serialized))).toEqual(evidence);
    const ambiguous = serialized.replace(
      `  "schema": "${PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA}",`,
    );
    expect(() => parseProductionDependencyEvidence(Buffer.from(ambiguous)))
      .toThrow(/canonical generated JSON/);
  });
});
