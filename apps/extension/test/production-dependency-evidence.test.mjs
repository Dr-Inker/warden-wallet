import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA,
  createProductionDependencyEvidence,
  parseProductionDependencyEvidence,
  serializeProductionDependencyEvidence,
  verifyProductionDependencyEvidenceAttachment,
} from "../scripts/production-dependency-evidence.mjs";
import {
  createArtifactManifest,
  createCanonicalZip,
} from "../scripts/release-artifact.mjs";

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
  permissions: ["storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

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

  it("fails closed when any registry component lacks declared-license metadata", () => {
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
