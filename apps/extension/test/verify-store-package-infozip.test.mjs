import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";

const mockedStorePackage = vi.hoisted(() => ({
  calls: [],
  result: undefined,
}));

vi.mock("../scripts/store-package.mjs", async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    verifyStorePackage: (...args) => {
      mockedStorePackage.calls.push(args);
      if (mockedStorePackage.result === undefined) {
        throw new Error("store-package mock result was not initialized");
      }
      return mockedStorePackage.result;
    },
  };
});

const verifierPath = fileURLToPath(
  new URL("../scripts/verify-store-package.mjs", import.meta.url),
);
const temporaryDirectories = [];

const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden store Info-ZIP fixture",
  version: "1.2.3",
  permissions: ["storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

afterEach(async () => {
  mockedStorePackage.calls.length = 0;
  mockedStorePackage.result = undefined;
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("standalone store-package Info-ZIP handoff", () => {
  it("keeps the independent parser on the verified embedded archive descriptor", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "warden-store-package-infozip-test-"),
    );
    temporaryDirectories.push(directory);
    const entries = [
      {
        path: "background.js",
        data: Buffer.from("globalThis.storeInfoZipFixture = true;\n"),
      },
      {
        path: "manifest.json",
        data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`),
      },
    ];
    const archiveBytes = createCanonicalZip(entries);
    const attachment = (suffix) => ({
      file: `warden-extension-1.2.3.${suffix}.json`,
      bytes: Buffer.from(`${suffix} fixture\n`),
    });
    const artifactManifest = createArtifactManifest({
      entries,
      archiveBytes,
      artifactFileName: "warden-extension-1.2.3.zip",
      source: {
        gitCommit: "a".repeat(40),
        lockfileSha256: "b".repeat(64),
      },
      toolchain: {
        node: "22.23.2",
        pnpm: "11.12.0",
        esbuild: "0.28.2",
      },
      dependencyEvidence: attachment("sbom"),
      bundleInputEvidence: attachment("bundle-inputs"),
      staticInputEvidence: attachment("static-inputs"),
      releaseRecipeInputEvidence: attachment("recipe-inputs"),
    });
    const artifactManifestBytes = Buffer.from(
      serializeArtifactManifest(artifactManifest),
    );
    const candidateBytes = Buffer.from("synthetic CRX fixture boundary\n");
    const candidatePath = join(directory, "candidate.crx");
    const reviewedArchivePath = join(directory, "reviewed.zip");
    const artifactManifestPath = join(directory, "reviewed.artifact.json");
    const replacementPath = join(directory, "replacement.zip");
    const replacementBytes = Buffer.from("replacement is not the embedded ZIP\n");
    const observationPath = join(directory, "unzip-observation.json");
    const probeDirectory = join(directory, "probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await Promise.all([
      writeFile(candidatePath, candidateBytes),
      writeFile(reviewedArchivePath, archiveBytes),
      writeFile(artifactManifestPath, artifactManifestBytes),
      writeFile(replacementPath, replacementBytes),
      writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, rename, stat, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
let replacementApplied = false;
try {
  await rename(${JSON.stringify(replacementPath)}, inspectedPath);
  replacementApplied = true;
} catch {}
const inspectedBytes = await readFile(inspectedPath);
const descriptor = /^\\/proc\\/(\\d+)\\/fd\\/(\\d+)$/.exec(inspectedPath);
let accessMode = null;
if (descriptor !== null) {
  const descriptorInfo = await readFile(
    "/proc/" + descriptor[1] + "/fdinfo/" + descriptor[2],
    "utf8",
  );
  const flagsMatch = /^flags:\\s+([0-7]+)$/m.exec(descriptorInfo);
  if (flagsMatch === null) {
    throw new Error("expected octal descriptor flags");
  }
  accessMode = Number.parseInt(flagsMatch[1], 8) & 0o3;
}
const inspectedStat = await stat(inspectedPath);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
  inspectedPath,
  replacementApplied,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  accessMode,
  inodeMode: inspectedStat.mode & 0o777,
}));
`),
    ]);
    await chmod(probePath, 0o755);

    mockedStorePackage.result = {
      archiveBytes,
      archiveSha256: sha256(archiveBytes),
      extensionId: "a".repeat(32),
      files: entries.length,
      headerBytes: 12,
      headerSha256: "c".repeat(64),
      packageBytes: candidateBytes.length,
      packageSha256: sha256(candidateBytes),
      publisherKeySha256: "d".repeat(64),
      treeSha256: artifactManifest.payload.treeSha256,
    };

    const originalArgv = process.argv;
    const originalPath = process.env.PATH;
    const originalTmpdir = process.env.TMPDIR;
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    process.argv = [
      process.execPath,
      verifierPath,
      candidatePath,
      sha256(candidateBytes),
      "a".repeat(32),
      sha256(artifactManifestBytes),
      reviewedArchivePath,
      artifactManifestPath,
    ];
    process.env.PATH = `${probeDirectory}:${originalPath ?? ""}`;
    process.env.TMPDIR = directory;
    let cliReportedSuccess = false;
    try {
      await import("../scripts/verify-store-package.mjs");
      cliReportedSuccess = log.mock.calls.some(([line]) =>
        line === "independent embedded ZIP reader unzip -t passed"
      );
    } finally {
      process.argv = originalArgv;
      if (originalPath === undefined) {
        delete process.env.PATH;
      } else {
        process.env.PATH = originalPath;
      }
      if (originalTmpdir === undefined) {
        delete process.env.TMPDIR;
      } else {
        process.env.TMPDIR = originalTmpdir;
      }
      log.mockRestore();
    }

    expect(mockedStorePackage.calls).toHaveLength(1);
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect({
      cliReportedSuccess,
      inspectedPath: observation.inspectedPath,
      replacementApplied: observation.replacementApplied,
      sha256: observation.sha256,
      accessMode: observation.accessMode,
      inodeMode: observation.inodeMode,
      privateDirectories: (await readdir(directory)).filter((name) =>
        name.startsWith("warden-store-package-verify-")
      ),
    }).toEqual({
      cliReportedSuccess: true,
      inspectedPath: expect.stringMatching(/^\/proc\/\d+\/fd\/\d+$/),
      replacementApplied: false,
      sha256: sha256(archiveBytes),
      accessMode: 0,
      inodeMode: 0o400,
      privateDirectories: [],
    });
  });
});
