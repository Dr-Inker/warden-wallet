import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";

const execFile = promisify(execFileCallback);
const verifierPath = fileURLToPath(
  new URL("../scripts/verify-release.mjs", import.meta.url),
);
const packagerPath = fileURLToPath(
  new URL("../scripts/package-release.mjs", import.meta.url),
);
const releaseDirectory = fileURLToPath(new URL("../release/", import.meta.url));
const temporaryDirectories = [];
const INPUT_POLICIES = Object.freeze([
  Object.freeze({ label: "upload archive", maximumBytes: 512 * 1024 * 1024 }),
  Object.freeze({ label: "artifact manifest", maximumBytes: 8 * 1024 * 1024 }),
  Object.freeze({ label: "dependency evidence", maximumBytes: 256 * 1024 * 1024 }),
  Object.freeze({ label: "bundle input evidence", maximumBytes: 256 * 1024 * 1024 }),
  Object.freeze({ label: "static input evidence", maximumBytes: 256 * 1024 * 1024 }),
  Object.freeze({ label: "release recipe input evidence", maximumBytes: 256 * 1024 * 1024 }),
]);
const FIXTURE_MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden release verifier CLI fixture",
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

function fixtureInputBytes() {
  const entries = [
    {
      path: "manifest.json",
      data: Buffer.from(`${JSON.stringify(FIXTURE_MANIFEST, null, 2)}\n`),
    },
  ];
  const archiveBytes = createCanonicalZip(entries);
  const evidenceBytes = INPUT_POLICIES.slice(2).map((_, index) =>
    Buffer.from(`evidence fixture ${index}\n`),
  );
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
    dependencyEvidence: {
      file: "warden-extension-1.2.3.sbom.json",
      bytes: evidenceBytes[0],
    },
    bundleInputEvidence: {
      file: "warden-extension-1.2.3.bundle-inputs.json",
      bytes: evidenceBytes[1],
    },
    staticInputEvidence: {
      file: "warden-extension-1.2.3.static-inputs.json",
      bytes: evidenceBytes[2],
    },
    releaseRecipeInputEvidence: {
      file: "warden-extension-1.2.3.recipe-inputs.json",
      bytes: evidenceBytes[3],
    },
  });
  return [
    archiveBytes,
    Buffer.from(serializeArtifactManifest(artifactManifest)),
    ...evidenceBytes,
  ];
}

async function writeFixtureInputs(directory) {
  const inputPaths = INPUT_POLICIES.map((_, index) =>
    join(directory, `input-${index}.bin`),
  );
  const inputBytes = fixtureInputBytes();
  await Promise.all(
    inputPaths.map((inputPath, index) => writeFile(inputPath, inputBytes[index])),
  );
  return { inputBytes, inputPaths };
}

async function writePackagedInputs(directory) {
  await execFile(process.execPath, [packagerPath], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  const version = JSON.parse(
    await readFile(new URL("../manifest.json", import.meta.url), "utf8"),
  ).version;
  const releaseBase = `warden-extension-${version}`;
  const releaseNames = [
    `${releaseBase}.zip`,
    `${releaseBase}.artifact.json`,
    `${releaseBase}.sbom.json`,
    `${releaseBase}.bundle-inputs.json`,
    `${releaseBase}.static-inputs.json`,
    `${releaseBase}.recipe-inputs.json`,
  ];
  const inputPaths = releaseNames.map((name) => join(directory, name));
  const inputBytes = await Promise.all(
    releaseNames.map((name) => readFile(join(releaseDirectory, name))),
  );
  await Promise.all(
    inputPaths.map((path, index) => writeFile(path, inputBytes[index])),
  );
  return { inputBytes, inputPaths };
}

async function rejectedOutput(args) {
  try {
    await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
  throw new Error("release verifier unexpectedly succeeded");
}

async function settledOutput(args) {
  try {
    const result = await execFile(process.execPath, [verifierPath, ...args], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
    });
    return `${result.stdout ?? ""}${result.stderr ?? ""}`;
  } catch (error) {
    return `${error.stdout ?? ""}${error.stderr ?? ""}`;
  }
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("deterministic upload verifier CLI", () => {
  it("keeps independent unzip on the stable archive bytes when the requested path is replaced", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputBytes, inputPaths } = await writePackagedInputs(directory);

    const replacementPath = join(directory, "replacement.zip");
    const replacementBytes = Buffer.from("replacement bytes are not the reviewed archive\n");
    await writeFile(replacementPath, replacementBytes);
    const observationPath = join(directory, "unzip-observation.json");
    const probeDirectory = join(directory, "probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

const inspectedPath = process.argv[3];
await rename(
  process.env.WARDEN_TEST_REPLACEMENT_PATH,
  process.env.WARDEN_TEST_REQUESTED_ARCHIVE_PATH,
);
const inspectedBytes = await readFile(inspectedPath);
const temporaryDirectories = (await readdir(process.env.TMPDIR)).filter((name) =>
  name.startsWith("warden-release-unzip-"),
);
if (temporaryDirectories.length !== 1) {
  throw new Error("expected exactly one private unzip directory");
}
const [archiveStat, directoryStat] = await Promise.all([
  stat(inspectedPath),
  stat(join(process.env.TMPDIR, temporaryDirectories[0])),
]);
await writeFile(process.env.WARDEN_TEST_OBSERVATION_PATH, JSON.stringify({
  inspectedPath,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  archiveMode: archiveStat.mode & 0o777,
  directoryMode: directoryStat.mode & 0o777,
}));
process.exitCode = Number(process.env.WARDEN_TEST_UNZIP_EXIT_CODE ?? "0");
`);
    await chmod(probePath, 0o755);

    const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
        TMPDIR: directory,
        WARDEN_TEST_REPLACEMENT_PATH: replacementPath,
        WARDEN_TEST_REQUESTED_ARCHIVE_PATH: inputPaths[0],
        WARDEN_TEST_OBSERVATION_PATH: observationPath,
      },
    });
    expect(result.stdout).toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.inspectedPath).not.toBe(inputPaths[0]);
    expect(observation.sha256).toBe(sha256(inputBytes[0]));
    expect(observation.sha256).not.toBe(sha256(replacementBytes));
    expect(observation.archiveMode).toBe(0o600);
    expect(observation.directoryMode).toBe(0o700);
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);

    await writeFile(inputPaths[0], inputBytes[0]);
    await writeFile(replacementPath, replacementBytes);
    let rejected;
    try {
      await execFile(process.execPath, [verifierPath, ...inputPaths], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
          TMPDIR: directory,
          WARDEN_TEST_REPLACEMENT_PATH: replacementPath,
          WARDEN_TEST_REQUESTED_ARCHIVE_PATH: inputPaths[0],
          WARDEN_TEST_OBSERVATION_PATH: observationPath,
          WARDEN_TEST_UNZIP_EXIT_CODE: "9",
        },
      });
    } catch (error) {
      rejected = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    }
    expect(rejected).toMatch(/independent unzip -t validation failed/);
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);
  });

  it("keeps independent unzip on the open descriptor when its temporary name is replaced", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputBytes, inputPaths } = await writePackagedInputs(directory);
    const replacementPath = join(directory, "named-temp-replacement.zip");
    const replacementBytes = Buffer.from("replacement for the named unzip copy\n");
    await writeFile(replacementPath, replacementBytes);
    const observationPath = join(directory, "named-temp-observation.json");
    const probeDirectory = join(directory, "named-temp-probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, rename, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
let replacementApplied = false;
try {
  await rename(process.env.WARDEN_TEST_REPLACEMENT_PATH, inspectedPath);
  replacementApplied = true;
} catch (error) {
  if (!/^\\/proc\\/\\d+\\/fd\\/\\d+$/.test(inspectedPath)) {
    throw error;
  }
}
const inspectedBytes = await readFile(inspectedPath);
await writeFile(process.env.WARDEN_TEST_OBSERVATION_PATH, JSON.stringify({
  inspectedPath,
  replacementApplied,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
}));
`);
    await chmod(probePath, 0o755);

    const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
        TMPDIR: directory,
        WARDEN_TEST_REPLACEMENT_PATH: replacementPath,
        WARDEN_TEST_OBSERVATION_PATH: observationPath,
      },
    });
    expect(result.stdout).toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.replacementApplied).toBe(false);
    expect(observation.inspectedPath).toMatch(/^\/proc\/\d+\/fd\/\d+$/);
    expect(observation.sha256).toBe(sha256(inputBytes[0]));
    expect(observation.sha256).not.toBe(sha256(replacementBytes));
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);
  });

  it("rejects descriptor-byte mutation after independent unzip exits zero", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputBytes, inputPaths } = await writePackagedInputs(directory);
    const observationPath = join(directory, "descriptor-mutation-observation.json");
    const probeDirectory = join(directory, "descriptor-mutation-probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
const inspectedBytes = await readFile(inspectedPath);
const replacementBytes = Buffer.alloc(inspectedBytes.length, 0x61);
replacementBytes[0] = inspectedBytes[0] ^ 0xff;
await writeFile(inspectedPath, replacementBytes);
await writeFile(process.env.WARDEN_TEST_OBSERVATION_PATH, JSON.stringify({
  inspectedPath,
  inspectedSha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  replacementSha256: createHash("sha256").update(replacementBytes).digest("hex"),
  replacementBytes: replacementBytes.length,
}));
`);
    await chmod(probePath, 0o755);

    let output;
    try {
      const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
          TMPDIR: directory,
          WARDEN_TEST_OBSERVATION_PATH: observationPath,
        },
      });
      output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    } catch (error) {
      output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    }
    expect(output).toMatch(
      /temporary archive bytes changed during independent unzip -t validation/,
    );
    expect(output).not.toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.inspectedPath).toMatch(/^\/proc\/\d+\/fd\/\d+$/);
    expect(observation.inspectedSha256).toBe(sha256(inputBytes[0]));
    expect(observation.replacementSha256).not.toBe(sha256(inputBytes[0]));
    expect(observation.replacementBytes).toBe(inputBytes[0].length);
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);
  });

  it("rejects a final-symlink archive before reading later inputs", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const archiveTargetPath = join(directory, "archive-target.zip");
    const archiveSymlinkPath = join(directory, "archive-link.zip");
    const artifactPath = join(directory, "missing.artifact.json");
    await writeFile(archiveTargetPath, "archive target bytes\n");
    await symlink(archiveTargetPath, archiveSymlinkPath);

    const output = await rejectedOutput([
      archiveSymlinkPath,
      artifactPath,
      join(directory, "missing.sbom.json"),
      join(directory, "missing.bundle-inputs.json"),
      join(directory, "missing.static-inputs.json"),
      join(directory, "missing.recipe-inputs.json"),
    ]);

    expect(output).toMatch(
      /upload archive could not be opened as a non-symlink regular file/,
    );
    expect(output).not.toContain(artifactPath);
  });

  it("routes every file candidate through the shared final-symlink refusal", async () => {
    for (const [selectedIndex, policy] of INPUT_POLICIES.entries()) {
      const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
      temporaryDirectories.push(directory);
      const { inputBytes, inputPaths } = await writeFixtureInputs(directory);
      const targetPath = join(directory, `target-${selectedIndex}.bin`);
      await writeFile(targetPath, inputBytes[selectedIndex]);
      await rm(inputPaths[selectedIndex]);
      await symlink(targetPath, inputPaths[selectedIndex]);

      const output = await rejectedOutput(inputPaths);
      expect(output).toContain(
        `${policy.label} could not be opened as a non-symlink regular file`,
      );
    }
  });

  it("enforces the explicit pre-read ceiling for every file candidate", async () => {
    for (const [selectedIndex, policy] of INPUT_POLICIES.entries()) {
      const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
      temporaryDirectories.push(directory);
      const { inputPaths } = await writeFixtureInputs(directory);
      await truncate(inputPaths[selectedIndex], policy.maximumBytes + 1);

      const output = await rejectedOutput(inputPaths);
      expect(output).toContain(
        `${policy.label} must be a nonempty regular file no larger than ${policy.maximumBytes} bytes`,
      );
    }
  });

  it("accepts the documented pnpm argument separator before reading the candidate", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const candidatePath = join(directory, "missing-candidate.zip");
    const explicitArguments = [
      candidatePath,
      join(directory, "missing.artifact.json"),
      join(directory, "missing.sbom.json"),
      join(directory, "missing.bundle-inputs.json"),
      join(directory, "missing.static-inputs.json"),
      join(directory, "missing.recipe-inputs.json"),
    ];

    for (const optionalUnpacked of [[], [join(directory, "missing-unpacked")]]) {
      for (const separator of [[], ["--"]]) {
        const output = await rejectedOutput([
          ...separator,
          ...explicitArguments,
          ...optionalUnpacked,
        ]);
        expect(output).toContain(candidatePath);
        expect(output).not.toMatch(/usage: verify-release/);
      }
    }
  });

  it("preserves the zero-argument default with or without one package separator", async () => {
    const outputs = [];
    for (const args of [[], ["--"]]) {
      const output = await settledOutput(args);
      expect(output).not.toMatch(/usage: verify-release/);
      outputs.push(output);
    }
    expect(outputs[1]).toBe(outputs[0]);
  });

  it("enforces exact zero, six, or seven semantic arguments", async () => {
    for (const argumentCount of [1, 2, 3, 4, 5, 8]) {
      const arguments_ = Array.from(
        { length: argumentCount },
        (_, index) => `missing-${index}`,
      );
      for (const separator of [[], ["--"]]) {
        const output = await rejectedOutput([...separator, ...arguments_]);
        expect(output).toMatch(/usage: verify-release/);
      }
    }
  });

  it("removes only one leading package separator", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const candidatePath = join(directory, "missing-candidate.zip");
    const output = await rejectedOutput([
      "--",
      "--",
      candidatePath,
      join(directory, "missing.artifact.json"),
      join(directory, "missing.sbom.json"),
      join(directory, "missing.bundle-inputs.json"),
      join(directory, "missing.static-inputs.json"),
      join(directory, "missing.recipe-inputs.json"),
    ]);

    expect(output).toMatch(/open '.*\/--'/);
    expect(output).not.toContain(candidatePath);
    expect(output).not.toMatch(/usage: verify-release/);
  });
});
