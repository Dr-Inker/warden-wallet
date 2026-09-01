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
    const exitCodeMarkerPath = join(directory, "unzip-exit-code-9");
    const probeDirectory = join(directory, "probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { access, readFile, readdir, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

const inspectedPath = process.argv[3];
await rename(
  ${JSON.stringify(replacementPath)},
  ${JSON.stringify(inputPaths[0])},
);
const inspectedBytes = await readFile(inspectedPath);
const temporaryDirectories = (await readdir(${JSON.stringify(directory)})).filter((name) =>
  name.startsWith("warden-release-unzip-"),
);
if (temporaryDirectories.length !== 1) {
  throw new Error("expected exactly one private unzip directory");
}
const [archiveStat, directoryStat] = await Promise.all([
  stat(inspectedPath),
  stat(join(${JSON.stringify(directory)}, temporaryDirectories[0])),
]);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
  inspectedPath,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  archiveMode: archiveStat.mode & 0o777,
  directoryMode: directoryStat.mode & 0o777,
}));
try {
  await access(${JSON.stringify(exitCodeMarkerPath)});
  process.exitCode = 9;
} catch {}
`);
    await chmod(probePath, 0o755);

    const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
        TMPDIR: directory,
      },
    });
    expect(result.stdout).toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.inspectedPath).not.toBe(inputPaths[0]);
    expect(observation.sha256).toBe(sha256(inputBytes[0]));
    expect(observation.sha256).not.toBe(sha256(replacementBytes));
    expect(observation.archiveMode).toBe(0o400);
    expect(observation.directoryMode).toBe(0o700);
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);

    await writeFile(inputPaths[0], inputBytes[0]);
    await writeFile(replacementPath, replacementBytes);
    await writeFile(exitCodeMarkerPath, "9\n");
    let rejected;
    try {
      await execFile(process.execPath, [verifierPath, ...inputPaths], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
          TMPDIR: directory,
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
  await rename(${JSON.stringify(replacementPath)}, inspectedPath);
  replacementApplied = true;
} catch (error) {
  if (!/^\\/proc\\/\\d+\\/fd\\/\\d+$/.test(inspectedPath)) {
    throw error;
  }
}
const inspectedBytes = await readFile(inspectedPath);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
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
import { chmod, readFile, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
const inspectedBytes = await readFile(inspectedPath);
const replacementBytes = Buffer.alloc(inspectedBytes.length, 0x61);
replacementBytes[0] = inspectedBytes[0] ^ 0xff;
await chmod(inspectedPath, 0o600);
await writeFile(inspectedPath, replacementBytes);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
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

  it("runs independent unzip on the sealed descriptor from its private directory", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputBytes, inputPaths } = await writePackagedInputs(directory);
    const observationPath = join(directory, "descriptor-access-observation.json");
    const probeDirectory = join(directory, "descriptor-access-probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
const descriptor = /^\\/proc\\/(\\d+)\\/fd\\/(\\d+)$/.exec(inspectedPath);
if (descriptor === null) {
  throw new Error("expected a procfs descriptor path");
}
const workingDirectory = process.cwd();
const [inspectedBytes, descriptorInfo, inspectedStat, workingDirectoryStat] = await Promise.all([
  readFile(inspectedPath),
  readFile("/proc/" + descriptor[1] + "/fdinfo/" + descriptor[2], "utf8"),
  stat(inspectedPath),
  stat(workingDirectory),
]);
const flagsMatch = /^flags:\\s+([0-7]+)$/m.exec(descriptorInfo);
if (flagsMatch === null) {
  throw new Error("expected octal descriptor flags");
}
const flags = Number.parseInt(flagsMatch[1], 8);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
  inspectedPath,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  accessMode: flags & 0o3,
  inodeMode: inspectedStat.mode & 0o777,
  workingDirectory,
  workingDirectoryMode: workingDirectoryStat.mode & 0o777,
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
      },
    });
    expect(result.stdout).toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.inspectedPath).toMatch(/^\/proc\/\d+\/fd\/\d+$/);
    expect(observation.sha256).toBe(sha256(inputBytes[0]));
    expect(observation.accessMode).toBe(0);
    expect(observation.inodeMode).toBe(0o400);
    expect(observation.workingDirectory.startsWith(
      `${directory}/warden-release-unzip-`,
    )).toBe(true);
    expect(observation.workingDirectoryMode).toBe(0o700);
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);
  });

  it("gives independent unzip only the contracted child environment", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputBytes, inputPaths } = await writePackagedInputs(directory);
    const observationPath = join(directory, "child-environment-observation.json");
    const probeDirectory = join(directory, "child-environment-probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";

const inspectedPath = process.argv[3];
const descriptor = /^\\/proc\\/(\\d+)\\/fd\\/(\\d+)$/.exec(inspectedPath);
if (descriptor === null) {
  throw new Error("expected a procfs descriptor path");
}
const workingDirectory = process.cwd();
const [inspectedBytes, descriptorInfo, inspectedStat, workingDirectoryStat] = await Promise.all([
  readFile(inspectedPath),
  readFile("/proc/" + descriptor[1] + "/fdinfo/" + descriptor[2], "utf8"),
  stat(inspectedPath),
  stat(workingDirectory),
]);
const flagsMatch = /^flags:\\s+([0-7]+)$/m.exec(descriptorInfo);
if (flagsMatch === null) {
  throw new Error("expected octal descriptor flags");
}
const flags = Number.parseInt(flagsMatch[1], 8);
await writeFile(${JSON.stringify(observationPath)}, JSON.stringify({
  inspectedPath,
  sha256: createHash("sha256").update(inspectedBytes).digest("hex"),
  accessMode: flags & 0o3,
  inodeMode: inspectedStat.mode & 0o777,
  workingDirectory,
  workingDirectoryMode: workingDirectoryStat.mode & 0o777,
  environmentKeys: Object.keys(process.env).sort(),
  path: process.env.PATH,
  lang: process.env.LANG,
  lcAll: process.env.LC_ALL,
  secretMarkerPresent: Object.hasOwn(process.env, "WARDEN_TEST_UNZIP_SECRET_MARKER"),
  tmpdirPresent: Object.hasOwn(process.env, "TMPDIR"),
}));
`);
    await chmod(probePath, 0o755);
    const expectedPath = `${probeDirectory}:${process.env.PATH ?? ""}`;

    const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      env: {
        ...process.env,
        PATH: expectedPath,
        TMPDIR: directory,
        WARDEN_TEST_UNZIP_SECRET_MARKER: "must-not-reach-child",
      },
    });
    expect(result.stdout).toContain("independent ZIP reader unzip -t passed");
    const observation = JSON.parse(await readFile(observationPath, "utf8"));
    expect(observation.inspectedPath).toMatch(/^\/proc\/\d+\/fd\/\d+$/);
    expect(observation.sha256).toBe(sha256(inputBytes[0]));
    expect(observation.accessMode).toBe(0);
    expect(observation.inodeMode).toBe(0o400);
    expect(observation.workingDirectory.startsWith(
      `${directory}/warden-release-unzip-`,
    )).toBe(true);
    expect(observation.workingDirectoryMode).toBe(0o700);
    expect(observation.secretMarkerPresent).toBe(false);
    expect(observation.tmpdirPresent).toBe(false);
    expect(observation.environmentKeys).toEqual(["LANG", "LC_ALL", "PATH"]);
    expect(observation.path).toBe(expectedPath);
    expect(observation.lang).toBe("C");
    expect(observation.lcAll).toBe("C");
    expect((await readdir(directory)).filter((name) =>
      name.startsWith("warden-release-unzip-"),
    )).toEqual([]);
  });

  it("kills a stalled independent unzip direct child within its archive deadline", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-verify-cli-test-"));
    temporaryDirectories.push(directory);
    const { inputPaths } = await writePackagedInputs(directory);
    const startMarkerPath = join(directory, "timeout-probe-started");
    const completionMarkerPath = join(directory, "timeout-probe-completed");
    const probeDirectory = join(directory, "timeout-probe-bin");
    const probePath = join(probeDirectory, "unzip");
    await mkdir(probeDirectory, { recursive: true });
    await writeFile(probePath, `#!/usr/bin/env node
import { writeFile } from "node:fs/promises";

await writeFile(${JSON.stringify(startMarkerPath)}, "started\\n");
await new Promise((resolve) => setTimeout(resolve, 12_000));
await writeFile(${JSON.stringify(completionMarkerPath)}, "completed\\n");
`);
    await chmod(probePath, 0o755);

    let output;
    const startedAt = performance.now();
    try {
      const result = await execFile(process.execPath, [verifierPath, ...inputPaths], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        env: {
          ...process.env,
          PATH: `${probeDirectory}:${process.env.PATH ?? ""}`,
          TMPDIR: directory,
        },
      });
      output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
    } catch (error) {
      output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    }
    const elapsedMs = performance.now() - startedAt;
    expect(await readFile(startMarkerPath, "utf8")).toBe("started\n");
    let completionMarkerPresent = true;
    try {
      await readFile(completionMarkerPath);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
      completionMarkerPresent = false;
    }
    expect({
      failedClosed: /independent unzip -t validation failed/.test(output),
      completionMarkerPresent,
      completedBeforeTenSeconds: elapsedMs < 10_000,
      privateDirectories: (await readdir(directory)).filter((name) =>
        name.startsWith("warden-release-unzip-"),
      ),
    }).toEqual({
      failedClosed: true,
      completionMarkerPresent: false,
      completedBeforeTenSeconds: true,
      privateDirectories: [],
    });
  }, 20_000);

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
