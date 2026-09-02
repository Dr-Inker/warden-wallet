import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  RELEASE_GIT_EXECUTABLE,
  RELEASE_GIT_KILL_SIGNAL,
  releaseGitEnvironment,
  runReleaseGit,
} from "../scripts/release-git.mjs";

const execFile = promisify(execFileCallback);
const GIT = "/usr/bin/git";
const testDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(testDirectory, "..", "..", "..");

const SHIM_MARKER_NAME = "shim-was-executed";
const SHIM_COMMIT = "f".repeat(40);
const UNTRACKED_FILE = "untracked-producer-probe.txt";

const fixture = {};

async function git(arguments_, cwd) {
  return await execFile(GIT, arguments_, {
    cwd,
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_OPTIONAL_LOCKS: "0",
      GIT_AUTHOR_NAME: "Warden Release Test",
      GIT_AUTHOR_EMAIL: "release-test@example.invalid",
      GIT_COMMITTER_NAME: "Warden Release Test",
      GIT_COMMITTER_EMAIL: "release-test@example.invalid",
    },
  });
}

async function createRepository(root, name, fileText) {
  const path = join(root, name);
  await execFile("/bin/mkdir", ["-p", path]);
  await git(["init", "--quiet", "--initial-branch=main", "."], path);
  await writeFile(join(path, "tracked.txt"), fileText, "utf8");
  await git(["add", "tracked.txt"], path);
  await git(["commit", "--quiet", "--no-gpg-sign", "-m", `commit for ${name}`], path);
  const { stdout } = await git(["rev-parse", "HEAD"], path);
  return { path, head: stdout.trim() };
}

beforeAll(async () => {
  fixture.root = await mkdtemp(join(tmpdir(), "warden-release-git-"));
  fixture.real = await createRepository(fixture.root, "real", "real repository payload\n");
  fixture.decoy = await createRepository(fixture.root, "decoy", "decoy repository payload\n");
  // The real repository is deliberately dirty: an unsanitized clean-tree gate that
  // reads the decoy repository would wrongly report a clean tree.
  await writeFile(join(fixture.real.path, UNTRACKED_FILE), "dirty\n", "utf8");

  fixture.shimDirectory = join(fixture.root, "shim-bin");
  fixture.shimMarker = join(fixture.root, SHIM_MARKER_NAME);
  await execFile("/bin/mkdir", ["-p", fixture.shimDirectory]);
  await writeFile(
    join(fixture.shimDirectory, "git"),
    [
      "#!/bin/sh",
      `printf 'yes\\n' >> '${fixture.shimMarker}'`,
      `printf '${SHIM_COMMIT}\\n'`,
      "exit 0",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  await execFile("/bin/chmod", ["0755", join(fixture.shimDirectory, "git")]);

  fixture.savedEnvironment = { ...process.env };
});

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (!(key in fixture.savedEnvironment)) {
      delete process.env[key];
    }
  }
  Object.assign(process.env, fixture.savedEnvironment);
});

afterAll(async () => {
  if (fixture.root) {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

async function shimWasExecuted() {
  try {
    await readFile(fixture.shimMarker, "utf8");
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

describe("release producer git child processes", () => {
  it("uses an absolute git path and ignores a git shim placed first on PATH", async () => {
    process.env.PATH = `${fixture.shimDirectory}:${process.env.PATH ?? ""}`;

    const { stdout: commit } = await runReleaseGit(["rev-parse", "HEAD"], {
      cwd: fixture.real.path,
    });
    const { stdout: status } = await runReleaseGit(
      ["status", "--porcelain=v1", "--untracked-files=all"],
      { cwd: fixture.real.path },
    );

    expect(await shimWasExecuted()).toBe(false);
    expect(commit.trim()).toBe(fixture.real.head);
    expect(commit.trim()).not.toBe(SHIM_COMMIT);
    expect(status).toContain(UNTRACKED_FILE);
    expect(RELEASE_GIT_EXECUTABLE).toBe(GIT);
  });

  it("ignores an inherited GIT_DIR pointing at a different repository", async () => {
    process.env.GIT_DIR = join(fixture.decoy.path, ".git");
    process.env.GIT_WORK_TREE = fixture.decoy.path;
    process.env.GIT_INDEX_FILE = join(fixture.decoy.path, ".git", "index");
    process.env.GIT_CEILING_DIRECTORIES = fixture.root;
    process.env.GIT_OBJECT_DIRECTORY = join(fixture.decoy.path, ".git", "objects");

    const { stdout: commit } = await runReleaseGit(["rev-parse", "HEAD"], {
      cwd: fixture.real.path,
    });
    const { stdout: status } = await runReleaseGit(
      ["status", "--porcelain=v1", "--untracked-files=all"],
      { cwd: fixture.real.path },
    );

    expect(commit.trim()).toBe(fixture.real.head);
    expect(commit.trim()).not.toBe(fixture.decoy.head);
    expect(status).toContain(UNTRACKED_FILE);
  });

  it("builds the git child environment from an allow-list, not the inherited environment", () => {
    process.env.GIT_DIR = join(fixture.decoy.path, ".git");
    process.env.WARDEN_RELEASE_LEAK_PROBE = "leaked";

    const environment = releaseGitEnvironment();

    expect(environment).toEqual({
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_OPTIONAL_LOCKS: "0",
    });
    expect(Object.keys(environment)).not.toContain("GIT_DIR");
    expect(Object.keys(environment)).not.toContain("WARDEN_RELEASE_LEAK_PROBE");
  });

  it("bounds a hung git child with a timeout and a non-catchable kill signal", async () => {
    expect(RELEASE_GIT_KILL_SIGNAL).toBe("SIGKILL");
    await expect(
      runReleaseGit(["hash-object", "--stdin"], {
        cwd: fixture.real.path,
        timeoutMs: 750,
      }),
    ).rejects.toMatchObject({ killed: true, signal: "SIGKILL" });
  });

  it("leaves no producer-side script spawning a bare git command", async () => {
    const producers = [
      join(repositoryRoot, "apps", "extension", "scripts", "package-release.mjs"),
      join(repositoryRoot, "apps", "extension", "scripts", "release-artifact.mjs"),
      join(repositoryRoot, "scripts", "local-dual-extension-release.mjs"),
    ];
    for (const producer of producers) {
      const text = await readFile(producer, "utf8");
      expect(text).not.toMatch(/\brun\s*\(\s*"git"/);
      expect(text).not.toMatch(/\bexecFile\w*\s*\(\s*"git"/);
      expect(text).not.toMatch(/\bspawn\w*\s*\(\s*"git"/);
    }
  });
});
