import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

// Release-producing git children must not inherit the caller's PATH or git
// environment. `pnpm run` prepends node_modules/.bin to PATH, so a dependency
// shipping a `git` bin would otherwise shadow the real one for the producer,
// and an inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE would let a different
// repository answer the clean-tree gate and supply source.gitCommit.
export const RELEASE_GIT_EXECUTABLE = "/usr/bin/git";
export const RELEASE_GIT_MAX_BUFFER_BYTES = 16 * 1024 * 1024;
export const RELEASE_GIT_TIMEOUT_MS = 10 * 60 * 1000;
export const RELEASE_GIT_KILL_SIGNAL = "SIGKILL";

export function releaseGitEnvironment() {
  return {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
  };
}

export async function runReleaseGit(
  args,
  {
    cwd,
    maxBuffer = RELEASE_GIT_MAX_BUFFER_BYTES,
    timeoutMs = RELEASE_GIT_TIMEOUT_MS,
  } = {},
) {
  return await execFile(RELEASE_GIT_EXECUTABLE, ["-c", "core.fsmonitor=false", ...args], {
    cwd,
    env: releaseGitEnvironment(),
    encoding: "utf8",
    maxBuffer,
    timeout: timeoutMs,
    killSignal: RELEASE_GIT_KILL_SIGNAL,
    windowsHide: true,
  });
}

export async function assertReleaseGitSourceTree({ cwd, label = "release source tree" }) {
  const { stdout: status } = await runReleaseGit(
    ["status", "--porcelain=v1", "--untracked-files=all"],
    { cwd },
  );
  if (status !== "") {
    throw new Error(`${label} requires a clean source tree:\n${status.trimEnd()}`);
  }

  const { stdout: taggedFiles } = await runReleaseGit(
    ["ls-files", "--cached", "-v", "-z"],
    { cwd },
  );
  const unsafeIndexEntries = taggedFiles
    .split("\0")
    .filter(Boolean)
    .filter((record) => record.length < 3 || record[1] !== " " || record[0] !== "H");
  if (unsafeIndexEntries.length > 0) {
    const displayed = unsafeIndexEntries
      .slice(0, 20)
      .map((record) => JSON.stringify(record))
      .join(", ");
    throw new Error(
      `${label} rejects non-default Git index flags (including assume-unchanged and skip-worktree): ${displayed}`,
    );
  }
}
