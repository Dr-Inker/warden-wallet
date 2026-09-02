import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

test("WRDF-0135 covers every declared direct package in committed license evidence", async () => {
  const lockfile = await readFile("pnpm-lock.yaml");
  const expectedLockfileHash = `${createHash("sha256").update(lockfile).digest("hex")}  pnpm-lock.yaml`;
  const recordedLockfileHash = (
    await readFile("docs/security/third-party/pnpm-lock.sha256", "utf8")
  ).trim();
  assert.equal(
    recordedLockfileHash,
    expectedLockfileHash,
    "pnpm license evidence is stale: regenerate it and its pnpm-lock.sha256 binding",
  );

  const { stdout } = await execFile("/usr/bin/git", ["ls-files", "--cached", "-z"], {
    encoding: "buffer",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_OPTIONAL_LOCKS: "0",
    },
  });
  const manifests = stdout
    .toString("utf8")
    .split("\0")
    .filter((file) => file === "package.json" || file.endsWith("/package.json"));
  assert.ok(manifests.length > 0, "no tracked package manifests were found");

  const declared = new Set();
  for (const manifestPath of manifests) {
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, range] of Object.entries(manifest[field] ?? {})) {
        if (typeof range === "string" && !range.startsWith("workspace:")) declared.add(name);
      }
    }
  }

  const evidence = JSON.parse(
    await readFile("docs/security/third-party/pnpm-licenses.json", "utf8"),
  );
  const evidenced = new Set(
    Object.values(evidence).flat().map((entry) => entry.name),
  );
  const missing = [...declared].filter((name) => !evidenced.has(name)).sort();
  assert.deepEqual(missing, [], `direct packages missing from license evidence: ${missing.join(", ")}`);
});
