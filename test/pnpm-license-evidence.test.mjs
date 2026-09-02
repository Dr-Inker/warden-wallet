import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { test } from "node:test";
import path from "node:path";
import { promisify } from "node:util";

import { assertPnpmLicenseEvidenceMatches } from "../scripts/pnpm-license-evidence.mjs";

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
  const { stdout: freshLicenseOutput } = await execFile(
    "pnpm",
    ["licenses", "list", "--json"],
    {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      env: {
        ...process.env,
        COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
        LANG: "C",
        LC_ALL: "C",
      },
    },
  );
  assertPnpmLicenseEvidenceMatches(evidence, JSON.parse(freshLicenseOutput));
  const evidenced = new Set(
    Object.values(evidence).flat().map((entry) => entry.name),
  );
  const missing = [...declared].filter((name) => !evidenced.has(name)).sort();
  assert.deepEqual(missing, [], `direct packages missing from license evidence: ${missing.join(", ")}`);
});

test("WRDF-0137 rejects license evidence whose versions differ from a fresh normalized inventory", async () => {
  const fresh = JSON.parse(
    await readFile("docs/security/third-party/pnpm-licenses.json", "utf8"),
  );
  const stale = structuredClone(fresh);
  const entry = Object.values(stale).flat()[0];
  assert.ok(entry, "license evidence fixture must contain at least one package");
  entry.versions = ["0.0.0-stale"];

  assert.throws(
    () => assertPnpmLicenseEvidenceMatches(stale, fresh),
    /name, version, and license inventory does not match/,
  );
});

test("vendored YAML parser exactly reproduces from pinned source and bundler", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "warden-yaml-bundle-"));
  try {
    const output = path.join(directory, "yaml-parser.mjs");
    await execFile("pnpm", [
      "exec",
      "esbuild",
      "scripts/vendor/yaml-parser.entry.mjs",
      "--bundle",
      "--platform=node",
      "--format=esm",
      "--target=node22",
      "--minify",
      "--legal-comments=eof",
      '--banner:js=import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
      `--outfile=${output}`,
    ], {
      encoding: "utf8",
      env: {
        ...process.env,
        COREPACK_ENABLE_DOWNLOAD_PROMPT: "0",
        LANG: "C",
        LC_ALL: "C",
      },
    });
    assert.deepEqual(
      await readFile(output),
      await readFile("scripts/vendor/yaml-parser.mjs"),
      "vendored YAML parser differs from its pinned source build",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("WRDF-0139 preserves the upstream ISC notice with the vendored YAML parser", async () => {
  assert.equal(
    await readFile("scripts/vendor/yaml-LICENSE", "utf8"),
    await readFile("node_modules/yaml/LICENSE", "utf8"),
    "the vendored yaml@2.8.1 parser must carry its exact upstream ISC notice",
  );
});
