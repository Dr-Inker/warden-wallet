import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import path from "node:path";

const WORKFLOWS_DIR = path.resolve(".github/workflows");
const IMMUTABLE_ACTION = /^[^/@\s]+\/[^/@\s]+(?:\/[^@\s]+)*@[0-9a-f]{40}$/;
const IMMUTABLE_DOCKER_ACTION = /^docker:\/\/[^\s@]+@sha256:[0-9a-f]{64}$/;

async function workflowFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await workflowFiles(candidate));
    } else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
      files.push(candidate);
    }
  }

  return files;
}

function parseUsesValue(line) {
  const match = line.match(/^\s*(?:-\s*)?uses:\s*(.*?)\s*(?:#.*)?$/);
  if (!match) return null;

  const value = match[1];
  if (
    value.length >= 2
    && ((value.startsWith("\"") && value.endsWith("\""))
      || (value.startsWith("'") && value.endsWith("'")))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function isImmutableExternalReference(value) {
  return IMMUTABLE_ACTION.test(value) || IMMUTABLE_DOCKER_ACTION.test(value);
}

test("pin grammar distinguishes immutable and mutable action references", () => {
  const commit = "0123456789abcdef0123456789abcdef01234567";
  const digest = "a".repeat(64);

  for (const value of [
    `actions/checkout@${commit}`,
    `owner/repository/subdirectory@${commit}`,
    `docker://ghcr.io/owner/action@sha256:${digest}`,
  ]) {
    assert.equal(isImmutableExternalReference(value), true, value);
  }

  for (const value of [
    "actions/checkout@v4",
    "actions/checkout@main",
    "actions/checkout@0123456789abcdef",
    "actions/checkout@${{ github.sha }}",
    "docker://ghcr.io/owner/action:latest",
    `actions/checkout@${commit.toUpperCase()}`,
  ]) {
    assert.equal(isImmutableExternalReference(value), false, value);
  }

  assert.equal(parseUsesValue("      uses: actions/checkout@v4 # mutable"), "actions/checkout@v4");
  assert.equal(parseUsesValue(`      uses: 'actions/checkout@${commit}' # v4`), `actions/checkout@${commit}`);
  assert.equal(parseUsesValue("      run: uses: actions/checkout@v4"), null);
});

test("every external GitHub Actions reference is immutable", async () => {
  const files = await workflowFiles(WORKFLOWS_DIR);
  assert.ok(files.length > 0, "no GitHub Actions workflow files were found");

  // The walk above is a recursive glob, so a new workflow is audited without
  // touching this test. Naming the two that exist keeps that property honest:
  // if one is renamed out of .github/workflows (or into a directory this walk
  // stops recursing into), the audit silently stops covering it, and this
  // assertion is what notices.
  const audited = new Set(files.map((file) => path.basename(file)));
  for (const expected of ["ci.yml", "release-verify.yml"]) {
    assert.ok(
      audited.has(expected),
      `${expected} was not discovered by the workflow audit — every workflow under .github/workflows must be pin-audited`,
    );
  }

  const externalReferences = [];
  const mutableReferences = [];

  for (const file of files) {
    const relativeFile = path.relative(process.cwd(), file);
    const lines = (await readFile(file, "utf8")).split(/\r?\n/);

    for (const [index, line] of lines.entries()) {
      const value = parseUsesValue(line);
      if (value === null || value.startsWith("./")) continue;

      externalReferences.push(value);
      if (!isImmutableExternalReference(value)) {
        mutableReferences.push(`${relativeFile}:${index + 1}: ${value}`);
      }
    }
  }

  assert.ok(externalReferences.length > 0, "audit found no external action references");
  assert.deepEqual(
    mutableReferences,
    [],
    `external actions must use a full 40-character commit SHA (or Docker sha256 digest):\n${mutableReferences.join("\n")}`,
  );
});
