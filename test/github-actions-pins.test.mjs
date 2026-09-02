import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { test } from "node:test";
import path from "node:path";

import {
  auditGitHubActionReferences,
  isImmutableExternalReference,
  parseUsesValue,
} from "../scripts/github-actions-pins.mjs";

const WORKFLOWS_DIR = path.resolve(".github/workflows");

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
  const { files, externalReferences, mutableReferences } =
    await auditGitHubActionReferences(process.cwd(), WORKFLOWS_DIR);
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

  assert.ok(externalReferences.length > 0, "audit found no external action references");
  assert.deepEqual(
    mutableReferences,
    [],
    `external actions must use a full 40-character commit SHA (or Docker sha256 digest):\n${mutableReferences.join("\n")}`,
  );
});

test("WRDF-0130 audits semantic uses keys and recursively follows local composite actions", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "warden-actions-audit-"));
  try {
    const workflows = path.join(root, ".github", "workflows");
    const localAction = path.join(root, ".github", "actions", "local");
    await mkdir(workflows, { recursive: true });
    await mkdir(localAction, { recursive: true });
    await writeFile(path.join(workflows, "fixture.yml"), [
      "jobs:",
      "  quoted:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - \"uses\": owner/quoted@v1",
      "      - { uses: owner/flow@main }",
      "      - uses: ./.github/actions/local",
      "",
    ].join("\n"));
    await writeFile(path.join(localAction, "action.yml"), [
      "name: local",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: owner/nested@v2",
      "",
    ].join("\n"));

    const { mutableReferences } = await auditGitHubActionReferences(root, workflows);
    assert.deepEqual(
      mutableReferences.map((entry) => entry.replace(/^.*?:\d+: /, "")).sort(),
      ["owner/flow@main", "owner/nested@v2", "owner/quoted@v1"],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
