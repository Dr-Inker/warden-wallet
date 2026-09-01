import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  LOCAL_DUAL_RELEASE_SCHEMA,
  createLocalDualReleaseReport,
  parseLocalDualReleaseReport,
  releaseComparisonPaths,
  serializeLocalDualReleaseReport,
} from "../../../scripts/local-dual-extension-release.mjs";

const SOURCE_SHA = "a".repeat(40);
const VERSION = "1.2.3";
const TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});
const ORCHESTRATOR = Object.freeze({
  path: "repo:scripts/local-dual-extension-release.mjs",
  bytes: 12345,
  sha256: "b".repeat(64),
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function builderFiles(reverse = false) {
  const files = releaseComparisonPaths(VERSION).map((path) => ({
    path,
    data: Buffer.from(`canonical fixture bytes for ${path}\n`),
  }));
  return reverse ? files.reverse() : files;
}

function report(firstFiles = builderFiles(), secondFiles = builderFiles(true)) {
  return createLocalDualReleaseReport({
    sourceGitCommit: SOURCE_SHA,
    toolchain: TOOLCHAIN,
    orchestrator: ORCHESTRATOR,
    extensionVersion: VERSION,
    firstFiles,
    secondFiles,
  });
}

describe("same-host local dual extension release report", () => {
  it("canonically records fourteen byte-identical release files without temp paths", () => {
    const forward = report();
    const reverse = report(builderFiles(true), builderFiles());
    expect(serializeLocalDualReleaseReport(reverse))
      .toBe(serializeLocalDualReleaseReport(forward));
    expect(forward.schema).toBe(LOCAL_DUAL_RELEASE_SCHEMA);
    expect(forward.scope).toEqual({
      checkoutModel: "same-host-sequential-local-shared-object-clones",
      dependencyStoreModel: "shared-readonly-pnpm-content-addressed-store",
      independentBuilderClaim: "not-asserted",
      signedTagClaim: "not-asserted",
    });
    expect(forward.source).toEqual({ gitCommit: SOURCE_SHA, extensionVersion: VERSION });
    expect(forward.builders).toEqual([
      { id: "local-a", sourceGitCommit: SOURCE_SHA },
      { id: "local-b", sourceGitCommit: SOURCE_SHA },
    ]);
    expect(forward.comparison.fileCount).toBe(14);
    expect(forward.comparison.files.map((file) => file.path))
      .toEqual(releaseComparisonPaths(VERSION));
    const first = builderFiles().sort((left, right) =>
      Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))
    )[0];
    expect(forward.comparison.files[0]).toEqual({
      path: first.path,
      bytes: first.data.length,
      sha256: sha256(first.data),
    });
    expect(serializeLocalDualReleaseReport(forward)).not.toMatch(/\/tmp\/|\/opt\/|\/root\//);
  });

  it("rejects one-byte release drift between the two local builders", () => {
    const second = builderFiles();
    second[0] = {
      path: second[0].path,
      data: Buffer.from(second[0].data),
    };
    second[0].data[0] ^= 1;
    expect(() => report(builderFiles(), second)).toThrow(/release bytes differ/);
  });

  it("rejects missing, extra, duplicate, or moved release files", () => {
    expect(() => report(builderFiles().slice(1), builderFiles()))
      .toThrow(/fourteen-file comparison set/);
    expect(() => report(
      [...builderFiles(), { path: "release/extra.json", data: Buffer.from("extra\n") }],
      builderFiles(),
    )).toThrow(/fourteen-file comparison set/);
    const duplicate = builderFiles();
    duplicate.push({ ...duplicate[0] });
    expect(() => report(duplicate, builderFiles())).toThrow(/duplicate/);
    const moved = builderFiles();
    moved[0] = { ...moved[0], path: "release/moved.artifact.json" };
    expect(() => report(moved, builderFiles())).toThrow(/fourteen-file comparison set/);
  });

  it("rejects duplicate-key and noncanonical report JSON", () => {
    const value = report();
    const serialized = serializeLocalDualReleaseReport(value);
    expect(parseLocalDualReleaseReport(Buffer.from(serialized))).toEqual(value);
    const ambiguous = serialized.replace(
      `  "schema": "${LOCAL_DUAL_RELEASE_SCHEMA}",`,
      `  "schema": "attacker.invalid",\n  "schema": "${LOCAL_DUAL_RELEASE_SCHEMA}",`,
    );
    expect(() => parseLocalDualReleaseReport(Buffer.from(ambiguous)))
      .toThrow(/canonical generated JSON/);
  });
});
