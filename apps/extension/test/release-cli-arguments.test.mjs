import { describe, expect, it } from "vitest";

import { normalizeReleaseCliArguments } from "../scripts/release-cli-arguments.mjs";

describe("release CLI argument normalization", () => {
  it("preserves direct arguments and removes exactly one leading separator", () => {
    expect(normalizeReleaseCliArguments(["artifact", "digest"]))
      .toEqual(["artifact", "digest"]);
    expect(normalizeReleaseCliArguments(["--", "artifact", "digest"]))
      .toEqual(["artifact", "digest"]);
  });

  it("leaves doubled, interior, and trailing separators for the CLI grammar", () => {
    expect(normalizeReleaseCliArguments(["--", "--", "artifact"]))
      .toEqual(["--", "artifact"]);
    expect(normalizeReleaseCliArguments(["artifact", "--", "digest"]))
      .toEqual(["artifact", "--", "digest"]);
    expect(normalizeReleaseCliArguments(["artifact", "digest", "--"]))
      .toEqual(["artifact", "digest", "--"]);
  });

  it("does not mutate caller-owned arguments and rejects non-string input", () => {
    const rawArguments = ["--", "artifact", "digest"];
    normalizeReleaseCliArguments(rawArguments);
    expect(rawArguments).toEqual(["--", "artifact", "digest"]);
    expect(() => normalizeReleaseCliArguments("-- artifact"))
      .toThrow(/arguments must be an array of strings/);
    expect(() => normalizeReleaseCliArguments(["artifact", 1]))
      .toThrow(/arguments must be an array of strings/);
  });
});
