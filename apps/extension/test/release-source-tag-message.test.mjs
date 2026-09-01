import { describe, expect, it } from "vitest";

import * as releaseSourceTag from "../scripts/release-source-tag.mjs";

describe("canonical release source-tag message", () => {
  it("formats the exact authenticated artifact identity for an operator", () => {
    const artifactManifestSha256 = "a".repeat(64);

    expect(releaseSourceTag.formatReleaseTagMessage).toBeTypeOf("function");
    expect(releaseSourceTag.formatReleaseTagMessage(artifactManifestSha256)).toBe(
      [
        "warden.extension-release-tag.v1",
        `artifact-manifest-sha256 ${artifactManifestSha256}`,
        "",
      ].join("\n"),
    );
  });
});
