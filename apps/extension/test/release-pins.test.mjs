import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import {
  RELEASE_PINS_SCHEMA,
  buildVerifierInvocations,
  loadReleasePins,
  parseReleasePins,
  releasePinsChildEnvironment,
} from "../scripts/release-pins.mjs";

const APP_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const COMMITTED_PINS_PATH = join(APP_DIRECTORY, "release-pins.json");

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function temporaryDirectory() {
  const directory = await mkdtemp(join(tmpdir(), "warden-release-pins-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

const SHA1_A = "3f9a1c07b25e48d6013a7f5c9e2b64d80af1735c";
const FPR_PRIMARY = "AAAABBBBCCCCDDDDEEEEFFFF00001111222233334";
const FPR_SIGNING = "9999AAAABBBBCCCCDDDDEEEEFFFF0000111122223";
const FPR_REVIEW_PRIMARY = "1234567890ABCDEF1234567890ABCDEF12345678";
const FPR_REVIEW_SIGNING = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
const SHA256_ARTIFACT = "7b1c04e9f3a25d68b0e4172c9d5a836f4e01bc9772d3a5e6081f4b3c2d9e70a1";
const SHA256_REPORT = "2e5d80a17c4b3f6091d2ea78bc035419f6d8027a3b1c9e45d70f6a281c3b954d";
const SHA256_SIGNATURE = "91af3c07d5b28e461037fa9c2d5b8140e7c36a92b0d418f5372ea6c1904bd83f";
const SHA256_PACKAGE = "c40b17e93a2d586f01c7e4b2938da05f61472c8ed30b915a4f826d70e1c3b948";
const EXTENSION_ID = "moabcdefghijklmnopabcdefghijklmn";

function minimalPins() {
  return {
    schema: RELEASE_PINS_SCHEMA,
    tag: "warden-extension-v1.0.0",
    tagObjectSha: SHA1_A,
    primaryFingerprint: FPR_PRIMARY.slice(0, 40),
    signingFingerprint: FPR_SIGNING.slice(0, 40),
    artifactManifestPath: "release/warden-extension-1.0.0.artifact.json",
    artifactManifestSha256: SHA256_ARTIFACT,
    reviewedUploadArchivePath: "release/warden-extension-1.0.0.zip",
    dualReleaseReport: null,
    artifactReviewSignature: null,
    storePackage: null,
  };
}

function dualReportPins() {
  return {
    ...minimalPins(),
    dualReleaseReport: {
      path: "release/warden-extension-1.0.0.dual-local.json",
      sha256: SHA256_REPORT,
    },
  };
}

function reviewSignaturePins() {
  return {
    ...dualReportPins(),
    artifactReviewSignature: {
      path: "release/warden-extension-1.0.0.artifact.json.asc",
      sha256: SHA256_SIGNATURE,
      primaryFingerprint: FPR_REVIEW_PRIMARY,
      signingFingerprint: FPR_REVIEW_SIGNING,
    },
  };
}

function fullPins() {
  return {
    ...reviewSignaturePins(),
    storePackage: {
      path: "release/warden-extension-1.0.0.crx",
      sha256: SHA256_PACKAGE,
      extensionId: EXTENSION_ID,
    },
  };
}

function pinsText(mutate) {
  const pins = fullPins();
  mutate?.(pins);
  return JSON.stringify(pins, null, 2);
}

describe("release pins loading", () => {
  it("fails closed when the pins file is missing", async () => {
    const directory = await temporaryDirectory();
    await expect(loadReleasePins(join(directory, "absent.json"))).rejects.toThrow(
      /release pins file could not be read/,
    );
  });

  it("fails closed on unparsable pins", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "release-pins.json");
    await writeFile(path, "{not json");
    await expect(loadReleasePins(path)).rejects.toThrow(/is not valid JSON/);
  });

  it("reads and validates a well-formed pins file from disk", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "release-pins.json");
    await writeFile(path, pinsText());
    const pins = await loadReleasePins(path);
    expect(pins.tag).toBe("warden-extension-v1.0.0");
    expect(pins.storePackage.extensionId).toBe(EXTENSION_ID);
  });

  it("REJECTS the placeholder pins file committed to the repository", async () => {
    await expect(loadReleasePins(COMMITTED_PINS_PATH)).rejects.toThrow(/placeholder/);
  });
});

describe("release pins structural validation", () => {
  it("rejects non-object documents", () => {
    for (const text of ["[]", '"x"', "null", "3"]) {
      expect(() => parseReleasePins(text)).toThrow(/must be a JSON object/);
    }
  });

  it("rejects a wrong or absent schema tag", () => {
    expect(() => parseReleasePins(pinsText((p) => { p.schema = "warden.other.v1"; }))).toThrow(
      /schema must be/,
    );
    expect(() => parseReleasePins(pinsText((p) => { delete p.schema; }))).toThrow(/schema must be/);
  });

  it("rejects a missing required key", () => {
    for (const key of [
      "tag",
      "tagObjectSha",
      "primaryFingerprint",
      "signingFingerprint",
      "artifactManifestPath",
      "artifactManifestSha256",
      "reviewedUploadArchivePath",
      "dualReleaseReport",
      "artifactReviewSignature",
      "storePackage",
    ]) {
      expect(() => parseReleasePins(pinsText((p) => { delete p[key]; })), key).toThrow(
        new RegExp(`missing required key ${key}`),
      );
    }
  });

  it("rejects unknown keys at the top level and inside every optional tuple", () => {
    expect(() => parseReleasePins(pinsText((p) => { p.extra = 1; }))).toThrow(
      /unknown key\(s\): extra/,
    );
    expect(() =>
      parseReleasePins(pinsText((p) => { p.dualReleaseReport.extra = 1; })),
    ).toThrow(/dualReleaseReport: unknown key\(s\): extra/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactReviewSignature.extra = 1; })),
    ).toThrow(/artifactReviewSignature: unknown key\(s\): extra/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.storePackage.extra = 1; })),
    ).toThrow(/storePackage: unknown key\(s\): extra/);
  });

  it("rejects an optional tuple that is neither null nor an object", () => {
    expect(() => parseReleasePins(pinsText((p) => { p.dualReleaseReport = "yes"; }))).toThrow(
      /dualReleaseReport must be null or a JSON object/,
    );
  });
});

describe("release pins placeholder rejection", () => {
  it("rejects every placeholder token in every scalar field", () => {
    const fields = [
      "tag",
      "tagObjectSha",
      "primaryFingerprint",
      "signingFingerprint",
      "artifactManifestPath",
      "artifactManifestSha256",
      "reviewedUploadArchivePath",
    ];
    for (const field of fields) {
      for (const token of ["", "   ", "TODO", "REPLACE_ME", "replace_me", "CHANGE_ME"]) {
        expect(
          () => parseReleasePins(pinsText((p) => { p[field] = token; })),
          `${field}=${JSON.stringify(token)}`,
        ).toThrow(/placeholder/);
      }
    }
  });

  it("rejects all-zero hex in every hex field", () => {
    expect(() => parseReleasePins(pinsText((p) => { p.tagObjectSha = "0".repeat(40); }))).toThrow(
      /placeholder/,
    );
    expect(() =>
      parseReleasePins(pinsText((p) => { p.primaryFingerprint = "0".repeat(40); })),
    ).toThrow(/placeholder/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.signingFingerprint = "0".repeat(40); })),
    ).toThrow(/placeholder/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactManifestSha256 = "0".repeat(64); })),
    ).toThrow(/placeholder/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.storePackage.sha256 = "0".repeat(64); })),
    ).toThrow(/placeholder/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.dualReleaseReport.sha256 = "0".repeat(64); })),
    ).toThrow(/placeholder/);
  });

  it("rejects a placeholder extension id", () => {
    for (const token of ["REPLACE_ME", "a".repeat(32), ""]) {
      expect(() => parseReleasePins(pinsText((p) => { p.storePackage.extensionId = token; }))).toThrow(
        /placeholder|extensionId/,
      );
    }
  });
});

describe("release pins field grammar", () => {
  it("requires a 40-lowercase-hex tag object sha", () => {
    for (const bad of [SHA1_A.slice(0, 39), `${SHA1_A}1`, SHA1_A.toUpperCase(), "g".repeat(40), 1]) {
      expect(() => parseReleasePins(pinsText((p) => { p.tagObjectSha = bad; })), String(bad)).toThrow(
        /tagObjectSha must be 40 lowercase hex/,
      );
    }
  });

  it("requires 40-UPPERCASE-hex OpenPGP fingerprints", () => {
    for (const field of ["primaryFingerprint", "signingFingerprint"]) {
      for (const bad of [
        FPR_PRIMARY.slice(0, 40).toLowerCase(),
        FPR_PRIMARY.slice(0, 39),
        FPR_PRIMARY.slice(0, 41),
        "GGGG".repeat(10),
        7,
      ]) {
        expect(
          () => parseReleasePins(pinsText((p) => { p[field] = bad; })),
          `${field}=${String(bad)}`,
        ).toThrow(new RegExp(`${field} must be 40 uppercase hex`));
      }
    }
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactReviewSignature.primaryFingerprint = "abc"; })),
    ).toThrow(/artifactReviewSignature\.primaryFingerprint must be 40 uppercase hex/);
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactReviewSignature.signingFingerprint = "abc"; })),
    ).toThrow(/artifactReviewSignature\.signingFingerprint must be 40 uppercase hex/);
  });

  it("requires 64-lowercase-hex SHA-256 digests", () => {
    for (const bad of [
      SHA256_ARTIFACT.slice(0, 63),
      `${SHA256_ARTIFACT}a`,
      SHA256_ARTIFACT.toUpperCase(),
      "z".repeat(64),
      false,
    ]) {
      expect(
        () => parseReleasePins(pinsText((p) => { p.artifactManifestSha256 = bad; })),
        String(bad),
      ).toThrow(/artifactManifestSha256 must be 64 lowercase hex/);
    }
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactReviewSignature.sha256 = "abc"; })),
    ).toThrow(/artifactReviewSignature\.sha256 must be 64 lowercase hex/);
    expect(() => parseReleasePins(pinsText((p) => { p.storePackage.sha256 = "abc"; }))).toThrow(
      /storePackage\.sha256 must be 64 lowercase hex/,
    );
    expect(() => parseReleasePins(pinsText((p) => { p.dualReleaseReport.sha256 = "abc"; }))).toThrow(
      /dualReleaseReport\.sha256 must be 64 lowercase hex/,
    );
  });

  it("requires a 32-character a-p Chrome extension id", () => {
    for (const bad of [
      EXTENSION_ID.slice(0, 31),
      `${EXTENSION_ID}a`,
      EXTENSION_ID.toUpperCase(),
      "abcdefghijklmnopabcdefghijklmnoz",
      null,
    ]) {
      expect(
        () => parseReleasePins(pinsText((p) => { p.storePackage.extensionId = bad; })),
        String(bad),
      ).toThrow(/storePackage\.extensionId must be 32 characters a-p/);
    }
  });

  it("requires a safe relative repository path for every file operand", () => {
    const pathFields = [
      ["artifactManifestPath", (p, v) => { p.artifactManifestPath = v; }],
      ["reviewedUploadArchivePath", (p, v) => { p.reviewedUploadArchivePath = v; }],
      ["dualReleaseReport.path", (p, v) => { p.dualReleaseReport.path = v; }],
      ["artifactReviewSignature.path", (p, v) => { p.artifactReviewSignature.path = v; }],
      ["storePackage.path", (p, v) => { p.storePackage.path = v; }],
    ];
    for (const [label, set] of pathFields) {
      for (const bad of ["/etc/passwd", "../secrets.json", "a/../../b", "release/", "rel\0ease", 5]) {
        expect(
          () => parseReleasePins(pinsText((p) => set(p, bad))),
          `${label}=${String(bad)}`,
        ).toThrow(/must be a relative path/);
      }
    }
  });

  it("requires a plausible tag name", () => {
    for (const bad of [" v1.0.0", "v1.0.0 ", "v1\n0", "v".repeat(257), 4]) {
      expect(() => parseReleasePins(pinsText((p) => { p.tag = bad; })), String(bad)).toThrow(
        /tag must be/,
      );
    }
  });
});

describe("release pins optional-tuple nesting", () => {
  it("refuses a store-package tuple without the review-signature tuple", () => {
    expect(() =>
      parseReleasePins(pinsText((p) => { p.artifactReviewSignature = null; })),
    ).toThrow(/storePackage requires artifactReviewSignature/);
  });

  it("refuses a review-signature tuple without the dual-report tuple", () => {
    expect(() =>
      parseReleasePins(
        pinsText((p) => {
          p.storePackage = null;
          p.dualReleaseReport = null;
        }),
      ),
    ).toThrow(/artifactReviewSignature requires dualReleaseReport/);
  });

  it("accepts each honest tier", () => {
    expect(parseReleasePins(JSON.stringify(minimalPins())).dualReleaseReport).toBe(null);
    expect(parseReleasePins(JSON.stringify(dualReportPins())).artifactReviewSignature).toBe(null);
    expect(parseReleasePins(JSON.stringify(reviewSignaturePins())).storePackage).toBe(null);
    expect(parseReleasePins(JSON.stringify(fullPins())).storePackage.extensionId).toBe(EXTENSION_ID);
  });
});

describe("verifier invocation vectors", () => {
  const appDirectory = "/repo/apps/extension";
  const p = (relative) => join(appDirectory, relative);

  it("builds the five-operand-plus-path source-tag call and skips both optional verifiers", () => {
    const invocations = buildVerifierInvocations(parseReleasePins(JSON.stringify(minimalPins())), {
      appDirectory,
    });
    expect(invocations.map((i) => `${i.id}:${i.run}`)).toEqual([
      "release-source-tag:true",
      "reviewed-artifact-signature:false",
      "store-package:false",
    ]);
    expect(invocations[0].script).toBe(p("scripts/verify-release-source-tag.mjs"));
    expect(invocations[0].args).toEqual([
      "warden-extension-v1.0.0",
      SHA1_A,
      FPR_PRIMARY.slice(0, 40),
      FPR_SIGNING.slice(0, 40),
      p("release/warden-extension-1.0.0.artifact.json"),
      SHA256_ARTIFACT,
    ]);
    expect(invocations[1].skipReason).toMatch(/artifactReviewSignature/);
    expect(invocations[2].skipReason).toMatch(/storePackage/);
  });

  it("composes the dual-report tuple into an eight-operand source-tag call", () => {
    const invocations = buildVerifierInvocations(
      parseReleasePins(JSON.stringify(dualReportPins())),
      { appDirectory },
    );
    expect(invocations[0].args).toEqual([
      "warden-extension-v1.0.0",
      SHA1_A,
      FPR_PRIMARY.slice(0, 40),
      FPR_SIGNING.slice(0, 40),
      p("release/warden-extension-1.0.0.artifact.json"),
      SHA256_ARTIFACT,
      p("release/warden-extension-1.0.0.dual-local.json"),
      SHA256_REPORT,
    ]);
    expect(invocations[1].run).toBe(false);
  });

  it("composes the review-signature tuple into a twelve-operand source-tag call and runs the signature verifier", () => {
    const invocations = buildVerifierInvocations(
      parseReleasePins(JSON.stringify(reviewSignaturePins())),
      { appDirectory },
    );
    expect(invocations[0].args).toHaveLength(12);
    expect(invocations[0].args.slice(8)).toEqual([
      p("release/warden-extension-1.0.0.artifact.json.asc"),
      SHA256_SIGNATURE,
      FPR_REVIEW_PRIMARY,
      FPR_REVIEW_SIGNING,
    ]);
    expect(invocations[1].run).toBe(true);
    expect(invocations[1].script).toBe(p("scripts/verify-reviewed-artifact-signature.mjs"));
    expect(invocations[1].args).toEqual([
      p("release/warden-extension-1.0.0.artifact.json"),
      p("release/warden-extension-1.0.0.artifact.json.asc"),
      SHA256_ARTIFACT,
      SHA256_SIGNATURE,
      FPR_REVIEW_PRIMARY,
      FPR_REVIEW_SIGNING,
    ]);
    expect(invocations[2].run).toBe(false);
  });

  it("composes the store tuple into a sixteen-operand source-tag call and runs the store verifier", () => {
    const invocations = buildVerifierInvocations(parseReleasePins(JSON.stringify(fullPins())), {
      appDirectory,
    });
    expect(invocations[0].args).toHaveLength(16);
    expect(invocations[0].args.slice(12)).toEqual([
      p("release/warden-extension-1.0.0.crx"),
      SHA256_PACKAGE,
      EXTENSION_ID,
      p("release/warden-extension-1.0.0.zip"),
    ]);
    expect(invocations[2].run).toBe(true);
    expect(invocations[2].script).toBe(p("scripts/verify-store-package.mjs"));
    expect(invocations[2].args).toEqual([
      p("release/warden-extension-1.0.0.crx"),
      SHA256_PACKAGE,
      EXTENSION_ID,
      SHA256_ARTIFACT,
      p("release/warden-extension-1.0.0.zip"),
      p("release/warden-extension-1.0.0.artifact.json"),
    ]);
  });

  it("never emits an argument that is not a string", () => {
    for (const invocation of buildVerifierInvocations(
      parseReleasePins(JSON.stringify(fullPins())),
      { appDirectory },
    )) {
      for (const argument of invocation.args) {
        expect(typeof argument).toBe("string");
      }
    }
  });
});

describe("verifier child environment", () => {
  it("is an allow-list that drops injected variables and carries GNUPGHOME", () => {
    const environment = releasePinsChildEnvironment({
      GNUPGHOME: "/var/lib/warden-release-keyring",
      PATH: "/attacker/bin:/usr/bin",
      LD_PRELOAD: "/attacker/evil.so",
      NODE_OPTIONS: "--require /attacker/hook.js",
      GIT_DIR: "/attacker/repo/.git",
      GNUPGHOME_EXTRA: "x",
    });
    expect(environment).toEqual({
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_OPTIONAL_LOCKS: "0",
      GNUPGHOME: "/var/lib/warden-release-keyring",
    });
  });

  it("fails closed when GNUPGHOME is absent or not absolute", () => {
    expect(() => releasePinsChildEnvironment({})).toThrow(/GNUPGHOME/);
    expect(() => releasePinsChildEnvironment({ GNUPGHOME: "relative/dir" })).toThrow(/GNUPGHOME/);
    expect(() => releasePinsChildEnvironment({ GNUPGHOME: " /abs " })).toThrow(/GNUPGHOME/);
  });
});
