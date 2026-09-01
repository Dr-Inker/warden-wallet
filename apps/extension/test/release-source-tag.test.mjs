import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  GIT_GPG_LAUNCHER_MODE,
  GIT_GPG_LAUNCHER_TEXT,
  parseAnnotatedTagObject,
  parseSingleOpenPgpSignatureStatus,
  verifyReleaseSourceTag,
} from "../scripts/release-source-tag.mjs";
import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";
import {
  createLocalDualReleaseReport,
  releaseComparisonPaths,
  serializeLocalDualReleaseReport,
} from "../../../scripts/local-dual-extension-release.mjs";

const execFile = promisify(execFileCallback);
const GIT = "/usr/bin/git";
const GPG = "/usr/bin/gpg";
const GPG_LAUNCHER_PREFIX = "warden-release-source-gpg-launcher-";
const FIXTURE_VERSION = "1.2.3";
const fixture = {};

const ARTIFACT_ATTACHMENTS = Object.freeze({
  dependencyEvidence: {
    file: `warden-extension-${FIXTURE_VERSION}.sbom.json`,
    bytes: Buffer.from("canonical signed-source dependency evidence fixture\n"),
  },
  bundleInputEvidence: {
    file: `warden-extension-${FIXTURE_VERSION}.bundle-inputs.json`,
    bytes: Buffer.from("canonical signed-source bundle evidence fixture\n"),
  },
  staticInputEvidence: {
    file: `warden-extension-${FIXTURE_VERSION}.static-inputs.json`,
    bytes: Buffer.from("canonical signed-source static evidence fixture\n"),
  },
  releaseRecipeInputEvidence: {
    file: `warden-extension-${FIXTURE_VERSION}.recipe-inputs.json`,
    bytes: Buffer.from("canonical signed-source recipe evidence fixture\n"),
  },
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function localDualReportBytes(sourceGitCommit, extensionVersion = FIXTURE_VERSION) {
  const files = releaseComparisonPaths(extensionVersion).map((path) => ({
    path,
    data: Buffer.from(`canonical signed-source fixture bytes for ${path}\n`),
  }));
  return Buffer.from(serializeLocalDualReleaseReport(createLocalDualReleaseReport({
    sourceGitCommit,
    toolchain: { node: "22.23.2", pnpm: "11.12.0", esbuild: "0.28.2" },
    orchestrator: {
      path: "repo:scripts/local-dual-extension-release.mjs",
      bytes: 12345,
      sha256: "a".repeat(64),
    },
    extensionVersion,
    firstFiles: files,
    secondFiles: [...files].reverse(),
  })), "utf8");
}

function releaseArtifact(sourceGitCommit) {
  const extensionManifest = {
    manifest_version: 3,
    name: "Warden signed-source fixture",
    version: FIXTURE_VERSION,
    permissions: ["storage"],
    background: { service_worker: "background.js", type: "module" },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'self';",
    },
  };
  const entries = [
    { path: "approval.css", data: Buffer.from("body { color: #123456; }\n") },
    { path: "approval.html", data: Buffer.from("<!doctype html><title>Approve</title>\n") },
    { path: "approval.js", data: Buffer.from("globalThis.approve = false;\n") },
    { path: "background.js", data: Buffer.from("globalThis.background = true;\n") },
    { path: "content.js", data: Buffer.from("globalThis.content = true;\n") },
    {
      path: "manifest.json",
      data: Buffer.from(`${JSON.stringify(extensionManifest, null, 2)}\n`),
    },
    { path: "popup.html", data: Buffer.from("<!doctype html><title>Warden</title>\n") },
    { path: "popup.js", data: Buffer.from("globalThis.popup = true;\n") },
  ];
  const archiveBytes = createCanonicalZip(entries);
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: `warden-extension-${FIXTURE_VERSION}.zip`,
    source: { gitCommit: sourceGitCommit, lockfileSha256: "b".repeat(64) },
    toolchain: { node: "22.23.2", pnpm: "11.12.0", esbuild: "0.28.2" },
    ...ARTIFACT_ATTACHMENTS,
  });
  return {
    artifactManifest,
    artifactManifestBytes: Buffer.from(serializeArtifactManifest(artifactManifest), "utf8"),
  };
}

async function command(file, arguments_, { cwd, env = process.env } = {}) {
  return execFile(file, arguments_, {
    cwd,
    env,
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
  });
}

async function git(arguments_, env = process.env) {
  return command(GIT, arguments_, { cwd: fixture.repository, env });
}

async function signedTag(name, message, env, signingFingerprint = fixture.signingFingerprint) {
  await git([
    "-c",
    `gpg.program=${GPG}`,
    "tag",
    "-s",
    "-u",
    `${signingFingerprint}!`,
    "-m",
    message,
    name,
  ], env);
  return (await git(["rev-parse", `refs/tags/${name}`])).stdout.trim();
}

beforeAll(async () => {
  fixture.root = await mkdtemp(join(tmpdir(), "warden-release-source-tag-test-"));
  fixture.repository = join(fixture.root, "repository");
  fixture.gnupgHome = join(fixture.root, "gnupg");
  fixture.emptyGnuPgHome = join(fixture.root, "empty-gnupg");
  await mkdir(fixture.repository, { mode: 0o700 });
  await mkdir(fixture.gnupgHome, { mode: 0o700 });
  await mkdir(fixture.emptyGnuPgHome, { mode: 0o700 });
  fixture.environment = { ...process.env, GNUPGHOME: fixture.gnupgHome };

  await command(GPG, [
    "--batch",
    "--homedir",
    fixture.gnupgHome,
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--quick-generate-key",
    "Warden release fixture <release-fixture@example.invalid>",
    "ed25519",
    "sign",
    "0",
  ]);
  const keys = await command(GPG, [
    "--batch",
    "--homedir",
    fixture.gnupgHome,
    "--with-colons",
    "--list-secret-keys",
  ]);
  const lines = keys.stdout.split("\n").map((line) => line.split(":"));
  const secretKeyIndex = lines.findIndex((fields) => fields[0] === "sec");
  fixture.fingerprint = lines.slice(secretKeyIndex + 1)
    .find((fields) => fields[0] === "fpr")?.[9];
  if (!/^[0-9A-F]{40}(?:[0-9A-F]{24})?$/.test(fixture.fingerprint ?? "")) {
    throw new Error("failed to create an ephemeral full OpenPGP fingerprint");
  }
  for (let index = 0; index < 2; index += 1) {
    await command(GPG, [
      "--batch",
      "--homedir",
      fixture.gnupgHome,
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "",
      "--quick-add-key",
      fixture.fingerprint,
      "ed25519",
      "sign",
      "0",
    ]);
  }
  const keysWithSubkeys = await command(GPG, [
    "--batch",
    "--homedir",
    fixture.gnupgHome,
    "--with-colons",
    "--list-secret-keys",
  ]);
  const fingerprints = keysWithSubkeys.stdout.split("\n")
    .map((line) => line.split(":"))
    .filter((fields) => fields[0] === "fpr")
    .map((fields) => fields[9]);
  if (
    fingerprints.length !== 3 ||
    fingerprints[0] !== fixture.fingerprint ||
    fingerprints.some((fingerprint) => !/^[0-9A-F]{40}(?:[0-9A-F]{24})?$/.test(fingerprint))
  ) {
    throw new Error("failed to create two distinct ephemeral signing subkeys");
  }
  [fixture.fingerprint, fixture.signingFingerprint, fixture.siblingSigningFingerprint] =
    fingerprints;

  await git(["init", "--quiet"]);
  await git(["config", "user.name", "Warden release fixture"]);
  await git(["config", "user.email", "release-fixture@example.invalid"]);
  await writeFile(join(fixture.repository, "payload.txt"), "first release payload\n");
  await git(["add", "payload.txt"]);
  await git(["commit", "--quiet", "-m", "first release fixture"]);
  fixture.firstCommit = (await git(["rev-parse", "HEAD"])).stdout.trim();
  fixture.releaseTagObject = await signedTag(
    "release-fixture",
    "fixture valid release",
    fixture.environment,
  );
  fixture.siblingTagObject = await signedTag(
    "sibling-signing-fixture",
    "fixture valid sibling signing subkey",
    fixture.environment,
    fixture.siblingSigningFingerprint,
  );
  fixture.primaryTagObject = await signedTag(
    "primary-signing-fixture",
    "fixture valid primary signing key",
    fixture.environment,
    fixture.fingerprint,
  );
  await writeFile(join(fixture.gnupgHome, "gpg.conf"), "digest-algo SHA224\n", {
    mode: 0o600,
  });
  fixture.unapprovedHashTagObject = await signedTag(
    "unapproved-hash-fixture",
    "fixture valid signature with an unapproved hash",
    fixture.environment,
  );
  await rm(join(fixture.gnupgHome, "gpg.conf"));
  fixture.movedTagObject = await signedTag(
    "moved-fixture",
    "fixture before move",
    fixture.environment,
  );
  const originalBadObject = await signedTag(
    "bad-signature-fixture",
    "fixture before tamper",
    fixture.environment,
  );
  const originalBadBytes = (await git(["cat-file", "tag", originalBadObject])).stdout;
  const tamperedBytes = originalBadBytes.replace(
    "fixture before tamper",
    "fixture after tamper!",
  );
  if (tamperedBytes === originalBadBytes) {
    throw new Error("failed to mutate the ephemeral signed tag bytes");
  }
  const tamperedPath = join(fixture.root, "tampered-tag-object");
  await writeFile(tamperedPath, tamperedBytes);
  fixture.badTagObject = (await git([
    "hash-object",
    "-t",
    "tag",
    "-w",
    tamperedPath,
  ])).stdout.trim();
  await git([
    "update-ref",
    "refs/tags/bad-signature-fixture",
    fixture.badTagObject,
    originalBadObject,
  ]);

  await writeFile(join(fixture.repository, "payload.txt"), "second release payload\n");
  await git(["add", "payload.txt"]);
  await git(["commit", "--quiet", "-m", "second release fixture"]);
  fixture.secondCommit = (await git(["rev-parse", "HEAD"])).stdout.trim();
  await git([
    "-c",
    `gpg.program=${GPG}`,
    "tag",
    "-f",
    "-s",
    "-u",
    `${fixture.signingFingerprint}!`,
    "-m",
    "fixture after move",
    "moved-fixture",
  ], fixture.environment);
  await git(["tag", "lightweight-fixture"]);
  fixture.lightweightObject = (await git([
    "rev-parse",
    "refs/tags/lightweight-fixture",
  ])).stdout.trim();
  await git(["config", "gpg.program", "/bin/false"]);
  await git(["config", "gpg.openpgp.program", "/bin/false"]);
  fixture.environment = {
    ...fixture.environment,
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "gpg.openpgp.program",
    GIT_CONFIG_VALUE_0: "/bin/false",
    GIT_DIR: join(fixture.root, "attacker-selected-git-dir"),
  };
}, 20_000);

afterAll(async () => {
  if (fixture.root) {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

afterEach(async () => {
  const leakedLaunchers = (await readdir(tmpdir()))
    .filter((name) => name.startsWith(GPG_LAUNCHER_PREFIX));
  expect(leakedLaunchers).toEqual([]);
});

function verify(options = {}) {
  return verifyReleaseSourceTag({
    repositoryRoot: fixture.repository,
    tagName: "release-fixture",
    expectedTagObject: fixture.releaseTagObject,
    expectedPrimaryFingerprint: fixture.fingerprint,
    expectedSigningFingerprint: fixture.signingFingerprint,
    artifactManifest: {
      source: { gitCommit: fixture.firstCommit },
      extension: { version: FIXTURE_VERSION },
    },
    environment: fixture.environment,
    ...options,
  });
}

describe("release source annotated-tag verification", () => {
  it("pins the private offline GnuPG launcher contract", () => {
    expect(GIT_GPG_LAUNCHER_MODE).toBe(0o700);
    expect(GIT_GPG_LAUNCHER_TEXT).toBe([
      "#!/bin/sh",
      "set -eu",
      "exec /usr/bin/gpg \\",
      "  --no-options \\",
      "  --homedir \"$GNUPGHOME\" \\",
      "  --batch \\",
      "  --no-tty \\",
      "  --no-auto-key-import \\",
      "  --no-auto-key-retrieve \\",
      "  --auto-key-locate clear \\",
      "  \"$@\"",
      "",
    ].join("\n"));
  });

  it("binds an exact annotated tag object plus primary and signing fingerprints", async () => {
    await expect(verify()).resolves.toEqual({
      tagName: "release-fixture",
      tagRef: "refs/tags/release-fixture",
      tagObject: fixture.releaseTagObject,
      sourceCommit: fixture.firstCommit,
      signingFingerprint: fixture.signingFingerprint,
      primaryFingerprint: fixture.fingerprint,
      signatureCreationDate: expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      signatureTimestamp: expect.any(Number),
      signatureExpirationTimestamp: null,
      signatureVersion: 4,
      publicKeyAlgorithm: 22,
      hashAlgorithm: 10,
      signatureClass: "00",
    });
  });

  it("rejects a separately valid dual report for a different source commit", async () => {
    const dualReleaseReportBytes = localDualReportBytes(fixture.secondCommit);
    await expect(verify({
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/dual release report source differs from the artifact source commit/);
  });

  it("binds the signed source to an independently digested canonical dual report", async () => {
    const dualReleaseReportBytes = localDualReportBytes(fixture.firstCommit);
    const expectedDualReleaseReportSha256 = sha256(dualReleaseReportBytes);
    await expect(verify({
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256,
    })).resolves.toMatchObject({
      sourceCommit: fixture.firstCommit,
      dualReleaseReport: {
        sha256: expectedDualReleaseReportSha256,
        sourceCommit: fixture.firstCommit,
        extensionVersion: FIXTURE_VERSION,
        comparisonFileCount: 14,
        scope: {
          checkoutModel: "same-host-sequential-local-shared-object-clones",
          dependencyStoreModel: "shared-readonly-pnpm-content-addressed-store",
          independentBuilderClaim: "not-asserted",
          signedTagClaim: "not-asserted",
        },
      },
    });
  });

  it("rejects a report whose fourteen records do not describe the selected artifact", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(fixture.firstCommit);
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/dual release report artifact manifest record differs/);
  });

  it("checks the independent report digest before parsing candidate bytes", async () => {
    const dualReleaseReportBytes = Buffer.from("not canonical report JSON\n");
    await expect(verify({
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: "0".repeat(64),
    })).rejects.toThrow(/differs from the independently supplied SHA-256/);
    await expect(verify({
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/not valid JSON/);
    await expect(verify({ dualReleaseReportBytes }))
      .rejects.toThrow(/must be provided together/);
    await expect(verify({ expectedDualReleaseReportSha256: "0".repeat(64) }))
      .rejects.toThrow(/must be provided together/);
  });

  it("rejects a canonical dual report for a different extension version", async () => {
    const dualReleaseReportBytes = localDualReportBytes(fixture.firstCommit, "9.8.7");
    await expect(verify({
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/extension version differs/);
  });

  it("retains key, subkey, and signature refusal after binding the report", async () => {
    const dualReleaseReportBytes = localDualReportBytes(fixture.firstCommit);
    const reportOptions = {
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    };
    await expect(verify({
      ...reportOptions,
      environment: { GNUPGHOME: fixture.emptyGnuPgHome },
    })).rejects.toThrow(/ERRSIG|NO_PUBKEY|signature/);
    await expect(verify({
      ...reportOptions,
      tagName: "sibling-signing-fixture",
      expectedTagObject: fixture.siblingTagObject,
    })).rejects.toThrow(/signing fingerprint differs from the independently supplied signing key/);
    await expect(verify({
      ...reportOptions,
      tagName: "bad-signature-fixture",
      expectedTagObject: fixture.badTagObject,
    })).rejects.toThrow(/BADSIG|signature/);
  });

  it("rejects a lightweight tag, moved tag, or wrong artifact commit", async () => {
    await expect(verify({
      tagName: "lightweight-fixture",
      expectedTagObject: fixture.lightweightObject,
      artifactManifest: { source: { gitCommit: fixture.secondCommit } },
    })).rejects.toThrow(/annotated tag object/);
    await expect(verify({
      tagName: "moved-fixture",
      expectedTagObject: fixture.movedTagObject,
    })).rejects.toThrow(/moved or differs/);
    await expect(verify({
      artifactManifest: { source: { gitCommit: fixture.secondCommit } },
    })).rejects.toThrow(/differs from the artifact source commit/);
  });

  it("rejects a bad signature and independently supplied wrong identities", async () => {
    await expect(verify({
      tagName: "bad-signature-fixture",
      expectedTagObject: fixture.badTagObject,
    })).rejects.toThrow(/BADSIG|signature/);
    await expect(verify({
      expectedPrimaryFingerprint: "0".repeat(40),
    })).rejects.toThrow(/differs from the independently supplied primary key/);
    await expect(verify({
      expectedSigningFingerprint: "0".repeat(40),
    })).rejects.toThrow(/differs from the independently supplied signing key/);
    await expect(verify({
      expectedPrimaryFingerprint: fixture.signingFingerprint,
    })).rejects.toThrow(/differs from the independently supplied primary key/);
    await expect(verify({
      expectedSigningFingerprint: fixture.fingerprint,
    })).rejects.toThrow(/differs from the independently supplied signing key/);
    await expect(verify({
      expectedSigningFingerprint: fixture.signingFingerprint.slice(0, 16),
    })).rejects.toThrow(/expected signing fingerprint must be a 40- or 64-character/);
    await expect(verify({
      expectedPrimaryFingerprint: "not-a-fingerprint",
    })).rejects.toThrow(/expected primary fingerprint must be a 40- or 64-character/);
    await expect(verify({
      environment: { GNUPGHOME: fixture.emptyGnuPgHome },
    })).rejects.toThrow(/ERRSIG|NO_PUBKEY|signature/);
  });

  it("refuses an unexpected sibling subkey and accepts only the independently selected key", async () => {
    const siblingOptions = {
      tagName: "sibling-signing-fixture",
      expectedTagObject: fixture.siblingTagObject,
    };
    await expect(verify(siblingOptions))
      .rejects.toThrow(/signing fingerprint differs from the independently supplied signing key/);
    await expect(verify({
      ...siblingOptions,
      expectedSigningFingerprint: fixture.siblingSigningFingerprint,
    })).resolves.toMatchObject({
      signingFingerprint: fixture.siblingSigningFingerprint,
      primaryFingerprint: fixture.fingerprint,
    });
    await expect(verify({
      tagName: "primary-signing-fixture",
      expectedTagObject: fixture.primaryTagObject,
      expectedSigningFingerprint: fixture.fingerprint,
    })).resolves.toMatchObject({
      signingFingerprint: fixture.fingerprint,
      primaryFingerprint: fixture.fingerprint,
    });
  });

  it("ignores mutable keyring options while verifying the selected signing key", async () => {
    const optionsPath = join(fixture.gnupgHome, "gpg.conf");
    const emptyKeyringPath = join(fixture.root, "hostile-empty-keyring.kbx");
    await writeFile(
      optionsPath,
      `no-default-keyring\nkeyring ${emptyKeyringPath}\n`,
      { mode: 0o600 },
    );
    try {
      await expect(verify()).resolves.toMatchObject({
        signingFingerprint: fixture.signingFingerprint,
        primaryFingerprint: fixture.fingerprint,
      });
    } finally {
      await rm(optionsPath, { force: true });
    }
  });

  it("rejects a cryptographically valid tag made with an unapproved hash", async () => {
    await expect(verify({
      tagName: "unapproved-hash-fixture",
      expectedTagObject: fixture.unapprovedHashTagObject,
    })).rejects.toThrow(/hash algorithm 11 is not allowed/);
  });

  it("parses one VALIDSIG primary/subkey identity and rejects ambiguous status", () => {
    const primary = "A".repeat(40);
    const signing = `${"B".repeat(24)}${"C".repeat(16)}`;
    const validStatus = [
      "[GNUPG:] NEWSIG",
      `[GNUPG:] GOODSIG ${"C".repeat(16)} Warden%20fixture`,
      `[GNUPG:] VALIDSIG ${signing} 2026-09-01 1788220800 0 4 0 22 8 00 ${primary}`,
      "[GNUPG:] TRUST_UNDEFINED 0 pgp",
      "[GNUPG:] FUTURE_STATUS ignored-for-forward-compatibility",
      "",
    ].join("\n");
    expect(parseSingleOpenPgpSignatureStatus(validStatus, primary, signing)).toEqual({
      signingFingerprint: signing,
      primaryFingerprint: primary,
      signatureCreationDate: "2026-09-01",
      signatureTimestamp: 1_788_220_800,
      signatureExpirationTimestamp: null,
      signatureVersion: 4,
      publicKeyAlgorithm: 22,
      hashAlgorithm: 8,
      signatureClass: "00",
    });
    expect(() => parseSingleOpenPgpSignatureStatus(
      validStatus.replace("[GNUPG:] TRUST_UNDEFINED", "[GNUPG:] NEWSIG\n[GNUPG:] TRUST_UNDEFINED"),
      primary,
      signing,
    )).toThrow(/exactly one signature/);
    expect(() => parseSingleOpenPgpSignatureStatus(
      validStatus.replace("[GNUPG:] GOODSIG", "[GNUPG:] EXPKEYSIG"),
      primary,
      signing,
    )).toThrow(/EXPKEYSIG/);
    expect(() => parseSingleOpenPgpSignatureStatus(
      validStatus.replace(
        "[GNUPG:] TRUST_UNDEFINED",
        `[GNUPG:] VALIDSIG ${signing} 2026-09-01 1788220800 0 4 0 22 8 00 ${primary}\n[GNUPG:] TRUST_UNDEFINED`,
      ),
      primary,
      signing,
    )).toThrow(/exactly one cryptographic VALIDSIG/);
    expect(() => parseSingleOpenPgpSignatureStatus(
      validStatus.replace(
        `[GNUPG:] GOODSIG ${"C".repeat(16)} Warden%20fixture`,
        `[GNUPG:] ERRSIG ${"C".repeat(16)} 22 8 00 1788220800 9 ${signing}\n[GNUPG:] NO_PUBKEY ${"C".repeat(16)}`,
      ),
      primary,
      signing,
    )).toThrow(/ERRSIG|NO_PUBKEY/);
  });

  it("rejects structurally ambiguous or nested annotated tag objects", () => {
    const commit = "a".repeat(40);
    const headers = [
      `object ${commit}`,
      "type commit",
      "tag release-fixture",
      "tagger Fixture <fixture@example.invalid> 1788220800 +0000",
    ];
    expect(parseAnnotatedTagObject(`${headers.join("\n")}\n\nmessage\n`, "release-fixture"))
      .toEqual({ targetCommit: commit });
    expect(() => parseAnnotatedTagObject(
      `${headers[0]}\nobject ${"b".repeat(40)}\n${headers.slice(1).join("\n")}\n\nmessage\n`,
      "release-fixture",
    )).toThrow(/duplicate object headers/);
    expect(() => parseAnnotatedTagObject(
      `${headers.join("\n").replace("type commit", "type tag")}\n\nmessage\n`,
      "release-fixture",
    )).toThrow(/point directly to a commit/);
  });

  it("rejects invalid or revision-like tag inputs before verification", async () => {
    await expect(verify({ tagName: "release-fixture^{}" }))
      .rejects.toThrow(/exact valid Git tag ref/);
    await expect(verify({ tagName: " release-fixture" }))
      .rejects.toThrow(/tag name is invalid/);
    await expect(verify({ expectedTagObject: fixture.releaseTagObject.toUpperCase() }))
      .rejects.toThrow(/full lowercase/);
    await expect(verify({ environment: {} }))
      .rejects.toThrow(/GNUPGHOME must explicitly select/);
  });
});
