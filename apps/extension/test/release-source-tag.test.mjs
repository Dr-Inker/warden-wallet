import { execFile as execFileCallback } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  GIT_GPG_LAUNCHER_MODE,
  GIT_GPG_LAUNCHER_TEXT,
  RELEASE_TAG_MESSAGE_SCHEMA,
  parseAnnotatedTagObject,
  parseSingleOpenPgpSignatureStatus,
  verifyReleaseSourceTag,
} from "../scripts/release-source-tag.mjs";
import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";
import { verifyReviewedArtifactSignature } from "../scripts/reviewed-artifact-signature.mjs";
import { verifyStorePackage } from "../scripts/store-package.mjs";
import {
  createLocalDualReleaseReport,
  releaseComparisonPaths,
  serializeLocalDualReleaseReport,
} from "../../../scripts/local-dual-extension-release.mjs";

const execFile = promisify(execFileCallback);
const GIT = "/usr/bin/git";
const GPG = "/usr/bin/gpg";
const GPG_LAUNCHER_PREFIX = "warden-release-source-gpg-launcher-";
const EXPECTED_RELEASE_TAG_MESSAGE_SCHEMA = "warden.extension-release-tag.v1";
const FIXTURE_VERSION = "1.2.3";
const fixture = {};
const storeDeveloperKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const storePublisherKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const storeDeveloperPublicKey = storeDeveloperKeys.publicKey.export({
  format: "der",
  type: "spki",
});
const storePublisherPublicKey = storePublisherKeys.publicKey.export({
  format: "der",
  type: "spki",
});

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

function releaseTagMessage(artifactManifestSha256) {
  return [
    EXPECTED_RELEASE_TAG_MESSAGE_SCHEMA,
    `artifact-manifest-sha256 ${artifactManifestSha256}`,
  ].join("\n");
}

function protobufVarint(value) {
  const bytes = [];
  let remaining = BigInt(value);
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining !== 0n) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (remaining !== 0n);
  return Buffer.from(bytes);
}

function protobufBytes(fieldNumber, bytes) {
  return Buffer.concat([
    protobufVarint(fieldNumber * 8 + 2),
    protobufVarint(bytes.length),
    bytes,
  ]);
}

function crxProofBytes(publicKey, signature) {
  return Buffer.concat([
    protobufBytes(1, publicKey),
    protobufBytes(2, signature),
  ]);
}

function storeCrxBytes(archiveBytes, { verifiedContentsBytes } = {}) {
  const crxId = Buffer.from(sha256(storeDeveloperPublicKey), "hex").subarray(0, 16);
  const signedData = protobufBytes(1, crxId);
  const signedDataLength = Buffer.alloc(4);
  signedDataLength.writeUInt32LE(signedData.length, 0);
  const signedBytes = Buffer.concat([
    Buffer.from("CRX3 SignedData\0", "utf8"),
    signedDataLength,
    signedData,
    archiveBytes,
  ]);
  const headerFields = [
    protobufBytes(2, crxProofBytes(
      storeDeveloperPublicKey,
      sign("sha256", signedBytes, storeDeveloperKeys.privateKey),
    )),
    protobufBytes(3, crxProofBytes(
      storePublisherPublicKey,
      sign("sha256", signedBytes, storePublisherKeys.privateKey),
    )),
  ];
  if (verifiedContentsBytes !== undefined) {
    headerFields.push(protobufBytes(4, verifiedContentsBytes));
  }
  headerFields.push(protobufBytes(10000, signedData));
  const header = Buffer.concat(headerFields);
  const fixed = Buffer.alloc(12);
  fixed.write("Cr24", 0, "ascii");
  fixed.writeUInt32LE(3, 4);
  fixed.writeUInt32LE(header.length, 8);
  return Buffer.concat([fixed, header, archiveBytes]);
}

const expectedStoreExtensionId = [
  ...Buffer.from(sha256(storeDeveloperPublicKey), "hex").subarray(0, 16),
].map((byte) => String.fromCharCode(97 + (byte >>> 4), 97 + (byte & 0x0f))).join("");
const storePublisherKeySha256 = sha256(storePublisherPublicKey);

function localDualReportBytes(
  sourceGitCommit,
  extensionVersion = FIXTURE_VERSION,
  releaseFiles,
) {
  const files = releaseFiles ?? releaseComparisonPaths(extensionVersion).map((path) => ({
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

function releaseArtifact(
  sourceGitCommit,
  approvalCssBytes = Buffer.from("body { color: #123456; }\n"),
) {
  const extensionManifest = {
    manifest_version: 3,
    name: "Warden signed-source fixture",
    version: FIXTURE_VERSION,
    permissions: ["alarms", "storage"],
    background: { service_worker: "background.js", type: "module" },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'self';",
    },
  };
  const entries = [
    { path: "approval.css", data: approvalCssBytes },
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
  const artifactManifestBytes = Buffer.from(
    serializeArtifactManifest(artifactManifest),
    "utf8",
  );
  return {
    entries,
    archiveBytes,
    artifactManifest,
    artifactManifestBytes,
    releaseFiles: [
      {
        path: `release/warden-extension-${FIXTURE_VERSION}.artifact.json`,
        data: artifactManifestBytes,
      },
      {
        path: `release/warden-extension-${FIXTURE_VERSION}.zip`,
        data: archiveBytes,
      },
      ...Object.values(ARTIFACT_ATTACHMENTS).map((attachment) => ({
        path: `release/${attachment.file}`,
        data: attachment.bytes,
      })),
      ...entries.map((entry) => ({
        path: `release/unpacked/${entry.path}`,
        data: entry.data,
      })),
    ],
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

async function signedTag(
  name,
  message,
  env,
  signingFingerprint = fixture.signingFingerprint,
  targetCommit,
) {
  const arguments_ = [
    "-c",
    `gpg.program=${GPG}`,
    "tag",
    "-s",
    "-u",
    `${signingFingerprint}!`,
    "-m",
    message,
    name,
  ];
  if (targetCommit !== undefined) {
    arguments_.push(targetCommit);
  }
  await git(arguments_, env);
  return (await git(["rev-parse", `refs/tags/${name}`])).stdout.trim();
}

async function detachedArtifactSignature(name, artifactBytes) {
  const artifactPath = join(fixture.root, `${name}.artifact.json`);
  const signaturePath = join(fixture.root, `${name}.artifact.json.sig`);
  await writeFile(artifactPath, artifactBytes);
  await command(GPG, [
    "--no-options",
    "--homedir",
    fixture.gnupgHome,
    "--batch",
    "--yes",
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--local-user",
    `${fixture.signingFingerprint}!`,
    "--detach-sign",
    "--output",
    signaturePath,
    artifactPath,
  ], { env: fixture.environment });
  return {
    artifactPath,
    signaturePath,
    signatureBytes: await readFile(signaturePath),
  };
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
  fixture.reviewedArtifact = releaseArtifact(fixture.firstCommit);
  fixture.differentArtifact = releaseArtifact(
    fixture.firstCommit,
    Buffer.from("body { color: #654321; }\n"),
  );
  const reviewedArtifactSha256 = sha256(
    fixture.reviewedArtifact.artifactManifestBytes,
  );
  const differentArtifactSha256 = sha256(
    fixture.differentArtifact.artifactManifestBytes,
  );
  fixture.releaseTagObject = await signedTag(
    "release-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
  );
  fixture.siblingTagObject = await signedTag(
    "sibling-signing-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
    fixture.siblingSigningFingerprint,
  );
  fixture.primaryTagObject = await signedTag(
    "primary-signing-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
    fixture.fingerprint,
  );
  fixture.differentArtifactTagObject = await signedTag(
    "different-artifact-fixture",
    releaseTagMessage(differentArtifactSha256),
    fixture.environment,
  );
  fixture.unboundArtifactTagObject = await signedTag(
    "unbound-artifact-fixture",
    "fixture valid but artifact-unbound release",
    fixture.environment,
  );
  fixture.wrongArtifactDigestTagObject = await signedTag(
    "wrong-artifact-digest-fixture",
    releaseTagMessage("0".repeat(64)),
    fixture.environment,
  );
  fixture.uppercaseArtifactDigestTagObject = await signedTag(
    "uppercase-artifact-digest-fixture",
    releaseTagMessage(reviewedArtifactSha256.toUpperCase()),
    fixture.environment,
  );
  fixture.duplicateArtifactDigestTagObject = await signedTag(
    "duplicate-artifact-digest-fixture",
    `${releaseTagMessage(reviewedArtifactSha256)}\nartifact-manifest-sha256 ${reviewedArtifactSha256}`,
    fixture.environment,
  );
  fixture.reviewedArtifactSignature = await detachedArtifactSignature(
    "reviewed-release",
    fixture.reviewedArtifact.artifactManifestBytes,
  );
  fixture.reviewedArtifactSignatureBytes =
    fixture.reviewedArtifactSignature.signatureBytes;
  await writeFile(join(fixture.gnupgHome, "gpg.conf"), "digest-algo SHA224\n", {
    mode: 0o600,
  });
  fixture.unapprovedHashTagObject = await signedTag(
    "unapproved-hash-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
  );
  await rm(join(fixture.gnupgHome, "gpg.conf"));
  fixture.movedTagObject = await signedTag(
    "moved-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
  );
  const originalBadObject = await signedTag(
    "bad-signature-fixture",
    releaseTagMessage(reviewedArtifactSha256),
    fixture.environment,
  );
  const originalBadBytes = (await git(["cat-file", "tag", originalBadObject])).stdout;
  const tamperedBytes = originalBadBytes.replace(
    "tagger Warden release fixture",
    "tagger Xarden release fixture",
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
  fixture.secondArtifact = releaseArtifact(fixture.secondCommit);
  fixture.wrongArtifactCommitTagObject = await signedTag(
    "wrong-artifact-commit-fixture",
    releaseTagMessage(sha256(fixture.secondArtifact.artifactManifestBytes)),
    fixture.environment,
    fixture.signingFingerprint,
    fixture.firstCommit,
  );
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
  const hasOwn = (name) => Object.prototype.hasOwnProperty.call(options, name);
  const artifactManifest = hasOwn("artifactManifest")
    ? options.artifactManifest
    : fixture.reviewedArtifact.artifactManifest;
  const artifactManifestBytes = hasOwn("artifactManifestBytes")
    ? options.artifactManifestBytes
    : fixture.reviewedArtifact.artifactManifestBytes;
  const expectedArtifactManifestSha256 = hasOwn("expectedArtifactManifestSha256")
    ? options.expectedArtifactManifestSha256
    : artifactManifestBytes instanceof Uint8Array
      ? sha256(artifactManifestBytes)
      : undefined;
  const forwardedOptions = { ...options };
  delete forwardedOptions.artifactManifest;
  delete forwardedOptions.artifactManifestBytes;
  delete forwardedOptions.expectedArtifactManifestSha256;
  return verifyReleaseSourceTag({
    repositoryRoot: fixture.repository,
    tagName: "release-fixture",
    expectedTagObject: fixture.releaseTagObject,
    expectedPrimaryFingerprint: fixture.fingerprint,
    expectedSigningFingerprint: fixture.signingFingerprint,
    artifactManifest,
    artifactManifestBytes,
    expectedArtifactManifestSha256,
    environment: fixture.environment,
    ...forwardedOptions,
  });
}

describe("release source annotated-tag verification", () => {
  it("requires the authenticated tag message to bind the exact artifact digest", async () => {
    await expect(verify({
      tagName: "unbound-artifact-fixture",
      expectedTagObject: fixture.unboundArtifactTagObject,
    })).rejects.toThrow(
      /annotated tag message must bind the exact artifact manifest SHA-256/,
    );
  });

  it("rejects wrong, uppercase, or duplicated signed artifact identities", async () => {
    await expect(verify({
      tagName: "wrong-artifact-digest-fixture",
      expectedTagObject: fixture.wrongArtifactDigestTagObject,
    })).rejects.toThrow(
      /annotated tag message artifact manifest SHA-256 differs from the exact artifact/,
    );
    for (const [tagName, expectedTagObject] of [
      ["uppercase-artifact-digest-fixture", fixture.uppercaseArtifactDigestTagObject],
      ["duplicate-artifact-digest-fixture", fixture.duplicateArtifactDigestTagObject],
    ]) {
      await expect(verify({ tagName, expectedTagObject })).rejects.toThrow(
        /annotated tag message must bind the exact artifact manifest SHA-256/,
      );
    }
  });

  it("requires exact artifact bytes and an independent digest in the shared verifier", async () => {
    await expect(verify({
      artifactManifestBytes: undefined,
      expectedArtifactManifestSha256: undefined,
    })).rejects.toThrow(
      /exact artifact manifest bytes and independently supplied SHA-256 are required/,
    );
    await expect(verify({
      artifactManifestBytes: fixture.reviewedArtifact.artifactManifestBytes,
      expectedArtifactManifestSha256: sha256(
        fixture.reviewedArtifact.artifactManifestBytes,
      ).toUpperCase(),
      environment: {},
    })).rejects.toThrow(/expected artifact manifest SHA-256 must be a lowercase digest/);
    await expect(verify({
      artifactManifestBytes: fixture.reviewedArtifact.artifactManifestBytes,
      expectedArtifactManifestSha256: "0".repeat(64),
      environment: {},
    })).rejects.toThrow(/artifact manifest differs from the independently supplied SHA-256/);
    await expect(verify({
      artifactManifest: fixture.differentArtifact.artifactManifest,
      artifactManifestBytes: fixture.reviewedArtifact.artifactManifestBytes,
      expectedArtifactManifestSha256: sha256(
        fixture.reviewedArtifact.artifactManifestBytes,
      ),
      environment: {},
    })).rejects.toThrow(/supplied artifact manifest differs from the exact artifact manifest bytes/);
  });

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
      artifactManifestSha256: sha256(
        fixture.reviewedArtifact.artifactManifestBytes,
      ),
      signedArtifactManifestSha256: sha256(
        fixture.reviewedArtifact.artifactManifestBytes,
      ),
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

  it("WRDF-0129 reads the selected tag object with replacement processing disabled", async () => {
    await git(["update-ref", "-d", "refs/tags/release-fixture", fixture.releaseTagObject]);
    const replacementObject = await signedTag(
      "release-fixture",
      releaseTagMessage(sha256(fixture.reviewedArtifact.artifactManifestBytes)),
      { ...process.env, GNUPGHOME: fixture.gnupgHome },
      fixture.siblingSigningFingerprint,
      fixture.firstCommit,
    );
    await git([
      "update-ref",
      "refs/tags/release-fixture",
      fixture.releaseTagObject,
      replacementObject,
    ]);
    await git(["replace", fixture.releaseTagObject, replacementObject]);

    let result;
    try {
      result = await verify();
    } finally {
      await git(["replace", "-d", fixture.releaseTagObject]);
    }
    expect(result.tagObject).toBe(fixture.releaseTagObject);
    expect(result.signingFingerprint).toBe(fixture.signingFingerprint);
  });

  it("rejects a separately valid dual report for a different source commit", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(fixture.secondCommit);
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/dual release report source differs from the artifact source commit/);
  });

  it("binds the signed source to an independently digested canonical dual report", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      artifact.releaseFiles,
    );
    const expectedDualReleaseReportSha256 = sha256(dualReleaseReportBytes);
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256,
    })).resolves.toMatchObject({
      sourceCommit: fixture.firstCommit,
      dualReleaseReport: {
        sha256: expectedDualReleaseReportSha256,
        sourceCommit: fixture.firstCommit,
        extensionVersion: FIXTURE_VERSION,
        comparisonFileCount: 14,
        artifactManifestSha256: sha256(artifact.artifactManifestBytes),
        boundReleaseFileCount: 14,
        scope: {
          checkoutModel: "same-host-sequential-local-shared-object-clones",
          dependencyStoreModel: "shared-readonly-pnpm-content-addressed-store",
          independentBuilderClaim: "not-asserted",
          signedTagClaim: "not-asserted",
        },
      },
    });
  });

  it("rejects a separately valid artifact review for different exact release outputs", async () => {
    await expect(verifyReviewedArtifactSignature({
      artifactBytes: fixture.reviewedArtifact.artifactManifestBytes,
      signatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedPrimaryFingerprint: fixture.fingerprint,
      expectedSigningFingerprint: fixture.signingFingerprint,
      environment: fixture.environment,
    })).resolves.toMatchObject({
      artifactSha256: sha256(fixture.reviewedArtifact.artifactManifestBytes),
    });
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.differentArtifact.releaseFiles,
    );
    await expect(verify({
      tagName: "different-artifact-fixture",
      expectedTagObject: fixture.differentArtifactTagObject,
      ...fixture.differentArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
    })).rejects.toThrow(/reviewed artifact|artifact review|signature/);
  });

  it("authenticates one exact artifact buffer through review, source, and output binding", async () => {
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    const expectedArtifactReviewSignatureSha256 = sha256(
      fixture.reviewedArtifactSignatureBytes,
    );
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256,
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
    })).resolves.toMatchObject({
      sourceCommit: fixture.firstCommit,
      artifactReview: {
        artifactSha256: sha256(fixture.reviewedArtifact.artifactManifestBytes),
        signatureSha256: expectedArtifactReviewSignatureSha256,
        primaryFingerprint: fixture.fingerprint,
        signingFingerprint: fixture.signingFingerprint,
      },
      dualReleaseReport: {
        artifactManifestSha256: sha256(
          fixture.reviewedArtifact.artifactManifestBytes,
        ),
        boundReleaseFileCount: 14,
      },
    });
  });

  it("rejects a separately valid store package for different exact reviewed outputs", async () => {
    const differentCrxBytes = storeCrxBytes(fixture.differentArtifact.archiveBytes);
    expect(verifyStorePackage({
      crxBytes: differentCrxBytes,
      artifactManifest: fixture.differentArtifact.artifactManifest,
      expectedExtensionId: expectedStoreExtensionId,
      requiredPublisherKeySha256: storePublisherKeySha256,
    })).toMatchObject({
      extensionId: expectedStoreExtensionId,
      treeSha256: fixture.differentArtifact.artifactManifest.payload.treeSha256,
    });
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
      reviewedUploadArchiveBytes: fixture.differentArtifact.archiveBytes,
      storePackageBytes: differentCrxBytes,
      expectedStorePackageSha256: sha256(differentCrxBytes),
      expectedStoreExtensionId,
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    })).rejects.toThrow(/store|reviewed upload|archive|payload/);
  });

  it("rejects a separately valid store package with a different exact CRX digest", async () => {
    const approvedCrxBytes = storeCrxBytes(fixture.reviewedArtifact.archiveBytes);
    const differentCrxBytes = storeCrxBytes(
      fixture.reviewedArtifact.archiveBytes,
      { verifiedContentsBytes: Buffer.from("different valid CRX3 header bytes\n") },
    );
    expect(sha256(differentCrxBytes)).not.toBe(sha256(approvedCrxBytes));
    for (const crxBytes of [approvedCrxBytes, differentCrxBytes]) {
      expect(verifyStorePackage({
        crxBytes,
        artifactManifest: fixture.reviewedArtifact.artifactManifest,
        expectedExtensionId: expectedStoreExtensionId,
        requiredPublisherKeySha256: storePublisherKeySha256,
      })).toMatchObject({
        extensionId: expectedStoreExtensionId,
        treeSha256: fixture.reviewedArtifact.artifactManifest.payload.treeSha256,
      });
    }
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes: differentCrxBytes,
      expectedStorePackageSha256: sha256(approvedCrxBytes),
      expectedStoreExtensionId,
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    })).rejects.toThrow(/store package differs from the independently supplied SHA-256/);
  });

  it("authenticates one reviewed upload and its store-returned CRX3 package", async () => {
    const storePackageBytes = storeCrxBytes(fixture.reviewedArtifact.archiveBytes);
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes,
      expectedStorePackageSha256: sha256(storePackageBytes),
      expectedStoreExtensionId,
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    })).resolves.toMatchObject({
      sourceCommit: fixture.firstCommit,
      storePackage: {
        artifactManifestSha256: sha256(
          fixture.reviewedArtifact.artifactManifestBytes,
        ),
        reviewedUploadArchiveSha256: sha256(
          fixture.reviewedArtifact.archiveBytes,
        ),
        packageBytes: storePackageBytes.length,
        packageSha256: sha256(storePackageBytes),
        embeddedArchiveBytes: fixture.reviewedArtifact.archiveBytes.length,
        embeddedArchiveSha256: sha256(fixture.reviewedArtifact.archiveBytes),
        extensionId: expectedStoreExtensionId,
        publisherKeySha256: storePublisherKeySha256,
        files: fixture.reviewedArtifact.entries.length,
        treeSha256: fixture.reviewedArtifact.artifactManifest.payload.treeSha256,
      },
    });
  });

  it("requires an atomic store tuple, an artifact review, and independent digest/id", async () => {
    const storePackageBytes = storeCrxBytes(fixture.reviewedArtifact.archiveBytes);
    await expect(verify({
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
    })).rejects.toThrow(/must be provided together/);
    await expect(verify({
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes,
      expectedStoreExtensionId,
    })).rejects.toThrow(/must be provided together/);
    await expect(verify({
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes,
      expectedStorePackageSha256: sha256(storePackageBytes),
      expectedStoreExtensionId,
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    })).rejects.toThrow(/requires the exact artifact review binding/);

    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes,
      expectedStorePackageSha256: sha256(storePackageBytes),
      expectedStoreExtensionId: "a".repeat(32),
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    })).rejects.toThrow(/extension id differs/);
  });

  it("checks the independent store-package digest before candidate parsing", async () => {
    const storePackageBytes = Buffer.from("not a CRX3 package\n");
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    const options = {
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
      reviewedUploadArchiveBytes: fixture.reviewedArtifact.archiveBytes,
      storePackageBytes,
      expectedStorePackageSha256: "0".repeat(64),
      expectedStoreExtensionId,
      requiredStorePublisherKeySha256: storePublisherKeySha256,
    };
    await expect(verify(options)).rejects.toThrow(
      /store package differs from the independently supplied SHA-256/,
    );
    await expect(verify({
      ...options,
      expectedStorePackageSha256: sha256(storePackageBytes),
    })).rejects.toThrow(/store package verification failed.*CRX3/);
  });

  it("checks the independent review-signature digest before candidate use", async () => {
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      fixture.reviewedArtifact.releaseFiles,
    );
    const options = {
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: Buffer.from("not an OpenPGP signature\n"),
      expectedArtifactReviewSignatureSha256: "0".repeat(64),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
    };
    await expect(verify(options)).rejects.toThrow(
      /artifact review signature differs from the independently supplied SHA-256/,
    );
    await expect(verify({
      ...options,
      expectedArtifactReviewSignatureSha256: sha256(
        options.artifactReviewSignatureBytes,
      ),
    })).rejects.toThrow(/NODATA|signature|status/);
    await expect(verify({
      ...fixture.reviewedArtifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
    })).rejects.toThrow(/must be provided together/);
    await expect(verify({
      ...fixture.reviewedArtifact,
      artifactReviewSignatureBytes: fixture.reviewedArtifactSignatureBytes,
      expectedArtifactReviewSignatureSha256: sha256(
        fixture.reviewedArtifactSignatureBytes,
      ),
      expectedArtifactReviewPrimaryFingerprint: fixture.fingerprint,
      expectedArtifactReviewSigningFingerprint: fixture.signingFingerprint,
    })).rejects.toThrow(/requires the exact dual release report binding/);
  });

  it("rejects a report whose fourteen records do not describe the selected artifact", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const mismatchedFiles = artifact.releaseFiles.map((file) => ({
      path: file.path,
      data: file.path.endsWith(".artifact.json")
        ? Buffer.concat([file.data, Buffer.from(" ")])
        : file.data,
    }));
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      mismatchedFiles,
    );
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/dual release report artifact manifest record differs/);
  });

  it("rejects archive, evidence-sidecar, and unpacked-payload record drift", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const cases = [
      [`release/warden-extension-${FIXTURE_VERSION}.zip`, /archive record differs/],
      [
        `release/warden-extension-${FIXTURE_VERSION}.bundle-inputs.json`,
        /bundle input evidence record differs/,
      ],
      ["release/unpacked/background.js", /unpacked payload background.js record differs/],
    ];
    for (const [path, expectedError] of cases) {
      const mismatchedFiles = artifact.releaseFiles.map((file) => {
        if (file.path !== path) {
          return file;
        }
        const data = Buffer.from(file.data);
        data[0] ^= 1;
        return { path: file.path, data };
      });
      const dualReleaseReportBytes = localDualReportBytes(
        fixture.firstCommit,
        FIXTURE_VERSION,
        mismatchedFiles,
      );
      await expect(verify({
        ...artifact,
        dualReleaseReportBytes,
        expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
      })).rejects.toThrow(expectedError);
    }
  });

  it("checks the independent report digest before parsing candidate bytes", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = Buffer.from("not canonical report JSON\n");
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: "0".repeat(64),
    })).rejects.toThrow(/differs from the independently supplied SHA-256/);
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/not valid JSON/);
    await expect(verify({ dualReleaseReportBytes }))
      .rejects.toThrow(/must be provided together/);
    await expect(verify({ expectedDualReleaseReportSha256: "0".repeat(64) }))
      .rejects.toThrow(/must be provided together/);
    const canonicalReportBytes = localDualReportBytes(fixture.firstCommit);
    await expect(verify({
      artifactManifestBytes: undefined,
      expectedArtifactManifestSha256: undefined,
      dualReleaseReportBytes: canonicalReportBytes,
      expectedDualReleaseReportSha256: sha256(canonicalReportBytes),
    })).rejects.toThrow(
      /exact artifact manifest bytes and independently supplied SHA-256 are required/,
    );
  });

  it("requires canonical exact artifact bytes before comparing report records", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      artifact.releaseFiles,
    );
    await expect(verify({
      ...artifact,
      artifactManifestBytes: Buffer.concat([
        artifact.artifactManifestBytes,
        Buffer.from(" "),
      ]),
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/canonical generated JSON serialization/);
  });

  it("rejects a canonical dual report for a different extension version", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(fixture.firstCommit, "9.8.7");
    await expect(verify({
      ...artifact,
      dualReleaseReportBytes,
      expectedDualReleaseReportSha256: sha256(dualReleaseReportBytes),
    })).rejects.toThrow(/extension version differs/);
  });

  it("retains key, subkey, and signature refusal after binding the report", async () => {
    const artifact = releaseArtifact(fixture.firstCommit);
    const dualReleaseReportBytes = localDualReportBytes(
      fixture.firstCommit,
      FIXTURE_VERSION,
      artifact.releaseFiles,
    );
    const reportOptions = {
      ...artifact,
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
      ...releaseArtifact(fixture.secondCommit),
    })).rejects.toThrow(/annotated tag object/);
    await expect(verify({
      tagName: "moved-fixture",
      expectedTagObject: fixture.movedTagObject,
    })).rejects.toThrow(/moved or differs/);
    await expect(verify({
      tagName: "wrong-artifact-commit-fixture",
      expectedTagObject: fixture.wrongArtifactCommitTagObject,
      ...fixture.secondArtifact,
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
    const artifactManifestSha256 = "b".repeat(64);
    const headers = [
      `object ${commit}`,
      "type commit",
      "tag release-fixture",
      "tagger Fixture <fixture@example.invalid> 1788220800 +0000",
    ];
    const body = `${releaseTagMessage(artifactManifestSha256)}\n-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n`;
    expect(parseAnnotatedTagObject(
      `${headers.join("\n")}\n\n${body}`,
      "release-fixture",
      artifactManifestSha256,
    )).toEqual({
      targetCommit: commit,
      signedArtifactManifestSha256: artifactManifestSha256,
    });
    expect(RELEASE_TAG_MESSAGE_SCHEMA).toBe(EXPECTED_RELEASE_TAG_MESSAGE_SCHEMA);
    expect(() => parseAnnotatedTagObject(
      `${headers[0]}\nobject ${"b".repeat(40)}\n${headers.slice(1).join("\n")}\n\n${body}`,
      "release-fixture",
      artifactManifestSha256,
    )).toThrow(/duplicate object headers/);
    expect(() => parseAnnotatedTagObject(
      `${headers.join("\n").replace("type commit", "type tag")}\n\n${body}`,
      "release-fixture",
      artifactManifestSha256,
    )).toThrow(/point directly to a commit/);
    for (const message of [
      `prefix\n${releaseTagMessage(artifactManifestSha256)}`,
      `${releaseTagMessage(artifactManifestSha256)}\nsuffix`,
    ]) {
      expect(() => parseAnnotatedTagObject(
        `${headers.join("\n")}\n\n${message}\n-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n`,
        "release-fixture",
        artifactManifestSha256,
      )).toThrow(/annotated tag message must bind the exact artifact manifest SHA-256/);
    }
    expect(() => parseAnnotatedTagObject(
      `${headers.join("\n")}\n\n${body}suffix\n`,
      "release-fixture",
      artifactManifestSha256,
    )).toThrow(/annotated tag message must bind the exact artifact manifest SHA-256/);
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
