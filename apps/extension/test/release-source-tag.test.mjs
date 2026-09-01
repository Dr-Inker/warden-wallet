import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  parseAnnotatedTagObject,
  parseGitVerifyTagStatus,
  verifyReleaseSourceTag,
} from "../scripts/release-source-tag.mjs";

const execFile = promisify(execFileCallback);
const GIT = "/usr/bin/git";
const GPG = "/usr/bin/gpg";
const fixture = {};

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

async function signedTag(name, message, env) {
  await git([
    "-c",
    `gpg.program=${GPG}`,
    "tag",
    "-s",
    "-u",
    fixture.fingerprint,
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
  await mkdir(fixture.repository, { mode: 0o700 });
  await mkdir(fixture.gnupgHome, { mode: 0o700 });
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
    fixture.fingerprint,
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

function verify(options = {}) {
  return verifyReleaseSourceTag({
    repositoryRoot: fixture.repository,
    tagName: "release-fixture",
    expectedTagObject: fixture.releaseTagObject,
    expectedSignerFingerprint: fixture.fingerprint,
    artifactManifest: { source: { gitCommit: fixture.firstCommit } },
    environment: fixture.environment,
    ...options,
  });
}

describe("release source annotated-tag verification", () => {
  it("binds an exact annotated tag object, artifact commit, and primary fingerprint", async () => {
    await expect(verify()).resolves.toEqual({
      tagName: "release-fixture",
      tagRef: "refs/tags/release-fixture",
      tagObject: fixture.releaseTagObject,
      sourceCommit: fixture.firstCommit,
      signingFingerprint: fixture.fingerprint,
      primaryFingerprint: fixture.fingerprint,
    });
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

  it("rejects a bad signature and an independently supplied wrong signer", async () => {
    await expect(verify({
      tagName: "bad-signature-fixture",
      expectedTagObject: fixture.badTagObject,
    })).rejects.toThrow(/BADSIG|signature/);
    await expect(verify({
      expectedSignerFingerprint: "0".repeat(40),
    })).rejects.toThrow(/differs from the independently supplied signer/);
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
    expect(parseGitVerifyTagStatus(validStatus, primary)).toEqual({
      signingFingerprint: signing,
      primaryFingerprint: primary,
    });
    expect(() => parseGitVerifyTagStatus(
      validStatus.replace("[GNUPG:] TRUST_UNDEFINED", "[GNUPG:] NEWSIG\n[GNUPG:] TRUST_UNDEFINED"),
      primary,
    )).toThrow(/exactly one signature/);
    expect(() => parseGitVerifyTagStatus(
      validStatus.replace("[GNUPG:] GOODSIG", "[GNUPG:] EXPKEYSIG"),
      primary,
    )).toThrow(/EXPKEYSIG/);
    expect(() => parseGitVerifyTagStatus(
      validStatus.replace(
        "[GNUPG:] TRUST_UNDEFINED",
        `[GNUPG:] VALIDSIG ${signing} 2026-09-01 1788220800 0 4 0 22 8 00 ${primary}\n[GNUPG:] TRUST_UNDEFINED`,
      ),
      primary,
    )).toThrow(/exactly one cryptographic VALIDSIG/);
    expect(() => parseGitVerifyTagStatus(
      validStatus.replace(
        `[GNUPG:] GOODSIG ${"C".repeat(16)} Warden%20fixture`,
        `[GNUPG:] ERRSIG ${"C".repeat(16)} 22 8 00 1788220800 9 ${signing}\n[GNUPG:] NO_PUBKEY ${"C".repeat(16)}`,
      ),
      primary,
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
