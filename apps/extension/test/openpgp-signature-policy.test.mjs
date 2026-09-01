import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  OPENPGP_RELEASE_SIGNATURE_POLICY,
  parseSingleOpenPgpSignatureStatus as parseOpenPgpStatus,
} from "../scripts/release-source-tag.mjs";

const execFile = promisify(execFileCallback);
const GPG = "/usr/bin/gpg";
const fixture = {};
const DEFAULT_SIGNING_FINGERPRINT = `${"B".repeat(24)}${"C".repeat(16)}`;

function parseStatus(
  statusText,
  expectedPrimaryFingerprint,
  expectedSigningFingerprint = DEFAULT_SIGNING_FINGERPRINT,
) {
  return parseOpenPgpStatus(
    statusText,
    expectedPrimaryFingerprint,
    expectedSigningFingerprint,
  );
}

function statusLine({
  primary = "A".repeat(40),
  signing = DEFAULT_SIGNING_FINGERPRINT,
  goodSignatureIdentity = "C".repeat(16),
  signatureVersion = "4",
  reserved = "0",
  publicKeyAlgorithm = "22",
  hashAlgorithm = "8",
  signatureClass = "00",
  primaryField = primary,
  trailingArguments = [],
} = {}) {
  return [
    "[GNUPG:] NEWSIG",
    `[GNUPG:] GOODSIG ${goodSignatureIdentity} Warden%20fixture`,
    [
      "[GNUPG:] VALIDSIG",
      signing,
      "2026-09-01",
      "1788220800",
      "0",
      signatureVersion,
      reserved,
      publicKeyAlgorithm,
      hashAlgorithm,
      signatureClass,
      primaryField,
      ...trailingArguments,
    ].join(" "),
    "",
  ].join("\n");
}

async function gpg(home, arguments_) {
  return execFile(GPG, ["--no-options", "--homedir", home, ...arguments_], {
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", GNUPGHOME: home },
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
  });
}

async function exerciseInstalledAlgorithm({ name, generator, expectedAlgorithm }) {
  const home = join(fixture.root, `gnupg-${name}`);
  await mkdir(home, { mode: 0o700 });
  const userId = `Warden ${name} signature policy <${name}@example.invalid>`;
  await gpg(home, [
    "--batch",
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--quick-generate-key",
    userId,
    generator,
    "sign",
    "0",
  ]);
  const keys = await gpg(home, ["--batch", "--with-colons", "--list-secret-keys", userId]);
  const records = keys.stdout.split("\n").map((line) => line.split(":"));
  const secretKey = records.findIndex((fields) => fields[0] === "sec");
  const fingerprint = records.slice(secretKey + 1)
    .find((fields) => fields[0] === "fpr")?.[9];
  if (!/^[0-9A-F]{40}(?:[0-9A-F]{24})?$/.test(fingerprint ?? "")) {
    throw new Error(`failed to read the ${name} fixture fingerprint`);
  }
  const dataPath = join(fixture.root, `${name}.artifact`);
  const signaturePath = join(fixture.root, `${name}.artifact.sig`);
  await writeFile(dataPath, Buffer.from(`Warden ${name} policy fixture\n`));
  await gpg(home, [
    "--batch",
    "--yes",
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--local-user",
    fingerprint,
    "--digest-algo",
    "SHA256",
    "--detach-sign",
    "--output",
    signaturePath,
    dataPath,
  ]);
  const verification = await gpg(home, [
    "--batch",
    "--no-tty",
    "--status-fd=1",
    "--verify",
    signaturePath,
    dataPath,
  ]);
  expect(verification.stderr).toContain("Good signature");
  expect(parseStatus(verification.stdout, fingerprint, fingerprint)).toMatchObject({
    primaryFingerprint: fingerprint,
    signatureVersion: 4,
    publicKeyAlgorithm: expectedAlgorithm,
    hashAlgorithm: 8,
    signatureClass: "00",
  });
}

beforeAll(async () => {
  fixture.root = await mkdtemp(join(tmpdir(), "warden-openpgp-signature-policy-test-"));
});

afterAll(async () => {
  if (fixture.root) {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

describe("shared OpenPGP release signature policy", () => {
  it("pins the reviewed algorithm and binary-document allowlists", () => {
    expect(OPENPGP_RELEASE_SIGNATURE_POLICY).toEqual({
      signatureVersions: [4, 6],
      publicKeyAlgorithms: [1, 19, 22, 27, 28],
      hashAlgorithms: [8, 9, 10],
      signatureClass: "00",
    });
    expect(Object.isFrozen(OPENPGP_RELEASE_SIGNATURE_POLICY)).toBe(true);
    expect(Object.isFrozen(OPENPGP_RELEASE_SIGNATURE_POLICY.signatureVersions)).toBe(true);
    expect(Object.isFrozen(OPENPGP_RELEASE_SIGNATURE_POLICY.publicKeyAlgorithms)).toBe(true);
    expect(Object.isFrozen(OPENPGP_RELEASE_SIGNATURE_POLICY.hashAlgorithms)).toBe(true);
  });

  it("accepts every explicitly approved public-key and SHA-2 algorithm id", () => {
    const primary = "A".repeat(40);
    for (const publicKeyAlgorithm of OPENPGP_RELEASE_SIGNATURE_POLICY.publicKeyAlgorithms) {
      for (const hashAlgorithm of OPENPGP_RELEASE_SIGNATURE_POLICY.hashAlgorithms) {
        expect(parseStatus(statusLine({
          primary,
          publicKeyAlgorithm: String(publicKeyAlgorithm),
          hashAlgorithm: String(hashAlgorithm),
        }), primary)).toMatchObject({
          publicKeyAlgorithm,
          hashAlgorithm,
          signatureClass: "00",
        });
      }
    }
  });

  it("rejects weak, deprecated-unapproved, encryption-only, unknown, or malformed ids", () => {
    const primary = "A".repeat(40);
    for (const publicKeyAlgorithm of ["0", "2", "3", "17", "18", "20", "29", "255"]) {
      expect(() => parseStatus(
        statusLine({ primary, publicKeyAlgorithm }),
        primary,
      )).toThrow(/public-key algorithm .*not allowed/);
    }
    for (const hashAlgorithm of ["0", "1", "2", "3", "11", "12", "14", "255"]) {
      expect(() => parseStatus(
        statusLine({ primary, hashAlgorithm }),
        primary,
      )).toThrow(/hash algorithm .*not allowed/);
    }
    for (const publicKeyAlgorithm of ["01", "-1", "256", "1x"]) {
      expect(() => parseStatus(
        statusLine({ primary, publicKeyAlgorithm }),
        primary,
      )).toThrow(/canonical decimal octet/);
    }
  });

  it("requires an exact binary-document signature class and exact OpenPGP status shape", () => {
    const primary = "A".repeat(40);
    for (const signatureClass of ["01", "02", "10", "FF"]) {
      expect(() => parseStatus(
        statusLine({ primary, signatureClass }),
        primary,
      )).toThrow(/signature class .*not allowed/);
    }
    for (const signatureClass of ["0", "000", "GG"]) {
      expect(() => parseStatus(
        statusLine({ primary, signatureClass }),
        primary,
      )).toThrow(/exactly one hexadecimal octet/);
    }
    expect(() => parseStatus(
      statusLine({ primary, reserved: "1" }),
      primary,
    )).toThrow(/reserved field must be zero/);
    for (const signatureVersion of ["0", "3", "5", "7", "255"]) {
      expect(() => parseStatus(
        statusLine({ primary, signatureVersion }),
        primary,
      )).toThrow(/signature version .*not allowed/);
    }
    expect(() => parseStatus(
      statusLine({ primary, signatureVersion: "04" }),
      primary,
    )).toThrow(/signature version must be a canonical decimal octet/);
    expect(() => parseStatus(
      statusLine({ primary, primaryField: "" }),
      primary,
    )).toThrow(/exactly ten arguments/);
    expect(() => parseStatus(
      statusLine({ primary, trailingArguments: ["unexpected"] }),
      primary,
    )).toThrow(/exactly ten arguments/);
  });

  it("matches v4 and v6 key ids at the correct fingerprint end", () => {
    const v4Signing = `${"A".repeat(24)}${"B".repeat(16)}`;
    expect(parseStatus(statusLine({
      primary: v4Signing,
      signing: v4Signing,
      goodSignatureIdentity: "B".repeat(16),
    }), v4Signing, v4Signing)).toMatchObject({ signingFingerprint: v4Signing });

    const v6Signing = `${"C".repeat(16)}${"D".repeat(48)}`;
    expect(parseStatus(statusLine({
      primary: v6Signing,
      signing: v6Signing,
      goodSignatureIdentity: "C".repeat(16),
      signatureVersion: "6",
      publicKeyAlgorithm: "27",
    }), v6Signing, v6Signing)).toMatchObject({
      signingFingerprint: v6Signing,
      signatureVersion: 6,
      publicKeyAlgorithm: 27,
    });
    expect(() => parseStatus(statusLine({
      primary: v6Signing,
      signing: v6Signing,
      goodSignatureIdentity: "D".repeat(16),
      signatureVersion: "6",
      publicKeyAlgorithm: "27",
    }), v6Signing, v6Signing)).toThrow(/GOODSIG identity differs/);
  });

  it("requires independent exact primary and signing fingerprints", () => {
    const primary = "A".repeat(40);
    const signing = DEFAULT_SIGNING_FINGERPRINT;
    const status = statusLine({ primary, signing });
    expect(parseStatus(status, primary, signing)).toMatchObject({
      signingFingerprint: signing,
      primaryFingerprint: primary,
    });
    expect(() => parseStatus(status, primary, "D".repeat(40)))
      .toThrow(/signing fingerprint differs from the independently supplied signing key/);
    expect(() => parseStatus(status, "D".repeat(40), signing))
      .toThrow(/primary fingerprint differs from the independently supplied primary key/);
    expect(() => parseStatus(status, primary, signing.slice(0, 16)))
      .toThrow(/expected signing fingerprint must be a 40- or 64-character/);
    expect(() => parseStatus(status, "not-a-fingerprint", signing))
      .toThrow(/expected primary fingerprint must be a 40- or 64-character/);
  });

  it("observes the approved RSA, ECDSA, and installed EdDSA ids from real signatures", async () => {
    for (const algorithm of [
      { name: "rsa", generator: "rsa2048", expectedAlgorithm: 1 },
      { name: "ecdsa", generator: "nistp256", expectedAlgorithm: 19 },
      { name: "eddsa", generator: "ed25519", expectedAlgorithm: 22 },
    ]) {
      await exerciseInstalledAlgorithm(algorithm);
    }
  }, 30_000);
});
