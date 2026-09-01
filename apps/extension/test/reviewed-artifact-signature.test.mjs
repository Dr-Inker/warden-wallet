import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  MAX_DETACHED_SIGNATURE_BYTES,
  MAX_REVIEWED_ARTIFACT_BYTES,
  verifyReviewedArtifactSignature,
} from "../scripts/reviewed-artifact-signature.mjs";
import {
  createArtifactManifest,
  createCanonicalZip,
  serializeArtifactManifest,
} from "../scripts/release-artifact.mjs";

const execFile = promisify(execFileCallback);
const GPG = "/usr/bin/gpg";
const fixture = {};
const testDirectory = dirname(fileURLToPath(import.meta.url));
const verifierCli = join(testDirectory, "../scripts/verify-reviewed-artifact-signature.mjs");

const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden reviewed artifact signature fixture",
  version: "1.2.3",
  permissions: ["storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function gpg(arguments_, homedir = fixture.gnupgHome) {
  return execFile(GPG, ["--no-options", "--homedir", homedir, ...arguments_], {
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", GNUPGHOME: homedir },
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
  });
}

beforeAll(async () => {
  fixture.root = await mkdtemp(join(tmpdir(), "warden-reviewed-artifact-signature-test-"));
  fixture.gnupgHome = join(fixture.root, "gnupg");
  fixture.emptyGnuPgHome = join(fixture.root, "empty-gnupg");
  await mkdir(fixture.gnupgHome, { mode: 0o700 });
  await mkdir(fixture.emptyGnuPgHome, { mode: 0o700 });
  await gpg([
    "--batch",
    "--pinentry-mode",
    "loopback",
    "--passphrase",
    "",
    "--quick-generate-key",
    "Warden artifact review fixture <artifact-review@example.invalid>",
    "ed25519",
    "sign",
    "0",
  ]);
  const keys = await gpg(["--batch", "--with-colons", "--list-secret-keys"]);
  const lines = keys.stdout.split("\n").map((line) => line.split(":"));
  const secretKeyIndex = lines.findIndex((fields) => fields[0] === "sec");
  fixture.fingerprint = lines.slice(secretKeyIndex + 1)
    .find((fields) => fields[0] === "fpr")?.[9];
  if (!/^[0-9A-F]{40}(?:[0-9A-F]{24})?$/.test(fixture.fingerprint ?? "")) {
    throw new Error("failed to create an ephemeral artifact-review fingerprint");
  }
  const entries = [
    { path: "background.js", data: Buffer.from("globalThis.background = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(MANIFEST, null, 2)}\n`) },
  ];
  const archiveBytes = createCanonicalZip(entries);
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: {
      gitCommit: "a".repeat(40),
      lockfileSha256: "b".repeat(64),
    },
    toolchain: { node: "22.23.2", pnpm: "11.12.0", esbuild: "0.28.2" },
    dependencyEvidence: {
      file: "warden-extension-1.2.3.sbom.json",
      bytes: Buffer.from("dependency fixture\n"),
    },
    bundleInputEvidence: {
      file: "warden-extension-1.2.3.bundle-inputs.json",
      bytes: Buffer.from("bundle fixture\n"),
    },
    staticInputEvidence: {
      file: "warden-extension-1.2.3.static-inputs.json",
      bytes: Buffer.from("static fixture\n"),
    },
    releaseRecipeInputEvidence: {
      file: "warden-extension-1.2.3.recipe-inputs.json",
      bytes: Buffer.from("recipe fixture\n"),
    },
  });
  fixture.artifactBytes = Buffer.from(serializeArtifactManifest(artifactManifest));
  fixture.artifactPath = join(fixture.root, "reviewed-artifact.json");
  const firstSignaturePath = join(fixture.root, "reviewed-artifact.json.sig");
  const secondSignaturePath = join(fixture.root, "reviewed-artifact.second.sig");
  await writeFile(fixture.artifactPath, fixture.artifactBytes);
  for (const signaturePath of [firstSignaturePath, secondSignaturePath]) {
    await gpg([
      "--batch",
      "--yes",
      "--pinentry-mode",
      "loopback",
      "--passphrase",
      "",
      "--local-user",
      fixture.fingerprint,
      "--detach-sign",
      "--output",
      signaturePath,
      fixture.artifactPath,
    ]);
  }
  fixture.signatureBytes = await readFile(firstSignaturePath);
  fixture.signaturePath = firstSignaturePath;
  fixture.secondSignatureBytes = await readFile(secondSignaturePath);
  fixture.environment = { ...process.env, GNUPGHOME: fixture.gnupgHome };
  await writeFile(
    join(fixture.gnupgHome, "gpg.conf"),
    "auto-key-retrieve\nauto-key-import\n",
    { mode: 0o600 },
  );
}, 20_000);

afterAll(async () => {
  if (fixture.root) {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

function verify(options = {}) {
  return verifyReviewedArtifactSignature({
    artifactBytes: fixture.artifactBytes,
    signatureBytes: fixture.signatureBytes,
    expectedSignerFingerprint: fixture.fingerprint,
    environment: fixture.environment,
    ...options,
  });
}

describe("reviewed artifact detached-signature verification", () => {
  it("authenticates the exact artifact bytes and full primary fingerprint", async () => {
    await expect(verify()).resolves.toEqual({
      artifactBytes: fixture.artifactBytes.length,
      artifactSha256: sha256(fixture.artifactBytes),
      signatureBytes: fixture.signatureBytes.length,
      signatureSha256: sha256(fixture.signatureBytes),
      signingFingerprint: fixture.fingerprint,
      primaryFingerprint: fixture.fingerprint,
    });
  });

  it("runs the production CLI over the same authenticated canonical bytes", async () => {
    const result = await execFile(process.execPath, [
      verifierCli,
      fixture.artifactPath,
      fixture.signaturePath,
      fixture.fingerprint,
    ], {
      env: fixture.environment,
      encoding: "utf8",
      maxBuffer: 2 * 1024 * 1024,
    });
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain(`artifact sha256 ${sha256(fixture.artifactBytes)}`);
    expect(result.stdout).toContain(`signature sha256 ${sha256(fixture.signatureBytes)}`);
    expect(result.stdout).toContain(`OpenPGP primary fingerprint ${fixture.fingerprint}`);
    expect(result.stdout).toContain(`artifact source commit ${"a".repeat(40)}`);
  });

  it("rejects a one-byte artifact change or independently supplied wrong key", async () => {
    const changedArtifact = Buffer.from(fixture.artifactBytes);
    changedArtifact[0] ^= 1;
    await expect(verify({ artifactBytes: changedArtifact }))
      .rejects.toThrow(/BADSIG|signature/);
    await expect(verify({ expectedSignerFingerprint: "0".repeat(40) }))
      .rejects.toThrow(/differs from the independently supplied signer/);
  });

  it("rejects malformed, changed, trailing, or concatenated signature packets", async () => {
    const changedSignature = Buffer.from(fixture.signatureBytes);
    changedSignature[Math.floor(changedSignature.length / 2)] ^= 1;
    await expect(verify({ signatureBytes: changedSignature }))
      .rejects.toThrow(/signature|GnuPG|status/);
    await expect(verify({ signatureBytes: Buffer.from("not an OpenPGP signature\n") }))
      .rejects.toThrow(/NODATA|signature|status/);
    await expect(verify({
      signatureBytes: Buffer.concat([fixture.signatureBytes, Buffer.from([0])]),
    })).rejects.toThrow(/NODATA|signature|status|exited/);
    await expect(verify({
      signatureBytes: Buffer.concat([
        fixture.signatureBytes,
        fixture.secondSignatureBytes,
      ]),
    })).rejects.toThrow(/exactly one signature|VALIDSIG/);
  });

  it("rejects a key absent from the explicitly selected verification home", async () => {
    await expect(verify({
      environment: { GNUPGHOME: fixture.emptyGnuPgHome },
    })).rejects.toThrow(/ERRSIG|NO_PUBKEY|signature/);
    await expect(verify({ environment: {} }))
      .rejects.toThrow(/GNUPGHOME must explicitly select/);
  });

  it("enforces nonempty byte inputs and explicit size bounds", async () => {
    await expect(verify({ artifactBytes: Buffer.alloc(0) }))
      .rejects.toThrow(/reviewed artifact manifest must be between/);
    await expect(verify({ signatureBytes: Buffer.alloc(0) }))
      .rejects.toThrow(/detached signature must be between/);
    await expect(verify({ artifactBytes: Buffer.alloc(MAX_REVIEWED_ARTIFACT_BYTES + 1) }))
      .rejects.toThrow(String(MAX_REVIEWED_ARTIFACT_BYTES));
    await expect(verify({ signatureBytes: Buffer.alloc(MAX_DETACHED_SIGNATURE_BYTES + 1) }))
      .rejects.toThrow(String(MAX_DETACHED_SIGNATURE_BYTES));
    await expect(verify({ artifactBytes: "not bytes" }))
      .rejects.toThrow(/must be byte data/);
  });
});
