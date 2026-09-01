import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  normalizeOpenPgpFingerprint,
  parseSingleOpenPgpSignatureStatus,
  requireExplicitGnuPgHome,
} from "./release-source-tag.mjs";

const GPG_EXECUTABLE = "/usr/bin/gpg";
export const MAX_REVIEWED_ARTIFACT_BYTES = 8 * 1024 * 1024;
export const MAX_DETACHED_SIGNATURE_BYTES = 1024 * 1024;
const MAX_GPG_OUTPUT_BYTES = 1024 * 1024;

function fail(message) {
  throw new Error(`reviewed extension artifact signature: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireBoundedBytes(value, maximumBytes, label) {
  if (!(value instanceof Uint8Array)) {
    fail(`${label} must be byte data`);
  }
  if (value.length === 0 || value.length > maximumBytes) {
    fail(`${label} must be between 1 and ${maximumBytes} bytes`);
  }
  return Buffer.from(value);
}

function verificationEnvironment(gnupgHome) {
  return {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GNUPGHOME: gnupgHome,
  };
}

function executeGpg(arguments_, environment) {
  return new Promise((resolve, reject) => {
    execFileCallback(
      GPG_EXECUTABLE,
      arguments_,
      {
        env: environment,
        encoding: "utf8",
        maxBuffer: MAX_GPG_OUTPUT_BYTES,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const numericExitCode = typeof error?.code === "number" ? error.code : null;
        if (error && numericExitCode === null) {
          reject(error);
          return;
        }
        resolve({
          exitCode: numericExitCode ?? 0,
          stdout,
          stderr,
        });
      },
    );
  });
}

export async function verifyReviewedArtifactSignature({
  artifactBytes,
  signatureBytes,
  expectedSignerFingerprint,
  environment,
}) {
  const artifact = requireBoundedBytes(
    artifactBytes,
    MAX_REVIEWED_ARTIFACT_BYTES,
    "reviewed artifact manifest",
  );
  const signature = requireBoundedBytes(
    signatureBytes,
    MAX_DETACHED_SIGNATURE_BYTES,
    "detached signature",
  );
  const expectedPrimaryFingerprint = normalizeOpenPgpFingerprint(
    expectedSignerFingerprint,
    "expected artifact-review signer fingerprint",
  );
  const gnupgHome = await requireExplicitGnuPgHome(environment);
  const temporaryDirectory = await mkdtemp(
    join(tmpdir(), "warden-reviewed-artifact-signature-"),
  );
  try {
    const artifactPath = join(temporaryDirectory, "reviewed-artifact.json");
    const signaturePath = join(temporaryDirectory, "reviewed-artifact.json.sig");
    await Promise.all([
      writeFile(artifactPath, artifact, { flag: "wx", mode: 0o600 }),
      writeFile(signaturePath, signature, { flag: "wx", mode: 0o600 }),
    ]);
    let verification;
    try {
      verification = await executeGpg(
        [
          "--no-options",
          "--homedir",
          gnupgHome,
          "--batch",
          "--no-tty",
          "--no-auto-key-import",
          "--no-auto-key-retrieve",
          "--auto-key-locate",
          "clear",
          "--status-fd=1",
          "--verify",
          signaturePath,
          artifactPath,
        ],
        verificationEnvironment(gnupgHome),
      );
    } catch (error) {
      fail(`GnuPG execution failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    const verified = parseSingleOpenPgpSignatureStatus(
      verification.stdout,
      expectedPrimaryFingerprint,
    );
    if (verification.exitCode !== 0) {
      fail(`GnuPG exited ${verification.exitCode} despite parsed status`);
    }
    return {
      artifactBytes: artifact.length,
      artifactSha256: sha256(artifact),
      signatureBytes: signature.length,
      signatureSha256: sha256(signature),
      signingFingerprint: verified.signingFingerprint,
      primaryFingerprint: verified.primaryFingerprint,
    };
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}
