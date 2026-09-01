import { execFile as execFileCallback } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import { isAbsolute } from "node:path";

const GIT_EXECUTABLE = "/usr/bin/git";
const GPG_EXECUTABLE = "/usr/bin/gpg";
const MAX_TAG_OBJECT_BYTES = 1024 * 1024;
const FULL_SHA1_PATTERN = /^[0-9a-f]{40}$/;
const FINGERPRINT_PATTERN = /^[0-9A-F]{40}(?:[0-9A-F]{24})?$/;
const TERMINAL_SIGNATURE_STATUSES = new Set([
  "GOODSIG",
  "BADSIG",
  "EXPSIG",
  "EXPKEYSIG",
  "REVKEYSIG",
  "ERRSIG",
]);
const REFUSAL_STATUSES = new Set([
  "BADSIG",
  "EXPSIG",
  "EXPKEYSIG",
  "REVKEYSIG",
  "ERRSIG",
  "NO_PUBKEY",
  "NODATA",
  "BADARMOR",
  "FAILURE",
  "ERROR",
]);

function fail(message) {
  throw new Error(`extension release source tag: ${message}`);
}

function normalizeFingerprint(value, label) {
  if (typeof value !== "string" || value !== value.trim()) {
    fail(`${label} must be an unspaced full OpenPGP fingerprint`);
  }
  const normalized = value.toUpperCase();
  if (!FINGERPRINT_PATTERN.test(normalized)) {
    fail(`${label} must be a 40- or 64-character full OpenPGP fingerprint`);
  }
  return normalized;
}

function assertFullSha1(value, label) {
  if (typeof value !== "string" || !FULL_SHA1_PATTERN.test(value)) {
    fail(`${label} must be a full lowercase 40-character Git object SHA`);
  }
}

function countStatus(statuses, keyword) {
  return statuses.filter((status) => status.keyword === keyword).length;
}

export function parseGitVerifyTagStatus(statusText, expectedSignerFingerprint) {
  if (typeof statusText !== "string") {
    fail("Git verification status must be text");
  }
  const expectedPrimaryFingerprint = normalizeFingerprint(
    expectedSignerFingerprint,
    "expected signer fingerprint",
  );
  const statuses = [];
  for (const line of statusText.split("\n")) {
    if (line.length === 0) {
      continue;
    }
    const prefix = "[GNUPG:] ";
    if (!line.startsWith(prefix)) {
      fail("git verify-tag --raw emitted non-status output");
    }
    const status = line.slice(prefix.length);
    const separator = status.indexOf(" ");
    const keyword = separator === -1 ? status : status.slice(0, separator);
    const argumentsText = separator === -1 ? "" : status.slice(separator + 1);
    if (!/^[A-Z][A-Z0-9_]*$/.test(keyword)) {
      fail("GnuPG emitted an invalid status keyword");
    }
    statuses.push({ keyword, argumentsText });
  }
  if (statuses.length === 0) {
    fail("git verify-tag --raw emitted no GnuPG status");
  }
  const refused = statuses.find((status) => REFUSAL_STATUSES.has(status.keyword));
  if (refused) {
    fail(`GnuPG refused the tag signature with ${refused.keyword}`);
  }
  if (countStatus(statuses, "NEWSIG") !== 1) {
    fail("GnuPG status must describe exactly one signature");
  }
  const terminalStatuses = statuses.filter((status) =>
    TERMINAL_SIGNATURE_STATUSES.has(status.keyword));
  if (terminalStatuses.length !== 1 || terminalStatuses[0].keyword !== "GOODSIG") {
    fail("GnuPG status must contain exactly one successful signature result");
  }
  const validSignatures = statuses.filter((status) => status.keyword === "VALIDSIG");
  if (validSignatures.length !== 1) {
    fail("GnuPG status must contain exactly one cryptographic VALIDSIG result");
  }
  const validArguments = validSignatures[0].argumentsText.split(" ").filter(Boolean);
  if (validArguments.length < 9) {
    fail("GnuPG VALIDSIG status is truncated");
  }
  const signingFingerprint = normalizeFingerprint(
    validArguments[0],
    "VALIDSIG signing fingerprint",
  );
  const primaryFingerprint = normalizeFingerprint(
    validArguments[9] ?? signingFingerprint,
    "VALIDSIG primary fingerprint",
  );
  if (primaryFingerprint !== expectedPrimaryFingerprint) {
    fail("VALIDSIG primary fingerprint differs from the independently supplied signer");
  }
  const goodSignatureIdentity = terminalStatuses[0].argumentsText.split(" ")[0]?.toUpperCase();
  if (
    typeof goodSignatureIdentity !== "string" ||
    !/^[0-9A-F]{16,64}$/.test(goodSignatureIdentity) ||
    !signingFingerprint.endsWith(goodSignatureIdentity)
  ) {
    fail("GOODSIG identity differs from the VALIDSIG signing fingerprint");
  }
  return {
    signingFingerprint,
    primaryFingerprint,
  };
}

function executeGit(arguments_, { repositoryRoot, environment, allowFailure = false }) {
  return new Promise((resolve, reject) => {
    execFileCallback(
      GIT_EXECUTABLE,
      arguments_,
      {
        cwd: repositoryRoot,
        env: environment,
        encoding: "utf8",
        maxBuffer: MAX_TAG_OBJECT_BYTES + 64 * 1024,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const numericExitCode = typeof error?.code === "number" ? error.code : null;
        if (error && numericExitCode === null) {
          reject(error);
          return;
        }
        if (error && !allowFailure) {
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

function verificationEnvironment(gnupgHome) {
  const sanitized = {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
  };
  sanitized.GNUPGHOME = gnupgHome;
  return sanitized;
}

async function requireGnuPgHome(environment) {
  const gnupgHome = (environment ?? process.env).GNUPGHOME;
  if (
    typeof gnupgHome !== "string" ||
    gnupgHome.length === 0 ||
    gnupgHome !== gnupgHome.trim() ||
    !isAbsolute(gnupgHome)
  ) {
    fail("GNUPGHOME must explicitly select an existing absolute verification keyring directory");
  }
  let metadata;
  let canonicalHome;
  try {
    [metadata, canonicalHome] = await Promise.all([stat(gnupgHome), realpath(gnupgHome)]);
  } catch (error) {
    fail(`GNUPGHOME is unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!metadata.isDirectory()) {
    fail("GNUPGHOME must select a directory");
  }
  return canonicalHome;
}

async function requireGitSuccess(arguments_, options, label) {
  try {
    return await executeGit(arguments_, options);
  } catch (error) {
    fail(`${label} failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function parseAnnotatedTagObject(tagObjectText, expectedTagName) {
  const headerEnd = tagObjectText.indexOf("\n\n");
  if (headerEnd === -1) {
    fail("annotated tag object has no message boundary");
  }
  const headers = tagObjectText.slice(0, headerEnd).split("\n");
  const parsed = new Map();
  for (const header of headers) {
    const separator = header.indexOf(" ");
    if (separator <= 0) {
      fail("annotated tag object contains a malformed header");
    }
    const name = header.slice(0, separator);
    if (parsed.has(name)) {
      fail(`annotated tag object contains duplicate ${name} headers`);
    }
    parsed.set(name, header.slice(separator + 1));
  }
  if (
    parsed.size !== 4 ||
    !parsed.has("object") ||
    !parsed.has("type") ||
    !parsed.has("tag") ||
    !parsed.has("tagger")
  ) {
    fail("annotated tag object must contain exactly object/type/tag/tagger headers");
  }
  const targetCommit = parsed.get("object");
  assertFullSha1(targetCommit, "annotated tag target");
  if (parsed.get("type") !== "commit") {
    fail("annotated release tag must point directly to a commit");
  }
  if (parsed.get("tag") !== expectedTagName) {
    fail("annotated tag object's name differs from the exact selected tag ref");
  }
  if (parsed.get("tagger").length === 0) {
    fail("annotated tag object has an empty tagger");
  }
  return { targetCommit };
}

async function resolveExactTagRef(tagName, options) {
  const ref = `refs/tags/${tagName}`;
  const checked = await executeGit(["check-ref-format", ref], {
    ...options,
    allowFailure: true,
  });
  if (checked.exitCode !== 0 || checked.stdout !== "" || checked.stderr !== "") {
    fail("selected tag name is not an exact valid Git tag ref");
  }
  const resolved = await executeGit(["show-ref", "--verify", "--hash", ref], {
    ...options,
    allowFailure: true,
  });
  if (resolved.exitCode !== 0 || resolved.stderr !== "") {
    fail("selected tag ref does not exist exactly once");
  }
  const lines = resolved.stdout.trimEnd().split("\n");
  if (lines.length !== 1 || !FULL_SHA1_PATTERN.test(lines[0])) {
    fail("selected tag ref resolved ambiguously or not to a full SHA-1 object id");
  }
  return { ref, objectSha: lines[0] };
}

export async function verifyReleaseSourceTag({
  repositoryRoot,
  tagName,
  expectedTagObject,
  expectedSignerFingerprint,
  artifactManifest,
  environment,
}) {
  if (typeof repositoryRoot !== "string" || repositoryRoot.length === 0) {
    fail("repository root is required");
  }
  if (
    typeof tagName !== "string" ||
    tagName.length === 0 ||
    tagName.length > 256 ||
    tagName !== tagName.trim() ||
    /[\0-\x20\x7f]/.test(tagName)
  ) {
    fail("selected tag name is invalid");
  }
  assertFullSha1(expectedTagObject, "expected tag object");
  const expectedPrimaryFingerprint = normalizeFingerprint(
    expectedSignerFingerprint,
    "expected signer fingerprint",
  );
  const artifactCommit = artifactManifest?.source?.gitCommit;
  assertFullSha1(artifactCommit, "artifact source commit");
  const gnupgHome = await requireGnuPgHome(environment);
  const gitOptions = {
    repositoryRoot,
    environment: verificationEnvironment(gnupgHome),
  };

  const initial = await resolveExactTagRef(tagName, gitOptions);
  if (initial.objectSha !== expectedTagObject) {
    fail("selected tag ref was moved or differs from the independently supplied tag object");
  }
  const objectType = await requireGitSuccess(
    ["cat-file", "-t", expectedTagObject],
    gitOptions,
    "reading selected tag object type",
  );
  if (objectType.stderr !== "" || objectType.stdout !== "tag\n") {
    fail("selected release ref must resolve to an annotated tag object, not a lightweight tag");
  }
  const objectSize = await requireGitSuccess(
    ["cat-file", "-s", expectedTagObject],
    gitOptions,
    "reading selected tag object size",
  );
  const parsedSize = Number(objectSize.stdout.trim());
  if (
    objectSize.stderr !== "" ||
    !Number.isSafeInteger(parsedSize) ||
    parsedSize <= 0 ||
    parsedSize > MAX_TAG_OBJECT_BYTES
  ) {
    fail(`annotated tag object must be between 1 and ${MAX_TAG_OBJECT_BYTES} bytes`);
  }
  const object = await requireGitSuccess(
    ["cat-file", "tag", expectedTagObject],
    gitOptions,
    "reading selected annotated tag object",
  );
  if (object.stderr !== "" || Buffer.byteLength(object.stdout) !== parsedSize) {
    fail("annotated tag object bytes differ from Git's declared object size");
  }
  const { targetCommit } = parseAnnotatedTagObject(object.stdout, tagName);
  if (targetCommit !== artifactCommit) {
    fail("annotated tag target differs from the artifact source commit");
  }

  const verification = await executeGit(
    [
      "-c",
      "gpg.format=openpgp",
      "-c",
      `gpg.program=${GPG_EXECUTABLE}`,
      "-c",
      `gpg.openpgp.program=${GPG_EXECUTABLE}`,
      "verify-tag",
      "--raw",
      expectedTagObject,
    ],
    { ...gitOptions, allowFailure: true },
  );
  if (verification.stdout !== "") {
    fail("git verify-tag --raw unexpectedly emitted stdout");
  }
  const signature = parseGitVerifyTagStatus(
    verification.stderr,
    expectedPrimaryFingerprint,
  );
  if (verification.exitCode !== 0) {
    fail(`git verify-tag exited ${verification.exitCode} despite parsed status`);
  }

  const final = await resolveExactTagRef(tagName, gitOptions);
  if (final.objectSha !== expectedTagObject) {
    fail("selected tag ref moved during signature verification");
  }
  return {
    tagName,
    tagRef: initial.ref,
    tagObject: expectedTagObject,
    sourceCommit: targetCommit,
    signingFingerprint: signature.signingFingerprint,
    primaryFingerprint: signature.primaryFingerprint,
  };
}
