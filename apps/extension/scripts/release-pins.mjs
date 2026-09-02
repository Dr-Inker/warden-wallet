#!/usr/bin/env node
// Owner-owned release pins — the anchor the CI release-verify job checks a
// pushed tag against (audit finding E-4).
//
// `pnpm --filter @warden/extension release:gate` packages the extension and
// then verifies the ZIP it just produced against the `.artifact.json` produced
// seconds earlier by the same job. That is a self-consistency check: replacing
// both files defeats it. The three ANCHORED verifiers —
// verify-release-source-tag.mjs, verify-reviewed-artifact-signature.mjs and
// verify-store-package.mjs — take their expectations as independent operands,
// so they are only as strong as where those operands come from. This module is
// where they come from: a committed, owner-authored `release-pins.json`.
//
// It fails CLOSED. A missing file, unparsable JSON, an unknown key, a missing
// key, a placeholder value, or any malformed fingerprint / digest / object SHA
// / extension id / path throws before a single verifier is spawned. The file
// committed to the repository is deliberately a placeholder, so the release-
// verify workflow FAILS on every tag until the owner replaces it with real
// pins. That is the intended state, not a bug.
//
// What this does NOT establish is written down in
// docs/security/RELEASE-INTEGRITY.md ("CI release-verify job"): the pins live
// in the same repository the tag comes from, so an attacker who can push both
// can move both. The owner must ALSO run these verifiers locally from a
// keyring and a pins record they hold outside this repository.
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { normalizeReleaseCliArguments } from "./release-cli-arguments.mjs";
import { releaseGitEnvironment } from "./release-git.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");

export const RELEASE_PINS_SCHEMA = "warden.extension-release-pins.v1";
export const RELEASE_PINS_FILENAME = "release-pins.json";
export const RELEASE_PINS_PATH = join(appDirectory, RELEASE_PINS_FILENAME);
export const RELEASE_PINS_CHILD_TIMEOUT_MS = 20 * 60 * 1000;
export const MAX_RELEASE_PINS_BYTES = 64 * 1024;

const TOP_LEVEL_KEYS = [
  "schema",
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
];
const DUAL_REPORT_KEYS = ["path", "sha256"];
const REVIEW_SIGNATURE_KEYS = ["path", "sha256", "primaryFingerprint", "signingFingerprint"];
const STORE_PACKAGE_KEYS = ["path", "sha256", "extensionId"];

const PLACEHOLDER_TOKENS = new Set([
  "",
  "todo",
  "tbd",
  "replace_me",
  "replace-me",
  "replaceme",
  "change_me",
  "change-me",
  "changeme",
  "xxx",
  "none",
  "placeholder",
  "unset",
]);

const LOWER_HEX_40 = /^[0-9a-f]{40}$/;
const UPPER_HEX_40 = /^[0-9A-F]{40}$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const EXTENSION_ID = /^[a-p]{32}$/;
const SAFE_RELATIVE_PATH = /^[A-Za-z0-9._][A-Za-z0-9._-]*(?:\/[A-Za-z0-9._][A-Za-z0-9._-]*)*$/;

function fail(message) {
  throw new Error(`extension release pins: ${message}`);
}

// A pin is a placeholder when it is blank, one of the well-known "fill this in"
// tokens, or an all-zero / single-repeated-character hex run. The last case is
// what makes the committed placeholder file mechanically detectable rather than
// merely conventionally so.
function assertNotPlaceholder(label, value) {
  const trimmed = value.trim();
  if (PLACEHOLDER_TOKENS.has(trimmed.toLowerCase())) {
    fail(`${label} is a placeholder (${JSON.stringify(value)}) — fill in the real release pin`);
  }
  if (/^[0-9a-fA-F]{8,}$/.test(trimmed) && new Set(trimmed.toLowerCase()).size === 1) {
    fail(`${label} is a placeholder (a single repeated hex character) — fill in the real release pin`);
  }
  if (/replace[_-]?me|change[_-]?me|\bTODO\b/i.test(trimmed)) {
    fail(`${label} is a placeholder (${JSON.stringify(value)}) — fill in the real release pin`);
  }
}

// Placeholder detection runs BEFORE grammar for every pin, so an unfilled
// field reports "this is a placeholder — fill it in" rather than a grammar
// complaint the owner has to decode.
function pinned(label, value, check) {
  if (typeof value === "string") {
    assertNotPlaceholder(label, value);
  }
  return check(label, value);
}

function requireString(label, value) {
  if (typeof value !== "string") {
    fail(`${label} must be a string`);
  }
  return value;
}

function checkTag(label, value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value !== value.trim() ||
    // eslint-disable-next-line no-control-regex
    /[\0-\x20\x7f]/.test(value)
  ) {
    fail(`${label} must be a nonempty, trimmed, control-character-free tag name of at most 256 characters`);
  }
  return value;
}

function checkTagObjectSha(label, value) {
  if (typeof value !== "string" || !LOWER_HEX_40.test(value)) {
    fail(`${label} must be 40 lowercase hex characters (an annotated-tag object SHA-1)`);
  }
  return value;
}

function checkFingerprint(label, value) {
  if (typeof value !== "string" || !UPPER_HEX_40.test(value)) {
    fail(`${label} must be 40 uppercase hex characters (an OpenPGP v4 fingerprint)`);
  }
  return value;
}

function checkSha256(label, value) {
  if (typeof value !== "string" || !LOWER_HEX_64.test(value)) {
    fail(`${label} must be 64 lowercase hex characters (a SHA-256 digest)`);
  }
  return value;
}

function checkExtensionId(label, value) {
  if (typeof value !== "string" || !EXTENSION_ID.test(value)) {
    fail(`${label} must be 32 characters a-p (a Chrome Web Store extension id)`);
  }
  if (new Set(value).size === 1) {
    fail(`${label} is a placeholder (a single repeated character) — fill in the real release pin`);
  }
  return value;
}

// File operands are resolved under apps/extension. They must be plain relative
// paths: an absolute path, a `..` segment, a trailing slash, a NUL, or a
// backslash would let a pins file point the verifiers at bytes outside the
// release directory.
function checkRelativePath(label, value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 512 ||
    !SAFE_RELATIVE_PATH.test(value) ||
    value.split("/").includes("..")
  ) {
    fail(`${label} must be a relative path under apps/extension with no "..", absolute prefix, or trailing separator`);
  }
  return value;
}

function requireExactKeys(label, object, allowed) {
  const present = Object.keys(object);
  const unknown = present.filter((key) => !allowed.includes(key)).sort();
  if (unknown.length > 0) {
    fail(`${label}unknown key(s): ${unknown.join(", ")}`);
  }
  for (const key of allowed) {
    if (!Object.hasOwn(object, key)) {
      fail(`${label}missing required key ${key}`);
    }
  }
}

function optionalTuple(label, value, allowed) {
  if (value === null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be null or a JSON object`);
  }
  requireExactKeys(`${label}: `, value, allowed);
  return value;
}

/**
 * Parse and fully validate release pins JSON. Pure: no filesystem, no spawning.
 * Throws on anything short of a complete, non-placeholder, well-formed record.
 */
export function parseReleasePins(text) {
  if (typeof text !== "string") {
    fail("pins document must be a string");
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch (error) {
    fail(`pins document is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    fail("pins document must be a JSON object");
  }
  if (document.schema !== RELEASE_PINS_SCHEMA) {
    fail(`schema must be ${JSON.stringify(RELEASE_PINS_SCHEMA)}`);
  }
  requireExactKeys("", document, TOP_LEVEL_KEYS);

  const dualReleaseReportRaw = optionalTuple(
    "dualReleaseReport",
    document.dualReleaseReport,
    DUAL_REPORT_KEYS,
  );
  const artifactReviewSignatureRaw = optionalTuple(
    "artifactReviewSignature",
    document.artifactReviewSignature,
    REVIEW_SIGNATURE_KEYS,
  );
  const storePackageRaw = optionalTuple("storePackage", document.storePackage, STORE_PACKAGE_KEYS);

  // The source-tag verifier's grammar is atomic and nested: the 16-argument
  // store tier is only reachable through the 12-argument review tier, which is
  // only reachable through the 8-argument dual-report tier. Pins that skip a
  // tier could never be turned into a legal invocation, so reject them here
  // rather than emitting an argument vector the verifier would refuse.
  if (storePackageRaw !== null && artifactReviewSignatureRaw === null) {
    fail("storePackage requires artifactReviewSignature (the source-tag verifier's tiers are nested)");
  }
  if (artifactReviewSignatureRaw !== null && dualReleaseReportRaw === null) {
    fail("artifactReviewSignature requires dualReleaseReport (the source-tag verifier's tiers are nested)");
  }

  return Object.freeze({
    schema: RELEASE_PINS_SCHEMA,
    tag: pinned("tag", document.tag, checkTag),
    tagObjectSha: pinned("tagObjectSha", document.tagObjectSha, checkTagObjectSha),
    primaryFingerprint: pinned("primaryFingerprint", document.primaryFingerprint, checkFingerprint),
    signingFingerprint: pinned("signingFingerprint", document.signingFingerprint, checkFingerprint),
    artifactManifestPath: pinned("artifactManifestPath", document.artifactManifestPath, checkRelativePath),
    artifactManifestSha256: pinned("artifactManifestSha256", document.artifactManifestSha256, checkSha256),
    reviewedUploadArchivePath: pinned("reviewedUploadArchivePath", document.reviewedUploadArchivePath, checkRelativePath),
    dualReleaseReport:
      dualReleaseReportRaw === null
        ? null
        : Object.freeze({
            path: pinned("dualReleaseReport.path", dualReleaseReportRaw.path, checkRelativePath),
            sha256: pinned("dualReleaseReport.sha256", dualReleaseReportRaw.sha256, checkSha256),
          }),
    artifactReviewSignature:
      artifactReviewSignatureRaw === null
        ? null
        : Object.freeze({
            path: pinned("artifactReviewSignature.path", artifactReviewSignatureRaw.path, checkRelativePath),
            sha256: pinned("artifactReviewSignature.sha256", artifactReviewSignatureRaw.sha256, checkSha256),
            primaryFingerprint: pinned("artifactReviewSignature.primaryFingerprint", artifactReviewSignatureRaw.primaryFingerprint, checkFingerprint),
            signingFingerprint: pinned("artifactReviewSignature.signingFingerprint", artifactReviewSignatureRaw.signingFingerprint, checkFingerprint),
          }),
    storePackage:
      storePackageRaw === null
        ? null
        : Object.freeze({
            path: pinned("storePackage.path", storePackageRaw.path, checkRelativePath),
            sha256: pinned("storePackage.sha256", storePackageRaw.sha256, checkSha256),
            extensionId: pinned("storePackage.extensionId", storePackageRaw.extensionId, checkExtensionId),
          }),
  });
}

/** Read and validate the pins file at `path`. Fails closed if it is unreadable. */
export async function loadReleasePins(path = RELEASE_PINS_PATH) {
  let text;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    fail(
      `release pins file could not be read at ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (text.length > MAX_RELEASE_PINS_BYTES) {
    fail(`release pins file at ${path} is larger than ${MAX_RELEASE_PINS_BYTES} bytes`);
  }
  return parseReleasePins(text);
}

/**
 * Build the exact argument vector for each anchored verifier. Pure: it never
 * touches the filesystem and never spawns. Every element is a string, and every
 * expectation comes from the pins — nothing is learned from the candidate.
 *
 * Returns one entry per verifier, in a fixed order, each either `run: true`
 * with a `script` and `args`, or `run: false` with a `skipReason` the CLI
 * prints loudly.
 */
export function buildVerifierInvocations(pins, { appDirectory: base = appDirectory } = {}) {
  const scriptPath = (name) => join(base, "scripts", name);
  const filePath = (relative) => join(base, relative);

  const artifactManifest = filePath(pins.artifactManifestPath);
  const reviewedUpload = filePath(pins.reviewedUploadArchivePath);

  const sourceTagArguments = [
    pins.tag,
    pins.tagObjectSha,
    pins.primaryFingerprint,
    pins.signingFingerprint,
    artifactManifest,
    pins.artifactManifestSha256,
  ];
  if (pins.dualReleaseReport !== null) {
    sourceTagArguments.push(filePath(pins.dualReleaseReport.path), pins.dualReleaseReport.sha256);
  }
  if (pins.artifactReviewSignature !== null) {
    sourceTagArguments.push(
      filePath(pins.artifactReviewSignature.path),
      pins.artifactReviewSignature.sha256,
      pins.artifactReviewSignature.primaryFingerprint,
      pins.artifactReviewSignature.signingFingerprint,
    );
  }
  if (pins.storePackage !== null) {
    sourceTagArguments.push(
      filePath(pins.storePackage.path),
      pins.storePackage.sha256,
      pins.storePackage.extensionId,
      reviewedUpload,
    );
  }

  return [
    {
      id: "release-source-tag",
      title: "signed release source tag -> artifact manifest",
      run: true,
      script: scriptPath("verify-release-source-tag.mjs"),
      args: sourceTagArguments,
    },
    pins.artifactReviewSignature === null
      ? {
          id: "reviewed-artifact-signature",
          title: "detached OpenPGP signature over the reviewed artifact manifest",
          run: false,
          skipReason:
            "release-pins.json sets artifactReviewSignature: null — no detached artifact-review signature is pinned, so the reviewed-artifact-signature verifier CANNOT run and this release is NOT bound to a reviewer signature",
        }
      : {
          id: "reviewed-artifact-signature",
          title: "detached OpenPGP signature over the reviewed artifact manifest",
          run: true,
          script: scriptPath("verify-reviewed-artifact-signature.mjs"),
          args: [
            artifactManifest,
            filePath(pins.artifactReviewSignature.path),
            pins.artifactManifestSha256,
            pins.artifactReviewSignature.sha256,
            pins.artifactReviewSignature.primaryFingerprint,
            pins.artifactReviewSignature.signingFingerprint,
          ],
        },
    pins.storePackage === null
      ? {
          id: "store-package",
          title: "Web Store CRX3 envelope -> reviewed upload ZIP",
          run: false,
          skipReason:
            "release-pins.json sets storePackage: null — no CRX3 package digest or extension id is pinned, so the store-package verifier CANNOT run and the published store envelope is NOT bound to this artifact",
        }
      : {
          id: "store-package",
          title: "Web Store CRX3 envelope -> reviewed upload ZIP",
          run: true,
          script: scriptPath("verify-store-package.mjs"),
          args: [
            filePath(pins.storePackage.path),
            pins.storePackage.sha256,
            pins.storePackage.extensionId,
            pins.artifactManifestSha256,
            reviewedUpload,
            artifactManifest,
          ],
        },
  ];
}

/**
 * Child environment for the verifier processes: the release git allow-list
 * (apps/extension/scripts/release-git.mjs — audit finding E-1) plus the one
 * additional variable the OpenPGP lane genuinely needs. Nothing is inherited
 * from `process.env`, so NODE_OPTIONS, LD_PRELOAD, GIT_DIR and a hostile PATH
 * cannot reach the verifiers or the git/gpg children they spawn.
 */
export function releasePinsChildEnvironment(environment = process.env) {
  const gnupgHome = environment?.GNUPGHOME;
  if (
    typeof gnupgHome !== "string" ||
    gnupgHome.length === 0 ||
    gnupgHome !== gnupgHome.trim() ||
    !isAbsolute(gnupgHome)
  ) {
    fail(
      "GNUPGHOME must explicitly select an existing absolute verification keyring directory holding the pinned release public key(s)",
    );
  }
  const allowed = releaseGitEnvironment();
  allowed.GNUPGHOME = gnupgHome;
  return allowed;
}

function usage() {
  fail(
    "usage: release-pins.mjs [--tag <expected-tag>] [--pins <release-pins.json>]",
  );
}

async function main() {
  const args = normalizeReleaseCliArguments(process.argv.slice(2));
  let expectedTag;
  let pinsPath = RELEASE_PINS_PATH;
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (value === undefined) usage();
    if (flag === "--tag") {
      expectedTag = requireString("--tag", value);
    } else if (flag === "--pins") {
      pinsPath = resolve(requireString("--pins", value));
    } else {
      usage();
    }
  }

  const pins = await loadReleasePins(pinsPath);
  if (expectedTag !== undefined && expectedTag !== pins.tag) {
    fail(
      `refusing to verify: the requested tag ${JSON.stringify(expectedTag)} is not the pinned release tag ${JSON.stringify(pins.tag)}`,
    );
  }
  const environment = releasePinsChildEnvironment();
  const invocations = buildVerifierInvocations(pins);

  console.log(`release pins ${pinsPath}`);
  console.log(`pinned tag ${pins.tag}`);
  console.log(`pinned tag object ${pins.tagObjectSha}`);
  console.log(`pinned primary fingerprint ${pins.primaryFingerprint}`);
  console.log(`pinned signing fingerprint ${pins.signingFingerprint}`);
  console.log(`pinned artifact manifest sha256 ${pins.artifactManifestSha256}`);

  let skipped = 0;
  for (const invocation of invocations) {
    if (!invocation.run) {
      skipped += 1;
      console.log("");
      console.log(`!! SKIPPED ${invocation.id} — ${invocation.title}`);
      console.log(`!! ${invocation.skipReason}`);
      continue;
    }
    console.log("");
    console.log(`== ${invocation.id} — ${invocation.title}`);
    // execFileSync with an explicit argv: no shell, no interpolation, no
    // operand ever passing through a command string.
    execFileSync(process.execPath, [invocation.script, ...invocation.args], {
      cwd: appDirectory,
      env: environment,
      stdio: "inherit",
      timeout: RELEASE_PINS_CHILD_TIMEOUT_MS,
      killSignal: "SIGKILL",
      windowsHide: true,
    });
  }

  console.log("");
  console.log(`anchored release verification passed for ${pins.tag}`);
  if (skipped > 0) {
    console.log(
      `!! ${skipped} of ${invocations.length} anchored verifiers were SKIPPED because their pins are absent — see the notices above`,
    );
  }
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
