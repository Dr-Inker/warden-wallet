import { createHash } from "node:crypto";
import { constants as fileConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  utimes,
  writeFile,
} from "node:fs/promises";
import { dirname, join, posix } from "node:path";

import { JS_BUNDLE_INPUT_EVIDENCE_SCHEMA } from "./bundle-input-evidence.mjs";
import { PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA } from "./production-dependency-evidence.mjs";
import { RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA } from "./release-recipe-input-evidence.mjs";
import { STATIC_INPUT_EVIDENCE_SCHEMA } from "./static-input-evidence.mjs";

export const ARTIFACT_SCHEMA = "warden.extension-artifact.v5";
export const CANONICAL_TIMESTAMP = "1980-01-01T00:00:00.000Z";

const CANONICAL_DATE = new Date(CANONICAL_TIMESTAMP);
const CANONICAL_FILE_MODE = 0o644;
const CANONICAL_DIRECTORY_MODE = 0o755;
const ZIP_UTF8_FLAG = 0x0800;
const ZIP_STORE_METHOD = 0;
const ZIP_VERSION_NEEDED = 20;
const ZIP_VERSION_MADE_BY_UNIX = 0x0314;
const ZIP_DOS_TIME = 0;
const ZIP_DOS_DATE = 0x0021;
const ZIP_EXTERNAL_FILE_ATTRIBUTES = (0o100644 << 16) >>> 0;
const MAX_ZIP_ENTRIES = 0xffff;
const MAX_ZIP_VALUE = 0xffffffff;
const MAX_ENTRY_BYTES = 256 * 1024 * 1024;

const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;

const EXPECTED_RELEASE_PERMISSIONS = Object.freeze(["storage"]);
const EXPECTED_RELEASE_CSP = Object.freeze({
  extension_pages: "script-src 'self'; object-src 'self';",
});

const CRC32_TABLE = new Uint32Array(256);
for (let index = 0; index < CRC32_TABLE.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  }
  CRC32_TABLE[index] = value >>> 0;
}

function fail(message) {
  throw new Error(`extension artifact: ${message}`);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactKeys(value, expected, label) {
  if (!isPlainObject(value)) {
    fail(`${label} must be an object`);
  }
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    fail(`${label} keys changed: expected ${expectedKeys.join(",")}, got ${actualKeys.join(",")}`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function compareUtf8Paths(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function assertSafeArtifactPath(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    path.includes("\0") ||
    path.includes("\\") ||
    path.startsWith("/") ||
    path.endsWith("/") ||
    path !== path.normalize("NFC") ||
    posix.normalize(path) !== path ||
    path.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    fail(`unsafe artifact path: ${JSON.stringify(path)}`);
  }
  const encoded = Buffer.from(path, "utf8");
  if (encoded.length === 0 || encoded.length > 0xffff) {
    fail(`artifact path is too long: ${JSON.stringify(path)}`);
  }
  return encoded;
}

function canonicalizeEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    fail("payload must contain at least one file");
  }
  if (entries.length > MAX_ZIP_ENTRIES) {
    fail(`payload exceeds ${MAX_ZIP_ENTRIES} files`);
  }
  const canonical = entries.map((entry) => {
    if (!isPlainObject(entry)) {
      fail("payload entry must be an object");
    }
    const pathBytes = assertSafeArtifactPath(entry.path);
    if (!(entry.data instanceof Uint8Array)) {
      fail(`payload entry ${entry.path} is not byte data`);
    }
    const data = Buffer.from(entry.data);
    if (data.length > MAX_ENTRY_BYTES || data.length > MAX_ZIP_VALUE) {
      fail(`payload entry ${entry.path} exceeds the release size limit`);
    }
    return { path: entry.path, pathBytes, data };
  }).sort((left, right) => compareUtf8Paths(left.path, right.path));

  for (let index = 1; index < canonical.length; index += 1) {
    if (canonical[index - 1].path === canonical[index].path) {
      fail(`duplicate artifact path: ${canonical[index].path}`);
    }
  }
  if (!canonical.some((entry) => entry.path === "manifest.json")) {
    fail("manifest.json must be at the archive root");
  }
  return canonical;
}

function decodeCanonicalUtf8(bytes, label) {
  const decoded = bytes.toString("utf8");
  if (!Buffer.from(decoded, "utf8").equals(bytes)) {
    fail(`${label} is not canonical UTF-8`);
  }
  assertSafeArtifactPath(decoded);
  return decoded;
}

function assertReadable(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > buffer.length) {
    fail(`truncated ${label}`);
  }
}

function readUInt16LE(buffer, offset, label) {
  assertReadable(buffer, offset, 2, label);
  return buffer.readUInt16LE(offset);
}

function readUInt32LE(buffer, offset, label) {
  assertReadable(buffer, offset, 4, label);
  return buffer.readUInt32LE(offset);
}

function assertFixedZipFields({
  versionNeeded,
  flags,
  method,
  dosTime,
  dosDate,
}, label) {
  if (versionNeeded !== ZIP_VERSION_NEEDED) {
    fail(`${label} has non-canonical ZIP version`);
  }
  if (flags !== ZIP_UTF8_FLAG) {
    fail(`${label} has non-canonical ZIP flags`);
  }
  if (method !== ZIP_STORE_METHOD) {
    fail(`${label} is not stored without compression`);
  }
  if (dosTime !== ZIP_DOS_TIME || dosDate !== ZIP_DOS_DATE) {
    fail(`${label} has non-canonical timestamp`);
  }
}

async function readStableRegularFile(path, relativePath) {
  let handle;
  try {
    handle = await open(path, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
  } catch (error) {
    fail(`could not open regular file ${relativePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile()) {
      fail(`non-regular payload entry: ${relativePath}`);
    }
    if (before.size > BigInt(MAX_ENTRY_BYTES)) {
      fail(`payload entry ${relativePath} exceeds the release size limit`);
    }
    const data = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      BigInt(data.length) !== after.size
    ) {
      fail(`payload entry changed while it was read: ${relativePath}`);
    }
    return data;
  } finally {
    await handle.close();
  }
}

export async function collectCanonicalPayload(rootDirectory) {
  const rootStat = await lstat(rootDirectory);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail("payload root must be a real directory, not a symlink");
  }
  const entries = [];

  async function walk(directory, prefix) {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => compareUtf8Paths(left.name, right.name));
    for (const child of children) {
      const relativePath = prefix === "" ? child.name : `${prefix}/${child.name}`;
      assertSafeArtifactPath(relativePath);
      const absolutePath = join(directory, child.name);
      const childStat = await lstat(absolutePath);
      if (childStat.isSymbolicLink()) {
        fail(`symlink is forbidden in payload: ${relativePath}`);
      }
      if (childStat.isDirectory()) {
        await walk(absolutePath, relativePath);
      } else if (childStat.isFile()) {
        entries.push({
          path: relativePath,
          data: await readStableRegularFile(absolutePath, relativePath),
        });
      } else {
        fail(`non-regular payload entry: ${relativePath}`);
      }
    }
  }

  await walk(rootDirectory, "");
  return canonicalizeEntries(entries).map(({ path, data }) => ({ path, data }));
}

export async function stageCanonicalUnpacked(entries, targetDirectory) {
  const canonical = canonicalizeEntries(entries);
  await mkdir(targetDirectory, { mode: CANONICAL_DIRECTORY_MODE });

  const directories = new Set([""]);
  for (const entry of canonical) {
    let parent = posix.dirname(entry.path);
    while (parent !== ".") {
      directories.add(parent);
      parent = posix.dirname(parent);
    }
  }
  const orderedDirectories = [...directories]
    .filter((path) => path !== "")
    .sort((left, right) => {
      const depth = left.split("/").length - right.split("/").length;
      return depth === 0 ? compareUtf8Paths(left, right) : depth;
    });
  for (const directory of orderedDirectories) {
    await mkdir(join(targetDirectory, ...directory.split("/")), { mode: CANONICAL_DIRECTORY_MODE });
  }

  for (const entry of canonical) {
    const target = join(targetDirectory, ...entry.path.split("/"));
    await writeFile(target, entry.data, { flag: "wx", mode: CANONICAL_FILE_MODE });
    await chmod(target, CANONICAL_FILE_MODE);
    await utimes(target, CANONICAL_DATE, CANONICAL_DATE);
  }

  for (const directory of ["", ...orderedDirectories].sort((left, right) => {
    const depth = right.split("/").length - left.split("/").length;
    return depth === 0 ? compareUtf8Paths(right, left) : depth;
  })) {
    const target = directory === "" ? targetDirectory : join(targetDirectory, ...directory.split("/"));
    await chmod(target, CANONICAL_DIRECTORY_MODE);
    await utimes(target, CANONICAL_DATE, CANONICAL_DATE);
  }
}

export function createCanonicalZip(entries) {
  const canonical = canonicalizeEntries(entries);
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;

  for (const entry of canonical) {
    const checksum = crc32(entry.data);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(LOCAL_FILE_HEADER_SIGNATURE, 0);
    localHeader.writeUInt16LE(ZIP_VERSION_NEEDED, 4);
    localHeader.writeUInt16LE(ZIP_UTF8_FLAG, 6);
    localHeader.writeUInt16LE(ZIP_STORE_METHOD, 8);
    localHeader.writeUInt16LE(ZIP_DOS_TIME, 10);
    localHeader.writeUInt16LE(ZIP_DOS_DATE, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(entry.data.length, 18);
    localHeader.writeUInt32LE(entry.data.length, 22);
    localHeader.writeUInt16LE(entry.pathBytes.length, 26);
    localHeader.writeUInt16LE(0, 28);
    localParts.push(localHeader, entry.pathBytes, entry.data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(CENTRAL_DIRECTORY_HEADER_SIGNATURE, 0);
    centralHeader.writeUInt16LE(ZIP_VERSION_MADE_BY_UNIX, 4);
    centralHeader.writeUInt16LE(ZIP_VERSION_NEEDED, 6);
    centralHeader.writeUInt16LE(ZIP_UTF8_FLAG, 8);
    centralHeader.writeUInt16LE(ZIP_STORE_METHOD, 10);
    centralHeader.writeUInt16LE(ZIP_DOS_TIME, 12);
    centralHeader.writeUInt16LE(ZIP_DOS_DATE, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(entry.data.length, 20);
    centralHeader.writeUInt32LE(entry.data.length, 24);
    centralHeader.writeUInt16LE(entry.pathBytes.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(ZIP_EXTERNAL_FILE_ATTRIBUTES, 38);
    centralHeader.writeUInt32LE(localOffset, 42);
    centralParts.push(centralHeader, entry.pathBytes);

    localOffset += localHeader.length + entry.pathBytes.length + entry.data.length;
    if (localOffset > MAX_ZIP_VALUE) {
      fail("payload exceeds classic ZIP offset limits; ZIP64 is deliberately unsupported");
    }
  }

  const centralDirectory = Buffer.concat(centralParts);
  if (centralDirectory.length > MAX_ZIP_VALUE || localOffset + centralDirectory.length > MAX_ZIP_VALUE) {
    fail("central directory exceeds classic ZIP limits; ZIP64 is deliberately unsupported");
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_OF_CENTRAL_DIRECTORY_SIGNATURE, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(canonical.length, 8);
  end.writeUInt16LE(canonical.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

export function parseCanonicalZip(archiveBytes) {
  if (!(archiveBytes instanceof Uint8Array)) {
    fail("archive must be byte data");
  }
  const archive = Buffer.from(archiveBytes);
  if (archive.length < 22) {
    fail("truncated end of central directory");
  }
  const endOffset = archive.length - 22;
  if (readUInt32LE(archive, endOffset, "end of central directory") !== END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
    fail("archive does not end with a canonical central directory");
  }
  const disk = readUInt16LE(archive, endOffset + 4, "end of central directory");
  const centralDisk = readUInt16LE(archive, endOffset + 6, "end of central directory");
  const diskEntries = readUInt16LE(archive, endOffset + 8, "end of central directory");
  const totalEntries = readUInt16LE(archive, endOffset + 10, "end of central directory");
  const centralSize = readUInt32LE(archive, endOffset + 12, "end of central directory");
  const centralOffset = readUInt32LE(archive, endOffset + 16, "end of central directory");
  const commentLength = readUInt16LE(archive, endOffset + 20, "end of central directory");
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries || totalEntries === 0 || commentLength !== 0) {
    fail("multi-disk, empty, or commented ZIP archives are non-canonical");
  }
  if (centralOffset + centralSize !== endOffset) {
    fail("central directory offset or size is inconsistent");
  }

  const records = [];
  let centralCursor = centralOffset;
  for (let index = 0; index < totalEntries; index += 1) {
    assertReadable(archive, centralCursor, 46, "central directory header");
    if (readUInt32LE(archive, centralCursor, "central directory header") !== CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      fail("invalid central directory header signature");
    }
    const versionMadeBy = readUInt16LE(archive, centralCursor + 4, "central directory header");
    const versionNeeded = readUInt16LE(archive, centralCursor + 6, "central directory header");
    const flags = readUInt16LE(archive, centralCursor + 8, "central directory header");
    const method = readUInt16LE(archive, centralCursor + 10, "central directory header");
    const dosTime = readUInt16LE(archive, centralCursor + 12, "central directory header");
    const dosDate = readUInt16LE(archive, centralCursor + 14, "central directory header");
    assertFixedZipFields({ versionNeeded, flags, method, dosTime, dosDate }, "central directory entry");
    if (versionMadeBy !== ZIP_VERSION_MADE_BY_UNIX) {
      fail("central directory entry has non-canonical creator platform");
    }
    const checksum = readUInt32LE(archive, centralCursor + 16, "central directory header");
    const compressedSize = readUInt32LE(archive, centralCursor + 20, "central directory header");
    const uncompressedSize = readUInt32LE(archive, centralCursor + 24, "central directory header");
    const pathLength = readUInt16LE(archive, centralCursor + 28, "central directory header");
    const extraLength = readUInt16LE(archive, centralCursor + 30, "central directory header");
    const entryCommentLength = readUInt16LE(archive, centralCursor + 32, "central directory header");
    const entryDisk = readUInt16LE(archive, centralCursor + 34, "central directory header");
    const internalAttributes = readUInt16LE(archive, centralCursor + 36, "central directory header");
    const externalAttributes = readUInt32LE(archive, centralCursor + 38, "central directory header");
    const localOffset = readUInt32LE(archive, centralCursor + 42, "central directory header");
    if (compressedSize !== uncompressedSize || compressedSize > MAX_ENTRY_BYTES) {
      fail("central directory entry has an invalid stored size");
    }
    if (extraLength !== 0 || entryCommentLength !== 0 || entryDisk !== 0 || internalAttributes !== 0) {
      fail("central directory entry contains non-canonical metadata");
    }
    if (externalAttributes !== ZIP_EXTERNAL_FILE_ATTRIBUTES) {
      fail("central directory entry does not use canonical file mode 0644");
    }
    assertReadable(archive, centralCursor + 46, pathLength, "central directory path");
    const pathBytes = archive.subarray(centralCursor + 46, centralCursor + 46 + pathLength);
    const path = decodeCanonicalUtf8(pathBytes, "central directory path");
    records.push({
      path,
      pathBytes: Buffer.from(pathBytes),
      checksum,
      size: uncompressedSize,
      localOffset,
    });
    centralCursor += 46 + pathLength;
  }
  if (centralCursor !== endOffset) {
    fail("central directory contains trailing or unparsed bytes");
  }

  const sortedPaths = records.map((record) => record.path).sort(compareUtf8Paths);
  if (records.some((record, index) => record.path !== sortedPaths[index])) {
    fail("central directory paths are not in canonical order");
  }
  for (let index = 1; index < records.length; index += 1) {
    if (records[index - 1].path === records[index].path) {
      fail(`duplicate artifact path: ${records[index].path}`);
    }
  }
  if (!records.some((record) => record.path === "manifest.json")) {
    fail("manifest.json must be at the archive root");
  }

  const entries = [];
  let localCursor = 0;
  for (const record of records) {
    if (record.localOffset !== localCursor) {
      fail(`local entry offset is non-canonical for ${record.path}`);
    }
    assertReadable(archive, localCursor, 30, "local file header");
    if (readUInt32LE(archive, localCursor, "local file header") !== LOCAL_FILE_HEADER_SIGNATURE) {
      fail(`invalid local file header for ${record.path}`);
    }
    const versionNeeded = readUInt16LE(archive, localCursor + 4, "local file header");
    const flags = readUInt16LE(archive, localCursor + 6, "local file header");
    const method = readUInt16LE(archive, localCursor + 8, "local file header");
    const dosTime = readUInt16LE(archive, localCursor + 10, "local file header");
    const dosDate = readUInt16LE(archive, localCursor + 12, "local file header");
    assertFixedZipFields({ versionNeeded, flags, method, dosTime, dosDate }, `local entry ${record.path}`);
    const checksum = readUInt32LE(archive, localCursor + 14, "local file header");
    const compressedSize = readUInt32LE(archive, localCursor + 18, "local file header");
    const uncompressedSize = readUInt32LE(archive, localCursor + 22, "local file header");
    const pathLength = readUInt16LE(archive, localCursor + 26, "local file header");
    const extraLength = readUInt16LE(archive, localCursor + 28, "local file header");
    if (
      checksum !== record.checksum ||
      compressedSize !== record.size ||
      uncompressedSize !== record.size ||
      extraLength !== 0 ||
      pathLength !== record.pathBytes.length
    ) {
      fail(`local and central metadata disagree for ${record.path}`);
    }
    assertReadable(archive, localCursor + 30, pathLength + record.size, `local entry ${record.path}`);
    const localPath = archive.subarray(localCursor + 30, localCursor + 30 + pathLength);
    if (!localPath.equals(record.pathBytes)) {
      fail(`local and central paths disagree for ${record.path}`);
    }
    const dataOffset = localCursor + 30 + pathLength;
    const data = Buffer.from(archive.subarray(dataOffset, dataOffset + record.size));
    if (crc32(data) !== record.checksum) {
      fail(`CRC-32 mismatch for ${record.path}`);
    }
    entries.push({ path: record.path, data });
    localCursor = dataOffset + record.size;
  }
  if (localCursor !== centralOffset) {
    fail("local payload contains trailing or unparsed bytes");
  }
  return entries;
}

function parseExtensionManifest(entries) {
  const manifestEntry = entries.find((entry) => entry.path === "manifest.json");
  if (manifestEntry === undefined) {
    fail("manifest.json must be at the archive root");
  }
  const manifestBytes = Buffer.from(manifestEntry.data);
  const manifestText = manifestBytes.toString("utf8");
  if (!Buffer.from(manifestText, "utf8").equals(manifestBytes)) {
    fail("manifest.json is not canonical UTF-8");
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch (error) {
    fail(`manifest.json is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!isPlainObject(manifest)) {
    fail("manifest.json root must be an object");
  }
  if (manifestText !== `${JSON.stringify(manifest, null, 2)}\n`) {
    fail("manifest.json must use the canonical two-space JSON serialization");
  }
  return manifest;
}

function jsonEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function extensionSnapshot(manifest) {
  if (manifest.manifest_version !== 3) {
    fail("release manifest must use manifest_version 3");
  }
  if (typeof manifest.version !== "string" || !/^\d+(?:\.\d+){0,3}$/.test(manifest.version)) {
    fail("release manifest version is invalid");
  }
  if (!jsonEqual(manifest.permissions, EXPECTED_RELEASE_PERMISSIONS)) {
    fail("release manifest permissions differ from the reviewed [storage] policy");
  }
  if (!jsonEqual(manifest.content_security_policy, EXPECTED_RELEASE_CSP)) {
    fail("release manifest content security policy differs from the reviewed local-code-only policy");
  }
  if (Object.hasOwn(manifest, "update_url")) {
    fail("release manifest must not declare an update URL");
  }
  return {
    manifestVersion: manifest.manifest_version,
    version: manifest.version,
    permissions: [...manifest.permissions],
    contentSecurityPolicy: structuredClone(manifest.content_security_policy),
    updateUrl: null,
  };
}

function payloadFileRecords(entries) {
  return entries.map((entry) => ({
    path: entry.path,
    bytes: entry.data.length,
    mode: "0644",
    sha256: sha256(entry.data),
  }));
}

function payloadTreeHash(files) {
  return sha256(Buffer.from(`${JSON.stringify(files)}\n`, "utf8"));
}

function assertHash(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertArtifactManifestShape(artifactManifest) {
  assertExactKeys(
    artifactManifest,
    ["schema", "source", "toolchain", "extension", "payload", "archive", "dependencyEvidence", "bundleInputEvidence", "staticInputEvidence", "releaseRecipeInputEvidence"],
    "artifact manifest",
  );
  if (artifactManifest.schema !== ARTIFACT_SCHEMA) {
    fail(`unsupported artifact manifest schema: ${String(artifactManifest.schema)}`);
  }
  assertExactKeys(artifactManifest.source, ["gitCommit", "lockfileSha256"], "artifact source");
  if (typeof artifactManifest.source.gitCommit !== "string" || !/^[0-9a-f]{40}$/.test(artifactManifest.source.gitCommit)) {
    fail("artifact source gitCommit must be a full lowercase commit SHA");
  }
  assertHash(artifactManifest.source.lockfileSha256, "artifact source lockfileSha256");
  assertExactKeys(artifactManifest.toolchain, ["node", "pnpm", "esbuild"], "artifact toolchain");
  for (const name of ["node", "pnpm", "esbuild"]) {
    if (typeof artifactManifest.toolchain[name] !== "string" || !/^\d+\.\d+\.\d+$/.test(artifactManifest.toolchain[name])) {
      fail(`artifact toolchain ${name} must be an exact semantic version`);
    }
  }
  assertExactKeys(
    artifactManifest.extension,
    ["manifestVersion", "version", "permissions", "contentSecurityPolicy", "updateUrl"],
    "artifact extension",
  );
  if (
    artifactManifest.extension.manifestVersion !== 3 ||
    typeof artifactManifest.extension.version !== "string" ||
    !jsonEqual(artifactManifest.extension.permissions, EXPECTED_RELEASE_PERMISSIONS) ||
    !jsonEqual(artifactManifest.extension.contentSecurityPolicy, EXPECTED_RELEASE_CSP) ||
    artifactManifest.extension.updateUrl !== null
  ) {
    fail("artifact extension policy is not the reviewed MV3 release policy");
  }
  assertExactKeys(artifactManifest.payload, ["timestamp", "treeSha256", "files"], "artifact payload");
  if (artifactManifest.payload.timestamp !== CANONICAL_TIMESTAMP || !Array.isArray(artifactManifest.payload.files) || artifactManifest.payload.files.length === 0) {
    fail("artifact payload timestamp or file list is invalid");
  }
  assertHash(artifactManifest.payload.treeSha256, "artifact payload treeSha256");
  let previousPath;
  for (const file of artifactManifest.payload.files) {
    assertExactKeys(file, ["path", "bytes", "mode", "sha256"], "artifact payload file");
    assertSafeArtifactPath(file.path);
    if (previousPath !== undefined && compareUtf8Paths(previousPath, file.path) >= 0) {
      fail("artifact payload files are not unique and canonically sorted");
    }
    previousPath = file.path;
    if (!Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > MAX_ENTRY_BYTES || file.mode !== "0644") {
      fail(`artifact payload metadata is invalid for ${file.path}`);
    }
    assertHash(file.sha256, `artifact payload hash for ${file.path}`);
  }
  if (!artifactManifest.payload.files.some((file) => file.path === "manifest.json")) {
    fail("artifact payload does not contain root manifest.json");
  }
  if (payloadTreeHash(artifactManifest.payload.files) !== artifactManifest.payload.treeSha256) {
    fail("artifact payload tree digest is inconsistent");
  }
  assertExactKeys(artifactManifest.archive, ["file", "format", "bytes", "sha256"], "artifact archive");
  if (
    typeof artifactManifest.archive.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.zip$/.test(artifactManifest.archive.file) ||
    artifactManifest.archive.format !== "zip-store-v1" ||
    !Number.isSafeInteger(artifactManifest.archive.bytes) ||
    artifactManifest.archive.bytes <= 0 ||
    artifactManifest.archive.bytes > MAX_ZIP_VALUE
  ) {
    fail("artifact archive metadata is invalid");
  }
  assertHash(artifactManifest.archive.sha256, "artifact archive sha256");
  assertExactKeys(
    artifactManifest.dependencyEvidence,
    ["file", "schema", "bytes", "sha256"],
    "artifact dependency evidence",
  );
  if (
    typeof artifactManifest.dependencyEvidence.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.sbom\.json$/.test(artifactManifest.dependencyEvidence.file) ||
    artifactManifest.dependencyEvidence.schema !== PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(artifactManifest.dependencyEvidence.bytes) ||
    artifactManifest.dependencyEvidence.bytes <= 0 ||
    artifactManifest.dependencyEvidence.bytes > MAX_ENTRY_BYTES
  ) {
    fail("artifact dependency evidence metadata is invalid");
  }
  assertHash(
    artifactManifest.dependencyEvidence.sha256,
    "artifact dependency evidence sha256",
  );
  assertExactKeys(
    artifactManifest.bundleInputEvidence,
    ["file", "schema", "bytes", "sha256"],
    "artifact bundle input evidence",
  );
  if (
    typeof artifactManifest.bundleInputEvidence.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.bundle-inputs\.json$/.test(artifactManifest.bundleInputEvidence.file) ||
    artifactManifest.bundleInputEvidence.schema !== JS_BUNDLE_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(artifactManifest.bundleInputEvidence.bytes) ||
    artifactManifest.bundleInputEvidence.bytes <= 0 ||
    artifactManifest.bundleInputEvidence.bytes > MAX_ENTRY_BYTES
  ) {
    fail("artifact bundle input evidence metadata is invalid");
  }
  assertHash(
    artifactManifest.bundleInputEvidence.sha256,
    "artifact bundle input evidence sha256",
  );
  assertExactKeys(
    artifactManifest.staticInputEvidence,
    ["file", "schema", "bytes", "sha256"],
    "artifact static input evidence",
  );
  if (
    typeof artifactManifest.staticInputEvidence.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.static-inputs\.json$/.test(artifactManifest.staticInputEvidence.file) ||
    artifactManifest.staticInputEvidence.schema !== STATIC_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(artifactManifest.staticInputEvidence.bytes) ||
    artifactManifest.staticInputEvidence.bytes <= 0 ||
    artifactManifest.staticInputEvidence.bytes > MAX_ENTRY_BYTES
  ) {
    fail("artifact static input evidence metadata is invalid");
  }
  assertHash(
    artifactManifest.staticInputEvidence.sha256,
    "artifact static input evidence sha256",
  );
  assertExactKeys(
    artifactManifest.releaseRecipeInputEvidence,
    ["file", "schema", "bytes", "sha256"],
    "artifact release recipe input evidence",
  );
  if (
    typeof artifactManifest.releaseRecipeInputEvidence.file !== "string" ||
    !/^[A-Za-z0-9._-]+\.recipe-inputs\.json$/.test(artifactManifest.releaseRecipeInputEvidence.file) ||
    artifactManifest.releaseRecipeInputEvidence.schema !== RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA ||
    !Number.isSafeInteger(artifactManifest.releaseRecipeInputEvidence.bytes) ||
    artifactManifest.releaseRecipeInputEvidence.bytes <= 0 ||
    artifactManifest.releaseRecipeInputEvidence.bytes > MAX_ENTRY_BYTES
  ) {
    fail("artifact release recipe input evidence metadata is invalid");
  }
  assertHash(
    artifactManifest.releaseRecipeInputEvidence.sha256,
    "artifact release recipe input evidence sha256",
  );
}

export function createArtifactManifest({
  entries,
  archiveBytes,
  artifactFileName,
  source,
  toolchain,
  dependencyEvidence,
  bundleInputEvidence,
  staticInputEvidence,
  releaseRecipeInputEvidence,
}) {
  const canonical = canonicalizeEntries(entries).map(({ path, data }) => ({ path, data }));
  const parsedArchive = parseCanonicalZip(archiveBytes);
  if (
    canonical.length !== parsedArchive.length ||
    canonical.some((entry, index) => entry.path !== parsedArchive[index].path || !entry.data.equals(parsedArchive[index].data))
  ) {
    fail("archive payload does not equal the files being attested");
  }
  const files = payloadFileRecords(canonical);
  if (
    !isPlainObject(dependencyEvidence) ||
    typeof dependencyEvidence.file !== "string" ||
    !(dependencyEvidence.bytes instanceof Uint8Array) ||
    dependencyEvidence.bytes.length === 0
  ) {
    fail("dependency evidence attachment must provide a file name and non-empty bytes");
  }
  if (
    !isPlainObject(bundleInputEvidence) ||
    typeof bundleInputEvidence.file !== "string" ||
    !(bundleInputEvidence.bytes instanceof Uint8Array) ||
    bundleInputEvidence.bytes.length === 0
  ) {
    fail("bundle input evidence attachment must provide a file name and non-empty bytes");
  }
  if (
    !isPlainObject(staticInputEvidence) ||
    typeof staticInputEvidence.file !== "string" ||
    !(staticInputEvidence.bytes instanceof Uint8Array) ||
    staticInputEvidence.bytes.length === 0
  ) {
    fail("static input evidence attachment must provide a file name and non-empty bytes");
  }
  if (
    !isPlainObject(releaseRecipeInputEvidence) ||
    typeof releaseRecipeInputEvidence.file !== "string" ||
    !(releaseRecipeInputEvidence.bytes instanceof Uint8Array) ||
    releaseRecipeInputEvidence.bytes.length === 0
  ) {
    fail("release recipe input evidence attachment must provide a file name and non-empty bytes");
  }
  const artifactManifest = {
    schema: ARTIFACT_SCHEMA,
    source: {
      gitCommit: source?.gitCommit,
      lockfileSha256: source?.lockfileSha256,
    },
    toolchain: {
      node: toolchain?.node,
      pnpm: toolchain?.pnpm,
      esbuild: toolchain?.esbuild,
    },
    extension: extensionSnapshot(parseExtensionManifest(canonical)),
    payload: {
      timestamp: CANONICAL_TIMESTAMP,
      treeSha256: payloadTreeHash(files),
      files,
    },
    archive: {
      file: artifactFileName,
      format: "zip-store-v1",
      bytes: archiveBytes.length,
      sha256: sha256(archiveBytes),
    },
    dependencyEvidence: {
      file: dependencyEvidence.file,
      schema: PRODUCTION_DEPENDENCY_EVIDENCE_SCHEMA,
      bytes: dependencyEvidence.bytes.length,
      sha256: sha256(dependencyEvidence.bytes),
    },
    bundleInputEvidence: {
      file: bundleInputEvidence.file,
      schema: JS_BUNDLE_INPUT_EVIDENCE_SCHEMA,
      bytes: bundleInputEvidence.bytes.length,
      sha256: sha256(bundleInputEvidence.bytes),
    },
    staticInputEvidence: {
      file: staticInputEvidence.file,
      schema: STATIC_INPUT_EVIDENCE_SCHEMA,
      bytes: staticInputEvidence.bytes.length,
      sha256: sha256(staticInputEvidence.bytes),
    },
    releaseRecipeInputEvidence: {
      file: releaseRecipeInputEvidence.file,
      schema: RELEASE_RECIPE_INPUT_EVIDENCE_SCHEMA,
      bytes: releaseRecipeInputEvidence.bytes.length,
      sha256: sha256(releaseRecipeInputEvidence.bytes),
    },
  };
  assertArtifactManifestShape(artifactManifest);
  return artifactManifest;
}

export function serializeArtifactManifest(artifactManifest) {
  assertArtifactManifestShape(artifactManifest);
  return `${JSON.stringify(artifactManifest, null, 2)}\n`;
}

export function parseArtifactManifest(bytes) {
  const artifactBytes = Buffer.from(bytes);
  const artifactText = artifactBytes.toString("utf8");
  if (!Buffer.from(artifactText, "utf8").equals(artifactBytes)) {
    fail("artifact manifest is not canonical UTF-8");
  }
  let artifactManifest;
  try {
    artifactManifest = JSON.parse(artifactText);
  } catch (error) {
    fail(`artifact manifest is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertArtifactManifestShape(artifactManifest);
  if (artifactText !== serializeArtifactManifest(artifactManifest)) {
    fail("artifact manifest must use the canonical generated JSON serialization");
  }
  return artifactManifest;
}

export function verifyArtifactPayloadEntries({ entries, artifactManifest }) {
  assertArtifactManifestShape(artifactManifest);
  const canonicalEntries = canonicalizeEntries(entries).map(({ path, data }) => ({ path, data }));
  const candidatePaths = canonicalEntries.map((entry) => entry.path);
  const reviewedPaths = artifactManifest.payload.files.map((entry) => entry.path);
  if (!jsonEqual(candidatePaths, reviewedPaths)) {
    fail("candidate payload path set differs from the reviewed artifact");
  }

  const candidateExtension = extensionSnapshot(parseExtensionManifest(canonicalEntries));
  if (!jsonEqual(candidateExtension.permissions, artifactManifest.extension.permissions)) {
    fail("candidate manifest permissions differ from the reviewed artifact");
  }
  if (!jsonEqual(candidateExtension.contentSecurityPolicy, artifactManifest.extension.contentSecurityPolicy)) {
    fail("candidate manifest content security policy differs from the reviewed artifact");
  }
  if (candidateExtension.updateUrl !== artifactManifest.extension.updateUrl) {
    fail("candidate manifest update URL differs from the reviewed artifact");
  }
  if (
    candidateExtension.manifestVersion !== artifactManifest.extension.manifestVersion ||
    candidateExtension.version !== artifactManifest.extension.version
  ) {
    fail("candidate extension identity differs from the reviewed artifact");
  }

  const candidateFiles = payloadFileRecords(canonicalEntries);
  for (let index = 0; index < candidateFiles.length; index += 1) {
    const candidate = candidateFiles[index];
    const reviewed = artifactManifest.payload.files[index];
    if (
      candidate.path !== reviewed.path ||
      candidate.bytes !== reviewed.bytes ||
      candidate.mode !== reviewed.mode ||
      candidate.sha256 !== reviewed.sha256
    ) {
      fail(`candidate file differs from the reviewed artifact: ${candidate.path}`);
    }
  }
  if (payloadTreeHash(candidateFiles) !== artifactManifest.payload.treeSha256) {
    fail("candidate payload tree digest differs from the reviewed artifact");
  }
  return {
    treeSha256: artifactManifest.payload.treeSha256,
    files: candidateFiles.length,
  };
}

export function verifyArtifactArchive({ archiveBytes, artifactManifest }) {
  const entries = parseCanonicalZip(archiveBytes);
  const payload = verifyArtifactPayloadEntries({ entries, artifactManifest });
  if (archiveBytes.length !== artifactManifest.archive.bytes || sha256(archiveBytes) !== artifactManifest.archive.sha256) {
    fail("candidate ZIP bytes differ from the reviewed canonical archive");
  }
  return {
    archiveSha256: artifactManifest.archive.sha256,
    treeSha256: payload.treeSha256,
    files: payload.files,
  };
}

export async function verifyCanonicalUnpacked({ rootDirectory, artifactManifest }) {
  assertArtifactManifestShape(artifactManifest);

  async function inspectMetadata(directory, prefix = "") {
    const directoryStat = await lstat(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
      fail(`unpacked directory is not a real directory: ${prefix || "."}`);
    }
    if ((directoryStat.mode & 0o777) !== CANONICAL_DIRECTORY_MODE) {
      fail(`unpacked directory does not use canonical mode 0755: ${prefix || "."}`);
    }
    if (directoryStat.mtime.getTime() !== CANONICAL_DATE.getTime()) {
      fail(`unpacked directory does not use canonical timestamp: ${prefix || "."}`);
    }
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => compareUtf8Paths(left.name, right.name));
    for (const child of children) {
      const relativePath = prefix === "" ? child.name : `${prefix}/${child.name}`;
      assertSafeArtifactPath(relativePath);
      const absolutePath = join(directory, child.name);
      const childStat = await lstat(absolutePath);
      if (childStat.isSymbolicLink()) {
        fail(`symlink is forbidden in unpacked payload: ${relativePath}`);
      }
      if (childStat.isDirectory()) {
        await inspectMetadata(absolutePath, relativePath);
      } else if (childStat.isFile()) {
        if ((childStat.mode & 0o777) !== CANONICAL_FILE_MODE) {
          fail(`unpacked file does not use canonical mode 0644: ${relativePath}`);
        }
        if (childStat.mtime.getTime() !== CANONICAL_DATE.getTime()) {
          fail(`unpacked file does not use canonical timestamp: ${relativePath}`);
        }
      } else {
        fail(`non-regular unpacked payload entry: ${relativePath}`);
      }
    }
  }

  await inspectMetadata(rootDirectory);
  const entries = await collectCanonicalPayload(rootDirectory);
  return verifyArtifactArchive({
    archiveBytes: createCanonicalZip(entries),
    artifactManifest,
  });
}
