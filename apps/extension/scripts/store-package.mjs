import {
  constants as cryptoConstants,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import { inflateRawSync } from "node:zlib";

import { verifyArtifactPayloadEntries } from "./release-artifact.mjs";

export const OFFICIAL_CHROME_WEB_STORE_PUBLISHER_KEY_SHA256 =
  "61f7f2a6bfcf74cd0bc1fe2497cc9b04254c658f79f2145392867ea8366367cf";

const CRX3_MAGIC = Buffer.from("Cr24", "ascii");
const CRX3_VERSION = 3;
const CRX3_FIXED_HEADER_BYTES = 12;
const CRX3_SIGNATURE_CONTEXT = Buffer.from("CRX3 SignedData\0", "utf8");
const MAX_CRX3_HEADER_BYTES = 1 << 18;
export const MAX_CRX3_PACKAGE_BYTES = 512 * 1024 * 1024;
const MAX_CRX3_PROOFS = 16;
const MAX_KEY_OR_SIGNATURE_BYTES = 1 << 16;

const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE = Buffer.from([0x50, 0x4b, 0x06, 0x06]);
const ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR = Buffer.from([0x50, 0x4b, 0x06, 0x07]);
const ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
const ZIP_UTF8_FLAG = 0x0800;
const ZIP_DATA_DESCRIPTOR_FLAG = 0x0008;
const ZIP_DEFLATE_OPTION_FLAGS = 0x0006;
const ZIP_ALLOWED_FLAGS = ZIP_UTF8_FLAG | ZIP_DATA_DESCRIPTOR_FLAG | ZIP_DEFLATE_OPTION_FLAGS;
const ZIP_STORE_METHOD = 0;
const ZIP_DEFLATE_METHOD = 8;
const MAX_ZIP_ENTRIES = 4096;
const MAX_ENTRY_BYTES = 256 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024;

const CRC32_TABLE = new Uint32Array(256);
for (let index = 0; index < CRC32_TABLE.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  }
  CRC32_TABLE[index] = value >>> 0;
}

function fail(message) {
  throw new Error(`extension store package: ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function crc32(bytes) {
  let checksum = 0xffffffff;
  for (const byte of bytes) {
    checksum = CRC32_TABLE[(checksum ^ byte) & 0xff] ^ (checksum >>> 8);
  }
  return (checksum ^ 0xffffffff) >>> 0;
}

function assertBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    fail(`${label} must be byte data`);
  }
}

function assertHash(value, label) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`);
  }
}

function assertReadable(bytes, offset, length, label) {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset > bytes.length - length
  ) {
    fail(`truncated ${label}`);
  }
}

function readUInt16LE(bytes, offset, label) {
  assertReadable(bytes, offset, 2, label);
  return bytes.readUInt16LE(offset);
}

function readUInt32LE(bytes, offset, label) {
  assertReadable(bytes, offset, 4, label);
  return bytes.readUInt32LE(offset);
}

function readVarint(bytes, start, label) {
  let value = 0n;
  let shift = 0n;
  for (let index = 0; index < 10; index += 1) {
    assertReadable(bytes, start + index, 1, label);
    const byte = bytes[start + index];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      if (index > 0 && byte === 0) {
        fail(`${label} is a non-minimal protobuf varint`);
      }
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        fail(`${label} exceeds the safe integer range`);
      }
      return { value: Number(value), cursor: start + index + 1 };
    }
    shift += 7n;
  }
  fail(`${label} is an overlong protobuf varint`);
}

function parseLengthDelimitedFields(bytes, label) {
  const fields = [];
  let cursor = 0;
  while (cursor < bytes.length) {
    const key = readVarint(bytes, cursor, `${label} field key`);
    cursor = key.cursor;
    const fieldNumber = Math.floor(key.value / 8);
    const wireType = key.value & 0x07;
    if (fieldNumber === 0 || wireType !== 2) {
      fail(`${label} contains an unsupported protobuf field or wire type`);
    }
    const length = readVarint(bytes, cursor, `${label} field length`);
    cursor = length.cursor;
    assertReadable(bytes, cursor, length.value, `${label} field data`);
    fields.push({ fieldNumber, data: Buffer.from(bytes.subarray(cursor, cursor + length.value)) });
    cursor += length.value;
  }
  return fields;
}

function parseProof(bytes, algorithm) {
  const fields = parseLengthDelimitedFields(bytes, `${algorithm} proof`);
  const publicKeys = fields.filter((field) => field.fieldNumber === 1);
  const signatures = fields.filter((field) => field.fieldNumber === 2);
  if (fields.length !== 2 || publicKeys.length !== 1 || signatures.length !== 1) {
    fail(`${algorithm} proof must contain exactly one public_key and one signature`);
  }
  const publicKey = publicKeys[0].data;
  const signature = signatures[0].data;
  if (
    publicKey.length === 0 ||
    signature.length === 0 ||
    publicKey.length > MAX_KEY_OR_SIGNATURE_BYTES ||
    signature.length > MAX_KEY_OR_SIGNATURE_BYTES
  ) {
    fail(`${algorithm} proof key or signature length is invalid`);
  }
  return {
    algorithm,
    publicKey,
    signature,
    keySha256: sha256(publicKey),
  };
}

function parseSignedData(bytes) {
  const fields = parseLengthDelimitedFields(bytes, "CRX3 signed data");
  const crxIds = fields.filter((field) => field.fieldNumber === 1);
  if (fields.length !== 1 || crxIds.length !== 1 || crxIds[0].data.length !== 16) {
    fail("CRX3 signed data must contain exactly one 16-byte crx_id");
  }
  return crxIds[0].data;
}

function extensionIdFromCrxId(crxId) {
  let extensionId = "";
  for (const byte of crxId) {
    extensionId += String.fromCharCode(97 + (byte >>> 4), 97 + (byte & 0x0f));
  }
  return extensionId;
}

function verifyProof(proof, signedBytes) {
  let publicKey;
  try {
    publicKey = createPublicKey({ key: proof.publicKey, format: "der", type: "spki" });
  } catch (error) {
    fail(`invalid ${proof.algorithm} public key: ${error instanceof Error ? error.message : String(error)}`);
  }
  let verified = false;
  if (proof.algorithm === "rsa") {
    if (publicKey.asymmetricKeyType !== "rsa") {
      fail("CRX3 RSA proof does not contain an RSA public key");
    }
    verified = verifySignature(
      "sha256",
      signedBytes,
      { key: publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      proof.signature,
    );
  } else {
    if (
      publicKey.asymmetricKeyType !== "ec" ||
      !["prime256v1", "P-256"].includes(publicKey.asymmetricKeyDetails?.namedCurve)
    ) {
      fail("CRX3 ECDSA proof must use the NIST P-256 curve");
    }
    verified = verifySignature("sha256", signedBytes, publicKey, proof.signature);
  }
  if (!verified) {
    fail(`CRX3 ${proof.algorithm} signature verification failed`);
  }
}

function containsZipEndToken(headerBytes) {
  return [
    ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE,
    ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR,
    ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE,
  ].some((token) => headerBytes.indexOf(token) !== -1);
}

export function parseAndVerifyCrx3({
  crxBytes,
  requiredPublisherKeySha256 = OFFICIAL_CHROME_WEB_STORE_PUBLISHER_KEY_SHA256,
}) {
  assertBytes(crxBytes, "CRX3 package");
  assertHash(requiredPublisherKeySha256, "required publisher key hash");
  const crx = Buffer.from(crxBytes);
  if (crx.length > MAX_CRX3_PACKAGE_BYTES) {
    fail(`CRX3 package exceeds the ${MAX_CRX3_PACKAGE_BYTES}-byte limit`);
  }
  assertReadable(crx, 0, CRX3_FIXED_HEADER_BYTES, "CRX3 fixed header");
  if (!crx.subarray(0, 4).equals(CRX3_MAGIC)) {
    fail("CRX3 magic must be Cr24");
  }
  if (readUInt32LE(crx, 4, "CRX3 version") !== CRX3_VERSION) {
    fail("CRX3 version must be 3");
  }
  const headerBytesLength = readUInt32LE(crx, 8, "CRX3 header length");
  if (headerBytesLength === 0 || headerBytesLength > MAX_CRX3_HEADER_BYTES) {
    fail(`CRX3 header length must be between 1 and ${MAX_CRX3_HEADER_BYTES} bytes`);
  }
  const archiveOffset = CRX3_FIXED_HEADER_BYTES + headerBytesLength;
  assertReadable(crx, CRX3_FIXED_HEADER_BYTES, headerBytesLength, "CRX3 protobuf header");
  if (archiveOffset >= crx.length) {
    fail("CRX3 package has no embedded ZIP archive");
  }
  const headerBytes = Buffer.from(crx.subarray(CRX3_FIXED_HEADER_BYTES, archiveOffset));
  if (containsZipEndToken(headerBytes)) {
    fail("CRX3 protobuf header contains an ambiguous ZIP end-record token");
  }
  const archiveBytes = Buffer.from(crx.subarray(archiveOffset));
  const fields = parseLengthDelimitedFields(headerBytes, "CRX3 file header");
  const proofs = [];
  let signedDataBytes;
  let verifiedContentsCount = 0;
  for (const field of fields) {
    if (field.fieldNumber === 2 || field.fieldNumber === 3) {
      proofs.push(parseProof(field.data, field.fieldNumber === 2 ? "rsa" : "ecdsa"));
    } else if (field.fieldNumber === 4) {
      verifiedContentsCount += 1;
    } else if (field.fieldNumber === 10000) {
      if (signedDataBytes !== undefined) {
        fail("CRX3 file header contains duplicate signed_header_data");
      }
      signedDataBytes = field.data;
    } else {
      fail(`CRX3 file header contains unsupported field ${field.fieldNumber}`);
    }
  }
  if (proofs.length === 0 || proofs.length > MAX_CRX3_PROOFS) {
    fail(`CRX3 file header must contain between 1 and ${MAX_CRX3_PROOFS} proofs`);
  }
  if (verifiedContentsCount > 1) {
    fail("CRX3 file header contains duplicate verified_contents");
  }
  if (signedDataBytes === undefined || signedDataBytes.length === 0) {
    fail("CRX3 file header is missing signed_header_data");
  }
  const crxId = parseSignedData(signedDataBytes);
  const signedDataLength = Buffer.alloc(4);
  signedDataLength.writeUInt32LE(signedDataBytes.length, 0);
  const signedBytes = Buffer.concat([
    CRX3_SIGNATURE_CONTEXT,
    signedDataLength,
    signedDataBytes,
    archiveBytes,
  ]);
  for (const proof of proofs) {
    verifyProof(proof, signedBytes);
  }
  const developerProofs = proofs.filter((proof) =>
    Buffer.from(proof.keySha256, "hex").subarray(0, 16).equals(crxId),
  );
  if (developerProofs.length !== 1) {
    fail("CRX3 file header must contain exactly one proof matching the declared crx_id");
  }
  const publisherProofs = proofs.filter(
    (proof) => proof.keySha256 === requiredPublisherKeySha256,
  );
  if (publisherProofs.length !== 1) {
    fail("CRX3 file header must contain exactly one required Chrome Web Store publisher proof");
  }
  return {
    archiveBytes,
    archiveOffset,
    archiveSha256: sha256(archiveBytes),
    crxId: crxId.toString("hex"),
    extensionId: extensionIdFromCrxId(crxId),
    headerBytes: headerBytes.length,
    headerSha256: sha256(headerBytes),
    packageBytes: crx.length,
    packageSha256: sha256(crx),
    proofs: proofs.length,
    publisherKeySha256: requiredPublisherKeySha256,
  };
}

function assertSafePath(path) {
  if (
    path.length === 0 ||
    path.includes("\\") ||
    path.includes("\0") ||
    path.startsWith("/") ||
    path.endsWith("/") ||
    /^[A-Za-z]:/.test(path) ||
    path.split("/").some((part) => part === "" || part === "." || part === "..")
  ) {
    fail(`unsafe embedded ZIP path: ${JSON.stringify(path)}`);
  }
}

function decodePath(pathBytes, flags, label) {
  if ((flags & ZIP_UTF8_FLAG) === 0 && pathBytes.some((byte) => byte > 0x7f)) {
    fail(`${label} uses an unsupported legacy filename encoding`);
  }
  const path = pathBytes.toString("utf8");
  if (!Buffer.from(path, "utf8").equals(pathBytes)) {
    fail(`${label} is not canonical UTF-8`);
  }
  assertSafePath(path);
  return path;
}

function assertZipFlags(flags, method, label) {
  if ((flags & ~ZIP_ALLOWED_FLAGS) !== 0) {
    fail(`${label} uses encrypted or unsupported general-purpose flags`);
  }
  if (method !== ZIP_DEFLATE_METHOD && (flags & ZIP_DEFLATE_OPTION_FLAGS) !== 0) {
    fail(`${label} uses deflate option flags with a non-deflate method`);
  }
}

function assertExtraFields(extraBytes, label) {
  let cursor = 0;
  while (cursor < extraBytes.length) {
    assertReadable(extraBytes, cursor, 4, `${label} extra field`);
    const id = extraBytes.readUInt16LE(cursor);
    const length = extraBytes.readUInt16LE(cursor + 2);
    cursor += 4;
    assertReadable(extraBytes, cursor, length, `${label} extra field data`);
    if (![0x000a, 0x5455].includes(id)) {
      fail(`${label} contains unsupported or semantic extra field 0x${id.toString(16).padStart(4, "0")}`);
    }
    cursor += length;
  }
}

function decompressEntry(record, compressedBytes) {
  let data;
  if (record.method === ZIP_STORE_METHOD) {
    if (record.compressedSize !== record.uncompressedSize) {
      fail(`stored embedded ZIP entry has unequal sizes: ${record.path}`);
    }
    data = Buffer.from(compressedBytes);
  } else if (record.method === ZIP_DEFLATE_METHOD) {
    try {
      data = inflateRawSync(compressedBytes, {
        maxOutputLength: Math.min(record.uncompressedSize + 1, MAX_ENTRY_BYTES + 1),
      });
    } catch (error) {
      fail(`cannot inflate embedded ZIP entry ${record.path}: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else {
    fail(`unsupported embedded ZIP compression method ${record.method} for ${record.path}`);
  }
  if (data.length !== record.uncompressedSize) {
    fail(`embedded ZIP uncompressed size differs for ${record.path}`);
  }
  if (crc32(data) !== record.checksum) {
    fail(`embedded ZIP CRC-32 differs for ${record.path}`);
  }
  return data;
}

function verifyDataDescriptor(bytes, start, end, record) {
  const length = end - start;
  let cursor = start;
  if (length === 16 && readUInt32LE(bytes, cursor, "ZIP data descriptor") === 0x08074b50) {
    cursor += 4;
  } else if (length !== 12) {
    fail(`embedded ZIP data descriptor length differs for ${record.path}`);
  }
  if (
    readUInt32LE(bytes, cursor, "ZIP data descriptor CRC") !== record.checksum ||
    readUInt32LE(bytes, cursor + 4, "ZIP data descriptor compressed size") !== record.compressedSize ||
    readUInt32LE(bytes, cursor + 8, "ZIP data descriptor uncompressed size") !== record.uncompressedSize
  ) {
    fail(`embedded ZIP data descriptor differs for ${record.path}`);
  }
}

export function parseStoreZip(archiveBytes) {
  assertBytes(archiveBytes, "embedded ZIP archive");
  const archive = Buffer.from(archiveBytes);
  if (archive.length < 22) {
    fail("embedded ZIP has a truncated end of central directory");
  }
  const endOffset = archive.length - 22;
  if (readUInt32LE(archive, endOffset, "ZIP end of central directory") !== END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
    fail("embedded ZIP must end at an unambiguous classic end of central directory");
  }
  const disk = readUInt16LE(archive, endOffset + 4, "ZIP end of central directory");
  const centralDisk = readUInt16LE(archive, endOffset + 6, "ZIP end of central directory");
  const diskEntries = readUInt16LE(archive, endOffset + 8, "ZIP end of central directory");
  const totalEntries = readUInt16LE(archive, endOffset + 10, "ZIP end of central directory");
  const centralSize = readUInt32LE(archive, endOffset + 12, "ZIP end of central directory");
  const centralOffset = readUInt32LE(archive, endOffset + 16, "ZIP end of central directory");
  const commentLength = readUInt16LE(archive, endOffset + 20, "ZIP end of central directory");
  if (
    disk !== 0 ||
    centralDisk !== 0 ||
    diskEntries !== totalEntries ||
    totalEntries === 0 ||
    totalEntries > MAX_ZIP_ENTRIES ||
    commentLength !== 0
  ) {
    fail("embedded ZIP must be single-disk, nonempty, bounded, and uncommented");
  }
  if (centralOffset + centralSize !== endOffset) {
    fail("embedded ZIP central directory offset or size is inconsistent");
  }

  const records = [];
  const paths = new Set();
  let centralCursor = centralOffset;
  let totalUncompressedBytes = 0;
  for (let index = 0; index < totalEntries; index += 1) {
    assertReadable(archive, centralCursor, 46, "ZIP central directory header");
    if (readUInt32LE(archive, centralCursor, "ZIP central directory header") !== CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      fail("embedded ZIP central directory header signature is invalid");
    }
    const flags = readUInt16LE(archive, centralCursor + 8, "ZIP central directory flags");
    const method = readUInt16LE(archive, centralCursor + 10, "ZIP central directory method");
    assertZipFlags(flags, method, "embedded ZIP central directory entry");
    if (![ZIP_STORE_METHOD, ZIP_DEFLATE_METHOD].includes(method)) {
      fail(`unsupported embedded ZIP compression method ${method}`);
    }
    const checksum = readUInt32LE(archive, centralCursor + 16, "ZIP central directory CRC");
    const compressedSize = readUInt32LE(archive, centralCursor + 20, "ZIP central directory size");
    const uncompressedSize = readUInt32LE(archive, centralCursor + 24, "ZIP central directory size");
    const pathLength = readUInt16LE(archive, centralCursor + 28, "ZIP central directory path length");
    const extraLength = readUInt16LE(archive, centralCursor + 30, "ZIP central directory extra length");
    const entryCommentLength = readUInt16LE(archive, centralCursor + 32, "ZIP central directory comment length");
    const entryDisk = readUInt16LE(archive, centralCursor + 34, "ZIP central directory disk");
    const localOffset = readUInt32LE(archive, centralCursor + 42, "ZIP local entry offset");
    if (
      compressedSize === 0xffffffff ||
      uncompressedSize === 0xffffffff ||
      localOffset === 0xffffffff ||
      compressedSize > archive.length ||
      uncompressedSize > MAX_ENTRY_BYTES
    ) {
      fail("embedded ZIP uses ZIP64 or exceeds bounded entry sizes");
    }
    if (entryCommentLength !== 0 || entryDisk !== 0 || pathLength === 0) {
      fail("embedded ZIP entry has a comment, another disk, or an empty path");
    }
    assertReadable(archive, centralCursor + 46, pathLength + extraLength, "ZIP central directory variable data");
    const pathBytes = Buffer.from(archive.subarray(centralCursor + 46, centralCursor + 46 + pathLength));
    const path = decodePath(pathBytes, flags, "embedded ZIP central directory path");
    if (paths.has(path)) {
      fail(`duplicate embedded ZIP path: ${path}`);
    }
    paths.add(path);
    const extraBytes = archive.subarray(
      centralCursor + 46 + pathLength,
      centralCursor + 46 + pathLength + extraLength,
    );
    assertExtraFields(extraBytes, `embedded ZIP central entry ${path}`);
    totalUncompressedBytes += uncompressedSize;
    if (totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
      fail("embedded ZIP exceeds the total uncompressed byte limit");
    }
    records.push({
      path,
      pathBytes,
      flags,
      method,
      checksum,
      compressedSize,
      uncompressedSize,
      localOffset,
    });
    centralCursor += 46 + pathLength + extraLength;
  }
  if (centralCursor !== endOffset) {
    fail("embedded ZIP central directory contains trailing or unparsed bytes");
  }

  const byLocalOffset = [...records].sort((left, right) => left.localOffset - right.localOffset);
  if (byLocalOffset[0].localOffset !== 0) {
    fail("embedded ZIP contains bytes before the first local entry");
  }
  const entries = [];
  for (let index = 0; index < byLocalOffset.length; index += 1) {
    const record = byLocalOffset[index];
    const nextOffset = byLocalOffset[index + 1]?.localOffset ?? centralOffset;
    assertReadable(archive, record.localOffset, 30, `ZIP local header ${record.path}`);
    if (readUInt32LE(archive, record.localOffset, `ZIP local header ${record.path}`) !== LOCAL_FILE_HEADER_SIGNATURE) {
      fail(`embedded ZIP local header signature is invalid for ${record.path}`);
    }
    const flags = readUInt16LE(archive, record.localOffset + 6, `ZIP local flags ${record.path}`);
    const method = readUInt16LE(archive, record.localOffset + 8, `ZIP local method ${record.path}`);
    const localChecksum = readUInt32LE(archive, record.localOffset + 14, `ZIP local CRC ${record.path}`);
    const localCompressedSize = readUInt32LE(archive, record.localOffset + 18, `ZIP local size ${record.path}`);
    const localUncompressedSize = readUInt32LE(archive, record.localOffset + 22, `ZIP local size ${record.path}`);
    const pathLength = readUInt16LE(archive, record.localOffset + 26, `ZIP local path length ${record.path}`);
    const extraLength = readUInt16LE(archive, record.localOffset + 28, `ZIP local extra length ${record.path}`);
    assertZipFlags(flags, method, `embedded ZIP local entry ${record.path}`);
    if (flags !== record.flags || method !== record.method || pathLength !== record.pathBytes.length) {
      fail(`embedded ZIP local and central metadata differ for ${record.path}`);
    }
    const usesDescriptor = (flags & ZIP_DATA_DESCRIPTOR_FLAG) !== 0;
    if (
      (!usesDescriptor && (
        localChecksum !== record.checksum ||
        localCompressedSize !== record.compressedSize ||
        localUncompressedSize !== record.uncompressedSize
      )) ||
      (usesDescriptor && (
        ![0, record.checksum].includes(localChecksum) ||
        ![0, record.compressedSize].includes(localCompressedSize) ||
        ![0, record.uncompressedSize].includes(localUncompressedSize)
      ))
    ) {
      fail(`embedded ZIP local sizes or CRC differ for ${record.path}`);
    }
    assertReadable(
      archive,
      record.localOffset + 30,
      pathLength + extraLength + record.compressedSize,
      `ZIP local entry ${record.path}`,
    );
    const localPath = archive.subarray(record.localOffset + 30, record.localOffset + 30 + pathLength);
    if (!localPath.equals(record.pathBytes)) {
      fail(`embedded ZIP local and central paths differ for ${record.path}`);
    }
    const localExtraStart = record.localOffset + 30 + pathLength;
    assertExtraFields(
      archive.subarray(localExtraStart, localExtraStart + extraLength),
      `embedded ZIP local entry ${record.path}`,
    );
    const dataStart = localExtraStart + extraLength;
    const dataEnd = dataStart + record.compressedSize;
    if (usesDescriptor) {
      verifyDataDescriptor(archive, dataEnd, nextOffset, record);
    } else if (dataEnd !== nextOffset) {
      fail(`embedded ZIP local payload contains trailing or hidden bytes after ${record.path}`);
    }
    const data = decompressEntry(record, archive.subarray(dataStart, dataEnd));
    entries.push({ path: record.path, data });
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.path, "utf8"), Buffer.from(right.path, "utf8")));
  return entries;
}

export function verifyStorePackage({
  crxBytes,
  artifactManifest,
  expectedExtensionId,
  requiredPublisherKeySha256 = OFFICIAL_CHROME_WEB_STORE_PUBLISHER_KEY_SHA256,
}) {
  if (typeof expectedExtensionId !== "string" || !/^[a-p]{32}$/.test(expectedExtensionId)) {
    fail("an independently reviewed expected extension id is required");
  }
  const envelope = parseAndVerifyCrx3({ crxBytes, requiredPublisherKeySha256 });
  if (envelope.extensionId !== expectedExtensionId) {
    fail("CRX3 extension id differs from the independently reviewed expected id");
  }
  const entries = parseStoreZip(envelope.archiveBytes);
  const payload = verifyArtifactPayloadEntries({ entries, artifactManifest });
  return {
    ...envelope,
    files: payload.files,
    treeSha256: payload.treeSha256,
  };
}
