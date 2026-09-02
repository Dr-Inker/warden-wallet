import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { deflateRawSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  createArtifactManifest,
  createCanonicalZip,
} from "../scripts/release-artifact.mjs";
import {
  parseAndVerifyCrx3,
  parseStoreZip,
  verifyStorePackage,
} from "../scripts/store-package.mjs";

const MANIFEST = Object.freeze({
  manifest_version: 3,
  name: "Warden store fixture",
  version: "1.2.3",
  permissions: ["alarms", "storage"],
  background: { service_worker: "background.js", type: "module" },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self';",
  },
});

const SOURCE = Object.freeze({
  gitCommit: "a".repeat(40),
  lockfileSha256: "b".repeat(64),
});

const TOOLCHAIN = Object.freeze({
  node: "22.23.2",
  pnpm: "11.12.0",
  esbuild: "0.28.2",
});

const developerKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publisherKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const developerPublicKey = developerKeys.publicKey.export({ format: "der", type: "spki" });
const publisherPublicKey = publisherKeys.publicKey.export({ format: "der", type: "spki" });
const publisherKeySha256 = sha256(publisherPublicKey);
const expectedExtensionId = [...Buffer.from(sha256(developerPublicKey), "hex").subarray(0, 16)]
  .map((byte) => String.fromCharCode(97 + (byte >>> 4), 97 + (byte & 0x0f)))
  .join("");

const CRC32_TABLE = new Uint32Array(256);
for (let index = 0; index < CRC32_TABLE.length; index += 1) {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) === 1 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  }
  CRC32_TABLE[index] = value >>> 0;
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

function varint(value) {
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
  return Buffer.concat([varint(fieldNumber * 8 + 2), varint(bytes.length), bytes]);
}

function proofBytes(publicKey, signature) {
  return Buffer.concat([
    protobufBytes(1, publicKey),
    protobufBytes(2, signature),
  ]);
}

function createCrx3(archiveBytes, {
  crxId = Buffer.from(sha256(developerPublicKey), "hex").subarray(0, 16),
  includePublisher = true,
  extraHeaderField = Buffer.alloc(0),
  duplicateSignedData = false,
} = {}) {
  const signedData = protobufBytes(1, crxId);
  const signedDataLength = Buffer.alloc(4);
  signedDataLength.writeUInt32LE(signedData.length, 0);
  const signedBytes = Buffer.concat([
    Buffer.from("CRX3 SignedData\0", "utf8"),
    signedDataLength,
    signedData,
    archiveBytes,
  ]);
  const developerProof = proofBytes(
    developerPublicKey,
    sign("sha256", signedBytes, developerKeys.privateKey),
  );
  const fields = [protobufBytes(2, developerProof)];
  if (includePublisher) {
    fields.push(protobufBytes(3, proofBytes(
      publisherPublicKey,
      sign("sha256", signedBytes, publisherKeys.privateKey),
    )));
  }
  fields.push(extraHeaderField, protobufBytes(10000, signedData));
  if (duplicateSignedData) {
    fields.push(protobufBytes(10000, signedData));
  }
  const header = Buffer.concat(fields);
  const fixed = Buffer.alloc(12);
  fixed.write("Cr24", 0, "ascii");
  fixed.writeUInt32LE(3, 4);
  fixed.writeUInt32LE(header.length, 8);
  return Buffer.concat([fixed, header, archiveBytes]);
}

function payloadEntries(manifest = MANIFEST) {
  return [
    { path: "approval.js", data: Buffer.from("globalThis.approve = false;\n") },
    { path: "background.js", data: Buffer.from("globalThis.background = true;\n") },
    { path: "manifest.json", data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) },
    { path: "popup.js", data: Buffer.from("globalThis.popup = true;\n") },
  ];
}

function artifact(entries = payloadEntries()) {
  const archiveBytes = createCanonicalZip(entries);
  const artifactManifest = createArtifactManifest({
    entries,
    archiveBytes,
    artifactFileName: "warden-extension-1.2.3.zip",
    source: SOURCE,
    toolchain: TOOLCHAIN,
    dependencyEvidence: {
      file: "warden-extension-1.2.3.sbom.json",
      bytes: Buffer.from("dependency evidence fixture\n"),
    },
    bundleInputEvidence: {
      file: "warden-extension-1.2.3.bundle-inputs.json",
      bytes: Buffer.from("bundle input fixture\n"),
    },
    staticInputEvidence: {
      file: "warden-extension-1.2.3.static-inputs.json",
      bytes: Buffer.from("static input fixture\n"),
    },
    releaseRecipeInputEvidence: {
      file: "warden-extension-1.2.3.recipe-inputs.json",
      bytes: Buffer.from("recipe input fixture\n"),
    },
  });
  return { archiveBytes, artifactManifest };
}

function timestampExtra() {
  return Buffer.from([0x55, 0x54, 0x01, 0x00, 0x00]);
}

function createStoreZip(entries, {
  dataDescriptor = false,
  extra = timestampExtra(),
  reverse = true,
} = {}) {
  const ordered = reverse ? [...entries].reverse() : [...entries];
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const entry of ordered) {
    const path = Buffer.from(entry.path, "utf8");
    const compressed = deflateRawSync(entry.data);
    const checksum = crc32(entry.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(dataDescriptor ? 0x0808 : 0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(0x4a21, 10);
    local.writeUInt16LE(0x5d01, 12);
    local.writeUInt32LE(dataDescriptor ? 0 : checksum, 14);
    local.writeUInt32LE(dataDescriptor ? 0 : compressed.length, 18);
    local.writeUInt32LE(dataDescriptor ? 0 : entry.data.length, 22);
    local.writeUInt16LE(path.length, 26);
    local.writeUInt16LE(extra.length, 28);
    const descriptor = dataDescriptor ? Buffer.alloc(16) : Buffer.alloc(0);
    if (dataDescriptor) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(checksum, 4);
      descriptor.writeUInt32LE(compressed.length, 8);
      descriptor.writeUInt32LE(entry.data.length, 12);
    }
    localParts.push(local, path, extra, compressed, descriptor);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x0314, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(dataDescriptor ? 0x0808 : 0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(0x4a21, 12);
    central.writeUInt16LE(0x5d01, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(path.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE((0o100600 << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, path, extra);
    localOffset += local.length + path.length + extra.length + compressed.length + descriptor.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(ordered.length, 8);
  end.writeUInt16LE(ordered.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

function verifyEntries(entries) {
  const { artifactManifest } = artifact();
  return verifyStorePackage({
    crxBytes: createCrx3(createStoreZip(entries)),
    artifactManifest,
    expectedExtensionId,
    requiredPublisherKeySha256: publisherKeySha256,
  });
}

function replaceManifest(entries, mutate) {
  const manifest = structuredClone(MANIFEST);
  mutate(manifest);
  return entries.map((entry) => entry.path === "manifest.json"
    ? { path: entry.path, data: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`) }
    : entry);
}

describe("CRX3 envelope", () => {
  it("verifies developer and required publisher proofs over the exact embedded archive", () => {
    const entries = payloadEntries();
    const archiveBytes = createStoreZip(entries);
    const crxBytes = createCrx3(archiveBytes);
    const parsed = parseAndVerifyCrx3({ crxBytes, requiredPublisherKeySha256: publisherKeySha256 });
    expect(parsed.archiveBytes.equals(archiveBytes)).toBe(true);
    expect(parsed.archiveOffset).toBe(12 + parsed.headerBytes);
    expect(parsed.archiveSha256).toBe(sha256(archiveBytes));
    expect(parsed.crxId).toBe(sha256(developerPublicKey).slice(0, 32));
    expect(parsed.extensionId).toMatch(/^[a-p]{32}$/);
    expect(parsed.proofs).toBe(2);
    expect(parsed.publisherKeySha256).toBe(publisherKeySha256);
  });

  it("requires the official publisher key by default and a matching developer id", () => {
    const archiveBytes = createStoreZip(payloadEntries());
    expect(() => parseAndVerifyCrx3({ crxBytes: createCrx3(archiveBytes) }))
      .toThrow(/required Chrome Web Store publisher proof/);
    expect(() => parseAndVerifyCrx3({
      crxBytes: createCrx3(archiveBytes, { includePublisher: false }),
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/required Chrome Web Store publisher proof/);
    expect(() => parseAndVerifyCrx3({
      crxBytes: createCrx3(archiveBytes, { crxId: Buffer.alloc(16, 0x5a) }),
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/matching the declared crx_id/);
  });

  it("rejects altered signatures and ambiguous or duplicate protobuf fields", () => {
    const archiveBytes = createStoreZip(payloadEntries());
    const altered = createCrx3(archiveBytes);
    altered[altered.length - 1] ^= 1;
    expect(() => parseAndVerifyCrx3({
      crxBytes: altered,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/signature verification failed/);
    expect(() => parseAndVerifyCrx3({
      crxBytes: createCrx3(archiveBytes, {
        extraHeaderField: protobufBytes(4, Buffer.from([0x50, 0x4b, 0x05, 0x06])),
      }),
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/ambiguous ZIP end-record token/);
    expect(() => parseAndVerifyCrx3({
      crxBytes: createCrx3(archiveBytes, { duplicateSignedData: true }),
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/duplicate signed_header_data/);
    const canonical = createCrx3(archiveBytes);
    const headerLength = canonical.readUInt32LE(8);
    const nonminimal = Buffer.concat([
      canonical.subarray(0, 8),
      Buffer.alloc(4),
      Buffer.from([canonical[12] | 0x80, 0]),
      canonical.subarray(13),
    ]);
    nonminimal.writeUInt32LE(headerLength + 1, 8);
    expect(() => parseAndVerifyCrx3({
      crxBytes: nonminimal,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/non-minimal protobuf varint/);
  });

  it("rejects wrong magic/version, excessive or truncated headers, and trailing archive ambiguity", () => {
    const archiveBytes = createStoreZip(payloadEntries());
    const wrongMagic = createCrx3(archiveBytes);
    wrongMagic[0] = 0;
    expect(() => parseAndVerifyCrx3({
      crxBytes: wrongMagic,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/magic/);
    const wrongVersion = createCrx3(archiveBytes);
    wrongVersion.writeUInt32LE(2, 4);
    expect(() => parseAndVerifyCrx3({
      crxBytes: wrongVersion,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/version/);
    const excessiveHeader = createCrx3(archiveBytes);
    excessiveHeader.writeUInt32LE((1 << 18) + 1, 8);
    expect(() => parseAndVerifyCrx3({
      crxBytes: excessiveHeader,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/header length/);
    const truncated = createCrx3(archiveBytes).subarray(0, 24);
    expect(() => parseAndVerifyCrx3({
      crxBytes: truncated,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/truncated CRX3 protobuf header/);
    const trailing = createCrx3(Buffer.concat([archiveBytes, Buffer.from([0])]));
    expect(() => verifyStorePackage({
      crxBytes: trailing,
      artifactManifest: artifact().artifactManifest,
      expectedExtensionId,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/unambiguous classic end/);
  });
});

describe("store-repackaged ZIP payload", () => {
  it("accepts different order, DEFLATE, timestamp extras, mtimes, and modes when every payload byte matches", () => {
    const entries = payloadEntries();
    const { archiveBytes: uploadArchive, artifactManifest } = artifact(entries);
    const storeArchive = createStoreZip(entries);
    expect(storeArchive.equals(uploadArchive)).toBe(false);
    const verified = verifyStorePackage({
      crxBytes: createCrx3(storeArchive),
      artifactManifest,
      expectedExtensionId,
      requiredPublisherKeySha256: publisherKeySha256,
    });
    expect(verified.files).toBe(entries.length);
    expect(verified.treeSha256).toBe(artifactManifest.payload.treeSha256);
    expect(verified.archiveSha256).toBe(sha256(storeArchive));
    expect(verified.archiveSha256).not.toBe(artifactManifest.archive.sha256);
  });

  it("accepts a bounded signed archive that uses exact data descriptors", () => {
    const entries = payloadEntries();
    const { artifactManifest } = artifact(entries);
    const verified = verifyStorePackage({
      crxBytes: createCrx3(createStoreZip(entries, { dataDescriptor: true })),
      artifactManifest,
      expectedExtensionId,
      requiredPublisherKeySha256: publisherKeySha256,
    });
    expect(verified.files).toBe(entries.length);
  });

  it("requires an independently supplied extension id and rejects a candidate-id mismatch", () => {
    const entries = payloadEntries();
    const crxBytes = createCrx3(createStoreZip(entries));
    const { artifactManifest } = artifact(entries);
    expect(() => verifyStorePackage({
      crxBytes,
      artifactManifest,
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/expected extension id is required/);
    expect(() => verifyStorePackage({
      crxBytes,
      artifactManifest,
      expectedExtensionId: "a".repeat(32),
      requiredPublisherKeySha256: publisherKeySha256,
    })).toThrow(/differs from the independently reviewed expected id/);
  });

  it("rejects one changed content byte and dependency-produced output drift", () => {
    const entries = payloadEntries();
    const changedPopup = entries.map((entry) => entry.path === "popup.js"
      ? { path: entry.path, data: Buffer.from("globalThis.popup = false;\n") }
      : entry);
    expect(() => verifyEntries(changedPopup)).toThrow(/popup\.js/);
    const changedBackground = entries.map((entry) => entry.path === "background.js"
      ? { path: entry.path, data: Buffer.from("globalThis.background = false;\n") }
      : entry);
    expect(() => verifyEntries(changedBackground)).toThrow(/background\.js/);
  });

  it("rejects changed permissions, relaxed CSP, and an introduced update URL", () => {
    const entries = payloadEntries();
    expect(() => verifyEntries(replaceManifest(entries, (manifest) => {
      manifest.permissions.push("tabs");
    }))).toThrow(/permissions/);
    expect(() => verifyEntries(replaceManifest(entries, (manifest) => {
      manifest.content_security_policy.extension_pages =
        "script-src 'self' 'unsafe-eval'; object-src 'self';";
    }))).toThrow(/content security policy/);
    expect(() => verifyEntries(replaceManifest(entries, (manifest) => {
      manifest.update_url = "https://attacker.invalid/update.xml";
    }))).toThrow(/update URL/);
  });

  it("rejects missing, extra, duplicate, unsafe, and hidden/trailing entries", () => {
    const entries = payloadEntries();
    expect(() => verifyEntries(entries.slice(1))).toThrow(/payload path set/);
    expect(() => verifyEntries([...entries, {
      path: "surprise.js",
      data: Buffer.from("surprise\n"),
    }])).toThrow(/payload path set/);
    expect(() => parseStoreZip(createStoreZip([entries[0], entries[0]])))
      .toThrow(/duplicate embedded ZIP path/);
    expect(() => parseStoreZip(createStoreZip([{
      path: "../escape.js",
      data: Buffer.from("escape\n"),
    }])))
      .toThrow(/unsafe embedded ZIP path/);
    expect(() => parseStoreZip(Buffer.concat([
      createStoreZip(entries),
      Buffer.from([0]),
    ]))).toThrow(/unambiguous classic end/);
  });

  it("rejects encryption, ZIP64 sentinels, unknown extras, and hidden local bytes", () => {
    const entries = payloadEntries();
    const encrypted = createStoreZip(entries);
    const encryptedEnd = encrypted.length - 22;
    const encryptedCentral = encrypted.readUInt32LE(encryptedEnd + 16);
    encrypted.writeUInt16LE(encrypted.readUInt16LE(encryptedCentral + 8) | 1, encryptedCentral + 8);
    expect(() => parseStoreZip(encrypted)).toThrow(/encrypted or unsupported/);

    const zip64 = createStoreZip(entries);
    const zip64Central = zip64.readUInt32LE(zip64.length - 6);
    zip64.writeUInt32LE(0xffffffff, zip64Central + 20);
    expect(() => parseStoreZip(zip64)).toThrow(/ZIP64/);

    expect(() => parseStoreZip(createStoreZip(entries, {
      extra: Buffer.from([0x34, 0x12, 0x00, 0x00]),
    }))).toThrow(/unsupported or semantic extra field/);

    const archive = createStoreZip(entries);
    const endOffset = archive.length - 22;
    const centralOffset = archive.readUInt32LE(endOffset + 16);
    const hidden = Buffer.concat([
      archive.subarray(0, centralOffset),
      Buffer.from([0x5a]),
      archive.subarray(centralOffset),
    ]);
    hidden.writeUInt32LE(centralOffset + 1, hidden.length - 6);
    expect(() => parseStoreZip(hidden)).toThrow(/trailing or hidden bytes/);
  });
});
