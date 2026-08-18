// Spike 2b step 1: convert out/assertion.json (Task 3) into raw byte inputs for
// the secp256r1 precompile + the on-chain program. Run:
//   cd spikes/02-webauthn/ts && node --experimental-strip-types src/prep.ts
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { p256 } from "@noble/curves/p256";

const a = JSON.parse(readFileSync(new URL("../../out/assertion.json", import.meta.url), "utf8"));
const b = (s: string) => Buffer.from(s, "base64");

const spki = b(a.pubkeyDerSpki); // DER SPKI; uncompressed point is the last 65 bytes
const uncompressed = spki.subarray(spki.length - 65);
const compressed = Buffer.from(p256.ProjectivePoint.fromHex(uncompressed).toRawBytes(true)); // 33 B

const sigAsSigned = p256.Signature.fromDER(b(a.signatureDer));
const wasHighS = sigAsSigned.hasHighS();
// the precompile requires low-S (SEC1 malleability guard) — normalize
const sig = wasHighS ? sigAsSigned.normalizeS() : sigAsSigned;

const authData = b(a.authenticatorData);
const cdj = b(a.clientDataJSON);
const message = Buffer.concat([authData, createHash("sha256").update(cdj).digest()]);

// sanity: the (normalized) signature must still verify over the WebAuthn message
const verified = p256.verify(sig.toCompactRawBytes(), createHash("sha256").update(message).digest(), compressed);

writeFileSync(
  new URL("../../out/raw.json", import.meta.url),
  JSON.stringify(
    {
      pubkey33: compressed.toString("hex"),
      sig64: Buffer.from(sig.toCompactRawBytes()).toString("hex"),
      // exactly what the authenticator emitted, before low-S normalization —
      // used by the negative test that proves the precompile enforces low-S
      sig64AsSigned: Buffer.from(sigAsSigned.toCompactRawBytes()).toString("hex"),
      message: message.toString("hex"),
      authenticatorData: authData.toString("hex"),
      clientDataJSON: cdj.toString("hex"),
      rpIdHash: authData.subarray(0, 32).toString("hex"),
      flags: authData[32],
      origin: a.origin,
      challenge: a.challenge,
      lowSNormalizationNeeded: wasHighS,
    },
    null,
    2,
  ) + "\n",
);
console.log("ok  lowSNormalizationNeeded=" + wasHighS + "  verify=" + verified + "  clientDataJSON=" + cdj.toString("utf8"));
