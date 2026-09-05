// Test data only. Node/OpenSSL signs assertions; Rust LiteSVM independently
// verifies and executes the exact instructions built by the TypeScript client.
import { createECDH, createPrivateKey, createHash, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { Keypair, PublicKey } from "@solana/web3.js";
import { hex, prepareCeremony, rootInstructions, walletAddress } from "../src/devnet.js";
import { challengeB64Url } from "../src/webauthn/transcript.js";

const scalar = Buffer.alloc(32, 9); // Public, deterministic TEST KEY; never a funding key.
const ecdh = createECDH("prime256v1"); ecdh.setPrivateKey(scalar);
const raw = ecdh.getPublicKey(undefined, "uncompressed");
const key = createPrivateKey({ format: "jwk", key: { kty: "EC", crv: "P-256", d: scalar.toString("base64url"),
  x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33).toString("base64url") } });
const publicKey = ecdh.getPublicKey(undefined, "compressed");
const salt = new Uint8Array(32).fill(3);
const wallet = { version: 1 as const, origin: `chrome-extension://${"a".repeat(32)}`, credentialId: "01", publicKey: hex(publicKey), salt: hex(salt), address: walletAddress(publicKey, salt).toBase58() };
const payer = Keypair.fromSeed(new Uint8Array(32).fill(7)).publicKey;
const destination = new PublicKey(new Uint8Array(32).fill(42));
const slot = 350_000_000, now = 1_760_000_000;
const hash = (data: Uint8Array) => createHash("sha256").update(data).digest();
function operation(action: "create" | "transfer") {
  const ceremony = prepareCeremony(wallet, { generation: 0n, nonce: action === "create" ? 0n : 1n, policyVersion: 1 }, action, slot, now, destination, 1_000_000n);
  const auth = Buffer.concat([hash(Buffer.from(wallet.origin)), Buffer.from([5, 0, 0, 0, 0])]);
  const client = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: challengeB64Url(ceremony.challenge), origin: wallet.origin, crossOrigin: false }));
  const signature = sign("sha256", Buffer.concat([auth, hash(client)]), key);
  const assertion = { authenticatorData: auth, clientDataJSON: client, signature };
  const instructions = rootInstructions(wallet, payer, ceremony, assertion, action, destination, 1_000_000n);
  return { challenge: hex(ceremony.challenge), assertion: Object.fromEntries(Object.entries(assertion).map(([k, v]) => [k, hex(v)])),
    instructions: instructions.map(ix => ({ programId: ix.programId.toBase58(), keys: ix.keys.map(m => ({ pubkey: m.pubkey.toBase58(), isSigner: m.isSigner, isWritable: m.isWritable })), data: hex(ix.data) })) };
}
writeFileSync(new URL("../test/fixtures/devnet-root.json", import.meta.url), JSON.stringify({ wallet, payer: payer.toBase58(), destination: destination.toBase58(), slot, now, create: operation("create"), transfer: operation("transfer") }, null, 2) + "\n");
