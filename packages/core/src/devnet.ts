/** Explicit devnet experiment. Never composed into the production wallet. */
import {
  Connection, Keypair, PublicKey, SYSVAR_INSTRUCTIONS_PUBKEY, SystemProgram,
  Transaction, TransactionInstruction,
} from "@solana/web3.js";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { assertionToCompact } from "./webauthn/assertion.js";
import { actionHash, challengeB64Url, deriveOwnerSeed, encodeCreateBody, transcriptHash } from "./webauthn/transcript.js";

export const DEVNET_RPC = "https://api.devnet.solana.com";
export const DEVNET_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
export const DEVNET_PROGRAM = "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2";
export const TEST_TRANSFER_LIMIT = 10_000_000n; // 0.01 SOL per approval
export const SMART_ACCOUNT_SIZE = 4120; // Rust SmartAccount::LEN (2008 + 8 * 264)
const program = new PublicKey(DEVNET_PROGRAM);
const loader = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
const nativeMint = new PublicKey("So11111111111111111111111111111111111111112");
const utf8 = (s: string) => new TextEncoder().encode(s);
export const hex = (b: Uint8Array): string => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
export function unhex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(s)) throw new Error("Invalid stored bytes");
  return Uint8Array.from(s.match(/../g)!, v => parseInt(v, 16));
}
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const join = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
function int(value: bigint, length: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) throw new Error("Integer out of range");
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = Number(value >> BigInt(i * 8) & 255n);
  return out;
}
const vec = (bytes: Uint8Array) => join(int(BigInt(bytes.length), 4), bytes);
const discriminator = (name: string) => sha256(utf8(`global:${name}`)).slice(0, 8);
const meta = (pubkey: PublicKey, isWritable = false, isSigner = false) => ({ pubkey, isWritable, isSigner });
const instruction = (programId: PublicKey, keys: ReturnType<typeof meta>[], data: Uint8Array) =>
  new TransactionInstruction({ programId, keys, data: data as Buffer });

export interface WalletMetadata {
  version: 1;
  origin: string;
  credentialId: string;
  publicKey: string;
  salt: string;
  address: string;
}
export function validateWallet(value: unknown, origin: string): WalletMetadata {
  if (!value || typeof value !== "object") throw new Error("Create a devnet wallet first");
  const w = value as WalletMetadata;
  if (w.version !== 1 || w.origin !== origin || !/^chrome-extension:\/\/[a-p]{32}$/.test(origin) ||
      typeof w.credentialId !== "string" || !/^(?:[0-9a-f]{2}){1,1024}$/.test(w.credentialId) ||
      typeof w.publicKey !== "string" || !/^(02|03)[0-9a-f]{64}$/.test(w.publicKey) ||
      typeof w.salt !== "string" || !/^[0-9a-f]{64}$/.test(w.salt)) throw new Error("Invalid devnet wallet metadata");
  p256.ProjectivePoint.fromHex(w.publicKey).assertValidity();
  const address = walletAddress(unhex(w.publicKey), unhex(w.salt)).toBase58();
  if (w.address !== address) throw new Error("Stored wallet address does not match its passkey");
  return { version: 1, origin, credentialId: w.credentialId, publicKey: w.publicKey, salt: w.salt, address };
}
export function walletAddress(publicKey: Uint8Array, salt: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync([utf8("account"), deriveOwnerSeed(publicKey, salt)], program)[0];
}
export function parseTestAmount(value: string): bigint {
  if (!/^(0|[1-9][0-9]*)(\.[0-9]{1,9})?$/.test(value) || value.length > 20) throw new Error("Enter SOL with at most 9 decimal places");
  const [whole, fraction = ""] = value.split(".");
  const amount = BigInt(whole!) * 1_000_000_000n + BigInt(fraction.padEnd(9, "0"));
  if (amount < 1n || amount > TEST_TRANSFER_LIMIT) throw new Error("Test transfers must be between 1 lamport and 0.01 SOL");
  return amount;
}
export function testPolicy(): Uint8Array {
  const cap = (perTx: bigint, perDay: bigint, perMonth: bigint) =>
    join(nativeMint.toBytes(), int(perTx, 8), int(perDay, 8), int(perMonth, 8));
  // Native SOL only. No sessions. 0.01 / 0.1 / 1 SOL account-wide caps.
  return join(int(1n, 4), int(1n, 4), cap(TEST_TRANSFER_LIMIT, 100_000_000n, 1_000_000_000n),
    int(0n, 4), int(1n, 4), cap(TEST_TRANSFER_LIMIT, 0n, 0n),
    int(3600n, 8), int(3600n, 8), int(3600n, 8), int(0n, 2));
}

export interface RootState { generation: bigint; nonce: bigint; policyVersion: number }
export function readRootState(data: Uint8Array, owner: PublicKey, executable: boolean, wallet: WalletMetadata): RootState {
  const origin = utf8(wallet.origin);
  const [address, bump] = PublicKey.findProgramAddressSync([utf8("account"), deriveOwnerSeed(unhex(wallet.publicKey), unhex(wallet.salt))], program);
  if (!owner.equals(program) || executable || data.length !== SMART_ACCOUNT_SIZE ||
      !equal(data.slice(0, 8), Uint8Array.of(186, 83, 247, 224, 59, 95, 223, 112)) ||
      data[8] !== 1 || data[9] !== bump || data[10] !== 0 || data[11] !== origin.length || data[12] !== 0 ||
      address.toBase58() !== wallet.address ||
      !equal(data.slice(14, 46), deriveOwnerSeed(unhex(wallet.publicKey), unhex(wallet.salt))) ||
      !equal(data.slice(46, 79), unhex(wallet.publicKey)) ||
      !equal(data.slice(79, 111), sha256(origin)) || !equal(data.slice(111, 111 + origin.length), origin) ||
      !equal(data.slice(175, 207), new PublicKey(DEVNET_GENESIS).toBytes())) {
    throw new Error("On-chain wallet does not match this devnet passkey, or is frozen");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(560, true) !== 1) throw new Error("Unsupported wallet policy version");
  return { generation: view.getBigUint64(528, true), nonce: view.getBigUint64(536, true), policyVersion: 1 };
}

export interface Ceremony {
  challenge: Uint8Array;
  expiry: bigint;
  slot: bigint;
}
export function prepareCeremony(wallet: WalletMetadata, state: RootState, action: "create" | "transfer", slot: number, now: number,
  destination?: PublicKey, amount?: bigint): Ceremony {
  let body: Uint8Array;
  if (action === "create") {
    body = encodeCreateBody({ salt: unhex(wallet.salt), rpIdHash: sha256(utf8(wallet.origin)), origin: wallet.origin,
      clusterTag: new PublicKey(DEVNET_GENESIS).toBytes(), policyHash: keccak_256(testPolicy()) });
  } else {
    if (!destination || amount === undefined || amount < 1n || amount > TEST_TRANSFER_LIMIT || destination.toBase58() === wallet.address) throw new Error("Invalid test transfer");
    body = join(Uint8Array.of(1), new Uint8Array(32), destination.toBytes(), int(amount, 8));
  }
  const expiry = BigInt(now + 120);
  const signedSlot = BigInt(slot);
  const challenge = transcriptHash({ clusterTag: new PublicKey(DEVNET_GENESIS).toBytes(), programId: program.toBytes(),
    account: new PublicKey(wallet.address).toBytes(), generation: state.generation, policyVersion: state.policyVersion,
    rootNonce: state.nonce, expiryTs: expiry, signedSlot, actionHash: actionHash(action === "create" ? 6 : 5, body) });
  return { challenge, expiry, slot: signedSlot };
}
export interface Assertion { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array }
export function rootInstructions(wallet: WalletMetadata, payer: PublicKey, ceremony: Ceremony, assertion: Assertion,
  action: "create" | "transfer", destination?: PublicKey, amount?: bigint): TransactionInstruction[] {
  const auth = assertion.authenticatorData;
  if (auth.length !== 37 || !equal(auth.slice(0, 32), sha256(utf8(wallet.origin))) || (auth[32]! & 5) !== 5 || assertion.clientDataJSON.length > 512) {
    throw new Error("Passkey must provide user presence, verification, and the extension RP binding");
  }
  const client = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(assertion.clientDataJSON));
  if (client.type !== "webauthn.get" || client.challenge !== challengeB64Url(ceremony.challenge) || client.origin !== wallet.origin || client.crossOrigin !== false) throw new Error("Passkey challenge or origin mismatch");
  const signature = assertionToCompact(assertion.signature);
  const message = join(auth, sha256(assertion.clientDataJSON));
  const publicKey = unhex(wallet.publicKey);
  if (!p256.verify(signature, sha256(message), publicKey)) throw new Error("Passkey signature does not match the saved wallet");
  const offsets = join(int(49n, 2), int(65535n, 2), int(16n, 2), int(65535n, 2), int(113n, 2), int(BigInt(message.length), 2), int(65535n, 2));
  const precompile = instruction(new PublicKey("Secp256r1SigVerify1111111111111111111111111"), [], join(Uint8Array.of(1, 0), offsets, publicKey, signature, message));
  const root = join(Uint8Array.of(0), vec(auth), vec(assertion.clientDataJSON), int(ceremony.expiry, 8), int(ceremony.slot, 8));
  const account = new PublicKey(wallet.address);
  if (action === "create") {
    const data = join(discriminator("create_account"), Uint8Array.of(0), publicKey, root, unhex(wallet.salt), sha256(utf8(wallet.origin)),
      vec(utf8(wallet.origin)), new PublicKey(DEVNET_GENESIS).toBytes(), testPolicy());
    return [precompile, instruction(program, [meta(payer, true, true), meta(account, true), meta(SYSVAR_INSTRUCTIONS_PUBKEY), meta(SystemProgram.programId), meta(program)], data)];
  }
  if (!destination || amount === undefined || amount < 1n || amount > TEST_TRANSFER_LIMIT || destination.equals(account)) throw new Error("Invalid test transfer");
  return [precompile, instruction(program, [meta(payer, false, true), meta(account, true), meta(program), meta(SYSVAR_INSTRUCTIONS_PUBKEY), meta(destination, true), meta(program), meta(program)],
    join(discriminator("transfer"), Uint8Array.of(1), root, Uint8Array.of(0), int(amount, 8)))];
}

export interface ProgramPin { sha256: string; bytes: number }
export function verifyProgramBytes(data: Uint8Array, pin: ProgramPin): void {
  if (!/^[0-9a-f]{64}$/.test(pin.sha256) || !Number.isSafeInteger(pin.bytes) || pin.bytes < 4 || data.length < 45 + pin.bytes ||
      new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0, true) !== 3 ||
      !equal(data.slice(45, 49), Uint8Array.of(127, 69, 76, 70)) ||
      hex(sha256(data.slice(45, 45 + pin.bytes))) !== pin.sha256 || data.slice(45 + pin.bytes).some(v => v !== 0)) {
    throw new Error("Devnet program binary does not match this test build");
  }
}
export function devnetConnection(): Connection {
  // No caller-controlled URL; verify the genesis before every write as well.
  return new Connection(DEVNET_RPC, { commitment: "confirmed", disableRetryOnRateLimit: true,
    fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(20_000), redirect: "error" }) });
}
export async function checkDevnet(connection: Connection, pin: ProgramPin): Promise<void> {
  if (connection.rpcEndpoint !== DEVNET_RPC || await connection.getGenesisHash() !== DEVNET_GENESIS) throw new Error("Refusing a network other than Solana devnet");
  const info = await connection.getAccountInfo(program, "confirmed");
  if (!info) throw new Error(`Warden is not deployed on devnet at ${DEVNET_PROGRAM}. Deploy the reviewed test binary before creating a wallet.`);
  if (!info.executable || !info.owner.equals(loader) || info.data.length !== 36 || info.data.readUInt32LE(0) !== 2) throw new Error("Unexpected devnet program account");
  const address = PublicKey.findProgramAddressSync([program.toBytes()], loader)[0];
  if (!new PublicKey(info.data.subarray(4, 36)).equals(address)) throw new Error("Unexpected ProgramData address");
  const code = await connection.getAccountInfo(address, "confirmed");
  if (!code || code.executable || !code.owner.equals(loader)) throw new Error("Invalid devnet ProgramData account");
  verifyProgramBytes(code.data, pin);
}
export async function getRootState(connection: Connection, wallet: WalletMetadata): Promise<RootState> {
  const account = await connection.getAccountInfo(new PublicKey(wallet.address), "confirmed");
  if (!account) throw new Error("Wallet metadata is saved, but the account has not been created on devnet yet");
  return readRootState(account.data, account.owner, account.executable, wallet);
}
export async function sendTestTransaction(connection: Connection, pin: ProgramPin, payer: Keypair, instructions: TransactionInstruction[],
  onSubmitted: (signature: string, lastValidBlockHeight: number) => void | Promise<void>): Promise<string> {
  await checkDevnet(connection, pin);
  const block = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction({ feePayer: payer.publicKey, ...block }).add(...instructions);
  tx.sign(payer);
  const wire = tx.serialize(); // web3 also enforces the 1,232-byte packet bound
  if (wire.length > 1232) throw new Error("Passkey response exceeds Solana's transaction size limit");
  // Capture the LOCAL signature before submission: a timed-out RPC may still
  // have accepted it. Never encourage blind resubmission of an uncertain send.
  const signature = encodeSignature(tx.signature!);
  await onSubmitted(signature, block.lastValidBlockHeight);
  const returned = await connection.sendRawTransaction(wire, { skipPreflight: false, maxRetries: 0, preflightCommitment: "confirmed" });
  if (returned !== signature) throw new Error("RPC returned a different transaction signature");
  await confirmTestSignature(connection, signature);
  return signature;
}
function encodeSignature(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let out = "";
  while (value) { out = alphabet[Number(value % 58n)]! + out; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = "1" + out; }
  return out;
}
export async function confirmTestSignature(connection: Connection, signature: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const status = (await connection.getSignatureStatuses([signature], { searchTransactionHistory: true })).value[0];
    if (status?.err) throw new Error(`Transaction failed on devnet: ${JSON.stringify(status.err)}`);
    if (status?.confirmationStatus === "confirmed" || status?.confirmationStatus === "finalized") return;
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
  throw new Error("Confirmation is still unknown. Check the transaction link before trying again");
}

export async function enrollPasskey(origin: string, rpId: string): Promise<WalletMetadata> {
  const result = await navigator.credentials.create({ publicKey: {
    rp: { id: rpId, name: "Warden DEVNET TEST" },
    user: { id: crypto.getRandomValues(new Uint8Array(32)), name: "warden-devnet", displayName: "Warden devnet test wallet" },
    challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" }, attestation: "none", timeout: 60_000,
  } }) as PublicKeyCredential | null;
  if (!result) throw new Error("Passkey creation was cancelled");
  const response = result.response as AuthenticatorAttestationResponse;
  if (response.getPublicKeyAlgorithm() !== -7) throw new Error("The authenticator did not return ES256");
  const spki = response.getPublicKey();
  if (!spki) throw new Error("This browser did not provide the passkey public key");
  // Import the entire SPKI, never assume an arbitrary suffix is a valid key.
  const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  const point = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  const publicKey = p256.ProjectivePoint.fromHex(point).toRawBytes(true);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  return validateWallet({ version: 1, origin, credentialId: hex(new Uint8Array(result.rawId)), publicKey: hex(publicKey), salt: hex(salt), address: walletAddress(publicKey, salt).toBase58() }, origin);
}
export async function assertPasskey(wallet: WalletMetadata, ceremony: Ceremony): Promise<Assertion> {
  const credential = await navigator.credentials.get({ publicKey: { rpId: wallet.origin.slice("chrome-extension://".length),
    challenge: new Uint8Array(ceremony.challenge), userVerification: "required", timeout: 45_000,
    allowCredentials: [{ type: "public-key", id: new Uint8Array(unhex(wallet.credentialId)) }] } }) as PublicKeyCredential | null;
  if (!credential || hex(new Uint8Array(credential.rawId)) !== wallet.credentialId) throw new Error("Passkey approval was cancelled or used a different credential");
  const response = credential.response as AuthenticatorAssertionResponse;
  return { authenticatorData: new Uint8Array(response.authenticatorData), clientDataJSON: new Uint8Array(response.clientDataJSON), signature: new Uint8Array(response.signature) };
}
