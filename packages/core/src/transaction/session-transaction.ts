//! Exact-byte construction for Warden's supported session transaction path.
//!
//! A Wallet Standard caller supplies a serialized transaction whose advertised
//! signer is the SmartAccount PDA. The PDA has no Ed25519 private key, so Warden
//! cannot sign that transaction in place: it must wrap the dApp instructions in
//! `execute`, make the bounded session key the real fee payer/signer, and return
//! a different transaction. Approval therefore binds `messageBytes` below — the
//! exact bytes Ed25519 signs — never the incoming envelope and never the mutable
//! signature vector of the final transaction.
//!
//! This module closes only the structural rewrite. It does not resolve cluster
//! state, prove a blockhash is fresh, decode intent, enforce the registry/policy,
//! simulate, approve, sign, or send. A coordinator must recheck the exact bound
//! blockhash immediately before signing; if it expired, the approval must be
//! cancelled and rebuilt, never refreshed under an existing approval.

import {
  PublicKey,
  SystemInstruction,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

import {
  computeAccountsHash,
  type LogicalAccount,
} from "../execute/payload.js";
import {
  wrapForExecute,
  type AccountMetaLite,
} from "../execute/wrap.js";
import { MAX_TX_BYTES } from "../constants.js";
import {
  parseSerializedTransactionEnvelope,
  TransactionEnvelopeError,
  type SupportedTransactionVersion,
} from "./envelope.js";

const PUBLIC_KEY_BYTES = 32;
const EXECUTE_NAMED_ACCOUNT_COUNT = 7;

// Independent literal from the shipped IDL / Anchor `global:execute` ABI.
const EXECUTE_DISCRIMINATOR = Uint8Array.of(
  130,
  221,
  242,
  154,
  13,
  193,
  189,
  29,
);

export type SessionTransactionBuildErrorCode =
  | "INVALID_AUTHORITY"
  | "INVALID_RECENT_BLOCKHASH"
  | "SOURCE_ENVELOPE_INVALID"
  | "SOURCE_SIGNER_MISMATCH"
  | "SOURCE_SIGNER_SET_UNSUPPORTED"
  | "SOURCE_SIGNATURE_PRESENT"
  | "SOURCE_INSTRUCTIONS_EMPTY"
  | "SOURCE_DURABLE_NONCE_UNSUPPORTED"
  | "SOURCE_INSTRUCTIONS_SYSVAR_UNSUPPORTED"
  | "SOURCE_WRAP_UNSUPPORTED"
  | "FINAL_TRANSACTION_TOO_LARGE"
  | "FINAL_INVARIANT_VIOLATION";

export class SessionTransactionBuildError extends Error {
  readonly code: SessionTransactionBuildErrorCode;

  constructor(
    code: SessionTransactionBuildErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session transaction: ${message}`, options);
    this.name = "SessionTransactionBuildError";
    this.code = code;
  }
}

export interface PrepareSessionTransactionOptions {
  /** The advertised Wallet Standard account and source transaction fee payer. */
  readonly smartAccount: PublicKey;
  /** The authorized Ed25519 session delegate; also the final fee payer. */
  readonly sessionSigner: PublicKey;
  /** The on-chain `SessionKey` account passed to `execute`. */
  readonly sessionAccount: PublicKey;
  /** The SmartAccount's adapter Registry passed to `execute`. */
  readonly registry: PublicKey;
  readonly wardenProgram: PublicKey;
  /** Explicit final recent blockhash bytes. Freshness is a coordinator recheck. */
  readonly recentBlockhash: Uint8Array;
}

/**
 * Copy-isolated prepared transaction. The unsigned transaction contains one
 * zero-filled signature slot and is a transport template only. `messageBytes`
 * is the immutable approval/signing object.
 */
export interface PreparedSessionTransaction {
  readonly sourceVersion: SupportedTransactionVersion;
  readonly sourceTransactionBytes: Uint8Array;
  readonly messageBytes: Uint8Array;
  readonly unsignedTransactionBytes: Uint8Array;
  readonly payload: Uint8Array;
  readonly accountsHash: Uint8Array;
  readonly messageByteLength: number;
  readonly transactionByteLength: number;
}

function fail(
  code: SessionTransactionBuildErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionTransactionBuildError(
    code,
    message,
    cause === undefined ? {} : { cause },
  );
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function allZero(value: Uint8Array): boolean {
  let combined = 0;
  for (const byte of value) combined |= byte;
  return combined === 0;
}

function snapshotPublicKey(value: unknown, name: string): PublicKey {
  if (!(value instanceof PublicKey)) {
    fail("INVALID_AUTHORITY", `${name} must be a PublicKey`);
  }
  try {
    return new PublicKey(value.toBytes());
  } catch (error) {
    fail("INVALID_AUTHORITY", `${name} is malformed`, error);
  }
}

interface SnapshottedOptions {
  readonly smartAccount: PublicKey;
  readonly sessionSigner: PublicKey;
  readonly sessionAccount: PublicKey;
  readonly registry: PublicKey;
  readonly wardenProgram: PublicKey;
  readonly recentBlockhash: Uint8Array;
}

function snapshotOptions(value: unknown): SnapshottedOptions {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array) {
    fail("INVALID_AUTHORITY", "options must be an object");
  }
  const options = value as Partial<PrepareSessionTransactionOptions>;
  const snapshotted: SnapshottedOptions = {
    smartAccount: snapshotPublicKey(options.smartAccount, "smartAccount"),
    sessionSigner: snapshotPublicKey(options.sessionSigner, "sessionSigner"),
    sessionAccount: snapshotPublicKey(options.sessionAccount, "sessionAccount"),
    registry: snapshotPublicKey(options.registry, "registry"),
    wardenProgram: snapshotPublicKey(options.wardenProgram, "wardenProgram"),
    recentBlockhash: snapshotRecentBlockhash(options.recentBlockhash),
  };

  const named = [
    ["smartAccount", snapshotted.smartAccount],
    ["sessionSigner", snapshotted.sessionSigner],
    ["sessionAccount", snapshotted.sessionAccount],
    ["registry", snapshotted.registry],
    ["wardenProgram", snapshotted.wardenProgram],
  ] as const;
  for (let left = 0; left < named.length; left++) {
    for (let right = left + 1; right < named.length; right++) {
      if (named[left]![1].equals(named[right]![1])) {
        fail(
          "INVALID_AUTHORITY",
          `${named[left]![0]} must not alias ${named[right]![0]}`,
        );
      }
    }
  }
  return snapshotted;
}

function snapshotRecentBlockhash(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== PUBLIC_KEY_BYTES) {
    fail(
      "INVALID_RECENT_BLOCKHASH",
      `recentBlockhash must contain exactly ${PUBLIC_KEY_BYTES} bytes`,
    );
  }
  const owned = value.slice();
  if (allZero(owned)) {
    owned.fill(0);
    fail("INVALID_RECENT_BLOCKHASH", "recentBlockhash must not be all zero");
  }
  return owned;
}

function isAdvanceNonceInstruction(instruction: TransactionInstruction): boolean {
  if (!instruction.programId.equals(SystemProgram.programId)) return false;
  try {
    return SystemInstruction.decodeInstructionType(instruction) ===
      "AdvanceNonceAccount";
  } catch {
    return false;
  }
}

function encodeInlineSessionExecute(payload: Uint8Array): Uint8Array {
  // Anchor discriminator || root(None) || payload(Some(Vec<u8>)).
  const out = new Uint8Array(8 + 1 + 1 + 4 + payload.length);
  out.set(EXECUTE_DISCRIMINATOR, 0);
  out[8] = 0;
  out[9] = 1;
  const length = payload.length >>> 0;
  out[10] = length & 0xff;
  out[11] = (length >>> 8) & 0xff;
  out[12] = (length >>> 16) & 0xff;
  out[13] = (length >>> 24) & 0xff;
  out.set(payload, 14);
  return out;
}

function copyMetas(values: readonly AccountMetaLite[]): AccountMetaLite[] {
  return values.map((value) => ({
    pubkey: new PublicKey(value.pubkey.toBytes()),
    isSigner: value.isSigner,
    isWritable: value.isWritable,
  }));
}

function compilationLooksOversized(error: unknown): boolean {
  if (error instanceof RangeError) return true;
  return error instanceof Error &&
    /encoding overruns|out of range|outside the bounds|offset/i.test(error.message);
}

class PreparedSessionTransactionValue implements PreparedSessionTransaction {
  readonly sourceVersion: SupportedTransactionVersion;
  readonly messageByteLength: number;
  readonly transactionByteLength: number;
  readonly #sourceTransactionBytes: Uint8Array;
  readonly #messageBytes: Uint8Array;
  readonly #unsignedTransactionBytes: Uint8Array;
  readonly #payload: Uint8Array;
  readonly #accountsHash: Uint8Array;

  constructor(params: {
    sourceVersion: SupportedTransactionVersion;
    sourceTransactionBytes: Uint8Array;
    messageBytes: Uint8Array;
    unsignedTransactionBytes: Uint8Array;
    payload: Uint8Array;
    accountsHash: Uint8Array;
  }) {
    this.sourceVersion = params.sourceVersion;
    this.#sourceTransactionBytes = params.sourceTransactionBytes.slice();
    this.#messageBytes = params.messageBytes.slice();
    this.#unsignedTransactionBytes = params.unsignedTransactionBytes.slice();
    this.#payload = params.payload.slice();
    this.#accountsHash = params.accountsHash.slice();
    this.messageByteLength = this.#messageBytes.length;
    this.transactionByteLength = this.#unsignedTransactionBytes.length;
    Object.freeze(this);
  }

  get sourceTransactionBytes(): Uint8Array {
    return this.#sourceTransactionBytes.slice();
  }

  get messageBytes(): Uint8Array {
    return this.#messageBytes.slice();
  }

  get unsignedTransactionBytes(): Uint8Array {
    return this.#unsignedTransactionBytes.slice();
  }

  get payload(): Uint8Array {
    return this.#payload.slice();
  }

  get accountsHash(): Uint8Array {
    return this.#accountsHash.slice();
  }
}

/**
 * Prepare the only currently supported generic dApp rewrite: an unsigned,
 * single-PDA-signer legacy/v0 source becomes an inline, lookup-free v0 session
 * `execute` transaction paid by the session signer.
 */
export function prepareSessionTransaction(
  serializedTransaction: Uint8Array,
  optionsValue: PrepareSessionTransactionOptions,
): PreparedSessionTransaction {
  const options = snapshotOptions(optionsValue);
  const smartAccountBytes = options.smartAccount.toBytes();

  let sourceEnvelope;
  try {
    sourceEnvelope = parseSerializedTransactionEnvelope(
      serializedTransaction,
      smartAccountBytes,
    );
  } catch (error) {
    smartAccountBytes.fill(0);
    if (
      error instanceof TransactionEnvelopeError &&
      error.code === "REQUESTED_SIGNER_MISSING"
    ) {
      fail(
        "SOURCE_SIGNER_MISMATCH",
        "the advertised SmartAccount is not a required source signer",
        error,
      );
    }
    fail("SOURCE_ENVELOPE_INVALID", "source envelope is invalid", error);
  }
  smartAccountBytes.fill(0);

  if (sourceEnvelope.header.numRequiredSignatures !== 1) {
    fail(
      "SOURCE_SIGNER_SET_UNSUPPORTED",
      "source transaction must require exactly the SmartAccount signer",
    );
  }
  if (sourceEnvelope.signatures.some((signature) => !allZero(signature))) {
    fail(
      "SOURCE_SIGNATURE_PRESENT",
      "source signatures and partial signatures cannot survive the rewrite",
    );
  }

  let sourceTransaction: VersionedTransaction;
  try {
    sourceTransaction = VersionedTransaction.deserialize(
      sourceEnvelope.transactionBytes,
    );
  } catch (error) {
    fail(
      "SOURCE_ENVELOPE_INVALID",
      "strict source bytes could not be deserialized by the transaction SDK",
      error,
    );
  }
  if (!bytesEqual(sourceTransaction.message.serialize(), sourceEnvelope.messageBytes)) {
    fail(
      "SOURCE_ENVELOPE_INVALID",
      "SDK deserialization changed the strict source message bytes",
    );
  }

  let sourceMessage: TransactionMessage;
  try {
    sourceMessage = TransactionMessage.decompile(sourceTransaction.message);
  } catch (error) {
    fail("SOURCE_ENVELOPE_INVALID", "source message cannot be decompiled", error);
  }
  if (sourceMessage.instructions.length === 0) {
    fail(
      "SOURCE_INSTRUCTIONS_EMPTY",
      "an empty source would produce an on-chain-invalid empty execute payload",
    );
  }
  if (isAdvanceNonceInstruction(sourceMessage.instructions[0]!)) {
    fail(
      "SOURCE_DURABLE_NONCE_UNSUPPORTED",
      "durable-nonce transactions cannot be rewritten with a fresh blockhash",
    );
  }
  if (
    sourceMessage.instructions.some((instruction) =>
      instruction.keys.some((meta) =>
        meta.pubkey.equals(SYSVAR_INSTRUCTIONS_PUBKEY),
      ),
    )
  ) {
    fail(
      "SOURCE_INSTRUCTIONS_SYSVAR_UNSUPPORTED",
      "instructions that inspect the top-level Instructions sysvar cannot be wrapped into CPI",
    );
  }

  let wrapped;
  try {
    wrapped = wrapForExecute(sourceTransaction.message, {
      wardenProgram: options.wardenProgram,
      smartAccount: options.smartAccount,
      signer: options.sessionSigner,
      payer: options.sessionSigner,
      session: options.sessionAccount,
      registry: options.registry,
      luts: [],
    });
  } catch (error) {
    fail(
      "SOURCE_WRAP_UNSUPPORTED",
      "source instruction privileges cannot be preserved by generic execute",
      error,
    );
  }
  if (wrapped.decoded.ixs.length === 0) {
    fail(
      "SOURCE_INSTRUCTIONS_EMPTY",
      "source contains only top-level budget instructions and no executable intent",
    );
  }

  const executeData = encodeInlineSessionExecute(wrapped.payload);
  const expectedExecuteMetas = copyMetas(wrapped.executeAccountMetas);
  const executeInstruction = new TransactionInstruction({
    programId: options.wardenProgram,
    keys: expectedExecuteMetas,
    data: Buffer.from(executeData),
  });

  let finalMessage;
  let finalMessageBytes: Uint8Array;
  let unsignedTransactionBytes: Uint8Array;
  try {
    finalMessage = new TransactionMessage({
      payerKey: options.sessionSigner,
      recentBlockhash: new PublicKey(options.recentBlockhash).toBase58(),
      instructions: [...wrapped.computeBudgetIxs, executeInstruction],
    }).compileToV0Message();
    finalMessageBytes = finalMessage.serialize();
    unsignedTransactionBytes = new VersionedTransaction(finalMessage).serialize();
  } catch (error) {
    if (compilationLooksOversized(error)) {
      fail(
        "FINAL_TRANSACTION_TOO_LARGE",
        `wrapped transaction exceeds the ${MAX_TX_BYTES}-byte packet limit`,
        error,
      );
    }
    fail("FINAL_INVARIANT_VIOLATION", "final v0 compilation failed", error);
  }
  if (unsignedTransactionBytes.length > MAX_TX_BYTES) {
    fail(
      "FINAL_TRANSACTION_TOO_LARGE",
      `wrapped transaction is ${unsignedTransactionBytes.length} bytes, exceeding ${MAX_TX_BYTES}`,
    );
  }

  let finalEnvelope;
  try {
    finalEnvelope = parseSerializedTransactionEnvelope(
      unsignedTransactionBytes,
      options.sessionSigner.toBytes(),
    );
  } catch (error) {
    fail(
      "FINAL_INVARIANT_VIOLATION",
      "final serialization failed the independent strict envelope parser",
      error,
    );
  }
  if (
    finalEnvelope.version !== 0 ||
    finalEnvelope.header.numRequiredSignatures !== 1 ||
    finalEnvelope.signatures.length !== 1 ||
    !allZero(finalEnvelope.signatures[0]!) ||
    !bytesEqual(finalEnvelope.messageBytes, finalMessageBytes) ||
    !bytesEqual(finalEnvelope.recentBlockhash, options.recentBlockhash)
  ) {
    fail(
      "FINAL_INVARIANT_VIOLATION",
      "final signer, signature slot, blockhash, version, or message bytes drifted",
    );
  }

  let finalDecompiled: TransactionMessage;
  try {
    finalDecompiled = TransactionMessage.decompile(finalMessage);
  } catch (error) {
    fail(
      "FINAL_INVARIANT_VIOLATION",
      "final message could not be decompiled for privilege verification",
      error,
    );
  }
  const finalExecute = finalDecompiled.instructions.at(-1);
  if (
    finalExecute === undefined ||
    !finalExecute.programId.equals(options.wardenProgram) ||
    !bytesEqual(finalExecute.data, executeData) ||
    finalExecute.keys.length !== expectedExecuteMetas.length
  ) {
    fail(
      "FINAL_INVARIANT_VIOLATION",
      "final execute instruction data or account shape drifted",
    );
  }
  for (let index = 0; index < expectedExecuteMetas.length; index++) {
    const expected = expectedExecuteMetas[index]!;
    const actual = finalExecute.keys[index]!;
    if (
      !actual.pubkey.equals(expected.pubkey) ||
      actual.isSigner !== expected.isSigner ||
      actual.isWritable !== expected.isWritable
    ) {
      fail(
        "FINAL_INVARIANT_VIOLATION",
        `final execute account meta ${index} drifted after compilation`,
      );
    }
  }

  const finalLogical: LogicalAccount[] = [
    finalExecute.keys[0]!,
    finalExecute.keys[1]!,
    ...finalExecute.keys.slice(EXECUTE_NAMED_ACCOUNT_COUNT),
  ].map((meta) => ({
    key: meta.pubkey.toBytes(),
    isSigner: meta.isSigner,
    isWritable: meta.isWritable,
  }));
  if (!bytesEqual(computeAccountsHash(finalLogical), wrapped.accountsHash)) {
    fail(
      "FINAL_INVARIANT_VIOLATION",
      "final runtime-visible logical accounts do not reproduce accountsHash",
    );
  }

  return new PreparedSessionTransactionValue({
    sourceVersion: sourceEnvelope.version,
    sourceTransactionBytes: sourceEnvelope.transactionBytes,
    messageBytes: finalEnvelope.messageBytes,
    unsignedTransactionBytes: finalEnvelope.transactionBytes,
    payload: wrapped.payload,
    accountsHash: wrapped.accountsHash,
  });
}
