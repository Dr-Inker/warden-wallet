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
import { ed25519 } from "@noble/curves/ed25519.js";

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

export type SessionTransactionSignErrorCode =
  | "INVALID_APPROVED_MESSAGE"
  | "INVALID_SESSION_SEED"
  | "APPROVED_MESSAGE_VERSION_UNSUPPORTED"
  | "APPROVED_MESSAGE_LOOKUPS_UNSUPPORTED"
  | "APPROVED_SIGNER_SET_UNSUPPORTED"
  | "SESSION_SIGNER_MISMATCH"
  | "APPROVED_BLOCKHASH_INVALID"
  | "SIGNED_TRANSACTION_TOO_LARGE"
  | "SIGNED_INVARIANT_VIOLATION";

export class SessionTransactionSignError extends Error {
  readonly code: SessionTransactionSignErrorCode;

  constructor(
    code: SessionTransactionSignErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(`session transaction signing: ${message}`, options);
    this.name = "SessionTransactionSignError";
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

/**
 * Copy-isolated result of signing one exact approval message. The transaction
 * differs from its canonical unsigned envelope only in the sole signature
 * slot; the message bytes themselves are never reconstructed or refreshed.
 */
export interface SignedSessionTransaction {
  readonly messageBytes: Uint8Array;
  readonly transactionBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly sessionSigner: Uint8Array;
  readonly recentBlockhash: Uint8Array;
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

function signFail(
  code: SessionTransactionSignErrorCode,
  message: string,
  cause?: unknown,
): never {
  throw new SessionTransactionSignError(
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

class SignedSessionTransactionValue implements SignedSessionTransaction {
  readonly messageByteLength: number;
  readonly transactionByteLength: number;
  readonly #messageBytes: Uint8Array;
  readonly #transactionBytes: Uint8Array;
  readonly #signature: Uint8Array;
  readonly #sessionSigner: Uint8Array;
  readonly #recentBlockhash: Uint8Array;

  constructor(params: {
    messageBytes: Uint8Array;
    transactionBytes: Uint8Array;
    signature: Uint8Array;
    sessionSigner: Uint8Array;
    recentBlockhash: Uint8Array;
  }) {
    this.#messageBytes = params.messageBytes.slice();
    this.#transactionBytes = params.transactionBytes.slice();
    this.#signature = params.signature.slice();
    this.#sessionSigner = params.sessionSigner.slice();
    this.#recentBlockhash = params.recentBlockhash.slice();
    this.messageByteLength = this.#messageBytes.length;
    this.transactionByteLength = this.#transactionBytes.length;
    Object.freeze(this);
  }

  get messageBytes(): Uint8Array {
    return this.#messageBytes.slice();
  }

  get transactionBytes(): Uint8Array {
    return this.#transactionBytes.slice();
  }

  get signature(): Uint8Array {
    return this.#signature.slice();
  }

  get sessionSigner(): Uint8Array {
    return this.#sessionSigner.slice();
  }

  get recentBlockhash(): Uint8Array {
    return this.#recentBlockhash.slice();
  }
}

function snapshotApprovedMessage(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length === 0) {
    signFail(
      "INVALID_APPROVED_MESSAGE",
      "approved message must be a non-empty Uint8Array",
    );
  }
  if (value.length + 65 > MAX_TX_BYTES) {
    signFail(
      "SIGNED_TRANSACTION_TOO_LARGE",
      `approved message cannot fit a ${MAX_TX_BYTES}-byte signed transaction`,
    );
  }
  return value.slice();
}

function snapshotSessionSeed(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    signFail(
      "INVALID_SESSION_SEED",
      "session signer seed must contain exactly 32 bytes",
    );
  }
  return value.slice();
}

/**
 * Sign the exact message stored in an already-claimed approval record.
 *
 * This function deliberately accepts no blockhash override, transaction
 * builder, or caller-provided signer identity. It derives the Ed25519 public
 * key from the leased seed, requires that key to be the message's sole signer,
 * and constructs the canonical one-signature transaction envelope around the
 * approved bytes. This is a cryptographic finalizer, not a semantic verdict: a
 * coordinator must still prove the local decoder/allowlist result, approval
 * digest, current authority/policy, and blockhash validity immediately before
 * invoking it.
 */
export function signApprovedSessionMessage(
  approvedMessageValue: Uint8Array,
  sessionSignerSeedValue: Uint8Array,
): SignedSessionTransaction {
  const approvedMessage = snapshotApprovedMessage(approvedMessageValue);
  const sessionSeed = snapshotSessionSeed(sessionSignerSeedValue);
  let sessionSigner: Uint8Array | undefined;
  let unsignedTransaction: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  let signedTransaction: Uint8Array | undefined;

  try {
    try {
      sessionSigner = ed25519.getPublicKey(sessionSeed);
    } catch (error) {
      signFail("INVALID_SESSION_SEED", "session signer key derivation failed", error);
    }

    // One canonical ShortU16 signature count, one empty signature, then the
    // exact message. No SDK recompile is permitted at this boundary.
    unsignedTransaction = new Uint8Array(1 + 64 + approvedMessage.length);
    unsignedTransaction[0] = 1;
    unsignedTransaction.set(approvedMessage, 65);

    let envelope;
    try {
      envelope = parseSerializedTransactionEnvelope(
        unsignedTransaction,
        sessionSigner,
      );
    } catch (error) {
      if (error instanceof TransactionEnvelopeError) {
        if (error.code === "SIGNATURE_COUNT_MISMATCH") {
          signFail(
            "APPROVED_SIGNER_SET_UNSUPPORTED",
            "approved message must require exactly one signer",
            error,
          );
        }
        if (error.code === "REQUESTED_SIGNER_MISSING") {
          signFail(
            "SESSION_SIGNER_MISMATCH",
            "leased session seed is not the approved message signer",
            error,
          );
        }
        if (error.code === "ADDRESS_LOOKUPS_UNSUPPORTED") {
          signFail(
            "APPROVED_MESSAGE_LOOKUPS_UNSUPPORTED",
            "approved message must not contain address-table lookups",
            error,
          );
        }
        if (error.code === "UNSUPPORTED_VERSION") {
          signFail(
            "APPROVED_MESSAGE_VERSION_UNSUPPORTED",
            "approved message version is unsupported",
            error,
          );
        }
      }
      signFail("INVALID_APPROVED_MESSAGE", "approved message is malformed", error);
    }

    if (envelope.version !== 0) {
      signFail(
        "APPROVED_MESSAGE_VERSION_UNSUPPORTED",
        "approved session message must be lookup-free v0",
      );
    }
    if (
      envelope.header.numRequiredSignatures !== 1 ||
      envelope.requiredSignerKeys.length !== 1 ||
      !bytesEqual(envelope.requiredSignerKeys[0]!, sessionSigner)
    ) {
      signFail(
        "APPROVED_SIGNER_SET_UNSUPPORTED",
        "approved message signer set drifted after strict parsing",
      );
    }
    if (!allZero(envelope.signatures[0]!)) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "canonical unsigned envelope unexpectedly contains a signature",
      );
    }
    if (allZero(envelope.recentBlockhash)) {
      signFail(
        "APPROVED_BLOCKHASH_INVALID",
        "approved message recent blockhash must not be all zero",
      );
    }
    if (!bytesEqual(envelope.messageBytes, approvedMessage)) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "strict parser changed the approved message bytes",
      );
    }

    let sdkUnsigned: VersionedTransaction;
    try {
      sdkUnsigned = VersionedTransaction.deserialize(unsignedTransaction);
    } catch (error) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "SDK rejected the strict approved message envelope",
        error,
      );
    }
    if (
      sdkUnsigned.version !== 0 ||
      sdkUnsigned.signatures.length !== 1 ||
      !allZero(sdkUnsigned.signatures[0]!) ||
      !bytesEqual(sdkUnsigned.message.serialize(), approvedMessage) ||
      !bytesEqual(sdkUnsigned.serialize(), unsignedTransaction)
    ) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "SDK interpretation drifted from the strict approved message envelope",
      );
    }

    try {
      signature = ed25519.sign(approvedMessage, sessionSeed);
    } catch (error) {
      signFail("SIGNED_INVARIANT_VIOLATION", "Ed25519 signing failed", error);
    }
    if (
      signature.length !== 64 ||
      !ed25519.verify(signature, approvedMessage, sessionSigner)
    ) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "Ed25519 signature did not verify over the approved message",
      );
    }

    signedTransaction = unsignedTransaction.slice();
    signedTransaction.set(signature, 1);

    let signedEnvelope;
    try {
      signedEnvelope = parseSerializedTransactionEnvelope(
        signedTransaction,
        sessionSigner,
      );
    } catch (error) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "signed transaction failed strict reparsing",
        error,
      );
    }
    if (
      signedEnvelope.version !== 0 ||
      signedEnvelope.header.numRequiredSignatures !== 1 ||
      signedEnvelope.signatures.length !== 1 ||
      !bytesEqual(signedEnvelope.signatures[0]!, signature) ||
      !bytesEqual(signedEnvelope.messageBytes, approvedMessage) ||
      !bytesEqual(signedEnvelope.recentBlockhash, envelope.recentBlockhash) ||
      !ed25519.verify(
        signedEnvelope.signatures[0]!,
        signedEnvelope.messageBytes,
        sessionSigner,
      )
    ) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "signature attachment changed or failed to authenticate the approved message",
      );
    }

    let sdkSigned: VersionedTransaction;
    try {
      sdkSigned = VersionedTransaction.deserialize(signedTransaction);
    } catch (error) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "SDK rejected the strictly reparsed signed transaction",
        error,
      );
    }
    if (
      sdkSigned.version !== 0 ||
      sdkSigned.signatures.length !== 1 ||
      !bytesEqual(sdkSigned.signatures[0]!, signature) ||
      !bytesEqual(sdkSigned.message.serialize(), approvedMessage) ||
      !bytesEqual(sdkSigned.serialize(), signedTransaction)
    ) {
      signFail(
        "SIGNED_INVARIANT_VIOLATION",
        "SDK serialization changed the signed transaction",
      );
    }

    return new SignedSessionTransactionValue({
      messageBytes: approvedMessage,
      transactionBytes: signedTransaction,
      signature,
      sessionSigner,
      recentBlockhash: signedEnvelope.recentBlockhash,
    });
  } finally {
    approvedMessage.fill(0);
    sessionSeed.fill(0);
    sessionSigner?.fill(0);
    unsignedTransaction?.fill(0);
    signature?.fill(0);
    signedTransaction?.fill(0);
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
