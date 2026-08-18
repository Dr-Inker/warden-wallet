use anchor_lang::prelude::*;
#[error_code]
pub enum WardenError {
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("account is frozen")]
    Frozen,
    #[msg("unauthorized signer")]
    Unauthorized,
    #[msg("invalid root assertion")]
    InvalidRootAssertion,
    #[msg("root nonce mismatch")]
    NonceMismatch,
    #[msg("expired")]
    Expired,
    #[msg("cap exceeded")]
    CapExceeded,
    #[msg("session expired")]
    SessionExpired,
    #[msg("operation not allowed for this signer")]
    OpNotAllowed,
    #[msg("invalid account data")]
    InvalidAccountData,
    #[msg("bad instruction layout")]
    BadInstructionLayout,
    // ---------------------------------------------------------------------
    // root_verify (Task 3). APPEND ONLY: Anchor derives the on-wire error
    // code from declaration order (6000 + index), so never reorder or insert
    // above this point — TS clients and tests assert exact `Custom(code)`.
    // ---------------------------------------------------------------------
    #[msg("clientDataJSON exceeds MAX_CLIENT_DATA_LEN")]
    ClientDataTooLong,
    #[msg("clientDataJSON is not well-formed JSON for the strict scanner")]
    ClientDataMalformed,
    #[msg("duplicate top-level key in clientDataJSON")]
    ClientDataDuplicateKey,
    #[msg("clientDataJSON is missing a required top-level key")]
    ClientDataMissingKey,
    #[msg("clientDataJSON.type is not webauthn.get")]
    ClientDataTypeMismatch,
    #[msg("clientDataJSON.crossOrigin is true")]
    CrossOriginNotAllowed,
    #[msg("clientDataJSON.origin does not match the account origin")]
    OriginMismatch,
    #[msg("clientDataJSON.challenge does not match the root transcript")]
    ChallengeMismatch,
    #[msg("authenticatorData is shorter than 37 bytes")]
    AuthDataTooShort,
    #[msg("authenticatorData rpIdHash does not match the account rp_id_hash")]
    RpIdHashMismatch,
    #[msg("authenticatorData flags lack user-present and user-verified")]
    UserVerificationRequired,
    #[msg("no secp256r1 precompile instruction at the named index before this one")]
    PrecompileNotFound,
    #[msg("secp256r1 precompile instruction does not bind this key and message")]
    PrecompileBindingMismatch,
    #[msg("root key kind is not supported by this instruction")]
    RootKindUnsupported,
    // ---------------------------------------------------------------------
    // create_account (Task 4). APPEND ONLY — see the note above.
    // ---------------------------------------------------------------------
    #[msg("origin is empty, too long, missing the chrome-extension:// prefix, contains a NUL byte, or has trailing whitespace")]
    InvalidOrigin,
    #[msg("cluster_tag must be non-zero")]
    ZeroClusterTag,
    #[msg("policy fails validation (timelock/recovery/session-life bounds or cap ordering)")]
    InvalidPolicy,
    // ---------------------------------------------------------------------
    // sessions (Task 5). APPEND ONLY — see the note above.
    // ---------------------------------------------------------------------
    #[msg("program_allowlist_id must be 0 until the Phase 1B adapter registry exists")]
    ProgramAllowlistUnsupported,
}
