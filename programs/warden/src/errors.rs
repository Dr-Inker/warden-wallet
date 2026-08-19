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
    #[msg("origin is not exactly chrome-extension:// + a 32-char a..p extension id")]
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
    // ---------------------------------------------------------------------
    // freeze / unfreeze (Task 6). APPEND ONLY — see the note above.
    // ---------------------------------------------------------------------
    #[msg("account is already frozen by root")]
    AlreadyFrozen,
    #[msg("the unfreeze timelock has not yet elapsed")]
    TimelockNotElapsed,
    // ---------------------------------------------------------------------
    // transfer (Task 7). APPEND ONLY — see the note above.
    // ---------------------------------------------------------------------
    #[msg("a native transfer would leave the account below the rent-exempt minimum")]
    RentFloor,
    #[msg("the destination token account is owned by the smart account itself")]
    VaultDestination,
    #[msg("per-session day / 30-day caps are not supported in Phase 1A — set per_day = per_30d = 0")]
    SessionDayCapsUnsupported,
    // ---------------------------------------------------------------------
    // Phase 1A milestone security review (Task 9). APPEND ONLY — see above.
    // ---------------------------------------------------------------------
    #[msg("root key is not a canonical compressed secp256r1 (P-256) point")]
    InvalidRootKey,
    #[msg("prior_authority_hash does not match the session's current retained authority")]
    SessionPriorStateMismatch,
    // ---------------------------------------------------------------------
    // Phase 1B Task 0 — slot-based root freshness + top-level-only root
    // paths. APPEND ONLY — see the note above. These are the first three
    // codes of the Phase 1B ABI block (6036+).
    // ---------------------------------------------------------------------
    #[msg("the root ceremony's signed_slot is more than MAX_ROOT_SLOT_AGE slots behind the current slot")]
    RootSlotStale,
    #[msg("the root ceremony's signed_slot is in the future")]
    RootSlotInFuture,
    #[msg("a root-authorized instruction may only be invoked at transaction level, never via CPI")]
    RootRequiresTopLevel,
}
