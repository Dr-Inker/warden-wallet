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
    #[msg("the root ceremony's signed_slot is at least MAX_ROOT_SLOT_AGE (150) slots behind the current slot")]
    RootSlotStale,
    #[msg("the root ceremony's signed_slot is in the future")]
    RootSlotInFuture,
    #[msg("a root-authorized instruction may only be invoked at transaction level, never via CPI")]
    RootRequiresTopLevel,
    // ---------------------------------------------------------------------
    // Phase 1B Task 1 — `conservation` (snapshot / compare / accounting), plus
    // the codes Tasks 3/4/5 raise, defined here so the ABI block is appended
    // ONCE and never renumbered mid-phase. APPEND ONLY — see the note above.
    // Codes 6039..=6050; the pinned drift table in tests/root_verify.rs is the
    // single place they are checked against this enum.
    // ---------------------------------------------------------------------
    #[msg("a CPI changed a vault-owned account in a way conservation forbids")]
    ConservationViolated,
    #[msg("a vault-owned account that is not an SPL/Token-2022 token account was passed writable")]
    UnsupportedAccountKind,
    #[msg("the mint of a writable vault-owned token account is not present in the account list")]
    MintMissing,
    #[msg("the mint carries a Token-2022 extension that is never allow-listable (transfer hook, permanent delegate, confidential transfer)")]
    Token2022ExtensionRejected,
    #[msg("the mint carries the Token-2022 transfer-fee extension, which Phase 1B does not support")]
    TransferFeeMintUnsupported,
    #[msg("an inner instruction targets the warden program itself")]
    SelfCpiRejected,
    #[msg("the execute payload is malformed")]
    PayloadInvalid,
    #[msg("the adapter registry does not allow this (program, instruction) pair")]
    RegistryDenied,
    #[msg("the staged content does not match this instruction")]
    StageInvalid,
    #[msg("the staged content has expired")]
    StageExpired,
    #[msg("compute-budget instructions are top-level only and may not appear in an execute payload")]
    ComputeBudgetInExecute,
    #[msg("this (program, instruction) pair is on the fixed deny-list and no registry entry can re-enable it")]
    DenyListed,
    // ---------------------------------------------------------------------
    // Task 1, round-1 review fix (Codex C2). APPEND ONLY — see above.
    // ---------------------------------------------------------------------
    #[msg("a CPI created, or converted an existing account into, an account the vault owns")]
    NewVaultAccountRejected,
    // ---------------------------------------------------------------------
    // Task 3 (registry). APPEND ONLY — see above.
    // ---------------------------------------------------------------------
    #[msg("the registry already holds the maximum number of entries")]
    RegistryFull,
    #[msg("init_registry must be signed by the program's upgrade authority")]
    RegistryUnauthorized,
    #[msg("the registry is already initialized")]
    RegistryAlreadyInitialized,
    #[msg("program_allowlist_id is not 0 and not an existing list in the account's registry")]
    InvalidAllowlistId,
    // ---------------------------------------------------------------------
    // Task 5 (execute). APPEND ONLY — see above. Codes 6056..=6057.
    // ---------------------------------------------------------------------
    #[msg("execute was passed more remaining accounts than MAX_EXECUTE_ACCOUNTS_TOTAL")]
    TooManyExecuteAccounts,
    #[msg("execute was passed more writable remaining accounts than MAX_EXECUTE_WRITABLE")]
    TooManyExecuteWritable,
    #[msg("Jupiter must be routed through swap (adapter-decoded max_in + quote sanity), not generic execute")]
    JupiterViaSwapOnly,
    #[msg("a pubkey appears more than once in the logical account list")]
    DuplicateLogicalAccount,
    // ---------------------------------------------------------------------
    // Task 6 (swap). APPEND ONLY — see above. Codes 6060..=6070.
    // ---------------------------------------------------------------------
    #[msg("swap may only CPI the pinned Jupiter program")]
    SwapProgramNotPinned,
    #[msg("swap instruction discriminator is not route or shared_accounts_route")]
    SwapBadDiscriminator,
    #[msg("swap route data is too short to carry the fixed argument tail")]
    SwapDataTooShort,
    #[msg("swap requires platform_fee_bps == 85 so the treasury fee is always taken")]
    SwapPlatformFeeBps,
    #[msg("swap user_transfer_authority is not the vault PDA")]
    SwapAuthorityNotVault,
    #[msg("swap source token account is not the vault ATA of in_mint")]
    SwapSourceNotVaultAta,
    #[msg("swap destination token account is not the vault ATA of out_mint")]
    SwapDestNotVaultAta,
    #[msg("swap platform_fee_account is not a treasury ATA of in_mint or out_mint")]
    SwapFeeAccountNotTreasury,
    #[msg("the swap route's declared in_amount exceeds the authorized max_in")]
    SwapMaxInExceeded,
    #[msg("the swap credited less than min_out to the vault out ATA")]
    SwapMinOutNotMet,
    #[msg("swap out_mint is not in the session's caps or the default allowed set")]
    SwapOutMintNotAllowed,
    #[msg("swap moved value the adapter did not authorize (unexpected vault outflow)")]
    SwapUnexpectedOutflow,
}
