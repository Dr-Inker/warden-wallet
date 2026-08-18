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
}
