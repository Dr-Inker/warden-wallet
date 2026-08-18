pub const ACCOUNT_SEED: &[u8] = b"account";
pub const SESSION_SEED: &[u8] = b"session";
pub const MAX_CLIENT_DATA_LEN: usize = 512;
pub const MAX_ROOT_EXPIRY_SECS: i64 = 600;
pub const MAX_MINT_CAPS: usize = 8;
pub const MAX_SESSIONS_LISTED: usize = 0; // sessions are separate PDAs; no list on the account
pub const DAY_SECS: i64 = 86_400;
pub const RING_DAYS: usize = 30;
/// Cap on how many distinct mints `create_account` may configure in a single
/// instruction (Task 4 round-1 review finding: a `PolicyArgs` carrying all
/// `MAX_MINT_CAPS` (8) mints across `caps`/`session_ceiling`/
/// `large_threshold` does not fit Solana's 1,232 B transaction packet limit
/// — see docs/program/PHASE1A-MEASUREMENTS.md for the measured sizes at 2
/// and `MAX_MINTS_AT_CREATE` mints). Independent of `MAX_MINT_CAPS`, which is
/// the on-chain `Policy`'s fixed array width and stays 8 either way: mints
/// beyond this count are added after creation via a root-authorized
/// `set_policy` instruction (Phase 1B), never by raising this constant.
pub const MAX_MINTS_AT_CREATE: usize = 4;
