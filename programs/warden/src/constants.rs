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

/// Cap on how many `MintCap`s a single `grant_session` may carry (Task 5).
///
/// A root-authorized instruction shares its 1,232 B transaction with the
/// secp256r1 precompile instruction (182 B of data, measured) and with
/// `RootArgs` — 37 B `authenticatorData`, a canonical Chrome-shaped
/// `clientDataJSON` of 164 B, and 9 B of scalars, so 218 B — which leaves
/// only a few hundred bytes for the instruction's own arguments. Each
/// `MintCap` is 56 B on the wire and each parallel lifetime cap another 8 B,
/// so every extra cap costs 64 B. The plan (rev 2) estimated 4 caps would NOT
/// fit and fixed the limit at 2; the measured 2-cap grant transaction is
/// 944 B (see docs/program/PHASE1A-MEASUREMENTS.md), asserted by
/// `sessions::grant_tx_fits_1232_bytes_with_2_caps`.
///
/// Independent of `MAX_MINT_CAPS` (8), which is the `SessionKey`'s fixed slot
/// count and stays 8: a session accumulates more than
/// `MAX_CAPS_PER_GRANT` mints across *several* grants, because `grant_session`
/// merges by mint into the existing slots rather than replacing them.
pub const MAX_CAPS_PER_GRANT: usize = 2;

/// The only `SessionKey::kind` Phase 1A supports: an Ed25519 delegate signer.
pub const SESSION_KIND_ED25519: u8 = 0;
