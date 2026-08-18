use anchor_lang::prelude::Pubkey;

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

// ---------------------------------------------------------------------------
// Token constants (Task 7, `transfer`)
// ---------------------------------------------------------------------------

/// SPL Token program id (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`) — the
/// ONLY token program Phase 1A's `transfer` will CPI into. Token-2022
/// (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`) lands in Phase 1B, where
/// the transfer-fee / transfer-hook / confidential-transfer extensions each
/// need their own rule before the vault may move a balance under them.
///
/// Hardcoded rather than imported: `spl-token` (v7) resolves
/// `solana-program 2.3.x`, whose `Pubkey` is a different, non-interconvertible
/// type from the `solana-program 3.x` one Anchor 1.1.2 uses — the same
/// finding spike 3b recorded. `transfer::token_program_id_matches_spl_token`
/// (a test, with the real `spl-token` crate as a dev-dependency) pins this
/// literal against `spl_token::ID`.
pub const SPL_TOKEN_ID: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/// SPL Token-2022 program id — declared only so `transfer` can reject it with
/// an honest error instead of "not the token program".
pub const SPL_TOKEN_2022_ID: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Wrapped-SOL mint (`So11111111111111111111111111111111111111112`) — the key
/// a native-SOL transfer looks its caps up under.
///
/// `Policy.caps` / `SessionKey.caps` are keyed by mint and `Pubkey::default()`
/// is `buckets::find_cap`'s unused-slot sentinel, so native SOL needs *some*
/// real key: the native mint is the conventional one (it is what every Solana
/// client already uses to mean "SOL" in a mint-keyed table). Note this is the
/// **cap lookup key only** — a native transfer moves lamports directly and
/// never touches the wrapped-SOL mint account.
pub const NATIVE_MINT: Pubkey = Pubkey::from_str_const("So11111111111111111111111111111111111111112");

/// Fixed-layout length of an SPL Token `Account`.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// `spl_token::state::AccountState::Initialized` discriminant.
pub const TOKEN_STATE_INITIALIZED: u8 = 1;
/// `spl_token::instruction::TokenInstruction::Transfer` tag.
pub const TOKEN_IX_TRANSFER: u8 = 3;
