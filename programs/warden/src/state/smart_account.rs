use anchor_lang::prelude::*;

use crate::constants::{MAX_MINT_CAPS, MAX_MINTS_AT_CREATE, RING_DAYS};
use crate::errors::WardenError;

/// The passkey-rooted smart account, laid out as a `bytemuck`-`Pod`
/// zero-copy account (instruction handlers use `AccountLoader<'info,
/// SmartAccount>`, not `Account<'info, T>`): `SmartAccount` is ~4 KB of
/// account data, and Borsh (de)serialization builds the whole struct as a
/// stack local, which overflowed the SBF VM's 4096-byte-per-call-frame
/// limit — `anchor build` reported `try_deserialize_unchecked` at an
/// estimated 6144-byte frame before this change (see task-2-report.md,
/// "Fix report — round 1"). Zero-copy casts the raw account buffer
/// directly; no stack copy of the whole struct is ever made.
///
/// Every field must be `bytemuck::Pod` (plain-old-data, no enums, no
/// padding — `bytemuck`'s `Pod` derive refuses to compile if any is
/// implicit). Enum-shaped state (`root`, `frozen`) is represented as an
/// explicit `u8` tag plus a fixed-size payload; `root()`/`set_root()` and
/// `frozen()`/`set_frozen()` bridge to/from the ergonomic `RootKey`/
/// `FrozenState` enums below, which remain plain-Borsh types — they are
/// what `create_account`/`grant`/`freeze` instructions carry as arguments
/// (Task 4+), not what's stored on-chain.
///
/// Layout is FINAL for Phase 1B: every 1B/1C field (`guardians_config`,
/// `registry`, `_reserved`) is present now, carved from `_reserved` in
/// later versions without a realloc. `version` documents each carve.
///
/// Field declaration order is deliberately NOT the brief's original order:
/// `#[repr(C)]` (which `#[account(zero_copy)]` applies) never reorders
/// fields, so to eliminate the implicit padding `Pod` would otherwise
/// reject, every 1-byte-aligned field (u8 tags and byte arrays) is grouped
/// first, padded once to an 8-byte boundary, and every 8-byte-aligned field
/// (u64/i64, and the nested `Policy`/`MintBuckets` — both internally
/// 8-aligned) follows with no further padding needed anywhere.
#[account(zero_copy)]
pub struct SmartAccount {
    pub version: u8,
    pub bump: u8,
    /// 0 = `RootKey::P256Passkey`, 1 = `RootKey::Ed25519`. See `root()`.
    pub root_kind: u8,
    pub origin_len: u8,
    /// 0 = `FrozenState::None`, 1 = `Root`, 2 = `Guardian`. See `frozen()`.
    pub frozen_kind: u8,
    pub frozen_guardian_idx: u8,
    pub owner_seed: [u8; 32],
    /// `P256Passkey`: the full 33-byte compressed point. `Ed25519`: the
    /// 32-byte pubkey in bytes `[0..32]`; byte 32 is unused (kept zero).
    pub root_pubkey: [u8; 33],
    /// == SHA-256(origin[..origin_len]) — enforced at create (Task 4).
    pub rp_id_hash: [u8; 32],
    /// Canonical full origin "chrome-extension://<32 chars>"; bytes beyond
    /// `origin_len` are zero; no NULs.
    pub origin: [u8; 64],
    /// Client-attested domain separator (genesis hash by convention) — NOT
    /// verified on-chain; bound into every root transcript.
    pub cluster_tag: [u8; 32],
    /// 1B: PDA of the guardians/recovery config (`Pubkey::default()` until
    /// set) — reserved now so no realloc later.
    pub guardians_config: Pubkey,
    /// 1B: adapter-registry PDA (default until set).
    pub registry: Pubkey,
    /// Forward-compat headroom; 1B/1C fields are carved from here without
    /// realloc.
    pub _reserved: [u8; 256],
    /// Rounds the 1-byte-aligned field block above up to an 8-byte
    /// boundary so nothing below needs further padding. Not addressable —
    /// pure alignment filler.
    pub _pad_align8: [u8; 1],
    pub generation: u64,
    pub root_nonce: u64,
    pub frozen_until: i64,
    pub frozen_at: i64,
    pub policy: Policy,
    /// Parallel to `policy.caps`.
    pub buckets: [MintBuckets; MAX_MINT_CAPS],
}

impl SmartAccount {
    /// 8-byte Anchor discriminator + the exact in-memory `Pod` size (no
    /// hidden padding: see `smart_account_len_matches_size_of` below, which
    /// asserts this against `core::mem::size_of::<SmartAccount>()` and
    /// against a hand-summed field list).
    pub const LEN: usize = 8 + core::mem::size_of::<SmartAccount>();

    /// Decode the `root_kind`/`root_pubkey` tag pair into the ergonomic
    /// enum. Errors on any tag other than 0/1 — on-chain state should never
    /// hold one (every writer goes through `set_root`), but a corrupted or
    /// future-versioned account must fail closed, not silently misread 33
    /// garbage bytes as a key.
    pub fn root(&self) -> Result<RootKey> {
        match self.root_kind {
            0 => Ok(RootKey::P256Passkey { pubkey: self.root_pubkey }),
            1 => {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&self.root_pubkey[..32]);
                Ok(RootKey::Ed25519 { pubkey: Pubkey::from(pk) })
            }
            _ => Err(WardenError::InvalidAccountData.into()),
        }
    }

    pub fn set_root(&mut self, r: &RootKey) {
        match r {
            RootKey::P256Passkey { pubkey } => {
                self.root_kind = 0;
                self.root_pubkey = *pubkey;
            }
            RootKey::Ed25519 { pubkey } => {
                self.root_kind = 1;
                self.root_pubkey = [0u8; 33];
                self.root_pubkey[..32].copy_from_slice(pubkey.as_ref());
            }
        }
    }

    /// Decode `frozen_kind`/`frozen_guardian_idx`/`frozen_until` into the
    /// ergonomic enum. Errors on any tag other than 0/1/2 (see `root()`).
    pub fn frozen(&self) -> Result<FrozenState> {
        match self.frozen_kind {
            0 => Ok(FrozenState::None),
            1 => Ok(FrozenState::Root),
            2 => Ok(FrozenState::Guardian { idx: self.frozen_guardian_idx, until: self.frozen_until }),
            _ => Err(WardenError::InvalidAccountData.into()),
        }
    }

    pub fn set_frozen(&mut self, f: &FrozenState) {
        match f {
            FrozenState::None => {
                self.frozen_kind = 0;
                self.frozen_guardian_idx = 0;
                self.frozen_until = 0;
            }
            FrozenState::Root => {
                self.frozen_kind = 1;
                self.frozen_guardian_idx = 0;
                self.frozen_until = 0;
            }
            FrozenState::Guardian { idx, until } => {
                self.frozen_kind = 2;
                self.frozen_guardian_idx = *idx;
                self.frozen_until = *until;
            }
        }
    }
}

/// Instruction-argument type only (`create_account`, Task 4) — NOT how the
/// root signer is stored on-chain; see `SmartAccount::root_kind`/
/// `root_pubkey` and `SmartAccount::root()`/`set_root()`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum RootKey {
    P256Passkey { pubkey: [u8; 33] },
    Ed25519 { pubkey: Pubkey },
}

/// Instruction-argument type only (`freeze`/`unfreeze`, Task 4+/1B) — NOT
/// how frozen state is stored on-chain; see `SmartAccount::frozen_kind`/
/// `frozen_guardian_idx`/`frozen_until` and `SmartAccount::frozen()`/
/// `set_frozen()`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum FrozenState {
    None,
    Root,
    Guardian { idx: u8, until: i64 },
}

/// Embedded in `SmartAccount` (zero-copy `Pod`). `version: u32` is followed
/// by 4 explicit padding bytes to bring the 8-byte-aligned `caps` array
/// (each `MintCap` is internally 8-aligned) to an 8-byte boundary;
/// `session_ops_ceiling: u16` is followed by 6 explicit padding bytes for
/// the same reason before `_reserved`. Without these, `bytemuck`'s `Pod`
/// derive refuses to compile (implicit padding is unsound to treat as
/// plain data).
#[zero_copy]
pub struct Policy {
    pub version: u32,
    pub _pad_version: [u8; 4],
    /// `mint == Pubkey::default()` => unused slot; SOL uses the native mint id.
    pub caps: [MintCap; MAX_MINT_CAPS],
    pub session_ceiling: [MintCap; MAX_MINT_CAPS],
    /// per_tx only used.
    pub large_threshold: [MintCap; MAX_MINT_CAPS],
    pub timelock_secs: i64,
    pub recovery_delay_secs: i64,
    pub max_session_life_secs: i64,
    pub session_ops_ceiling: u16,
    pub _pad_ceiling: [u8; 6],
    pub _reserved: [u8; 64],
}

impl Policy {
    pub const LEN: usize = core::mem::size_of::<Policy>();
}

/// Instruction-argument mirror of `Policy` (`create_account`, Task 4) — plain
/// Borsh, sparse on the wire: `caps`/`session_ceiling`/`large_threshold` are
/// `Vec<MintCap>` (each at most `MAX_MINTS_AT_CREATE` entries) instead of
/// `Policy`'s fixed 8-slot arrays, which is what let a single `create_account`
/// carrying a handful of mints blow past Solana's 1,232 B transaction limit
/// when this was a plain `[MintCap; 8]` mirror (round-1 review finding,
/// fixed here — see docs/program/PHASE1A-MEASUREMENTS.md).
///
/// `caps[i]` keeps its position (`Policy.caps[i]`); `session_ceiling`/
/// `large_threshold` entries are **not** positional — each is re-keyed by
/// `mint` onto the index of the `caps` entry with the same mint (see
/// `expand`). `create_account` additionally forces `policy.version` to 1
/// regardless of what's carried here, so this struct still declares
/// `version` only for symmetry with `Policy`'s field list.
// No `Debug`: `MintCap` (`#[zero_copy]`) doesn't derive it, and hand-writing
// one just to satisfy a derive nobody calls isn't worth the upkeep.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub struct PolicyArgs {
    pub version: u32,
    /// ≤ `MAX_MINTS_AT_CREATE` entries; every `mint` non-default and
    /// distinct within this vector.
    pub caps: Vec<MintCap>,
    /// ≤ `MAX_MINTS_AT_CREATE` entries; every `mint` must match exactly one
    /// `caps` entry (else `expand` rejects the whole policy) and be distinct
    /// within this vector (two entries keying onto the same `caps` slot is
    /// also rejected).
    pub session_ceiling: Vec<MintCap>,
    /// Same keying rules as `session_ceiling`, independently.
    pub large_threshold: Vec<MintCap>,
    pub timelock_secs: i64,
    pub recovery_delay_secs: i64,
    pub max_session_life_secs: i64,
    pub session_ops_ceiling: u16,
}

impl PolicyArgs {
    /// Expand the sparse wire representation into `Policy`'s fixed 8-slot
    /// layout (zero-filling every unused slot). Purely structural/keying
    /// validation lives here — `caps` positions are kept, `session_ceiling`/
    /// `large_threshold` are re-keyed by mint onto the matching `caps`
    /// index. Value-ordering validation (`per_tx <= per_day <= per_30d`,
    /// ceilings `<=` caps, timelock/recovery/session-life bounds) is
    /// `create_account::validate_policy`'s job, run on the `Policy` this
    /// returns.
    ///
    /// All failures below are `WardenError::InvalidAccountData` — every one
    /// of them is "the shape can't be resolved to a well-formed `Policy`",
    /// as distinct from "the shape resolved fine but a value is out of
    /// bounds" (`InvalidPolicy`, checked afterward):
    /// - more than `MAX_MINTS_AT_CREATE` entries in `caps`, `session_ceiling`,
    ///   or `large_threshold`;
    /// - a `caps` entry with `mint == Pubkey::default()`;
    /// - two `caps` entries sharing a `mint` (duplicate cap mint);
    /// - a `session_ceiling`/`large_threshold` entry whose `mint` matches no
    ///   `caps` entry (mismatched-mint / orphan ceiling or threshold);
    /// - two `session_ceiling` (or two `large_threshold`) entries sharing a
    ///   `mint` — they would collide on the same resolved `caps` index
    ///   (duplicate ceiling/threshold mint).
    pub fn expand(&self) -> Result<Policy> {
        require!(self.caps.len() <= MAX_MINTS_AT_CREATE, WardenError::InvalidAccountData);
        require!(
            self.session_ceiling.len() <= MAX_MINTS_AT_CREATE,
            WardenError::InvalidAccountData
        );
        require!(
            self.large_threshold.len() <= MAX_MINTS_AT_CREATE,
            WardenError::InvalidAccountData
        );

        let mut caps = [MintCap::default(); MAX_MINT_CAPS];
        for (i, c) in self.caps.iter().enumerate() {
            require!(c.mint != Pubkey::default(), WardenError::InvalidAccountData);
            let dup = caps[..i].iter().any(|existing| existing.mint == c.mint);
            require!(!dup, WardenError::InvalidAccountData);
            caps[i] = *c;
        }

        let session_ceiling = key_by_mint(&self.session_ceiling, &caps, self.caps.len())?;
        let large_threshold = key_by_mint(&self.large_threshold, &caps, self.caps.len())?;

        Ok(Policy {
            version: self.version,
            _pad_version: [0u8; 4],
            caps,
            session_ceiling,
            large_threshold,
            timelock_secs: self.timelock_secs,
            recovery_delay_secs: self.recovery_delay_secs,
            max_session_life_secs: self.max_session_life_secs,
            session_ops_ceiling: self.session_ops_ceiling,
            _pad_ceiling: [0u8; 6],
            _reserved: [0u8; 64],
        })
    }
}

/// Re-key `entries` by `mint` onto the index of the matching slot in
/// `caps[..used]` — see `PolicyArgs::expand`. Every entry must match exactly
/// one cap (`.position` already guarantees "at most one" once `expand` has
/// rejected duplicate cap mints; "at least one" is the `ok_or` below) and no
/// two entries may resolve to the same index.
fn key_by_mint(
    entries: &[MintCap],
    caps: &[MintCap; MAX_MINT_CAPS],
    used: usize,
) -> Result<[MintCap; MAX_MINT_CAPS]> {
    let mut out = [MintCap::default(); MAX_MINT_CAPS];
    for e in entries {
        let idx = caps[..used]
            .iter()
            .position(|c| c.mint == e.mint)
            .ok_or(WardenError::InvalidAccountData)?;
        require!(out[idx].mint == Pubkey::default(), WardenError::InvalidAccountData);
        out[idx] = *e;
    }
    Ok(out)
}

/// Zero-copy `Pod` (embedded in `Policy`/`SmartAccount`) AND plain Borsh
/// (embedded in `SessionKey`, which stays a normal non-zero-copy
/// `#[account]` — see that struct). `mint: Pubkey` (32 B, alignment 1) is
/// followed directly by three `u64`s (8 B, alignment 8); 32 is already a
/// multiple of 8, so no explicit padding is needed here.
///
/// `AnchorSerialize`/`AnchorDeserialize` are implemented **by hand** below
/// instead of derived: `#[zero_copy]` already derives `IdlBuild` (needed
/// under the `idl-build` feature that `anchor build`'s IDL-generation pass
/// enables), and anchor-derive-serde's `AnchorSerialize`/`AnchorDeserialize`
/// derive macros unconditionally derive `IdlBuild` too — stacking both on
/// one type is `E0119: conflicting implementations of trait IdlBuild`. A
/// hand-written impl gives the same Borsh wire format (field order,
/// identical to what `#[derive(AnchorSerialize, AnchorDeserialize)]` would
/// have produced) without emitting a second `IdlBuild` impl.
#[zero_copy]
#[derive(Default, PartialEq, Eq)]
pub struct MintCap {
    pub mint: Pubkey,
    pub per_tx: u64,
    pub per_day: u64,
    pub per_30d: u64,
}

impl MintCap {
    pub const LEN: usize = core::mem::size_of::<MintCap>();
}

impl AnchorSerialize for MintCap {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.mint.serialize(writer)?;
        self.per_tx.serialize(writer)?;
        self.per_day.serialize(writer)?;
        self.per_30d.serialize(writer)
    }
}

impl AnchorDeserialize for MintCap {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            mint: Pubkey::deserialize_reader(reader)?,
            per_tx: u64::deserialize_reader(reader)?,
            per_day: u64::deserialize_reader(reader)?,
            per_30d: u64::deserialize_reader(reader)?,
        })
    }
}

/// Zero-copy `Pod` (embedded in `SmartAccount.buckets`). All four fields
/// are 8-byte-aligned (`i64`/`u64`/`[u64; 30]`) and declared back to back,
/// so no padding is needed anywhere in this struct.
#[zero_copy]
#[derive(Default, PartialEq, Eq)]
pub struct MintBuckets {
    pub day_start: i64,
    pub spent_today: u64,
    pub ring_day_index: i64,
    pub ring: [u64; RING_DAYS],
}

impl MintBuckets {
    pub const LEN: usize = core::mem::size_of::<MintBuckets>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeroed_account() -> SmartAccount {
        // `Zeroable` (from `#[account(zero_copy)]`) guarantees an all-zero
        // value is a valid `SmartAccount`; that's exactly what a freshly
        // allocated, not-yet-initialized account's bytes look like too.
        bytemuck::Zeroable::zeroed()
    }

    #[test]
    fn root_round_trips_p256passkey() {
        let mut a = zeroed_account();
        let want = RootKey::P256Passkey { pubkey: [7u8; 33] };
        a.set_root(&want);
        assert!(a.root().unwrap() == want);
    }

    #[test]
    fn root_round_trips_ed25519() {
        let mut a = zeroed_account();
        let pk = Pubkey::new_unique();
        let want = RootKey::Ed25519 { pubkey: pk };
        a.set_root(&want);
        assert!(a.root().unwrap() == want);
        // Byte 32 of the storage slot is unused and must stay zero.
        assert_eq!(a.root_pubkey[32], 0);
    }

    #[test]
    fn root_invalid_tag_rejected() {
        let mut a = zeroed_account();
        a.root_kind = 2;
        assert_eq!(a.root().unwrap_err(), anchor_lang::error::Error::from(WardenError::InvalidAccountData));
    }

    #[test]
    fn frozen_round_trips_all_variants() {
        let mut a = zeroed_account();
        for want in [FrozenState::None, FrozenState::Root, FrozenState::Guardian { idx: 3, until: 12345 }] {
            a.set_frozen(&want);
            assert!(a.frozen().unwrap() == want);
        }
    }

    #[test]
    fn frozen_invalid_tag_rejected() {
        let mut a = zeroed_account();
        a.frozen_kind = 3;
        assert_eq!(a.frozen().unwrap_err(), anchor_lang::error::Error::from(WardenError::InvalidAccountData));
    }

    #[test]
    fn smart_account_len_matches_size_of() {
        // Hand-summed from the field list, grouped by the same alignment
        // logic documented on the struct: align-1 block (incl. the single
        // 1-byte pad to reach a multiple of 8) + align-8 block.
        let align1_block = 1 + 1 + 1 + 1 + 1 + 1 // version..frozen_guardian_idx
            + 32  // owner_seed
            + 33  // root_pubkey
            + 32  // rp_id_hash
            + 64  // origin
            + 32  // cluster_tag
            + 32  // guardians_config
            + 32  // registry
            + 256 // _reserved
            + 1; // _pad_align8
        assert_eq!(align1_block % 8, 0, "align-1 block must end on an 8-byte boundary");
        let align8_block = 8 + 8 + 8 + 8 // generation, root_nonce, frozen_until, frozen_at
            + Policy::LEN
            + MintBuckets::LEN * MAX_MINT_CAPS;
        let hand_summed = align1_block + align8_block;
        assert_eq!(core::mem::size_of::<SmartAccount>(), hand_summed);
        assert_eq!(SmartAccount::LEN, 8 + hand_summed);
    }

    #[test]
    fn policy_len_matches_size_of_with_documented_padding() {
        let hand_summed = 4 // version
            + 4 // _pad_version
            + MintCap::LEN * MAX_MINT_CAPS // caps
            + MintCap::LEN * MAX_MINT_CAPS // session_ceiling
            + MintCap::LEN * MAX_MINT_CAPS // large_threshold
            + 8 + 8 + 8 // timelock_secs, recovery_delay_secs, max_session_life_secs
            + 2 // session_ops_ceiling
            + 6 // _pad_ceiling
            + 64; // _reserved
        assert_eq!(Policy::LEN, hand_summed);
        assert_eq!(Policy::LEN, core::mem::size_of::<Policy>());
    }

    #[test]
    fn mint_cap_len_has_no_padding() {
        // Pubkey (32, align 1) is already a multiple of 8, so the three
        // trailing u64s need no padding before them.
        assert_eq!(MintCap::LEN, 32 + 8 + 8 + 8);
    }

    #[test]
    fn mint_buckets_len_has_no_padding() {
        assert_eq!(MintBuckets::LEN, 8 + 8 + 8 + 8 * RING_DAYS);
    }

    // -- PolicyArgs::expand ------------------------------------------------

    fn mint_cap(mint: Pubkey, per_tx: u64, per_day: u64, per_30d: u64) -> MintCap {
        MintCap { mint, per_tx, per_day, per_30d }
    }

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    /// `Result<Policy>::unwrap_err()` would need `Policy: Debug`, which it
    /// doesn't derive (matches `MintCap`'s own no-`Debug` note above) — this
    /// sidesteps that instead of adding a derive nobody else needs.
    fn expect_expand_err(a: &PolicyArgs, e: WardenError) {
        match a.expand() {
            Ok(_) => panic!("expand() must reject this PolicyArgs"),
            Err(actual) => assert_eq!(actual, err(e)),
        }
    }

    fn base_policy_args() -> PolicyArgs {
        PolicyArgs {
            version: 1,
            caps: vec![],
            session_ceiling: vec![],
            large_threshold: vec![],
            timelock_secs: 3600,
            recovery_delay_secs: 3600,
            max_session_life_secs: 2_592_000,
            session_ops_ceiling: 0,
        }
    }

    #[test]
    fn expand_zero_fills_padding_and_reserved_and_keeps_scalars() {
        let mut a = base_policy_args();
        a.version = 7;
        a.session_ops_ceiling = 3;
        let p = a.expand().unwrap();
        assert_eq!(p.version, 7);
        assert_eq!(p._pad_version, [0u8; 4]);
        assert_eq!(p._pad_ceiling, [0u8; 6]);
        assert_eq!(p._reserved, [0u8; 64]);
        assert_eq!(p.timelock_secs, 3600);
        assert_eq!(p.session_ops_ceiling, 3);
    }

    #[test]
    fn expand_keeps_caps_positional() {
        let sol = Pubkey::new_unique();
        let usdc = Pubkey::new_unique();
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(sol, 1, 2, 3), mint_cap(usdc, 4, 5, 6)];
        let p = a.expand().unwrap();
        assert_eq!(p.caps[0].mint, sol);
        assert_eq!(p.caps[1].mint, usdc);
        for slot in p.caps[2..].iter() {
            assert_eq!(slot.mint, Pubkey::default(), "unused slots must stay zero-filled");
        }
    }

    #[test]
    fn expand_rejects_too_many_caps() {
        let mut a = base_policy_args();
        a.caps = (0..(MAX_MINTS_AT_CREATE + 1))
            .map(|_| mint_cap(Pubkey::new_unique(), 1, 1, 1))
            .collect();
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    #[test]
    fn expand_rejects_too_many_session_ceilings() {
        let mint = Pubkey::new_unique();
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(mint, 10, 10, 10)];
        a.session_ceiling = (0..(MAX_MINTS_AT_CREATE + 1))
            .map(|_| mint_cap(Pubkey::new_unique(), 1, 1, 1))
            .collect();
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    #[test]
    fn expand_rejects_default_mint_cap() {
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(Pubkey::default(), 1, 1, 1)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    #[test]
    fn expand_rejects_duplicate_cap_mint() {
        let mint = Pubkey::new_unique();
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(mint, 1, 2, 3), mint_cap(mint, 4, 5, 6)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    /// A ceiling whose mint matches no `caps` entry at all — no caps
    /// configured at all, so the ceiling is entirely orphaned.
    #[test]
    fn expand_rejects_orphan_ceiling_with_no_caps() {
        let mut a = base_policy_args();
        a.session_ceiling = vec![mint_cap(Pubkey::new_unique(), 1, 1, 1)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    /// A ceiling whose mint differs from the one cap that IS configured —
    /// mismatched, not merely absent.
    #[test]
    fn expand_rejects_mismatched_mint_ceiling() {
        let sol = Pubkey::new_unique();
        let usdc = Pubkey::new_unique();
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(sol, 100, 200, 1000)];
        a.session_ceiling = vec![mint_cap(usdc, 1, 1, 1)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    #[test]
    fn expand_rejects_duplicate_ceiling_mint() {
        let mint = Pubkey::new_unique();
        let mut a = base_policy_args();
        a.caps = vec![mint_cap(mint, 100, 200, 1000)];
        a.session_ceiling = vec![mint_cap(mint, 1, 1, 1), mint_cap(mint, 2, 2, 2)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    #[test]
    fn expand_rejects_orphan_large_threshold() {
        let mut a = base_policy_args();
        a.large_threshold = vec![mint_cap(Pubkey::new_unique(), 1, 0, 0)];
        expect_expand_err(&a, WardenError::InvalidAccountData);
    }

    /// The core round-1 fix: `session_ceiling`/`large_threshold` land at the
    /// matching `caps` INDEX, not at their own position in the wire vector.
    #[test]
    fn expand_stores_ceiling_and_threshold_at_the_caps_index_not_wire_position() {
        let usdc = Pubkey::new_unique();
        let sol = Pubkey::new_unique();
        let mut a = base_policy_args();
        // caps[0] = USDC, caps[1] = SOL.
        a.caps = vec![mint_cap(usdc, 50, 100, 500), mint_cap(sol, 100, 200, 1000)];
        // Both ceiling and threshold name SOL first (wire position 0) even
        // though SOL is caps[1] — if re-keying were positional instead of
        // by-mint, this would land at index 0 (USDC's slot) instead.
        a.session_ceiling = vec![mint_cap(sol, 10, 20, 100)];
        a.large_threshold = vec![mint_cap(sol, 5, 0, 0)];
        let p = a.expand().unwrap();

        assert_eq!(p.session_ceiling[1].mint, sol);
        assert_eq!(p.session_ceiling[1].per_tx, 10);
        assert_eq!(p.session_ceiling[0].mint, Pubkey::default(), "USDC's slot must stay unused");

        assert_eq!(p.large_threshold[1].mint, sol);
        assert_eq!(p.large_threshold[1].per_tx, 5);
        assert_eq!(p.large_threshold[0].mint, Pubkey::default());
    }
}
