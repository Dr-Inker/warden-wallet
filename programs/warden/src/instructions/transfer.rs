//! `transfer` — move SOL or an SPL token balance out of the vault, either
//! under a session key (within its caps) or under the passkey root (bounded).
//!
//! This is the instruction that realises the wallet's headline property: **a
//! phished user loses at most the session cap**. That property does not come
//! from the session check alone — it comes from the fact that *every* outflow
//! path, session or root, debits the SAME account-wide `MintBuckets` for the
//! mint being moved (spec §5.2.4). Ten sessions do not get ten day caps, and
//! the root does not get an unmetered one on top of them.
//!
//! ## Two authorization shapes, one instruction
//!
//! ```text
//! session:  ix[0] = warden::transfer                      (session key signs)
//! root:     ix[0] = Secp256r1SigVerify precompile
//!           ix[1] = warden::transfer  (args.root = Some)
//! ```
//! Exactly one of `args.root` / the `session` account must be present
//! (`BadInstructionLayout` otherwise). Both at once is not extra proof, it is
//! an ambiguous instruction: it would leave "which rule set applies" to
//! handler ordering rather than to the caller's explicit intent.
//!
//! ## What the root ceremony signs
//!
//! `action_hash(OP_TRANSFER_ACTION, borsh(TransferBody { native, mint,
//! destination, amount }))`, where **`destination` is the key of the account
//! actually passed**, not a value from instruction data — there is no
//! destination argument at all. Substituting a different destination account
//! therefore changes the recomputed transcript, and the ceremony fails with
//! `ChallengeMismatch` (`root_transfer_with_substituted_destination_rejected`).
//!
//! ## What a session cap does and does not bound in Phase 1A
//!
//! `SessionKey` stores a full `MintCap` per mint but has **no bucket fields**
//! — no `day_start`, no 30-day ring — so there is nowhere to accumulate a
//! per-session day/30-day total. Phase 1A therefore enforces, per session:
//!
//! - `caps[mint].per_tx` — the per-transaction ceiling, and
//! - `lifetime_cap[mint]` vs `lifetime_spent[mint]` — the running total,
//!
//! i.e. **`per_tx x (calls) <= lifetime_cap`**, and leaves the day /
//! rolling-30-day limits to the **account-wide** buckets, which every session
//! and the root share. `grant_session` REFUSES a grant that sets a non-zero
//! `per_day`/`per_30d` (`SessionDayCapsUnsupported`), so there is no stored
//! session field that this handler silently fails to read — a cap that does
//! not cap would be worse than no cap. 1B: per-session day buckets need a
//! bucket PDA (a 30-slot ring is 248 B and does not fit `SessionKey._reserved`).
//!
//! ## Native SOL moves lamports directly
//!
//! The vault PDA is a *data* account owned by this program, so
//! `system_instruction::transfer` cannot move its lamports (the System program
//! only debits accounts it owns). A program may debit an account it owns
//! directly, which is what `move_lamports` does — with `checked_*` on both
//! sides and a post-transfer floor of `Rent::minimum_balance(data_len)`, so a
//! transfer can never make the vault itself rent-collectible (`RentFloor`).
//!
//! ## SPL: classic SPL Token only in Phase 1A
//!
//! `token_program` must be `SPL_TOKEN_ID`. Token-2022 is rejected because its
//! transfer-fee / transfer-hook / confidential-transfer extensions each change
//! what "move `amount`" means to the buckets — that is a Phase 1B decision,
//! not a silent one. The token accounts are parsed by hand at the fixed
//! offsets of the 165-byte SPL layout (spike 3b's finding: the `spl-token`
//! crate cannot be imported program-side under `solana-program 3.x`); ATA
//! creation is the client's job, never the vault's.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;

use crate::buckets::{self, find_cap};
use crate::constants::{
    ACCOUNT_SEED, NATIVE_MINT, SPL_TOKEN_ID, TOKEN_ACCOUNT_LEN, TOKEN_IX_TRANSFER,
    TOKEN_STATE_INITIALIZED,
};
use crate::errors::WardenError;
use crate::instructions::revoke_session::check_session_pda;
use crate::root_verify::transcript::{action_hash, OP_TRANSFER_ACTION};
use crate::root_verify::{verify_and_consume, RootArgs};
use crate::state::{FrozenState, MintCap, SessionKey, SmartAccount, OP_TRANSFER};

/// `mint == None` means native SOL. There is deliberately **no destination
/// argument**: the destination is the account passed, and the root ceremony
/// binds that account's key (see the module docs).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferArgs {
    /// `Some` = root path (requires `ix_sysvar`), `None` = session path
    /// (requires the `session` account).
    pub root: Option<RootArgs>,
    pub mint: Option<Pubkey>,
    pub amount: u64,
}

/// Exactly what the passkey signs on the ROOT path — rebuilt on-chain from the
/// arguments AND the accounts actually passed, never read from instruction
/// data.
///
/// `native` is carried alongside `mint` rather than inferred from
/// `mint == Pubkey::default()` so the signed document is unambiguous on its
/// own: a client displaying a pending assertion never has to know that the
/// zero pubkey is a sentinel.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransferBody {
    pub native: bool,
    /// `Pubkey::default()` when `native` — the caps are looked up under
    /// `NATIVE_MINT`, but the *signed* document says "no mint".
    pub mint: Pubkey,
    /// The destination ACCOUNT key: a plain account for SOL, a token account
    /// for SPL.
    pub destination: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    /// On the session path this MUST be the session's delegate key. On the
    /// root path it is only a fee payer and is not bound to anything — the
    /// ceremony already fixes destination and amount, so an unbound submitter
    /// can neither redirect nor resize the transfer.
    pub signer: Signer<'info>,
    /// Canonicality is re-proven in the handler from the `owner_seed`/`bump`
    /// the account itself stores (same as every other handler), not by a
    /// `seeds` constraint that would have to `load()` a second time.
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// Required on the session path; must be absent on the root path. Anchor's
    /// convention for an omitted optional account is to pass the program id in
    /// its place.
    #[account(mut)]
    pub session: Option<Account<'info, SessionKey>>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves. Required on the root path.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: Option<UncheckedAccount<'info>>,
    /// CHECK: for SOL, any account other than the vault itself (it is only
    /// credited — a program may credit any account); for SPL, a token account
    /// of `mint` not owned by the vault. Both are validated in the handler,
    /// which is also what the root ceremony binds.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: SPL only — the vault's token account for `mint` (token-level
    /// owner must be the smart account PDA). Validated in the handler.
    #[account(mut)]
    pub source_ata: Option<UncheckedAccount<'info>>,
    /// CHECK: SPL only — must be `SPL_TOKEN_ID`; checked in the handler so the
    /// rejection carries our own error rather than Anchor's.
    pub token_program: Option<UncheckedAccount<'info>>,
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path —
// see the matching note on `create_account::handler`.
pub(crate) fn handler(ctx: Context<Transfer>, args: TransferArgs) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;
    let program_id = ctx.program_id;
    let account_key = ctx.accounts.smart_account.key();
    let destination_key = ctx.accounts.destination.key();
    let signer_key = ctx.accounts.signer.key();

    // Exactly one authorization shape (module docs). Checked before anything
    // is loaded so an ambiguous instruction fails on its shape, not on
    // whichever rule happened to run first.
    require!(
        args.root.is_some() != ctx.accounts.session.is_some(),
        WardenError::BadInstructionLayout
    );

    let mut account = ctx.accounts.smart_account.load_mut()?;

    // Re-derive the account PDA from the seeds the account itself stores, so a
    // byte-identical copy planted at some other address cannot stand in (see
    // `rotate_nonce::handler` for the full argument).
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    // A frozen account moves nothing, by either authority — a freeze that
    // still let the (possibly phished) root spend would not be a freeze.
    require!(matches!(account.frozen()?, FrozenState::None), WardenError::Frozen);

    // Native SOL looks its caps up under the wrapped-SOL mint: `MintCap` slots
    // are keyed by mint and `Pubkey::default()` is `find_cap`'s unused-slot
    // sentinel, so "no mint" needs a real key (see `constants::NATIVE_MINT`).
    let cap_mint = args.mint.unwrap_or(NATIVE_MINT);

    // ---- authorize -------------------------------------------------------
    // `lifetime_spent` is computed here but committed only after the
    // account-wide debit below succeeds, so a session is never charged for a
    // transfer the account's own buckets refuse.
    let mut pending_lifetime: Option<(usize, u64)> = None;

    if let Some(root) = &args.root {
        let ix_sysvar = ctx
            .accounts
            .ix_sysvar
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?
            .to_account_info();

        // The passkey signed over the destination ACCOUNT that was passed —
        // rebuilt here, so a substitution changes the challenge.
        let body = TransferBody {
            native: args.mint.is_none(),
            mint: args.mint.unwrap_or_default(),
            destination: destination_key,
            amount: args.amount,
        };
        let mut body_bytes = Vec::new();
        body.serialize(&mut body_bytes)?;
        verify_and_consume(
            &mut account,
            &ix_sysvar,
            root,
            program_id,
            &account_key,
            action_hash(OP_TRANSFER_ACTION, &body_bytes),
            now,
            slot,
        )?;

        // AUTHORIZE FIRST, then validate (same ordering as `grant_session`).
        //
        // Root is bounded like a session (spec §5.2.4): a direct root transfer
        // may not exceed `policy.large_threshold[mint].per_tx`. A mint with no
        // threshold entry is not directly root-transferable at all — absent
        // means "not allowed", never "unlimited". Above the threshold the
        // route is Phase 1B's timelocked `queue`, which is why this is
        // `CapExceeded` and not a hard failure of the ceremony.
        let (_, threshold) = find_cap(&account.policy.large_threshold, &cap_mint)
            .ok_or(WardenError::CapExceeded)?;
        require!(args.amount <= threshold.per_tx, WardenError::CapExceeded);
    } else {
        let generation = account.generation;
        let session_account_key = ctx
            .accounts
            .session
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?
            .key();
        let session = ctx
            .accounts
            .session
            .as_mut()
            .ok_or(WardenError::BadInstructionLayout)?;
        authorize_session(
            session,
            &session_account_key,
            &signer_key,
            &account_key,
            generation,
            program_id,
            now,
        )?;

        // The session's own per-transaction ceiling. A mint with no cap in
        // THIS session's slots is not movable by it, whatever the account
        // policy allows (absent means "not granted").
        let (slot, cap) = find_cap(&session.caps, &cap_mint).ok_or(WardenError::CapExceeded)?;
        // A session cap is `per_tx` + `lifetime_cap` and NOTHING else in
        // Phase 1A; `grant_session::validate_shape` refuses to store a
        // non-zero `per_day`/`per_30d` (`SessionDayCapsUnsupported`) precisely
        // so that no field here is silently unread. The day / rolling-30-day
        // bound is the ACCOUNT-WIDE `buckets::debit` below, shared with every
        // other session and with the root.
        debug_assert!(
            cap.per_day == 0 && cap.per_30d == 0,
            "session day caps are rejected at grant time and never enforced here"
        );
        let per_tx = cap.per_tx;
        require!(args.amount <= per_tx, WardenError::CapExceeded);

        let spent = *session.lifetime_spent.get(slot).ok_or(WardenError::InvalidAccountData)?;
        let lifetime = *session.lifetime_cap.get(slot).ok_or(WardenError::InvalidAccountData)?;
        let new_spent = spent.checked_add(args.amount).ok_or(WardenError::Overflow)?;
        require!(new_spent <= lifetime, WardenError::CapExceeded);
        pending_lifetime = Some((slot, new_spent));
    }

    // ---- charge the ACCOUNT-WIDE buckets ---------------------------------
    // The one place every outflow converges. `debit` is atomic: on rejection
    // it leaves the buckets byte-identical (see `buckets::debit`).
    let (idx, account_cap) =
        find_cap(&account.policy.caps, &cap_mint).ok_or(WardenError::CapExceeded)?;
    let account_cap: MintCap = *account_cap;
    let bucket = account.buckets.get_mut(idx).ok_or(WardenError::InvalidAccountData)?;
    buckets::debit(bucket, &account_cap, args.amount, now)?;

    if let Some((slot, new_spent)) = pending_lifetime {
        let session = ctx
            .accounts
            .session
            .as_mut()
            .ok_or(WardenError::BadInstructionLayout)?;
        *session
            .lifetime_spent
            .get_mut(slot)
            .ok_or(WardenError::InvalidAccountData)? = new_spent;
    }

    // Seeds for the SPL CPI, captured before the account's data borrow is
    // released — which it MUST be before any CPI, or the runtime's own borrow
    // of the account fails.
    let owner_seed = account.owner_seed;
    let bump = account.bump;
    drop(account);

    // ---- move the value --------------------------------------------------
    match args.mint {
        None => {
            // Crediting the vault from the vault is not a transfer; it would
            // debit the caps while moving nothing.
            require_keys_neq!(destination_key, account_key, WardenError::InvalidAccountData);
            let src = ctx.accounts.smart_account.to_account_info();
            let dst = ctx.accounts.destination.to_account_info();
            let floor = Rent::get()?.minimum_balance(src.data_len());
            move_lamports(&src, &dst, args.amount, floor)?;
        }
        Some(mint) => {
            let token_program = ctx
                .accounts
                .token_program
                .as_ref()
                .ok_or(WardenError::BadInstructionLayout)?
                .to_account_info();
            let source = ctx
                .accounts
                .source_ata
                .as_ref()
                .ok_or(WardenError::BadInstructionLayout)?
                .to_account_info();
            let destination = ctx.accounts.destination.to_account_info();
            require_keys_eq!(
                token_program.key(),
                SPL_TOKEN_ID,
                WardenError::InvalidAccountData
            );

            let src_view = parse_token_account(&source)?;
            require_keys_eq!(src_view.mint, mint, WardenError::InvalidAccountData);
            // The vault PDA must be the token-level authority of the source —
            // this is what the CPI signature below actually authorizes.
            require_keys_eq!(src_view.owner, account_key, WardenError::InvalidAccountData);

            let dst_view = parse_token_account(&destination)?;
            require_keys_eq!(dst_view.mint, mint, WardenError::InvalidAccountData);
            // spec §5.1: moving to another vault-owned token account would
            // debit the caps while the value never leaves the wallet — an
            // attacker with a session could burn the day cap for free, or a
            // buggy client could "spend" into itself.
            require_keys_neq!(dst_view.owner, account_key, WardenError::VaultDestination);
            require_keys_neq!(destination.key(), source.key(), WardenError::VaultDestination);

            let mut data = Vec::with_capacity(9);
            data.push(TOKEN_IX_TRANSFER);
            data.extend_from_slice(&args.amount.to_le_bytes());
            let ix = Instruction {
                program_id: SPL_TOKEN_ID,
                accounts: vec![
                    AccountMeta::new(source.key(), false),
                    AccountMeta::new(destination.key(), false),
                    AccountMeta::new_readonly(account_key, true),
                ],
                data,
            };
            invoke_signed(
                &ix,
                &[
                    source,
                    destination,
                    ctx.accounts.smart_account.to_account_info(),
                    token_program,
                ],
                &[&[ACCOUNT_SEED, owner_seed.as_ref(), &[bump]]],
            )?;
        }
    }

    Ok(())
}

/// Everything a session must satisfy before it may move anything. Order is
/// deliberate: *who* (binding + signer) before *when* (expiry) before *what*
/// (ops mask), so an attacker probing with someone else's session never learns
/// anything about that session's expiry or permissions.
fn authorize_session(
    session: &SessionKey,
    session_account_key: &Pubkey,
    signer_key: &Pubkey,
    account_key: &Pubkey,
    generation: u64,
    program_id: &Pubkey,
    now: i64,
) -> Result<()> {
    // Binds the session to THIS account and proves it is the canonical
    // `["session", account, pubkey]` PDA (shared with `revoke_session`).
    check_session_pda(session, session_account_key, account_key, program_id)?;
    require_keys_eq!(*signer_key, session.pubkey, WardenError::Unauthorized);
    // A generation bump (key rotation / recovery, Phase 1B) invalidates every
    // session blessed under the old one, without touching their accounts.
    require!(
        session.generation_at_grant == generation,
        WardenError::Unauthorized
    );
    require!(now < session.expiry_ts, WardenError::SessionExpired);
    require!((session.ops_mask & OP_TRANSFER) != 0, WardenError::OpNotAllowed);
    Ok(())
}

/// Move `amount` lamports from an account this program owns to any other
/// account, leaving the source at or above `floor`.
///
/// Both sides use `checked_*`: the destination side matters as much as the
/// source, because a destination preloaded near `u64::MAX` would otherwise
/// wrap (`destination_lamport_overflow_rejected`).
fn move_lamports(src: &AccountInfo, dst: &AccountInfo, amount: u64, floor: u64) -> Result<()> {
    let new_src = src
        .lamports()
        .checked_sub(amount)
        .ok_or(WardenError::Overflow)?;
    require!(new_src >= floor, WardenError::RentFloor);
    let new_dst = dst
        .lamports()
        .checked_add(amount)
        .ok_or(WardenError::Overflow)?;
    **src.try_borrow_mut_lamports()? = new_src;
    **dst.try_borrow_mut_lamports()? = new_dst;
    Ok(())
}

/// The fields of an SPL Token `Account` this instruction needs, read at the
/// fixed offsets of the 165-byte layout:
/// ```text
///   mint   0..32   owner  32..64   amount 64..72   state  108
/// ```
/// (The `delegate`/`is_native`/`delegated_amount`/`close_authority` fields are
/// not consulted: this instruction transfers as the account's own authority,
/// so a delegate is irrelevant, and a native/wrapped-SOL token account behaves
/// like any other for a plain `Transfer`.)
struct TokenAccountView {
    mint: Pubkey,
    owner: Pubkey,
}

/// Hand-rolled rather than `spl_token::state::Account::unpack` — the crate
/// cannot be imported program-side (spike 3b: its `solana-program 2.3.x`
/// `Pubkey` is a different type from Anchor 1.1.2's). `tests/common/token.rs`
/// builds every fixture with the REAL crate's `pack`, so a layout change
/// breaks the tests loudly.
///
/// The length is required to be **exactly** `TOKEN_ACCOUNT_LEN`: an SPL Token
/// multisig (355 B) and a mint (82 B) are also owned by the token program, and
/// a `>=` check would happily read a multisig's first 64 bytes as a
/// mint/owner pair.
fn parse_token_account(ai: &AccountInfo) -> Result<TokenAccountView> {
    require_keys_eq!(*ai.owner, SPL_TOKEN_ID, WardenError::InvalidAccountData);
    let data = ai.try_borrow_data()?;
    require!(data.len() == TOKEN_ACCOUNT_LEN, WardenError::InvalidAccountData);
    let mint = read_pubkey(&data, 0)?;
    let owner = read_pubkey(&data, 1)?;
    let state = *data.get(108).ok_or(WardenError::InvalidAccountData)?;
    // An uninitialized or frozen account is not spendable; the token program
    // would refuse anyway, but failing here keeps the error ours and avoids
    // charging the caps for a transfer that cannot happen.
    require!(state == TOKEN_STATE_INITIALIZED, WardenError::InvalidAccountData);
    Ok(TokenAccountView { mint, owner })
}

/// Read the `n`-th 32-byte field (n = 0 → `mint`, n = 1 → `owner`). Indexed by
/// field rather than by byte offset so no arithmetic on `usize` is needed —
/// the crate denies `clippy::arithmetic_side_effects`.
fn read_pubkey(data: &[u8], field: usize) -> Result<Pubkey> {
    let range = match field {
        0 => 0..32,
        1 => 32..64,
        _ => return Err(WardenError::InvalidAccountData.into()),
    };
    let slice = data.get(range).ok_or(WardenError::InvalidAccountData)?;
    let bytes: [u8; 32] = slice.try_into().map_err(|_| WardenError::InvalidAccountData)?;
    Ok(Pubkey::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire encoding of the SPL `Transfer` instruction is a permanent
    /// fact this handler hardcodes (tag 3 ‖ amount u64 LE).
    #[test]
    fn spl_transfer_ix_data_is_tag3_plus_le_amount() {
        let mut data = Vec::with_capacity(9);
        data.push(TOKEN_IX_TRANSFER);
        data.extend_from_slice(&1_234_567_890u64.to_le_bytes());
        assert_eq!(data.len(), 9);
        assert_eq!(data[0], 3);
        assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), 1_234_567_890);
    }

    #[test]
    fn read_pubkey_rejects_short_data_and_unknown_fields() {
        let data = [0u8; 64];
        assert!(read_pubkey(&data, 0).is_ok());
        assert!(read_pubkey(&data, 1).is_ok());
        assert_eq!(
            read_pubkey(&data, 2).unwrap_err(),
            anchor_lang::error::Error::from(WardenError::InvalidAccountData)
        );
        assert_eq!(
            read_pubkey(&data[..31], 0).unwrap_err(),
            anchor_lang::error::Error::from(WardenError::InvalidAccountData)
        );
    }

    /// `TransferBody` is a signed wire format: its field order is permanent.
    #[test]
    fn transfer_body_borsh_layout_is_pinned() {
        let body = TransferBody {
            native: true,
            mint: Pubkey::default(),
            destination: Pubkey::new_from_array([3u8; 32]),
            amount: 7,
        };
        let mut buf = Vec::new();
        body.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 1 + 32 + 32 + 8);
        assert_eq!(buf[0], 1, "native flag first");
        assert_eq!(&buf[1..33], &[0u8; 32], "then mint");
        assert_eq!(&buf[33..65], &[3u8; 32], "then destination");
        assert_eq!(&buf[65..73], &7u64.to_le_bytes(), "then amount");
    }
}
