//! `execute` — run a payload of inner CPIs under the conservation regime
//! (Phase 1B Task 5): session-keyed against the adapter registry, or
//! root-authorized by a passkey ceremony that binds the exact payload bytes
//! and the exact account list.
//!
//! This is the instruction that makes Warden a *wallet* rather than a token
//! box: a dApp transaction is decompiled by the extension into an
//! [`crate::payload::ExecutePayload`] and re-executed here, between two
//! snapshots, so that **whatever the CPIs did, what actually left the vault is
//! measured and charged against the same caps as a plain `transfer`** (spec
//! §5.2). The CPI targets are untrusted by construction; the controls are:
//!
//! 1. **Structure** — `payload::parse_payload` + `payload::resolve_payload`:
//!    logical indexing only, no unknown flags, no conjured signers, the PDA
//!    never writable to a CPI, no warden / ComputeBudget as target *or* as a
//!    smuggled account (`SelfCpiRejected` / `ComputeBudgetInExecute`).
//! 2. **The fixed deny-list** (spec §5.2 rule 1a) — [`deny_scan`], run on
//!    BOTH paths, before any CPI and before any registry lookup. SPL Token and
//!    Token-2022 `Approve`/`Revoke`/`SetAuthority`/`ApproveChecked` are refused
//!    unconditionally; `CloseAccount` is refused unless the four vault-sweep
//!    conditions hold, in which case a [`CloseIntent`] is emitted for the
//!    conservation comparison. No registry entry and no policy can re-enable a
//!    denied pair — the deny fires first, so the error is `DenyListed`, never
//!    `RegistryDenied`.
//! 3. **The registry** (session path only) — every inner `(program, selector)`
//!    must pass `registry_allows` against the session's allowlist in THE
//!    account's registry. The root path skips this (a root ceremony may target
//!    any program) — which is exactly why the deny-list cannot live here.
//! 4. **Conservation** — `snapshot` of every remaining account (writable or
//!    not) plus the PDA's own lamports, before and after the CPIs;
//!    `compare_and_account` rejects every unexplained mutation and returns the
//!    per-mint [`Outflow`].
//! 5. **Caps** — session: per-mint `per_tx` + lifetime, then the account-wide
//!    buckets; root: per-mint `large_threshold.per_tx`, then the same
//!    account-wide buckets. Every outflow path converges on `buckets::debit`,
//!    which is the headline property (ten sessions do not get ten day caps,
//!    and the root does not get an unmetered one).
//!
//! ## Two authorization shapes, one instruction
//!
//! Exactly one of `args.root` / the `session` account (`BadInstructionLayout`
//! otherwise), same as `transfer`. The ROOT ceremony signs `action_hash(0x07,
//! borsh(`[`ExecuteBody`]`))` where both hashes are rebuilt on-chain — the
//! payload hash from the bytes actually executed, the accounts hash from the
//! logical list actually passed — so a bearer assertion cannot substitute the
//! payload, a program id, or any source/destination account, and cannot
//! reorder the list (`LZR-ACC-C1`: LazorKit bound accounts by index, not
//! pubkey; the hash binds `pubkey ‖ is_signer ‖ is_writable` in order).
//!
//! ## Inline vs staged payload
//!
//! Exactly one of `args.payload` / the `stage` account. A staged payload must
//! be finalized, unexpired, bound to this account, and captured at the
//! account's CURRENT `generation` and `policy_version` (spec §5.3 item 6 — a
//! rotation or policy change voids outstanding stages exactly as it voids
//! outstanding sessions). On success the stage is closed and its rent refunded
//! to its recorded creator (consume-once, WRD-STAGE-02); on failure the whole
//! transaction reverts, so the stage — and its rent — survive for a retry or
//! for GC. `payload_hash` is always recomputed from the bytes themselves, so
//! the staged and inline paths bind identically.
//!
//! ## Account ABI (spec §5.2, canonical)
//!
//! Physical: `[smart_account, signer, session?, ix_sysvar?, stage?, registry?,
//! stage_creator?, remaining…]`. The handler builds the LOGICAL list
//! `[smart_account, signer] ++ remaining_accounts` and every payload index
//! names a logical slot; **no code here indexes the physical slice.**
//! `stage_creator` is a named optional (appended after `registry`, in the
//! extensible named-optional zone the spec reserves before
//! `remaining_accounts`): the stage's recorded creator, required on the staged
//! path as the rent-refund destination — "creator owns the rent" is a Task 4
//! invariant and consume is just another close.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::AccountsClose;

use crate::buckets::{self, find_cap};
use crate::constants::{
    ACCOUNT_SEED, MAX_EXECUTE_ACCOUNTS_TOTAL, MAX_EXECUTE_WRITABLE, NATIVE_MINT,
    SPL_TOKEN_2022_ID, SPL_TOKEN_ID, STAGE_SEED,
};
use crate::conservation::{self, compare_and_account, CloseIntent, Snap};
use crate::errors::WardenError;
use crate::instructions::transfer::authorize_session;
use crate::payload::{
    compute_accounts_hash, enforce_pda_writable, parse_payload, resolve_payload, LogicalAccount,
    LogicalMeta, ResolvedInner, SplTokenOp,
};
use crate::registry::{registry_allows, AccountMetaLike};
use crate::root_verify::transcript::{action_hash, OP_EXECUTE_ACTION};
use crate::root_verify::{verify_and_consume, RootArgs};
use crate::state::{FrozenState, MintCap, Registry, SessionKey, SmartAccount, Stage, OP_EXECUTE};

/// `payload == None` means staged (the `stage` account supplies the bytes);
/// `Some` means inline. Exactly one source, checked before anything loads.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecuteArgs {
    /// `Some` = root path (requires `ix_sysvar`), `None` = session path
    /// (requires the `session` account).
    pub root: Option<RootArgs>,
    /// The `ExecutePayload` wire bytes, or `None` to consume the `stage`.
    pub payload: Option<Vec<u8>>,
}

/// Exactly what the passkey signs on the ROOT path (spec §5.2). Both fields
/// are rebuilt on-chain — `payload_hash` from the bytes actually executed
/// (inline or staged, identically), `accounts_hash` from the logical account
/// list actually passed (`payload::compute_accounts_hash`) — never read from
/// instruction data. Root `swap` (Task 6) binds the same `accounts_hash`
/// construction via `SwapBody`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExecuteBody {
    /// `Keccak256(payload bytes)`.
    pub payload_hash: [u8; 32],
    /// `Keccak256(logical list: pubkey ‖ is_signer ‖ is_writable, in order)`.
    pub accounts_hash: [u8; 32],
}

#[derive(Accounts)]
pub struct Execute<'info> {
    /// Canonicality is re-proven in the handler from the `owner_seed`/`bump`
    /// the account itself stores (same as every other handler).
    #[account(mut)]
    pub smart_account: AccountLoader<'info, SmartAccount>,
    /// Session path: MUST be the session's delegate key. Root path: the
    /// submitter — and unlike `transfer`'s root path, it is **ceremony-bound**
    /// (WRDF-0055): this account is `logical[1]`, so its pubkey AND its
    /// effective `is_signer`/`is_writable` flags are hashed into
    /// `accounts_hash`, which `ExecuteBody` signs. Substituting the submitter
    /// after signing fails `ChallengeMismatch`. Corollary for clients: the
    /// hashed flags are the COMPILED message's (Solana coalesces privileges —
    /// a signer that is also the fee payer becomes writable), so the SDK must
    /// reconstruct the logical list from the compiled transaction, exactly as
    /// spec §5.2 already mandates, never from IDL metas.
    pub signer: Signer<'info>,
    /// Required on the session path; must be absent on the root path.
    #[account(mut)]
    pub session: Option<Account<'info, SessionKey>>,
    /// CHECK: constrained to the Instructions sysvar address; read only via
    /// `load_instruction_at_checked` / `load_current_index_checked`, which
    /// re-check the address themselves. Required on the root path.
    #[account(address = solana_instructions_sysvar::ID @ WardenError::BadInstructionLayout)]
    pub ix_sysvar: Option<UncheckedAccount<'info>>,
    /// The staged payload to consume (`args.payload == None`). Canonicality is
    /// re-proven in the handler from the seeds the stage itself stores.
    #[account(mut)]
    pub stage: Option<Account<'info, Stage>>,
    /// THE account's adapter registry (`SmartAccount.registry`), required on
    /// the session path whenever the payload contains at least one inner
    /// instruction. The root path never reads it.
    pub registry: Option<AccountLoader<'info, Registry>>,
    /// CHECK: the stage's recorded `creator` — the rent-refund destination for
    /// the consume-close, required (and validated against `stage.creator` in
    /// the handler) whenever `stage` is present. "Creator owns the rent" is
    /// the Task 4 invariant; consume is just another close.
    #[account(mut)]
    pub stage_creator: Option<UncheckedAccount<'info>>,
    // remaining_accounts = the dApp accounts, logical[2 + k].
}

// Not `pub`: only `lib.rs`'s `#[program]` module calls this, by full path —
// see the matching note on `create_account::handler`.
pub(crate) fn handler<'info>(
    ctx: Context<'info, Execute<'info>>,
    args: ExecuteArgs,
) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;
    let slot = clock.slot;
    let program_id = ctx.program_id;
    let account_key = ctx.accounts.smart_account.key();
    let signer_key = ctx.accounts.signer.key();

    // Exactly one authorization shape and exactly one payload source, both
    // checked before anything is loaded so an ambiguous instruction fails on
    // its shape, not on whichever rule happened to run first.
    require!(
        args.root.is_some() != ctx.accounts.session.is_some(),
        WardenError::BadInstructionLayout
    );
    require!(
        args.payload.is_some() != ctx.accounts.stage.is_some(),
        WardenError::BadInstructionLayout
    );

    let mut account = ctx.accounts.smart_account.load_mut()?;

    // Re-derive the account PDA from the seeds the account itself stores (see
    // `rotate_nonce::handler` for the full argument).
    let expected = Pubkey::create_program_address(
        &[ACCOUNT_SEED, account.owner_seed.as_ref(), &[account.bump]],
        program_id,
    )
    .map_err(|_| WardenError::Unauthorized)?;
    require_keys_eq!(account_key, expected, WardenError::Unauthorized);

    // A frozen account runs nothing, by either authority.
    require!(matches!(account.frozen()?, FrozenState::None), WardenError::Frozen);

    // ---- payload source ---------------------------------------------------
    let payload_bytes: Vec<u8> = match &args.payload {
        Some(bytes) => bytes.clone(),
        None => {
            let stage = ctx
                .accounts
                .stage
                .as_ref()
                .ok_or(WardenError::BadInstructionLayout)?;
            // Canonical `["stage", account, creator, hash]` PDA, re-derived
            // from the stage's own fields — a byte-identical copy planted at
            // some other address cannot stand in.
            let expected_stage = Pubkey::create_program_address(
                &[
                    STAGE_SEED,
                    stage.account.as_ref(),
                    stage.creator.as_ref(),
                    stage.hash.as_ref(),
                    &[stage.bump],
                ],
                program_id,
            )
            .map_err(|_| WardenError::StageInvalid)?;
            require_keys_eq!(stage.key(), expected_stage, WardenError::StageInvalid);
            require!(stage.version == 1, WardenError::StageInvalid);
            // Bound to THIS account, sealed, and still fresh.
            require_keys_eq!(stage.account, account_key, WardenError::StageInvalid);
            require!(stage.finalized, WardenError::StageInvalid);
            require!(now < stage.expiry_ts, WardenError::StageExpired);
            // Captured at the account's CURRENT generation and policy_version
            // (spec §5.3 item 6): a rotation/recovery or policy change voids
            // an outstanding stage exactly as it voids an outstanding session.
            require!(stage.generation == account.generation, WardenError::StageInvalid);
            require!(
                stage.policy_version == account.policy.version,
                WardenError::StageInvalid
            );
            // The consume-close needs its refund destination up front, so a
            // successful execute can never strand the rent.
            let creator = ctx
                .accounts
                .stage_creator
                .as_ref()
                .ok_or(WardenError::BadInstructionLayout)?;
            require_keys_eq!(creator.key(), stage.creator, WardenError::StageInvalid);
            stage.data.clone()
        }
    };

    // ---- account-count caps (spec §5.2, PROVISIONAL pending the sweep) ----
    let remaining = ctx.remaining_accounts;
    require!(
        remaining.len() <= MAX_EXECUTE_ACCOUNTS_TOTAL,
        WardenError::TooManyExecuteAccounts
    );
    let writable_count = remaining.iter().filter(|ai| ai.is_writable).count();
    require!(
        writable_count <= MAX_EXECUTE_WRITABLE,
        WardenError::TooManyExecuteWritable
    );

    // ---- the logical account list (canonical ABI) -------------------------
    // logical[0] = smart_account, logical[1] = signer, logical[2+k] =
    // remaining_accounts[k]. Everything downstream — payload indices,
    // accounts_hash, CPI assembly — indexes THIS list, never the physical
    // slice.
    let sa_info = ctx.accounts.smart_account.to_account_info();
    let mut logical_infos: Vec<AccountInfo> =
        Vec::with_capacity(remaining.len().saturating_add(2));
    logical_infos.push(sa_info.clone());
    logical_infos.push(ctx.accounts.signer.to_account_info());
    logical_infos.extend_from_slice(remaining);

    let logical_meta: Vec<LogicalMeta> = logical_infos
        .iter()
        .map(|ai| LogicalMeta { key: *ai.key, executable: ai.executable })
        .collect();

    // WRD-EXEC-06 (WRDF-0053): the WHOLE logical list must be duplicate-free —
    // named accounts included, not only remaining-vs-remaining. An alias of the
    // PDA or the signer inside `remaining_accounts` would create two logical
    // indices, and two privilege roles, for one runtime account; positional
    // registry / adapter role checks would then read the wrong slot. The
    // accounts_hash binds whatever list is passed (so this is not a
    // captured-signature reorder), but the invariant requires the duplicate be
    // refused outright — before hashing, authorization, snapshot, or any CPI.
    for (i, a) in logical_meta.iter().enumerate() {
        for b in logical_meta.iter().skip(i.saturating_add(1)) {
            require!(a.key != b.key, WardenError::DuplicateLogicalAccount);
        }
    }

    // ---- structure: parse + resolve (payload rules 1–3 of the module docs) -
    let parsed = parse_payload(&payload_bytes)?;
    // GROK-EXP-04 (2026-08-22): an EMPTY payload ran nothing, so the session
    // list-id-0 / registry gate below (keyed on `!resolved.is_empty()`) never
    // fired, no cap was charged, and a staged `[0]` was still consume-closed
    // — a list-0 session could garbage-collect any Stage it could finalize a
    // 1-byte twin of. There is no legitimate empty `execute` on either path
    // (stage GC is `stage_close`), so refuse it before authorization, the
    // registry, the snapshot, or the stage consume.
    require!(!parsed.ixs.is_empty(), WardenError::PayloadInvalid);
    let resolved = resolve_payload(&parsed, &logical_meta, program_id)?;

    // WRD-EXEC-10 (WRDF-0051): defense-in-depth against a DIRECT Jupiter inner
    // instruction in generic `execute` — see `reject_jupiter`. It steers the
    // common direct-route mistake toward `swap` (where `max_in`/quote-sanity
    // live); it does NOT and cannot stop a forwarding program from reaching
    // Jupiter nested. The bound that holds for any nested value movement is
    // conservation's net per-mint cap; the intra-CPI `max_in`/quote bound is the
    // accepted §5.3 boundary, deferred to `swap` (Task 6).
    reject_jupiter(&resolved)?;

    // ---- authorize --------------------------------------------------------
    let mut session_list_id: u16 = 0;
    if let Some(root) = &args.root {
        let ix_sysvar = ctx
            .accounts
            .ix_sysvar
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?
            .to_account_info();
        // Both hashes rebuilt from what was actually passed (module docs).
        let logical_hash_list: Vec<LogicalAccount> = logical_infos
            .iter()
            .map(|ai| LogicalAccount {
                key: *ai.key,
                is_signer: ai.is_signer,
                is_writable: ai.is_writable,
            })
            .collect();
        let body = ExecuteBody {
            payload_hash: solana_keccak_hasher::hashv(&[&payload_bytes]).to_bytes(),
            accounts_hash: compute_accounts_hash(&logical_hash_list),
        };
        let mut body_bytes = Vec::new();
        body.serialize(&mut body_bytes)?;
        verify_and_consume(
            &mut account,
            &ix_sysvar,
            root,
            program_id,
            &account_key,
            action_hash(OP_EXECUTE_ACTION, &body_bytes),
            now,
            slot,
        )?;
    } else {
        let session_account_key = ctx
            .accounts
            .session
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?
            .key();
        let session = ctx
            .accounts
            .session
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?;
        authorize_session(
            session,
            &session_account_key,
            &signer_key,
            &account_key,
            account.generation,
            program_id,
            now,
            OP_EXECUTE,
        )?;
        session_list_id = session.program_allowlist_id;
    }

    // Seeds for the CPIs, captured before the account's data borrow is
    // released — which it MUST be before any snapshot or CPI borrows.
    let owner_seed = account.owner_seed;
    let bump = account.bump;
    let account_registry = account.registry;
    drop(account);

    // ---- BEFORE snapshot (spec §5.2 rule 2) -------------------------------
    let before = conservation::snapshot(remaining, &account_key)?;
    let pda_lamports_before = sa_info.lamports();
    // GROK-EXP-03: writable Stake / Vote / ProgramData accounts are refused
    // BEFORE any CPI (and again in `compare_and_account`).
    conservation::reject_unsupported_writable_owners(&before)?;

    // ---- the fixed deny-list (spec §5.2 rule 1a) — BOTH paths, before any
    // registry lookup and before any CPI runs -------------------------------
    let close_intents = deny_scan(&resolved, &before, &account_key)?;

    // The SmartAccount PDA may be writable to a CPI only as an account of a
    // deny-validated vault-sweep CloseAccount (spec §5.2 rule 3 + rule 4a). Run
    // AFTER deny_scan, so "the ix is such a close" is a proven licence.
    enforce_pda_writable(&resolved, &account_key)?;

    // ---- the adapter registry (session path only) -------------------------
    // (`resolved` is non-empty here — the empty payload was refused above —
    // so a session always meets the list-id / registry gate.)
    if args.root.is_none() {
        // List id 0 ⇒ every CPI denied: a session that wants `execute` must
        // carry a real allowlist (spec §5.2 rule 1).
        require!(session_list_id != 0, WardenError::RegistryDenied);
        let reg_loader = ctx
            .accounts
            .registry
            .as_ref()
            .ok_or(WardenError::RegistryDenied)?;
        // THE account's registry, not whichever registry the submitter liked.
        require_keys_eq!(reg_loader.key(), account_registry, WardenError::RegistryDenied);
        let reg = reg_loader.load()?;
        for r in &resolved {
            let metas: Vec<AccountMetaLike> = r
                .accounts
                .iter()
                .map(|a| AccountMetaLike {
                    pubkey: a.key,
                    is_signer: a.is_signer,
                    is_writable: a.is_writable,
                })
                .collect();
            require!(
                registry_allows(&reg, session_list_id, &r.program, &r.data, &metas, &account_key),
                WardenError::RegistryDenied
            );
        }
    }

    // ---- run the CPIs -----------------------------------------------------
    // `invoke_signed` always carries the vault seeds: they sign exactly the
    // PDA and nothing else, so passing them for an instruction that does not
    // reference the PDA is inert, and the payload's validated `flags` decide
    // whether the PDA is a signer of any given inner instruction.
    for (ix, r) in parsed.ixs.iter().zip(resolved.iter()) {
        let metas: Vec<AccountMeta> = r
            .accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: a.key,
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect();
        let instruction =
            Instruction { program_id: r.program, accounts: metas, data: r.data.clone() };
        let mut infos: Vec<AccountInfo> =
            Vec::with_capacity(ix.accounts.len().saturating_add(1));
        for (idx, _) in &ix.accounts {
            infos.push(
                logical_infos
                    .get(*idx as usize)
                    .ok_or(WardenError::PayloadInvalid)?
                    .clone(),
            );
        }
        infos.push(
            logical_infos
                .get(ix.program_idx as usize)
                .ok_or(WardenError::PayloadInvalid)?
                .clone(),
        );
        invoke_signed(&instruction, &infos, &[&[ACCOUNT_SEED, owner_seed.as_ref(), &[bump]]])?;
    }

    // ---- AFTER snapshot + conservation ------------------------------------
    let after = conservation::snapshot(remaining, &account_key)?;
    let pda_lamports_after = sa_info.lamports();
    let outflow = compare_and_account(
        &before,
        &after,
        &account_key,
        &close_intents,
        pda_lamports_before,
        pda_lamports_after,
    )?;

    // ---- charge the caps (spec §5.2 rule 4) -------------------------------
    // SOL (native + WSOL, already merged by accounting) is charged under
    // `NATIVE_MINT`, same key `transfer` uses; then each token mint in
    // first-seen order. Everything below runs after the CPIs, so any refusal
    // reverts the whole transaction, CPI effects included.
    let mut charges: Vec<(Pubkey, u64)> =
        Vec::with_capacity(outflow.by_mint.len().saturating_add(1));
    if outflow.sol > 0 {
        charges.push((NATIVE_MINT, outflow.sol));
    }
    charges.extend_from_slice(&outflow.by_mint);

    let mut account = ctx.accounts.smart_account.load_mut()?;
    if args.root.is_some() {
        // Root is bounded like a session (spec §5.2.4): per mint, at most
        // `large_threshold.per_tx` per transaction. Absent means "not
        // allowed", never "unlimited" — above it, the route is the timelocked
        // queue (Phase 1C), which is why this is `CapExceeded`.
        for (mint, amount) in &charges {
            let (_, threshold) = find_cap(&account.policy.large_threshold, mint)
                .ok_or(WardenError::CapExceeded)?;
            require!(*amount <= threshold.per_tx, WardenError::CapExceeded);
        }
    } else {
        let session = ctx
            .accounts
            .session
            .as_mut()
            .ok_or(WardenError::BadInstructionLayout)?;
        // Per mint: the session's own per-transaction ceiling, then its
        // lifetime running total. A mint with no cap in THIS session's slots
        // is not movable by it at all (absent means "not granted", so any
        // outflow of it — however small — is a reject).
        for (mint, amount) in &charges {
            let (slot_idx, cap) =
                find_cap(&session.caps, mint).ok_or(WardenError::CapExceeded)?;
            require!(*amount <= cap.per_tx, WardenError::CapExceeded);
            let spent = *session
                .lifetime_spent
                .get(slot_idx)
                .ok_or(WardenError::InvalidAccountData)?;
            let lifetime = *session
                .lifetime_cap
                .get(slot_idx)
                .ok_or(WardenError::InvalidAccountData)?;
            let new_spent = spent.checked_add(*amount).ok_or(WardenError::Overflow)?;
            require!(new_spent <= lifetime, WardenError::CapExceeded);
            *session
                .lifetime_spent
                .get_mut(slot_idx)
                .ok_or(WardenError::InvalidAccountData)? = new_spent;
        }
    }
    // The account-wide buckets — the one place every outflow path converges,
    // root and session alike. `debit` is atomic per bucket; a refusal reverts
    // the transaction, so partial multi-mint debits cannot persist.
    for (mint, amount) in &charges {
        let (idx, account_cap) =
            find_cap(&account.policy.caps, mint).ok_or(WardenError::CapExceeded)?;
        let account_cap: MintCap = *account_cap;
        let bucket = account.buckets.get_mut(idx).ok_or(WardenError::InvalidAccountData)?;
        buckets::debit(bucket, &account_cap, *amount, now)?;
    }
    drop(account);

    // ---- consume the stage (WRD-STAGE-02) ---------------------------------
    // Only reached on success: on any earlier failure the transaction reverts
    // and the stage survives untouched for a retry or for GC.
    if args.payload.is_none() {
        let stage = ctx
            .accounts
            .stage
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?;
        let creator = ctx
            .accounts
            .stage_creator
            .as_ref()
            .ok_or(WardenError::BadInstructionLayout)?;
        stage.close(creator.to_account_info())?;
    }

    Ok(())
}

/// Defense-in-depth: reject a **direct** Jupiter v6 inner instruction in generic
/// `execute` (WRDF-0051), steering the common client mistake — compiling a
/// Jupiter transaction and pushing it straight through `execute` — toward
/// `swap`, where the adapter preflight lives (`max_in` decoded from the
/// instruction's own data + pinned source/dest ATA + quote sanity, spec §5.2.7).
///
/// **This is NOT a completeness guarantee, and does not make Jupiter
/// "unreachable" (WRDF-0051 round 2).** A forwarding program P — reachable on
/// the root path, which targets any program, or as a registry-listed program on
/// the session path — can itself CPI into Jupiter while `reject_jupiter` sees
/// only P as the direct target. The bound that actually holds for *any* such
/// nested value movement is `conservation`'s **net per-mint cap** (session
/// `per_tx`+lifetime+buckets; root `large_threshold`+buckets): a caller loses at
/// most its cap, though possibly at a bad price. What generic `execute` cannot
/// add is the intra-CPI gross-turnover / `max_in` / quote-sanity bound — that is
/// the accepted §5.3 semantic boundary and is `swap`'s job (Task 6, WRD-EXEC-10,
/// still `unimplemented`). This guard closes the trivial direct route; it does
/// not claim to close the nested one.
fn reject_jupiter(resolved: &[ResolvedInner]) -> Result<()> {
    use crate::constants::JUPITER_V6_ID;
    for r in resolved {
        require!(r.program != JUPITER_V6_ID, WardenError::JupiterViaSwapOnly);
    }
    Ok(())
}

/// The fixed deny-list (spec §5.2 rule 1a), applied to every inner instruction
/// whose resolved program is SPL Token or Token-2022, on BOTH paths, before
/// dispatch and before any registry lookup.
///
/// `Approve`/`Revoke`/`SetAuthority`/`ApproveChecked` ⇒ `DenyListed`,
/// unconditionally. `CloseAccount` ⇒ `DenyListed` unless ALL FOUR vault-sweep
/// conditions hold (conjunctive):
///
/// 1. it is a **direct** inner instruction of this payload (true by
///    construction here — a close nested inside another program's CPI never
///    reaches this function, emits no intent, and is rejected downstream by
///    conservation as an unexplained disappearance, which is the intended
///    path, not a gap);
/// 2. the target's `amount` in the BEFORE snapshot is **0**;
/// 3. the decoded destination (SPL account order `[0] account,
///    `[1] destination, `[2] authority`) is the SmartAccount PDA;
/// 4. the target is neither the PDA itself nor a Mint (it must have
///    snapshotted as a parsed token account — a target outside the snapshot
///    set, e.g. the signer slot, cannot prove condition 2 and is refused).
///
/// Each permitted close emits a [`CloseIntent`] for `compare_and_account`,
/// which re-checks `amount_before` against its own snapshot and requires every
/// intent to be consumed exactly once — nothing downstream may INFER a close.
fn deny_scan(
    resolved: &[ResolvedInner],
    before: &[Snap],
    vault: &Pubkey,
) -> Result<Vec<CloseIntent>> {
    let mut intents = Vec::new();
    // GROK-EXP-06 (2026-08-22): a pubkey that was a VAULT TOKEN ACCOUNT in the
    // BEFORE snapshot may not be (re-)initialised by a direct instruction in
    // this payload. Conservation detects a nested close only as an AFTER-state
    // disappearance; close it nested and re-create the same pubkey before the
    // AFTER snapshot and every compared field is byte-identical, so the
    // detector is a no-op. The ATA program's `Create`/`CreateIdempotent` and
    // SPL/T22 `InitializeAccount*` are the only ways to put a token account at
    // an existing pubkey, so refusing them for BEFORE-vault-token targets is
    // the direct-instruction half of the detector. (Both halves nested inside
    // ONE middleman CPI remain invisible to any before/after comparison — see
    // PHASE1B-MEASUREMENTS.md; the vault cannot net-lose lamports that way
    // because rule 8 / rule 3 continuity still hold.)
    let was_vault_token = |key: &Pubkey| -> bool {
        before
            .iter()
            .any(|s| s.key == *key && s.token.as_ref().is_some_and(|t| t.owner == *vault))
    };
    for r in resolved {
        if r.program == crate::constants::ATA_PROGRAM_ID {
            if crate::payload::is_ata_create(&r.data) {
                // `[funder, ata, wallet, mint, system, token]` — the ATA is [1].
                let target = r.accounts.get(1).ok_or(WardenError::DenyListed)?;
                require!(!was_vault_token(&target.key), WardenError::DenyListed);
            }
            continue;
        }
        if r.program != SPL_TOKEN_ID && r.program != SPL_TOKEN_2022_ID {
            continue;
        }
        match crate::payload::classify_spl_token_op(&r.data) {
            SplTokenOp::DeniedUnconditional => return Err(WardenError::DenyListed.into()),
            SplTokenOp::InitializeAccount => {
                // `[account, mint, (owner), rent?]` — the account is [0].
                let target = r.accounts.first().ok_or(WardenError::DenyListed)?;
                require!(!was_vault_token(&target.key), WardenError::DenyListed);
            }
            SplTokenOp::CloseAccount => {
                // SPL / Token-2022 CloseAccount account order:
                // [0] account to close, [1] rent destination, [2] authority.
                // A close too short to even name a destination cannot prove
                // the sweep conditions — fail closed.
                let target = r.accounts.first().ok_or(WardenError::DenyListed)?;
                let destination = r.accounts.get(1).ok_or(WardenError::DenyListed)?;
                // (3) rent must come home to the vault PDA…
                require_keys_eq!(destination.key, *vault, WardenError::DenyListed);
                // (4) …and the target is neither the PDA itself…
                require_keys_neq!(target.key, *vault, WardenError::DenyListed);
                // …nor anything that did not snapshot as a parsed token
                // account (a Mint has `token == None`; so do the signer slot,
                // a stranger program's account, and a parse failure).
                let snap = before
                    .iter()
                    .find(|s| s.key == target.key)
                    .ok_or(WardenError::DenyListed)?;
                let token = snap.token.as_ref().ok_or(WardenError::DenyListed)?;
                require!(snap.mint.is_none(), WardenError::DenyListed);
                // (2) zero balance in the BEFORE snapshot.
                require!(token.amount == 0, WardenError::DenyListed);
                intents.push(CloseIntent {
                    account: target.key,
                    destination: destination.key,
                    amount_before: token.amount,
                });
            }
            SplTokenOp::Other => {}
        }
    }
    Ok(intents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        PROGRAM_SPL, TOKEN_IX_APPROVE, TOKEN_IX_APPROVE_CHECKED, TOKEN_IX_CLOSE_ACCOUNT,
        TOKEN_IX_REVOKE, TOKEN_IX_SET_AUTHORITY, TOKEN_IX_TRANSFER,
    };
    use crate::conservation::TokenSnap;

    fn err(e: WardenError) -> anchor_lang::error::Error {
        e.into()
    }

    /// `ExecuteBody` is a signed wire format: its field order is permanent.
    #[test]
    fn execute_body_borsh_layout_is_pinned() {
        let body = ExecuteBody { payload_hash: [0xAA; 32], accounts_hash: [0xBB; 32] };
        let mut buf = Vec::new();
        body.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 64);
        assert_eq!(&buf[..32], &[0xAA; 32], "payload_hash first");
        assert_eq!(&buf[32..], &[0xBB; 32], "then accounts_hash");
    }

    /// Cross-language pin: `action_hash(OP_EXECUTE_ACTION, borsh(ExecuteBody))`
    /// for a fixed body must equal the TS mirror's value
    /// (`packages/core/test/transcript.test.ts`, "OP_EXECUTE vector"). If this
    /// moves, every outstanding root `execute` ceremony breaks — that is a
    /// deliberate migration, never a refactor.
    #[test]
    fn execute_action_hash_matches_pinned_vector() {
        let body = ExecuteBody { payload_hash: [0x11; 32], accounts_hash: [0x22; 32] };
        let mut buf = Vec::new();
        body.serialize(&mut buf).unwrap();
        assert_eq!(
            hex::encode(action_hash(OP_EXECUTE_ACTION, &buf)),
            "971cfa437b2d03ae9063c9117d4c7ef61539d7a485d9ed1b991aab6e52d50c77"
        );
    }

    #[test]
    fn reject_jupiter_fires_on_the_v6_program_and_passes_others() {
        use crate::constants::JUPITER_V6_ID;
        let jup = ResolvedInner { program: JUPITER_V6_ID, accounts: vec![], data: vec![] };
        assert_eq!(
            reject_jupiter(&[jup]).unwrap_err(),
            err(WardenError::JupiterViaSwapOnly)
        );
        let other = ResolvedInner { program: Pubkey::new_unique(), accounts: vec![], data: vec![] };
        assert!(reject_jupiter(&[other]).is_ok());
    }

    // -- deny_scan (pure) ---------------------------------------------------

    fn acct(key: Pubkey, signer: bool, writable: bool) -> LogicalAccount {
        LogicalAccount { key, is_signer: signer, is_writable: writable }
    }

    /// An inner instruction resolved to an ARBITRARY token program — the
    /// deny-list covers SPL Token AND Token-2022 identically, so every case
    /// that is not specifically about one of them must be parametrizable over
    /// both (WRD-DENY-01).
    fn spl_ix_for(program: Pubkey, data: Vec<u8>, accounts: Vec<LogicalAccount>) -> ResolvedInner {
        ResolvedInner { program, accounts, data }
    }

    fn spl_ix(data: Vec<u8>, accounts: Vec<LogicalAccount>) -> ResolvedInner {
        spl_ix_for(SPL_TOKEN_ID, data, accounts)
    }

    fn token_snap(key: Pubkey, vault: Pubkey, amount: u64) -> Snap {
        Snap {
            key,
            exists: true,
            owner_program: SPL_TOKEN_ID,
            lamports: 2_039_280,
            data_len: 165,
            token: Some(TokenSnap {
                mint: Pubkey::new_unique(),
                owner: vault,
                amount,
                delegate: None,
                delegated_amount: 0,
                close_authority: None,
                state: 1,
                is_native: None,
                tlv_hash: [0; 32],
                program: PROGRAM_SPL,
            }),
            mint: None,
            token_parse_failed: false,
            is_writable: true,
        }
    }

    /// WRD-DENY-01: all four unconditional tags, on BOTH token programs. The
    /// deny branch keys on `r.program == SPL_TOKEN_ID || r.program ==
    /// SPL_TOKEN_2022_ID`, so covering only SPL Token would leave the
    /// Token-2022 half of the claim unproven — and Token-2022 shares the tag
    /// numbering, so a program-id typo there is invisible to a one-program test.
    #[test]
    fn deny_scan_rejects_the_four_unconditional_tags() {
        let vault = Pubkey::new_unique();
        for program in [SPL_TOKEN_ID, SPL_TOKEN_2022_ID] {
            for tag in [
                TOKEN_IX_APPROVE,
                TOKEN_IX_REVOKE,
                TOKEN_IX_SET_AUTHORITY,
                TOKEN_IX_APPROVE_CHECKED,
            ] {
                let ix =
                    spl_ix_for(program, vec![tag], vec![acct(Pubkey::new_unique(), false, true)]);
                assert_eq!(
                    deny_scan(&[ix], &[], &vault).unwrap_err(),
                    err(WardenError::DenyListed),
                    "program {program} tag {tag}"
                );
            }
        }
    }

    /// GROK-EXP-02: the authority-exercise tags are denied unconditionally,
    /// with no regard to accounts — the same class as SetAuthority.
    #[test]
    fn deny_scan_rejects_mint_to_and_freeze_family() {
        use crate::constants::{
            TOKEN_IX_FREEZE_ACCOUNT, TOKEN_IX_MINT_TO, TOKEN_IX_MINT_TO_CHECKED,
            TOKEN_IX_THAW_ACCOUNT,
        };
        let vault = Pubkey::new_unique();
        for tag in [TOKEN_IX_MINT_TO, TOKEN_IX_MINT_TO_CHECKED, TOKEN_IX_FREEZE_ACCOUNT, TOKEN_IX_THAW_ACCOUNT] {
            let mut data = vec![tag];
            data.extend_from_slice(&42_000u64.to_le_bytes());
            let ix = spl_ix(data, vec![acct(Pubkey::new_unique(), false, true), acct(Pubkey::new_unique(), false, true), acct(vault, true, false)]);
            assert_eq!(deny_scan(&[ix], &[], &vault).unwrap_err(), err(WardenError::DenyListed), "tag {tag}");
        }
        // Burn is NOT denied: it is a metered outflow (conservation + caps).
        let mut burn = vec![crate::constants::TOKEN_IX_BURN];
        burn.extend_from_slice(&1u64.to_le_bytes());
        let ix = spl_ix(burn, vec![acct(Pubkey::new_unique(), false, true), acct(Pubkey::new_unique(), false, true), acct(vault, true, false)]);
        assert!(deny_scan(&[ix], &[], &vault).unwrap().is_empty());
    }

    /// GROK-EXP-06: re-initialising a pubkey that was a vault token account
    /// BEFORE is denied (the direct half of the reincarnation detector), for
    /// every initialiser and for the ATA program's two creates; the same
    /// instructions against a pubkey that was NOT a vault token pass.
    #[test]
    fn deny_scan_rejects_reinitialising_a_before_vault_token_account() {
        use crate::constants::{
            ATA_IX_CREATE, ATA_IX_CREATE_IDEMPOTENT, ATA_PROGRAM_ID, TOKEN_IX_INITIALIZE_ACCOUNT,
            TOKEN_IX_INITIALIZE_ACCOUNT2, TOKEN_IX_INITIALIZE_ACCOUNT3,
        };
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let stranger_acct = Pubkey::new_unique();
        let before = vec![token_snap(target, vault, 0), token_snap(stranger_acct, Pubkey::new_unique(), 0)];
        let mint = Pubkey::new_unique();
        for tag in [TOKEN_IX_INITIALIZE_ACCOUNT, TOKEN_IX_INITIALIZE_ACCOUNT2, TOKEN_IX_INITIALIZE_ACCOUNT3] {
            let mut data = vec![tag];
            if tag != TOKEN_IX_INITIALIZE_ACCOUNT { data.extend_from_slice(vault.as_ref()); }
            let denied = spl_ix(data.clone(), vec![acct(target, false, true), acct(mint, false, false)]);
            assert_eq!(deny_scan(&[denied], &before, &vault).unwrap_err(), err(WardenError::DenyListed), "tag {tag}");
            // A stranger's account, or a fresh pubkey: not ours, passes.
            let ok = spl_ix(data.clone(), vec![acct(stranger_acct, false, true), acct(mint, false, false)]);
            assert!(deny_scan(&[ok], &before, &vault).unwrap().is_empty());
            let fresh = spl_ix(data, vec![acct(Pubkey::new_unique(), false, true), acct(mint, false, false)]);
            assert!(deny_scan(&[fresh], &before, &vault).unwrap().is_empty());
        }
        let ata_ix = |data: Vec<u8>, ata: Pubkey| ResolvedInner {
            program: ATA_PROGRAM_ID,
            accounts: vec![acct(Pubkey::new_unique(), true, true), acct(ata, false, true), acct(vault, false, false), acct(mint, false, false)],
            data,
        };
        for data in [vec![ATA_IX_CREATE], vec![ATA_IX_CREATE_IDEMPOTENT], vec![]] {
            assert_eq!(deny_scan(&[ata_ix(data.clone(), target)], &before, &vault).unwrap_err(), err(WardenError::DenyListed), "{data:?}");
            assert!(deny_scan(&[ata_ix(data, Pubkey::new_unique())], &before, &vault).unwrap().is_empty());
        }
        // A short ATA create that cannot even name the ATA fails closed.
        let short = ResolvedInner { program: ATA_PROGRAM_ID, accounts: vec![acct(Pubkey::new_unique(), true, true)], data: vec![ATA_IX_CREATE_IDEMPOTENT] };
        assert_eq!(deny_scan(&[short], &before, &vault).unwrap_err(), err(WardenError::DenyListed));
        // RecoverNested (tag 2) is not a create: passes the ATA branch.
        let recover = ResolvedInner { program: ATA_PROGRAM_ID, accounts: vec![acct(target, false, true)], data: vec![2] };
        assert!(deny_scan(&[recover], &before, &vault).unwrap().is_empty());
    }

    #[test]
    fn deny_scan_ignores_non_token_programs_and_other_ops() {
        let vault = Pubkey::new_unique();
        // A stranger program carrying a deny tag as its own opcode is not SPL.
        let stranger = ResolvedInner {
            program: Pubkey::new_unique(),
            accounts: vec![],
            data: vec![TOKEN_IX_SET_AUTHORITY],
        };
        // An SPL Transfer is `Other` and passes through to the registry.
        let transfer = spl_ix(
            vec![TOKEN_IX_TRANSFER, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![acct(Pubkey::new_unique(), false, true)],
        );
        let intents = deny_scan(&[stranger, transfer], &[], &vault).unwrap();
        assert!(intents.is_empty());
    }

    #[test]
    fn close_to_vault_with_zero_balance_emits_intent() {
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let before = vec![token_snap(target, vault, 0)];
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![acct(target, false, true), acct(vault, false, false), acct(vault, true, false)],
        );
        let intents = deny_scan(&[ix], &before, &vault).unwrap();
        assert_eq!(
            intents,
            vec![CloseIntent { account: target, destination: vault, amount_before: 0 }]
        );
    }

    #[test]
    fn close_to_stranger_rejected() {
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let stranger = Pubkey::new_unique();
        let before = vec![token_snap(target, vault, 0)];
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![acct(target, false, true), acct(stranger, false, true), acct(vault, true, false)],
        );
        assert_eq!(deny_scan(&[ix], &before, &vault).unwrap_err(), err(WardenError::DenyListed));
    }

    #[test]
    fn close_with_nonzero_balance_rejected() {
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let before = vec![token_snap(target, vault, 1)];
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![acct(target, false, true), acct(vault, false, false), acct(vault, true, false)],
        );
        assert_eq!(deny_scan(&[ix], &before, &vault).unwrap_err(), err(WardenError::DenyListed));
    }

    #[test]
    fn close_of_the_pda_itself_rejected() {
        let vault = Pubkey::new_unique();
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![acct(vault, false, true), acct(vault, false, false), acct(vault, true, false)],
        );
        assert_eq!(deny_scan(&[ix], &[], &vault).unwrap_err(), err(WardenError::DenyListed));
    }

    #[test]
    fn close_of_account_outside_snapshot_rejected() {
        // The target names the signer slot / any key not in `remaining` — the
        // sweep conditions cannot be proven, so it fails closed.
        let vault = Pubkey::new_unique();
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![
                acct(Pubkey::new_unique(), false, true),
                acct(vault, false, false),
                acct(vault, true, false),
            ],
        );
        assert_eq!(deny_scan(&[ix], &[], &vault).unwrap_err(), err(WardenError::DenyListed));
    }

    #[test]
    fn close_of_a_mint_rejected() {
        let vault = Pubkey::new_unique();
        let target = Pubkey::new_unique();
        let mut snap = token_snap(target, vault, 0);
        snap.token = None; // a mint parses as `mint: Some`, `token: None`
        let ix = spl_ix(
            vec![TOKEN_IX_CLOSE_ACCOUNT],
            vec![acct(target, false, true), acct(vault, false, false), acct(vault, true, false)],
        );
        assert_eq!(
            deny_scan(&[ix], &[snap], &vault).unwrap_err(),
            err(WardenError::DenyListed)
        );
    }

    #[test]
    fn close_with_too_few_accounts_rejected() {
        let vault = Pubkey::new_unique();
        let ix = spl_ix(vec![TOKEN_IX_CLOSE_ACCOUNT], vec![acct(Pubkey::new_unique(), false, true)]);
        assert_eq!(deny_scan(&[ix], &[], &vault).unwrap_err(), err(WardenError::DenyListed));
    }
}
