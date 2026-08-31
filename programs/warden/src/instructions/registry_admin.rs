//! `init_registry` — creates the single global adapter `Registry` (Task 3).
//!
//! **Authorised by warden's on-chain UPGRADE AUTHORITY**, not by any key baked
//! into `Anchor.toml`: the instruction takes warden's BPF-upgradeable
//! `ProgramData` account, reads its `upgrade_authority_address`, and requires
//! that exact key as a `Signer`. On localnet/devnet that is the dev deploy
//! keypair; on mainnet it is the Squads multisig. The registry is a singleton
//! (`init` on the `["registry"]` PDA fails on a second call) and **immutable in
//! 1B** — there is no update instruction; 1C adds a timelocked one.
//!
//! It writes the fixed default adapter set (`registry_default::write_defaults`)
//! and records `authority` (= the upgrade authority) and `treasury` (the
//! drinkerlabs treasury SmartAccount, a first-class field).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;

use crate::constants::REGISTRY_SEED;
use crate::errors::WardenError;
use crate::registry_default::write_defaults;
use crate::state::registry::Registry;

#[derive(Accounts)]
pub struct InitRegistry<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = Registry::LEN,
        seeds = [REGISTRY_SEED],
        bump
    )]
    pub registry: AccountLoader<'info, Registry>,

    /// Warden's `ProgramData` account. Its address and its
    /// `upgrade_authority_address` are both checked in the handler — the address
    /// against the canonical `[program_id]` derivation under the upgradeable
    /// loader, the authority against the `authority` signer below.
    /// CHECK: validated in the handler (address + decoded upgrade authority).
    pub program_data: UncheckedAccount<'info>,

    /// The upgrade authority, signing to prove control. Must equal
    /// `program_data.upgrade_authority_address`.
    pub authority: Signer<'info>,

    /// The drinkerlabs treasury SmartAccount whose ATA receives swap fees
    /// (Task 6). Stored as `Registry.treasury`; only its key is read here.
    /// CHECK: an arbitrary pubkey stored as the treasury; validated as a real
    /// SmartAccount when a swap uses it (Task 6), not here.
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub(crate) fn handler(ctx: Context<InitRegistry>) -> Result<()> {
    // 1. The ProgramData account must be warden's canonical one.
    let (expected_pd, _) =
        Pubkey::find_program_address(&[crate::ID.as_ref()], &bpf_loader_upgradeable::ID);
    require_keys_eq!(
        ctx.accounts.program_data.key(),
        expected_pd,
        WardenError::RegistryUnauthorized
    );

    // 2. Decode its upgrade authority and require the signer to be exactly it.
    let pd = &ctx.accounts.program_data;
    require!(
        pd.owner == &bpf_loader_upgradeable::ID,
        WardenError::RegistryUnauthorized
    );
    let data = pd.try_borrow_data()?;
    let program_data: anchor_lang::prelude::ProgramData =
        anchor_lang::AccountDeserialize::try_deserialize(&mut &data[..])?;
    let upgrade_authority = program_data
        .upgrade_authority_address
        .ok_or(WardenError::RegistryUnauthorized)?;
    require_keys_eq!(
        upgrade_authority,
        ctx.accounts.authority.key(),
        WardenError::RegistryUnauthorized
    );
    drop(data);

    // 3. Initialise the singleton and write the defaults.
    let mut reg = ctx.accounts.registry.load_init()?;
    reg.version = 1;
    reg.bump = ctx.bumps.registry;
    reg.authority = ctx.accounts.authority.key();
    reg.treasury = ctx.accounts.treasury.key();
    write_defaults(&mut reg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_authority_resolver_programdata_pda_matches_shipped_pin() {
        let (program_data, _) =
            Pubkey::find_program_address(&[crate::ID.as_ref()], &bpf_loader_upgradeable::ID);

        assert_eq!(
            program_data.to_string(),
            "Eb2gEx5X9TUwJ7z8hhg1SC4GHSEW72ohG7L7emve9bpf"
        );
    }

    #[test]
    fn client_authority_resolver_loader_state_layout_matches_snapshot_decoder() {
        let (program_data, _) =
            Pubkey::find_program_address(&[crate::ID.as_ref()], &bpf_loader_upgradeable::ID);
        let upgrade_authority = Pubkey::new_from_array([0xaa; 32]);
        let program =
            bincode::serialize(&bpf_loader_upgradeable::UpgradeableLoaderState::Program {
                programdata_address: program_data,
            })
            .expect("Program state must serialize");
        let program_data_header = bincode::serialize(
            &bpf_loader_upgradeable::UpgradeableLoaderState::ProgramData {
                slot: 0x0102_0304_0506_0708,
                upgrade_authority_address: Some(upgrade_authority),
            },
        )
        .expect("ProgramData state must serialize");

        assert_eq!(program.len(), 36);
        assert_eq!(&program[..4], &[2, 0, 0, 0]);
        assert_eq!(&program[4..], program_data.as_ref());
        assert_eq!(program_data_header.len(), 45);
        assert_eq!(&program_data_header[..4], &[3, 0, 0, 0]);
        assert_eq!(
            &program_data_header[4..12],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(program_data_header[12], 1);
        assert_eq!(&program_data_header[13..45], upgrade_authority.as_ref());
    }

    #[test]
    fn client_authority_resolver_clock_sysvar_layout_matches_snapshot_decoder() {
        let clock = Clock {
            slot: 0x0102_0304_0506_0708,
            epoch_start_timestamp: -2,
            epoch: 0x1112_1314_1516_1718,
            leader_schedule_epoch: 0x2122_2324_2526_2728,
            unix_timestamp: -5,
        };
        let encoded = bincode::serialize(&clock).expect("Clock must serialize");
        let expected = [
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x28, 0x27, 0x26, 0x25,
            0x24, 0x23, 0x22, 0x21, 0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        assert_eq!(encoded, expected);
    }
}
