//! Value accounting (spec §5.2 rules 4 and 4a).
//!
//! ## One number per mint, and SOL is one number
//!
//! `outflow[mint]` is the **signed net** across every vault-owned token
//! account of that mint, floored at 0 — not a sum of decreases. The difference
//! is load-bearing: moving 100 USDC from one vault ATA to another vault ATA is
//! `−100` on one account and `+100` on the other, and charging the caps 100
//! for an internal rebalance would be wrong. Spec §5.2 rule 4 says exactly
//! this ("negative ⇒ inflow, floored at 0 for cap purposes").
//!
//! The net is computed without signed arithmetic: decreases and increases are
//! each accumulated with `checked_add` into a `u64`, and the floor falls out of
//! one `saturating_sub` at the end. The crate denies
//! `clippy::arithmetic_side_effects`, and an `i128` accumulator would have
//! needed its own overflow argument anyway.
//!
//! ## SOL and wrapped SOL are the SAME number
//!
//! `constants::NATIVE_MINT` is the cap-lookup key for native SOL (see
//! `transfer`), so a WSOL entry in `by_mint` **and** a `sol` figure would
//! debit the same bucket twice for one movement. Spec §5.2 rule 4 merges them
//! by construction:
//!
//! ```text
//! outflow[SOL] = (pda_lamports_before − pda_lamports_after)
//!              + Σ_{vault WSOL accounts}(amount_before − amount_after)
//! ```
//!
//! and WSOL token accounts' own *lamports* are never counted separately —
//! they back the `amount`. `by_mint` therefore never contains `NATIVE_MINT`;
//! `outflow_never_lists_native_mint_in_by_mint` asserts it.
//!
//! The floor is applied **once, at the end, to the merged figure** — not to
//! the PDA term on its own. That is what makes the vault-sweep close arrive as
//! a genuine inflow that offsets a WSOL decrease, per rule 4a's "the returned
//! rent lamports arrive as an increase in the PDA's own lamports, which the
//! SOL equation already sees as an inflow. Nothing extra is added."

use anchor_lang::prelude::*;

use crate::errors::WardenError;

/// What left the vault this instruction.
///
/// There is deliberately **no `gross_turnover` field** — see the module docs
/// on [`super`] for the two permanent reasons and do not re-add it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outflow {
    /// Native SOL **and** wrapped SOL, merged into one number (see above).
    pub sol: u64,
    /// One entry per mint, in first-seen order. Never contains
    /// `constants::NATIVE_MINT`.
    pub by_mint: Vec<(Pubkey, u64)>,
}

/// Signed-net accumulator: decreases and increases kept apart so the whole
/// thing stays in unsigned, checked arithmetic.
#[derive(Default)]
pub(crate) struct Netter {
    sol_out: u64,
    sol_in: u64,
    /// `(mint, decreases, increases)`, first-seen order. A linear scan is the
    /// right structure at the §5.2 account cap (40) — a map would cost more
    /// CU than it saves.
    mints: Vec<(Pubkey, u64, u64)>,
}

impl Netter {
    pub(crate) fn add_sol_out(&mut self, v: u64) -> Result<()> {
        self.sol_out = self.sol_out.checked_add(v).ok_or(WardenError::Overflow)?;
        Ok(())
    }

    pub(crate) fn add_sol_in(&mut self, v: u64) -> Result<()> {
        self.sol_in = self.sol_in.checked_add(v).ok_or(WardenError::Overflow)?;
        Ok(())
    }

    pub(crate) fn add_mint_out(&mut self, mint: &Pubkey, v: u64) -> Result<()> {
        let row = self.row(mint);
        row.1 = row.1.checked_add(v).ok_or(WardenError::Overflow)?;
        Ok(())
    }

    pub(crate) fn add_mint_in(&mut self, mint: &Pubkey, v: u64) -> Result<()> {
        let row = self.row(mint);
        row.2 = row.2.checked_add(v).ok_or(WardenError::Overflow)?;
        Ok(())
    }

    fn row(&mut self, mint: &Pubkey) -> &mut (Pubkey, u64, u64) {
        if let Some(i) = self.mints.iter().position(|(m, _, _)| m == mint) {
            // `expect` cannot fire: `position` just returned this index.
            return self.mints.get_mut(i).expect("index from position");
        }
        self.mints.push((*mint, 0, 0));
        self.mints.last_mut().expect("just pushed")
    }

    /// Collapse to the caps-facing figure: net per mint, floored at 0, and
    /// mints whose net is an inflow (or zero) are dropped entirely rather than
    /// carried as a `0` entry — a debit of 0 against a mint with no cap would
    /// otherwise be indistinguishable from a real one.
    pub(crate) fn finish(self) -> Outflow {
        let mut by_mint = Vec::with_capacity(self.mints.len());
        for (mint, out, inn) in self.mints {
            let net = out.saturating_sub(inn);
            if net != 0 {
                by_mint.push((mint, net));
            }
        }
        Outflow { sol: self.sol_out.saturating_sub(self.sol_in), by_mint }
    }
}
