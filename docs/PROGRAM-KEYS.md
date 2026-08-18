# Program keys — warden

## What's committed, what isn't

- **Committed** (source of truth): the program id, in two places that must
  always agree — `declare_id!(...)` in `programs/warden/src/lib.rs` and
  `[programs.localnet].warden` in `Anchor.toml`. Currently (rotated
  2026-08-18, see "Rotation history" below):
  `6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2`.
- **Never committed**: the program *keypair* (the private key that can
  authorize a deploy/upgrade to that id) — `programs/warden/keypair.json` and
  `target/deploy/warden-keypair.json` are both gitignored (`**/keypair.json`,
  `target/deploy/*-keypair.json` in `.gitignore`).

## Why LiteSVM tests don't need a keypair

`programs/warden/tests/common/mod.rs` loads the program by reading
`target/deploy/warden.so` off disk and calling `svm.add_program(warden::ID, &so)`
— LiteSVM installs the program bytes directly into its in-process ledger under
the given program id; it never checks or needs the private key. `warden::ID`
comes from the crate's own `declare_id!`, so the smoke test (and every future
LiteSVM test) is fully reproducible from a clean clone: `anchor build` (or
`cargo-build-sbf`) produces `warden.so`, no keypair required. This is why the
test-gate rebuilds the `.so` when missing/stale but never touches the keypair.

## Deploying locally or to devnet under the declared id

To actually `anchor deploy`/`solana program deploy` under the id declared in
`Anchor.toml`/`declare_id!`, you need the *original* keypair for that id
(the owner holds this out-of-band — ask before you need it; it is not, and
will not be, committed).

## Generating a fresh dev id (when you don't have — or don't need — the original)

If you just need *some* working localnet id to deploy to (e.g. local
iteration, not matching the committed id):

```bash
solana-keygen new -o target/deploy/warden-keypair.json
anchor keys sync   # rewrites declare_id!() in lib.rs and Anchor.toml to match
```

**Do not commit the resulting `declare_id!`/`Anchor.toml` change** unless the
id change is actually intended (e.g. a deliberate mainnet-id rotation done
under the multisig per the plan's Global Constraints) — a stray `anchor keys
sync` diff is almost always a sign you generated a throwaway local key and
should `git checkout -- programs/warden/src/lib.rs Anchor.toml` before
committing anything else.

## Fresh-build id mismatch warning

`anchor build` looks for `target/deploy/warden-keypair.json` and — if it's
absent (the normal case on a clean clone, since it's gitignored) — silently
generates a new one, then compares its pubkey against `declare_id!()` and
**warns** (does not fail) on mismatch: `Program ID mismatch detected for
program 'warden' ...`. The build still succeeds and produces a correct
`warden.so` (the on-chain id embedded in the binary comes from `declare_id!`,
not from `target/deploy/warden-keypair.json`), and LiteSVM tests are
unaffected (see above) — **the committed declared id
(`declare_id!`/`Anchor.toml`) is authoritative**, not whatever keypair happens
to be sitting in `target/deploy/`. The mismatch warning only matters if you
intend to `anchor deploy`/`anchor keys sync` for real; the test gate never
does either, so it never depends on the keypair.

## Rotation history

- **2026-08-18 — id rotated, old id retired.** The original program keypair
  (id `7xc9rRHdt9n2aFmu4J6xgk8jVrg9obXArnr3fZcyNo7X`) was briefly committed to
  git in `687c5e8` before being removed (`git rm --cached`) in the following
  fix round. Per controller security ruling, a committed keypair is treated
  as burned regardless of whether the branch was ever pushed to a shared
  remote (it wasn't, in this case) — so the id itself was retired, not just
  the leftover file. New keypair generated via
  `solana-keygen new --no-bip39-passphrase -o target/deploy/warden-keypair.json --force`,
  then `anchor keys sync` rewrote `declare_id!()` (lib.rs) and
  `Anchor.toml`'s `[programs.localnet].warden` to the new id:
  **`6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2`**. Verified `git status`
  does not list either keypair path (still gitignored) after the rotation,
  and the gate (`./.claude/test-gate.sh`) was rerun end to end to confirm
  both `cargo test --workspace` tests still pass against the new id. The old
  id (`7xc9rRHdt9n2aFmu4J6xgk8jVrg9obXArnr3fZcyNo7X`) should be treated as
  retired/burned going forward — never reuse it, even though (like the new
  one) it was only ever a localnet/devnet-only id with no funds, no mainnet
  authority, and no program ever deployed under it outside this repo's own
  (keypair-independent) LiteSVM tests. The original commit that briefly held
  the first keypair was squashed out of `phase1a`'s history before any push
  (verified: `git cat-file -e 687c5e8` now fails — the commit no longer
  exists in this repo); the first keypair is retired regardless, since a
  committed private key is treated as burned the moment it's committed, not
  only if/when history containing it is later pushed.
