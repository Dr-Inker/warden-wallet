# Warden devnet website test

This is a separate experimental extension and website build. It implements
passkey enrollment, authenticated smart-account creation, account verification,
connection approval, and root-approved native SOL transfers. It does not enable
these capabilities in the regular extension or implement Wallet Standard.

## Checkpoint and readiness

The implementation/evidence checkpoint
`9a3e5ee90f5a5946fc6faab177a55fc6ce5c29e3` was pushed to `origin/phase1b`.
The tested code is `e61dfa62ccad27da05791a544b7c38d7a6772b5c`; exact commands
and results are in [the critique](CRITIQUE-2026-09-05.md). Documentation commits
after that code SHA do not inherit its test verdict.

The source and local build exist. Browser verification, independent review,
full-gate verification and real devnet passkey/transfer testing remain open.
`https://wardenwallet.io/test/` has not been published. The owner has been asked
for the original program keypair's secure path and the applicable Warden
deployment procedure; neither has been supplied. The RPC observation below is
the recorded implementation-session result, not a new network check performed
for this documentation update.

## Run locally

From `/opt/warden`, with `target/deploy/warden.so` already built:

```bash
pnpm --filter @warden/extension build:devnet
python3 -m http.server 4173 --bind 127.0.0.1 --directory apps/extension/dist/devnet/site
```

The build reads the local ELF, embeds its SHA-256 and byte length, and writes:

- `apps/extension/dist/devnet/extension/` — load this directory unpacked in
  Chrome 120+ using `chrome://extensions` and Developer mode.
- `apps/extension/dist/devnet/site/test/` — static website files for `/test/`.
- `apps/extension/dist/devnet/program-pin.json` — expected program fingerprint.

The regular extension build cleans `dist`; run `build:devnet` afterward. Keep
the unpacked extension at the same path, since changing the extension ID changes
the WebAuthn origin. Do not uninstall it while retaining a funded test account.
Only public credential metadata is saved. The temporary Ed25519 fee payer is
held in the wallet document's memory and is lost on reload or close.

1. Open the extension from Chrome's toolbar. Its initial check must find the
   matching program binary on devnet before any transaction can be sent.
2. Request 1 devnet SOL for the temporary fee payer. If the public faucet is
   rate limited, fund the displayed fee-payer address from another devnet source.
3. Choose **Create / resume wallet**. Create a passkey, then approve the separate
   account-creation ceremony. Metadata is saved before submission so an
   interrupted creation can resume at the same account address.
4. Choose **Add 0.05 devnet SOL** to fund the smart account above its rent floor.
5. Open `http://127.0.0.1:4173/test/`, enter the extension ID displayed in the
   wallet, and choose **Connect wallet**. Approve the connection in the extension.
6. Enter a different devnet recipient you control and an amount such as `0.001`.
   Choose **Review transfer in Warden**. The new review tab has a new temporary
   fee payer; fund it before approving. Review the exact site, account, recipient
   and amount, then approve with your passkey or reject the request.
7. The website reports confirmation only after a confirmed/finalized RPC status
   with no transaction error. Follow its devnet Explorer receipt link.

The policy allows native SOL only: 0.01 SOL per transfer, 0.1 SOL per day,
1 SOL per 30 days, and no session delegation. Root transfers debit the program's
existing shared buckets. Rent remains in the smart account.

## Unknown outcomes and interruptions

Before submission, the extension saves the locally derived transaction signature
and block-height expiry. A timeout cannot be reported as a successful transfer.
The saved pending receipt blocks further sends until **Check transaction** sees
confirmation, a chain error, or an absent receipt after the blockhash has expired
at finalized height. Reopen the extension to check after a tab/worker interruption.
Closing review is not a guarantee that a submitted transaction was cancelled.

Website connections are one request per Chrome port. The worker accepts only a
top-level, browser-identified document on `/test`, `/test/`, or `/test/index.html`
at `https://wardenwallet.io`, `http://localhost:4173`, or `http://127.0.0.1:4173`.
The review tab is bound to its exact Chrome tab ID and random internal URL.
Disconnect/restart invalidates the request; no approvals survive worker restart.
A bound review sends a 15-second keepalive, capped by the five-minute request
expiry, following Chrome's [MV3 messaging lifetime rules](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
Only `connect` and the bounded native transfer schema are accepted. There is no
page-supplied RPC endpoint, program ID, arbitrary transaction, or signing API.
Chrome's [external messaging manifest](https://developer.chrome.com/docs/extensions/reference/manifest/externally-connectable)
and [MessageSender metadata](https://developer.chrome.com/docs/extensions/reference/api/runtime#type-MessageSender)
provide the browser-owned transport and provenance fields.

## Deployment prerequisite — currently unresolved

Read-only RPC on 2026-09-05 returned devnet genesis
`EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` and `getAccountInfo.value: null`
at confirmed slot **493700271** for the checked-in program address
`6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2`.
Solana documents this result as an [absent account](https://solana.com/docs/rpc/http/getaccountinfo).
No deployment or airdrop was performed by this implementation session.

An authorized owner must deploy the reviewed Warden binary on devnet under that
address. The original program keypair is required; see [PROGRAM-KEYS.md](PROGRAM-KEYS.md).
Do not rotate the shared program ID or run `anchor keys sync` to work around a
missing key. The test build pins the exact ELF bytes and verifies devnet genesis,
the canonical upgradeable-loader ProgramData address, executable/owner metadata,
code hash and allocation padding before each write. This devnet check is not the
production deployment/Squads authority gate. Mutable devnet upgrade authority
remains a test-network trust assumption.

The site's configured name is **wardenwallet.io**, without a hyphen. Git pushes
do not publish its static files. The proposed publication consists of the three
files in `dist/devnet/site/test/` at the site's `/test/` path. No live files or
nginx configuration have been changed. Publishing awaits the applicable Warden
deployment procedure/authorization; the supplied host instructions require a
documented PLAYBOOK §8 procedure and no Warden playbook was found in this repo.

## Executable verification

```bash
pnpm --filter @warden/core exec vitest run test/devnet.test.ts
pnpm --filter @warden/extension exec vitest run test/devnet-protocol.test.ts
cargo test --locked -p warden --test devnet_client -- --nocapture
pnpm --filter @warden/core typecheck
pnpm --filter @warden/extension typecheck
pnpm --filter @warden/extension build
pnpm --filter @warden/extension build:devnet
pnpm --filter @warden/extension exec playwright test -c playwright.config.ts browser/devnet-flow.pw.ts --workers=1
```

`devnet_client` executes the TypeScript fixture's exact create/transfer bytes in
LiteSVM using the real secp256r1 precompile, checks packet sizes and exact balance
deltas, and rejects recipient substitution. Its assertion signatures are made
independently by Node/OpenSSL; the fixture generator lives under core `scripts/`
and is never bundled. Regeneration is an explicit maintenance action, not part
of a passing test. The browser lane checks real Chrome external-port provenance,
rejection, missing-deployment UX and rendered overflow/control sizes; its RPC
fixture is explicitly an absent deployment. It does not prove live transfers.

Exact command/SHA evidence and outstanding gates are recorded in
[CRITIQUE-2026-09-05.md](CRITIQUE-2026-09-05.md). Full deploy gate, independent
review, real browser passkey enrollment and live devnet confirmation must be
completed before declaring the end-to-end test ready for use.
