# Grok independent review — 2026-08-23 (result)

Reviewer: **grok-4.3** (xAI) via the local zero-dependency MCP server
(`/root/.claude/mcp-servers/grok/server.mjs`). Range reviewed:
`c5a4514..f4880cc` — the range the Codex lane could not complete (two
content-filter blocks; see PHASE1B-MEASUREMENTS.md "Round 4 — BLOCKED").

**Status of this document: UNRECORDED second opinion.** It is deliberately NOT in
REVIEW-RUNS.jsonl and no `WRDF-` id was minted from it by hand. That ledger's
value comes from `scripts/review.sh` computing its own seed list, validating
output with an independent validator, and writing both ledgers atomically with
rollback. A finding here is a LEAD to act on and then re-run through that
machinery — never a row to hand-write. (House rule, same as the 2026-08-22 Grok
audit.)

Seeded with: the handoff memo, `conservation/mod.rs`, `conservation/snapshot.rs`,
`PRIOR-ART-FINDINGS.md`, and the full diff. 37,590 prompt tokens.

## Main-loop verification of the central claim

Grok's Task-1 answer was CHECKED against source before any action was taken:

- `execute`'s gate (`instructions/execute.rs` ~:430-450) consults ONLY
  `holds_authority`. **Confirmed.**
- `scan_extensions` (`conservation/snapshot.rs:300-351`) extracts authority
  pubkeys for TransferFeeConfig and PermanentDelegate ONLY; `EXT_TRANSFER_HOOK`
  and the five confidential types set a danger bit with **no pubkey extracted**;
  everything else falls to `_ => out.unrecognized_ext = true`. **Confirmed.**
- The `execute.rs:438` comment claims unrecognised extensions are "handled on a
  different axis" — that axis is `prescan_vault_mints`
  (`conservation/compare.rs:352-358`), which rejects an unmodelable mint **only
  when WRITABLE**. **Confirmed.**

So a READ-ONLY mint whose PDA-held authority lives in an unmodelled extension is
caught by nothing — structurally identical to the PermanentDelegate bug that was
proven to drain a third party's tokens. The WRDF-0105 remediations closed the
INSTANCE three times; this is the CLASS.

**Adjudication: ACCEPTED.** Grok's recommended shape adopted — keep
`holds_authority` for the "vault-controlled" test, and additionally fail closed in
generic `execute` on `has_unrecognized_ext` or on danger bits whose authority
fields are not extracted (TransferHook, confidential). This preserves the
deliberate narrowness property (stranger-held mints with MODELLED extensions
still work) while refusing semantics the snapshot cannot represent. Cost, accepted
knowingly: a new Token-2022 extension becomes a liveness blocker in generic
`execute` until it is modelled.

---

## Verbatim reviewer output

**TASK 1 (enumeration completeness)**

`MintSnap::holds_authority` (programs/warden/src/conservation/mod.rs:174) and the five-role list documented at mod.rs:178-185 only ever inspect:
- `mint_authority` / `freeze_authority` (base mint layout, snapshot.rs:250)
- `transfer_fee_config_authority` / `withdraw_withheld_authority` (TransferFeeConfig TLV, snapshot.rs:313-314)
- `permanent_delegate` (PermanentDelegate TLV, snapshot.rs:310-330 — the change under review)

`scan_extensions` (snapshot.rs:302) walks the TLV once. Every other listed extension falls through to either `unrecognized_ext=true` (snapshot.rs:340) or a pure `DANGER_*` bit with no `Pubkey` stored:

- MintCloseAuthority, InterestBearingConfig (rate authority), PausableConfig, DefaultAccountState, GroupPointer, GroupMemberPointer, MetadataPointer, ScaledUiAmountConfig, TokenMetadata update authority: all unrecognized (snapshot.rs:340).
- TransferHook (both authority and program ID fields): only `DANGER_TRANSFER_HOOK` (snapshot.rs:332); no pubkey extracted.
- All four ConfidentialTransfer* extensions + ConfidentialTransferFee: only `DANGER_CONFIDENTIAL` (snapshot.rs:333-337); no mint authority / auditor / withdraw-withheld fields extracted.
- TransferFeeConfig is the only TLV that yields authority pubkeys; everything else is either a danger flag or `has_unrecognized_ext`.

Thus the predicate is still incomplete for any authority that lives in an unmodeled extension. A mint whose only vault-controlled role is e.g. its `TransferHook` program ID or its `InterestBearingConfig` rate authority will not be caught by `holds_authority`.

**TASK 2 (shape of the defence)**

A pure known-role whitelist is the wrong shape. It has already required three consecutive remediation rounds (documented in the seeded memo and in REVIEW-SCORECARD.jsonl entries for WRDF-0105) because every new Token-2022 extension that carries a reassignable authority must be manually added to both the extractor and the predicate. The deliberate narrowness property (stranger-held TransferFeeConfig mints must still be allowed — see the test at execute.rs:2197 and the new stranger-permanent-delegate test) is preserved by keying on *who* holds the role rather than blanket rejection, but that same design makes enumeration errors into security holes.

Recommended shape: keep the five-role `holds_authority` test for the “vault-controlled mint” gate, but change the generic-execute path to also reject any mint that carries `has_unrecognized_ext` (or any `DANGER_*` bit whose authority field is not modeled). This still permits a fully stranger-controlled mint with a known extension; it only refuses mints whose authority semantics the snapshot cannot reason about. Cost: new Token-2022 extensions become liveness blockers until modeled (exactly the trade-off already accepted for 1B via `has_unrecognized_ext` on vault mints).

**TASK 3 (PermanentDelegate fix)**

The change is correct and complete for PermanentDelegate:
- `parse_mint_fields` now stores `ext.permanent_delegate` (snapshot.rs:253).
- `holds_authority` now includes the fifth arm (mod.rs:185).
- `prescan_vault_mints` and `check_mint` compare the field (compare.rs:373, 592).
- The two new integration tests (execute.rs:2263 and 2307) plus the unit tests in conservation/tests.rs:2124 exercise both the authority path and the read-only case.

The “malformed <32-byte TLV yields None, safe because the token program requires exactly 32 bytes” claim appears only as a static comment (snapshot.rs:320-325) and in the seeded memo. It is a POTENTIAL / static_trace observation; no red test or on-chain execution of a truncated TLV is present in the range.

**TASK 4 (other issues in range)**

Three of the last five findings were adjudicator errors rather than code defects (WRDF-0105 round-2 brief dropped PermanentDelegate; WRDF-0108 promotion of an unimplemented conjunct; WRDF-0107 ledger provenance). The range records those admissions correctly. No additional defects were found.

All claims above are static_trace from the seeded files (conservation/mod.rs:174, snapshot.rs:302-340, compare.rs:355, execute.rs:430) or primary_source from the diff. No new red test was executed.

---
[grok-mcp] model=grok-4.3 prompt_tokens=37590 completion_tokens=961 reasoning_tokens=902