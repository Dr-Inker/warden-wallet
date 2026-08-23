# Memo — Codex content-filter block on the Warden review lane

**Written 2026-08-23 for the owner, who is logging into Codex directly to try to clear this.**

---

## The one-paragraph version

`scripts/review.sh` is the canonical adversarial-review lane for this repo (Codex
`gpt-5.6-sol` @ `max`, JSON-schema-validated, recorded in
`docs/security/REVIEW-RUNS.jsonl`). It is now **reliably blocked** by OpenAI's cyber
content filter on any range containing our own defensive regression tests. Those
tests deliberately execute a token drain in a local simulator to prove a
vulnerability was real — which is exactly what makes them good evidence, and
exactly what the classifier reacts to. Nothing is wrong with the code, the prompt,
or the account as far as we can tell; the security work simply *looks* like what
the filter exists to stop.

## Exact error

```
ERROR: This content was flagged for possible cybersecurity risk. If this seems
wrong, try rephrasing your request. To get authorized for security work, join the
Trusted Access for Cyber program: https://chatgpt.com/cyber
```

That last sentence is almost certainly the actionable path — see "What to try".

## Evidence — this is a pattern, not a one-off

| Date | Range | Lane | Result |
|---|---|---|---|
| 2026-08-22 | `9a427aa..deb16e4` | `scripts/review.sh` ×2 (incl. a defensively-reframed retry) | blocked |
| 2026-08-22 | same | `mcp__codex__codex` sol@max | hung, no return |
| **2026-08-23** | `c5a4514..f4880cc` | `scripts/review.sh` | **blocked** (2 hits) |
| **2026-08-23** | `c5a4514..f4880cc` | `scripts/review.sh` retry | **blocked** (2 hits) |
| **2026-08-23** | `c5a4514..eeb6a7a` | `scripts/review.sh` | **blocked** (3 hits) |

Notes:
- The 2026-08-22 block **cleared on its own after roughly 24 h** on an identical
  lane — the round then ran clean and returned 4 findings. So it is at least
  partly transient/probabilistic, not a hard account-level denial.
- One 2026-08-23 attempt reached the invariant-verdict stage and emitted **no
  findings section** before dying, i.e. it got most of the way through.
- One block fired right after Codex ran a **web search to `developers.jup.ag`**,
  so the trigger may not be solely our diff.
- Environment: `codex-cli 0.149.0`, config `~/.codex/config.toml`, review profile
  at `$CODEX_HOME/warden-review.config.toml`, invoked as `codex exec` (not
  `codex exec review` — see the header comment in `scripts/review.sh` for why).

## What almost certainly trips it

The diff under review contains regression tests such as
`wrdf0105_root_execute_t22_transfer_checked_under_pda_permanent_delegate_rejected`,
which drives a **third-party token account from 9,000 to 0** through a real
Token-2022 CPI in LiteSVM to prove the vulnerability existed, then asserts the
patched program refuses it. The prompt also embeds
`docs/security/PRIOR-ART-FINDINGS.md` — a corpus of real exploit classes from other
wallets — because seeding it is what makes the review effective.

## What to try, in order

1. **Trusted Access for Cyber** — <https://chatgpt.com/cyber>. This is what the
   error itself points at and is the correct long-term fix: it exists precisely for
   authorized defensive security work like this. Worth applying with the context
   below.
2. **Check whether the block is account-, org-, or model-scoped.** If you have a
   second org/profile, try the same range there. `gpt-5.6-sol` at `max` is our
   pinned reviewer — please do **not** silently fall back to a weaker model to get
   past it; a shallower reviewer that passes is worse than no round.
3. **Wait it out.** The 2026-08-22 instance cleared in ~24 h with no changes.

### Useful framing if you need to explain the use case

> Defensive security review of my own open-source Solana wallet
> (github.com/Dr-Inker/warden-wallet). The model is asked to find defects in a
> commit range. The repository contains regression tests that reproduce
> vulnerabilities in a local simulator in order to prove the fixes work — standard
> practice for security-critical code. Nothing targets a third party; the code is
> pre-release and not deployed to mainnet.

## What NOT to do

**Do not weaken or delete the drain-proving tests to appease the classifier.**
They are the strongest evidence in this repo — the PermanentDelegate finding was
only *confirmed* because an inverted test showed the drain executing (9,000 → 0,
zero recorded outflow, no cap debited). Losing that to make a tool happy would
trade real assurance for a green light. If a range cannot be reviewed by Codex,
route it to the Grok lane and record the limitation, which is what has been done.

Also: do not hand-write findings or ledger rows from a blocked round. The wrapper
rolls back on failure, and `REVIEW-RUNS.jsonl` is honest at **101 rounds** — it has
never been inflated by the six aborted attempts.

## Once it clears — the exact owed round

```bash
cd /opt/warden
git status --short                 # must be clean; remove any .claude/worktrees first
git checkout phase1b && git pull
scripts/review.sh c5a4514ab5e36faa6b4450bad7103f3f1cb5a7ca $(git rev-parse HEAD) --kind task-diff
```

This is **owed** and is not discharged by round 101 (that one was `grok-4.3` and is
recorded with an explicit caveat that it was materially shallower and ruled
`WRD-EXEC-09` `not_applicable` when that range is exactly what changed it).

Expect the round to take 15–25 minutes. It records itself on success and rolls both
ledgers back on any failure. Verify with:

```bash
tail -1 docs/security/REVIEW-RUNS.jsonl | python3 -m json.tool
```

## The fallback that already exists

`scripts/review-grok.sh` makes xAI `grok-4.3` a **recorded** reviewer through the
identical machinery (wrapper-computed seeds, expectations file, independent
validator, atomic dual-ledger append with rollback). Use
`--max-chars 1000000` — the 600 K default elides whole-file context and Grok
correctly refuses to rule on an incomplete evidence base rather than bluffing.

It is a **fallback, not an equivalent reviewer**. Treat a zero-finding Grok round as
"nothing this reviewer could see", never as "this range is clean".
