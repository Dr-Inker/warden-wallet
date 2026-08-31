# Session release statement v1

This document defines the repository-owned client release record consumed by
`@warden/core/transaction/session-release`. The record uses the in-toto
Statement v1 envelope shape, but the committed JSON is currently **unsigned**.
Its trust anchor is git review. It is not a DSSE signature, a Sigstore bundle,
an audit result, or proof that the named builder was trustworthy.

No production statement is committed today. The runtime registry is empty and
the committed composition factory refuses before reading RPC, approval, or
keyring capabilities. Synthetic values must never be added to that registry.
Each future registry entry embeds both its exact statement and its canonical
`RELEASE-INTEGRITY.md` table row. Runtime callers select only the committed
release name; they cannot supply a replacement document. A separate drift
assertion lets release tooling compare the repository document with that
source-owned row without making caller text part of wallet composition.

## v1 schema

The parser accepts exactly this shape and rejects missing, extra, inherited,
unknown-version, noncanonical, or wrongly ordered subject data:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "target/deploy/warden.so",
      "digest": { "sha256": "<64 lowercase hex>" }
    },
    {
      "name": "solana:programdata:<canonical ProgramData PDA>",
      "digest": { "sha256": "<64 lowercase hex over every account byte>" }
    }
  ],
  "predicateType": "https://github.com/Dr-Inker/warden-wallet/blob/main/docs/security/SESSION-RELEASE-STATEMENT.md#v1",
  "predicate": {
    "schemaVersion": 1,
    "releaseSha": "<full lowercase 40-hex git commit>",
    "deployManifest": {
      "name": "<committed manifest name>",
      "digest": "<canonical deploy-manifest sha256>"
    },
    "chain": "solana:mainnet",
    "genesisHash": "<canonical base58 genesis hash>",
    "wardenProgram": "<literal client Warden program id>",
    "wardenProgramData": {
      "address": "<canonical loader-v3 ProgramData PDA>",
      "slot": "<canonical decimal u64>",
      "upgradeAuthority": "<canonical nonzero base58 pubkey>",
      "allocationBytes": 96
    }
  }
}
```

`allocationBytes` must be greater than the 45-byte loader-v3 metadata prefix and
at most 10 MiB. Public chains require the client-pinned canonical genesis. The
localnet label may not alias any pinned public-cluster genesis. The
program id must equal the literal shipped by this client, and the ProgramData
address must be its canonical loader-v3 PDA.

The statement digest is SHA-256 over UTF-8 JSON reconstructed in the exact key
and subject order shown above, with validated canonical primitive values. Input
object insertion order therefore does not affect the digest. A release row must
carry that digest as the leading value in its dedicated column:
`session-release:<name>@<64-hex digest>`.

Binding additionally requires exact equality among the statement, the unique
`RELEASE-INTEGRITY.md` row, and the source-committed deploy manifest: release
SHA, artifact/code hash, manifest name and digest, genesis, program id, and the
Squads vault PDA derived as upgrade authority. No `reviewed: true` or status
string is accepted by the schema.

## Provenance limit

The format follows [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
and its immutable digest subjects. It does not implement the
[in-toto envelope](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md),
[SLSA provenance](https://slsa.dev/spec/v1.2/provenance), or
[Sigstore identity/bundle verification](https://docs.sigstore.dev/cosign/verifying/verify/).
Those remain separate release gates. Even a correctly authenticated provenance
statement would establish who produced which bytes—not that those bytes are
safe, audited, or appropriate to deploy.
