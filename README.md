# Open Receipt Specification (ORS)

A portable format for cryptographic agent policy acknowledgement receipts. A receipt is a signed record proving an AI agent acknowledged a specific policy before taking an action.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Specification

**[ORS-v0.3.md](ORS-v0.3.md)** — Current version (May 2026).

**[ORS-v0.2.md](ORS-v0.2.md)** — April 2026.

**[ORS-v0.1.md](ORS-v0.1.md)** — Initial release (February 2026).

v0.3 is fully backward compatible with v0.2 and v0.1. The core receipt format — required fields, canonicalization, hashing, and signing — is unchanged. Existing receipts and verification tooling continue to work without modification.

## What v0.3 adds

### Normative `ors.mandate` extension namespace

v0.3 documents the `ors.mandate` receipt-binding extension as a normative, optional extension under Section 11.1. The extension lives at `action_context.ors.mandate` and binds a recorded action to an OpenTerms Mandate commitment — a signed grant of authority from a principal to an agent — via four fixed members: `mandate_id`, `mandate_hash` (the lowercase hex SHA-256 of the canonical commitment), `scope_snapshot` (the scope axes the action actually consumed), and `chain_depth` (always `0` in v1). The four-member shape, types, and meaning are fixed by the OpenTerms Mandate Workstream 1 commitment specification, Section 6.1. `chain_material` and `utilization_ref` are not v1 members.

The extension is purely additive. A receipt with no `action_context.ors.mandate` member is a valid v0.3 receipt and is unaffected; existing v0.1 and v0.2 receipts remain valid v0.3 receipts. v0.3 does not change the core receipt format, the canonicalization, or the signing.

**Signing boundary.** The mandate commitment carries its own Ed25519 signature under a distinct domain-separation prefix (`OTMANDATE-v0.1\x00`), separate from the ORS receipt signing prefix (`ORSv0.1\x00`). The ORS receipt signature does not sign or vouch for the mandate; it commits only to the binding values `mandate_id` and `mandate_hash` (which are inside `action_context` and therefore in the canonicalized signed payload). A verifier that wishes to confirm the mandate binding follows the procedure in the W1 commitment specification, Section 7 — referenced from ORS-v0.3.md §11.1 rather than restated there.

A worked vector is included as [`examples/mandate_bound_receipt.illustrative.json`](examples/mandate_bound_receipt.illustrative.json), carrying the W1 §6.2 values verbatim. The `.illustrative` suffix marks the file as carrying a placeholder signature; real cryptographic conformance vectors live in the OpenTerms Mandate SDK conformance suite.

### Migration guide (Appendix D)

Concrete instructions for issuers, verifiers, and existing `ors.mandate` users upgrading from v0.2 to v0.3. No change is required of existing receipts or verifiers.

## What v0.2 adds

### Policy classification fields: `terms_type`, `terms_service`, `terms_version`

v0.1 receipts record that an agent acknowledged a policy at a specific URL. That proves the acknowledgment happened, but tells you nothing about what kind of policy it was or which service issued it. If you want to answer "did every model training run produce a Data Processing Agreement receipt?" or "how many API calls acknowledged an OpenAI privacy policy this month?", you previously had no structured way to query that across a receipt ledger.

v0.2 adds three optional signed fields to the payload:

- `terms_type` — the kind of policy acknowledged (e.g. `"Privacy Policy"`, `"Data Processing Agreement"`, `"Terms of Service"`). Recommended values follow [Open Terms Archive](https://opentermsarchive.org/) vocabulary so receipts from different issuers can be compared using the same taxonomy.
- `terms_service` — a slug identifying the service whose policy was acknowledged (e.g. `"openai"`, `"aws"`, `"github"`). Enables filtering all receipts for a given provider without parsing URLs.
- `terms_version` — the version of the policy document at acknowledgment time, typically a date string (e.g. `"2024-01-15"`). Answers "was the agent running on the current version of this policy, or a stale one?".

All three are optional and included in the signed canonical payload when present, so they are tamper-evident. They are self-asserted by the issuer; the spec deliberately does not require a registry lookup on issuance. An implementation can validate against a known taxonomy out of band if stricter governance is needed.

### `model_training` action type

v0.1's `action_type` enum covered `api_call`, `data_access`, `purchase`, and `custom`. AI training runs are a materially distinct class of action: they consume datasets at scale, trigger data licensing obligations, and are increasingly subject to regulatory disclosure requirements (EU AI Act, copyright litigation context). Folding them into `data_access` or `custom` meant losing structured signal. `model_training` is now a first-class action type, enabling receipt infrastructure to separately track and audit training-time policy acknowledgments from inference-time ones.

### Normative Merkle anchor specification (`ors.anchor`)

v0.1 defined `ors.anchor` as a placeholder — it listed some field names but gave no verification procedure. An implementor couldn't build a conformant Merkle inclusion verifier from the spec alone.

v0.2 promotes it to normative: required fields are defined (`type`, `root_hash`, `tree_size`), the leaf construction rule is specified (`SHA256("ORS_LEAF_V1" || canonical_hash_bytes)`), and the full inclusion proof verification procedure is written out step by step including the left-right sibling ordering rule derived from `leaf_index`. This is the primitive needed to anchor receipt batches to a transparency log or similar service and produce independently verifiable proof that a receipt existed at a given point in time, without requiring the verifier to trust the issuer's database.

### Normative zero-knowledge proof reference (`ors.zk_proof`)

Similarly, v0.1 sketched `ors.zk_proof` with four field names and no semantics. v0.2 specifies the required fields (`system`, `statement_hash`, `proof_hash`), the verification procedure (fetch proof artifact, verify hash integrity, verify against public inputs), and the critical binding rule: the receipt's `canonical_hash` MUST be a public input to the proof circuit so the proof cannot be detached and replayed against a different receipt. This makes `ors.zk_proof` usable for governance scenarios where an issuer needs to prove a receipt satisfied a constraint (e.g. budget under threshold, role membership satisfied) without revealing the underlying private inputs to an external auditor.

### JSON-LD compatibility note

Clarifies that `@context` must NOT be included in the canonicalized payload. Implementations that need semantic web tooling can add `@context` to the envelope after signing without affecting verification. This removes an ambiguity that would otherwise cause interoperability issues between implementations that add `@context` and those that don't.

### Migration guide (Appendix C)

Concrete instructions for issuers, verifiers, and `ors.anchor`/`ors.zk_proof` users upgrading from v0.1 to v0.2.

## Verify a receipt

```bash
# Against a live issuer
python verify.py examples/basic_api_call.json --jwks https://openterms.com/.well-known/jwks.json

# Against a local JWKS file
python verify.py receipt.json --jwks-file jwks.json

# Using issuer discovery (if the receipt includes an issuer field)
python verify.py receipt.json
```

Requires Python 3.10+ and the `cryptography` library (`pip install cryptography`).

## Examples

The `examples/` directory contains annotated receipt files demonstrating different features:

| File | Demonstrates |
|------|-------------|
| `basic_api_call.json` | Minimal receipt, required fields only |
| `data_access_with_context.json` | action_context, provider binding, ors.commitments |
| `purchase.json` | Purchase action type |
| `custom_action.json` | Custom action, issuer field, ors_version, pre/post state hashes |
| `chained_receipt.json` | Multi agent chain via ors.chain |
| `minimal_fields.json` | Absolute minimum, no optional fields |
| `large_context.json` | 40 key action_context, near size limits |
| `request_bound_api_call.json` | Anti replay with provider nonce and request hash |
| `refusal.json` | Declined decision, negative evidence for compliance |
| `policy_classification.json` | v0.2 policy classification fields: terms_type, terms_service, terms_version |
| `mandate_bound_receipt.illustrative.json` | v0.3 ors.mandate extension binding a receipt to an OpenTerms Mandate commitment (illustrative signature; real conformance vectors live in the SDK) |

Example canonical hashes are computed from the actual payload fields. Signatures are illustrative since no private key is distributed.

## Reference Implementation

[Openterms MCP server](https://github.com/jstibal/openterms-mcp) — open source (Apache 2.0), implements ORS receipt issuance and verification.

## Feedback

Please use [GitHub Issues](https://github.com/jstibal/ors-spec/issues) for questions, suggestions, and spec feedback.

## License

Apache 2.0. See [LICENSE](LICENSE).

Copyright 2026 Staticlabs Inc.
