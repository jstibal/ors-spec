# Open Receipt Specification (ORS) v0.3

## 1. Introduction

An ORS receipt is a cryptographically signed record proving an AI agent acknowledged a specific policy before taking an action. In v0.1, the standardized policy type is a terms document referenced by URL and content hash. v0.2 extended this with optional policy classification fields (`terms_type`, `terms_service`, `terms_version`) that allow receipts to identify what kind of policy was acknowledged and from which service, without changing the core cryptographic format. v0.3 adds one thing: it documents the `ors.mandate` extension namespace as a normative, optional extension. The extension is purely additive — a receipt with no `action_context.ors.mandate` member is unaffected — and the core receipt format (required fields, canonicalization, hashing, and signing) is unchanged. Existing v0.1 and v0.2 receipts remain valid v0.3 receipts.

ORS is a portable data format and a verification algorithm. It is not a network protocol, not a policy engine, and not a billing system. Implementations may add policy evaluation, payment settlement, and provider verification flows, but those are outside the core format.

Design goals:

* Portable across vendors and deployments.
* Verifiable by any third party using public keys.
* Tamper evident through canonicalization, hashing, and signing.
* Small enough to implement in one afternoon, with clear extension seams for richer provenance.

**Changes in v0.3:**

* Promoted the `ors.mandate` extension namespace from an unlisted external extension to a normative, optional extension namespace, with the four-member shape and meaning defined in OpenTerms Mandate Workstream 1, Section 6. The receipt's core cryptographic format is unchanged; the extension is purely additive. Added Appendix D: Migration guide from v0.2 to v0.3.

Relationship to Openterms:

Openterms (https://github.com/jstibal/openterms-mcp) is a reference implementation that issues and verifies receipts. ORS is written as a standalone standard. Conforming implementations can interoperate without reading any Openterms code.

### 1.1 Conformance language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as described in RFC 2119.

## 2. Terminology

**Receipt:** The signed data object described by this specification.

**Payload:** The subset of receipt fields that are canonicalized, hashed, and signed.

**Envelope:** The full receipt object, including the payload plus signature metadata and other issuance metadata.

**Issuer:** The system that creates and signs receipts.

**Agent:** The AI system requesting a receipt before acting.

**Provider:** The API provider or service whose policy is being acknowledged.

**Verifier:** Any party checking a receipt's validity.

**Policy type:** A human-readable classification of the kind of policy document being acknowledged (e.g., "Privacy Policy", "Terms of Service"). See Section 3a for guidance on values.

## 3. Receipt Schema

The receipt has two parts: the payload and the envelope.

### 3a. Payload fields (canonicalized and signed)

#### Required fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `workspace_id` | string (UUID v4) | Yes | Identifier for the workspace or organization issuing the receipt. |
| `agent_id` | string | Yes | Identifier for the AI agent taking the action. |
| `action_type` | string (enum) | Yes | One of: `api_call`, `data_access`, `purchase`, `model_training`, `custom`. |
| `terms_url` | string (URL) | Yes | URL of the terms document being acknowledged. MUST be HTTP or HTTPS. |
| `terms_hash` | string (hex) | Yes | SHA 256 hash of the terms document content. Lowercase hex, exactly 64 characters. |
| `timestamp` | string (ISO 8601) | Yes | When the agent requested the receipt. MUST be UTC, MUST end with `Z`. Format: `YYYY-MM-DDTHH:MM:SS.sssZ`. |
| `pricing_version` | string | Yes | Version identifier for the pricing schedule. Example: `2025-01`. |

#### Optional fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `terms_type` | string | No | Classification of the policy document type. See Section 3a.1. If present, it is signed. |
| `terms_service` | string | No | Identifier for the service whose policy is being acknowledged (e.g., `openai`, `aws`). If present, it is signed. |
| `terms_version` | string | No | Version of the policy document, typically a date string (e.g., `2024-01-15`) or a service-defined version identifier. If present, it is signed. |
| `action_context` | object | No | Freeform metadata about the action. Max 50 keys, max 4 KB serialized. MUST NOT contain PII. |
| `ors_version` | string | No | ORS format version identifier. If present, value SHOULD be `0.3`. |
| `issuer` | string (HTTPS origin) | No | Issuer identifier for JWKS discovery. Example: `https://issuer.example`. MUST be HTTPS. If present, it is signed. |
| `provider` | object | No | Optional provider identity binding. If present, it is signed. See Section 3a.2. |
| `decision` | string (enum) | No | `acknowledged` or `declined`. If omitted, default is `acknowledged`. |
| `request_binding` | object | No | Optional binding to a specific provider challenge or request commitment. If present, it is signed. See Section 3a.3. |

#### 3a.1 Policy classification fields

`terms_type`, `terms_service`, and `terms_version` are optional signed fields that allow a receipt to identify the policy being acknowledged in a structured way, independent of the URL.

**`terms_type`** SHOULD use a value from the following list where applicable. Implementations MUST NOT reject receipts whose `terms_type` does not appear on this list; the list is advisory, not exhaustive.

Recommended values (drawn from Open Terms Archive vocabulary):

* `Privacy Policy`
* `Terms of Service`
* `Terms of Use`
* `Community Guidelines`
* `Cookie Policy`
* `Data Processing Agreement`
* `Developer Agreement`
* `Acceptable Use Policy`
* `Service Level Agreement`
* `Whistleblower Policy`

When the policy type does not match any of the above, implementations MAY use a custom string. Custom values SHOULD be descriptive and consistent within a deployment.

**`terms_service`** is a short identifier for the service providing the policy. It SHOULD be a lowercase ASCII slug without spaces (e.g., `openai`, `aws`, `github`). It is not validated against a registry; its purpose is to enable receipt filtering and analytics.

**`terms_version`** identifies the version of the policy document at the time of acknowledgment. It SHOULD be a date string in `YYYY-MM-DD` format if a service-defined version is not available. It is distinct from `pricing_version`, which refers to the receipt issuer's pricing schedule, not the policy document version.

#### 3a.2 Provider object

If `provider` is present in the payload:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `origin` | string (HTTPS origin) | Yes | Provider HTTPS origin. Format: `https://{host}` or `https://{host}:{port}`. See normalization rules below. |
| `provider_id` | string | No | Provider identifier used by the issuer or provider. |

Security note: If `provider` is not included in the signed payload, a receipt can be context shifted, meaning it can be presented to a different provider than the one it was intended for. Self describing receipts (those with `provider` in the signed payload) offer stronger provenance. Verifiers SHOULD prefer them when available.

Provider origin normalization: To prevent canonicalization mismatches, `provider.origin` MUST be an HTTPS origin in the format `https://{host}` or `https://{host}:{port}`. Host MUST be lowercase. Default port (443) MUST be omitted. No trailing slash. No path. Examples: `https://api.example.com` (correct), `https://API.EXAMPLE.COM` (incorrect, not lowercase), `https://api.example.com/` (incorrect, trailing slash), `api.example.com` (incorrect, no scheme).

#### 3a.3 Request binding object

If `request_binding` is present in the payload:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `provider_nonce` | string | No | Provider supplied challenge nonce. |
| `request_hash` | string (hex) | No | SHA 256 hash commitment to a request representation. Lowercase hex, 64 characters. |
| `expires_at` | string (ISO 8601) | No | Optional expiry time for replay control. UTC, ends with `Z`. |
| `binding_method` | string (enum) | No | One of: `provider_nonce`, `request_hash`, `both`. |

Rules:

* If `binding_method` is `provider_nonce`, then `provider_nonce` MUST be present.
* If `binding_method` is `request_hash`, then `request_hash` MUST be present.
* If `binding_method` is `both`, then both MUST be present.
* If `binding_method` is omitted, verifiers MAY infer it from which fields are present.

Tradeoff note: Request binding is optional in v0.2, but SHOULD be used for any action where replay creates material risk. Without request binding, receipts can be cached and reused, which simplifies integration but does not guarantee replay resistance. With request binding, the provider must supply a challenge nonce or the agent must commit to a request hash, which adds coupling but provides stronger proof that a receipt was minted for a specific request.

### 3b. Envelope fields (also signed)

The following fields are generated by the issuer and included in the signed payload. They appear in the envelope but are canonicalized and signed alongside the fields in Section 3a.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `receipt_id` | string (UUID v4) | Yes | Unique identifier for this receipt. Generated by the issuer before signing. |
| `amount_charged` | integer | Yes | Cost of this receipt in minor currency units. Signed to prevent economic tampering. |
| `created_at` | string (ISO 8601) | Yes | Issuer timestamp when the receipt was created. UTC, ends with `Z`. |

These fields are included in canonicalization (Section 4) and covered by the signature. This prevents a class of attacks where a relay or middleware modifies the receipt identity or economic data while the signature remains valid.

### 3c. Signature metadata (not signed)

The following fields are part of the envelope but are NOT included in canonicalization, because they are outputs of the signing process itself:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `canonical_hash` | string (hex) | Yes | SHA 256 hash of the canonical JSON payload. Lowercase hex, 64 characters. |
| `signature` | string (base64url) | Yes | Ed25519 signature over the domain separated hash. Base64url encoded without padding (RFC 4648 Section 5). |
| `key_id` | string | Yes | Identifier of the signing key used. Used to look up the public key for verification. |

### 3d. Chain fields

Chain fields support multi-agent workflow provenance. In v0.2 they SHOULD be placed inside `action_context` under the reserved `ors.chain` namespace.

Recommended structure:

```json
{
  "action_context": {
    "ors": {
      "chain": {
        "parent_receipt_id": "550e8400-e29b-41d4-a716-446655440001",
        "chain_id": "chain_01HZYX",
        "chain_depth": 2,
        "originating_agent": "orchestrator-v1"
      }
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `parent_receipt_id` | string (UUID v4) | Receipt ID of the parent action in a multi agent chain. |
| `chain_id` | string | Identifier grouping all receipts in a single workflow. |
| `chain_depth` | integer | Depth in the chain. 0 is root, 1 is first child, etc. |
| `originating_agent` | string | Agent ID that initiated the chain. |

## 4. Canonicalization

Canonicalization produces identical bytes for semantically identical payloads. ORS canonicalization is based on RFC 8785 JSON Canonicalization Scheme, with one additional ORS rule: null values are removed before serialization.

Canonicalization applies to all signed fields: the payload fields from Section 3a (including `terms_type`, `terms_service`, and `terms_version` when present) and the signed envelope fields from Section 3b (`receipt_id`, `amount_charged`, `created_at`). Signature metadata fields from Section 3c (`canonical_hash`, `signature`, `key_id`) MUST NOT be included, because they are outputs of the signing process itself.

Algorithm:

1. Construct a payload object containing exactly the payload fields defined in Section 3a, plus the signed envelope fields defined in Section 3b (`receipt_id`, `amount_charged`, `created_at`). Do NOT include signature metadata fields from Section 3c (`canonical_hash`, `signature`, `key_id`). Include optional fields only if they are present in the receipt and their value is not null.
2. Strip null values recursively. Remove any key whose value is null at any nesting level.
3. Sort keys lexicographically at every object nesting level by Unicode code point order. This is recursive.
4. Serialize as compact JSON. No whitespace between tokens. Use separators `,` and `:` with no spaces.
5. Unicode handling: do not escape non ASCII Unicode characters unnecessarily. Only escape characters required by RFC 8259 (control characters U+0000 through U+001F). Use `ensure_ascii=False` in Python implementations.
6. Number representation: integers MUST remain as integers (no `.0` suffix). Floating point numbers SHOULD NOT appear in the payload. If they do, they MUST be finite and MUST NOT be NaN or Infinity.
7. Array order MUST be preserved exactly as provided. Arrays are NOT sorted.
8. Encode as UTF 8 bytes with no BOM.

### Canonicalization example

Input with policy classification fields:

```json
{
  "terms_url": "https://openai.com/policies/privacy-policy",
  "agent_id": "my-agent",
  "action_type": "api_call",
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "terms_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "timestamp": "2026-04-01T12:00:00.000Z",
  "pricing_version": "2025-01",
  "terms_type": "Privacy Policy",
  "terms_service": "openai",
  "terms_version": "2024-01-15",
  "action_context": null
}
```

Canonical output (action_context stripped because null, keys sorted):

```
{"action_type":"api_call","agent_id":"my-agent","pricing_version":"2025-01","terms_hash":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","terms_service":"openai","terms_type":"Privacy Policy","terms_url":"https://openai.com/policies/privacy-policy","terms_version":"2024-01-15","timestamp":"2026-04-01T12:00:00.000Z","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}
```

Note: `terms_service`, `terms_type`, and `terms_version` sort lexicographically into the payload alongside the other fields. They are covered by the signature exactly like any other optional signed field.

## 5. Hashing

* Hash algorithm: SHA 256
* Input: canonical JSON bytes from Section 4
* Output: 32 raw bytes
* `canonical_hash` is the lowercase hex encoding of these 32 bytes (64 hex characters)

## 6. Signing

* Algorithm: Ed25519 (RFC 8032)
* Domain separation: before signing, prepend the 8 byte prefix `ORSv0.1\x00` (the ASCII bytes `O`, `R`, `S`, `v`, `0`, `.`, `1`, followed by a null byte) to the raw 32 byte hash
* Input to sign: `ORSv0.1\x00` + raw 32 byte SHA 256 hash (40 bytes total)
* Output: 64 byte Ed25519 signature
* `signature` is the base64url encoding of these 64 bytes, without padding (RFC 4648 Section 5)
* `key_id` identifies which signing key was used, for public key lookup

Note: The domain separation prefix remains `ORSv0.1\x00` in v0.2. This preserves signature compatibility with v0.1 verification tooling. A v0.1 verifier can verify a v0.2 receipt that adds only the new optional fields, because the canonicalization and signing algorithm is unchanged.

**Critical implementation note:** The signature is over `ORSv0.1\x00` concatenated with the raw hash bytes, not the hex encoded string. Implementations that omit the domain prefix or sign the hex string will produce signatures that cannot be verified.

## 7. Public key distribution

Issuers MUST publish public signing keys so any verifier can validate receipts.

### 7.1 JWKS endpoint

* Path: `/.well-known/jwks.json`
* Format: JSON Web Key Set (RFC 7517)
* Each key MUST be an OKP (Octet Key Pair) with curve Ed25519
* Issuers SHOULD set Cache Control. Recommended: `public, max-age=86400`

Example:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-encoded-32-byte-public-key>",
      "kid": "key_abc123def456",
      "use": "sig"
    }
  ]
}
```

### 7.2 Key rotation

* Old keys MUST remain in the JWKS endpoint for as long as receipts signed by them need to be verifiable. Issuers SHOULD NOT remove old keys.
* `key_id` in the receipt maps to `kid` in the JWKS.

### 7.3 Issuer discovery

Verification can be performed with an out of band JWKS URL input.

If the signed payload includes `issuer`, verifiers MAY derive the JWKS URL as `{issuer}/.well-known/jwks.json`. If both an explicit JWKS URL input and `issuer` are available, verifiers SHOULD use the explicit JWKS URL input.

## 8. Verification algorithm

A verifier validates a receipt by recomputing the payload hash and verifying the signature with the issuer's public key.

```
VERIFY(receipt, jwks_source):

  1. Extract signed fields from the receipt:
     From Section 3a (required): workspace_id, agent_id, action_type,
               terms_url, terms_hash, timestamp, pricing_version
     From Section 3a (optional, include if present):
               terms_type, terms_service, terms_version,
               action_context, ors_version, issuer, provider,
               decision, request_binding
     From Section 3b (signed envelope): receipt_id, amount_charged,
               created_at

  2. Canonicalize the signed fields per Section 4.

  3. Hash:
     hash_bytes = SHA-256(canonical_bytes)
     hash_hex = lowercase_hex(hash_bytes)

  4. Compare:
     IF hash_hex != receipt.canonical_hash:
       RETURN {valid: false, error: "HASH_MISMATCH"}

  5. Load JWKS:
     IF jwks_source is a URL: GET jwks_source
     ELSE IF jwks_source is a file: read file
     Find key where kid == receipt.key_id
     IF not found:
       RETURN {valid: false, error: "KEY_NOT_FOUND"}

  6. Verify signature with domain separation:
     sig_bytes = base64url_decode(receipt.signature)
     pub_bytes = base64url_decode(jwk.x)
     message = "ORSv0.1\x00" + hash_bytes    (40 bytes total)
     IF length(pub_bytes) != 32: RETURN {valid: false, error: "INVALID_KEY_LENGTH"}
     IF length(sig_bytes) != 64: RETURN {valid: false, error: "INVALID_SIGNATURE_LENGTH"}
     IF Ed25519_verify(pub_bytes, message, sig_bytes) fails:
       RETURN {valid: false, error: "INVALID_SIGNATURE"}

  7. RETURN {valid: true}
```

### Verification postures

The Section 8 VERIFY algorithm establishes that a receipt is a cryptographically valid ORS receipt. It does not, on its own, establish that the action the receipt records was authorized by a mandate. A relying party that requires delegated authority — for example, an API route, a registry entry, or any policy whose enforcement depends on a mandate — needs a stricter check than "the receipt verifies." v0.3 names the two verification outcomes a relying party can demand. Implementations MUST distinguish them.

**Receipt-valid.** The receipt verifies under the Section 8 VERIFY algorithm. An absent `action_context.ors.mandate` extension is NOT a failure under this posture; an unbound receipt is a valid ORS receipt. If the receipt does carry the extension, the binding has not necessarily been verified under this posture — `mandate_id` and `mandate_hash` are committed to by the receipt signature, but the mandate commitment itself has not been retrieved, hashed, or signature-checked. This is the backward-compatible posture and matches the semantics of an ORS v0.1 or v0.2 verifier.

**Mandate-bound-and-verified.** The receipt verifies under the Section 8 VERIFY algorithm AND carries an `action_context.ors.mandate` extension whose binding has been verified — the mandate commitment has been retrieved, its canonical SHA-256 confirmed equal to `mandate_hash`, its own Ed25519 signature verified under its `OTMANDATE-v0.1\x00` domain prefix, and its validity window, agent join, and scope containment checked against the receipt. The authoritative procedure is the OpenTerms Mandate Workstream 1 commitment specification, Section 7; v0.3 references it rather than restating it.

**Mandate-required relying parties.** When a policy, a registry entry, an API route, or any relying party requires a mandate — for example, a registry whose `mandate_policy.required` is true — a receipt with no `action_context.ors.mandate` extension MUST be treated as a verification failure even if the receipt is otherwise a valid ORS receipt. It is not sufficient that the Section 8 VERIFY algorithm returned `{valid: true}`; the relying party MUST require the mandate-bound-and-verified posture and MUST NOT substitute a receipt-valid result for it. Likewise, a receipt that carries the extension but whose binding has not been verified per the mandate specification's Section 7 procedure MUST NOT be accepted under the mandate-required posture.

These postures describe relying-party outcomes; they do not change the Section 8 VERIFY algorithm itself, the canonicalization, or the signing.

### Decision semantics

A receipt can be cryptographically valid regardless of `decision`. Providers SHOULD treat `decision == "declined"` as proof of refusal, not as permission to serve the action. Refusal receipts exist so that auditors can prove a disallowed action was declined under a specific policy, providing negative evidence for compliance purposes.

## 9. HTTP header conventions

When an agent presents a receipt to a provider, it SHOULD use these HTTP headers:

| Header | Value | Description |
|--------|-------|-------------|
| `ORS-Receipt` | `{canonical_hash}` | The canonical hash of the receipt. Provider uses this to look up and verify the receipt. |
| `ORS-Verify` | `/v1/receipts/verify/{canonical_hash}` | URL path where the provider can verify this receipt. |

For compatibility with the Openterms reference implementation, the following headers are recognized as interoperable aliases:

| Alias Header | Maps to |
|-------------|---------|
| `X-Openterms-Receipt` | `ORS-Receipt` |
| `X-Openterms-Verify` | `ORS-Verify` |

Providers SHOULD accept both the standard headers and the Openterms aliases. Agents SHOULD send the standard headers. Agents MAY send both for maximum compatibility during the transition period.

Provider verification flow:

1. Agent includes `ORS-Receipt: {hash}` in its API request.
2. Provider extracts the hash.
3. Provider calls `GET {issuer_url}/v1/receipts/verify/{hash}`.
4. If the response indicates `valid: true`, serve the request.
5. If invalid or missing, reject with 403.

## 10. Validation rules

Implementations SHOULD enforce:

* `action_type` MUST be one of: `api_call`, `data_access`, `model_training`, `purchase`, `custom`.
* `workspace_id` MUST be a valid UUID v4.
* `terms_url` MUST begin with `http://` or `https://`.
* `terms_hash` MUST be exactly 64 lowercase hex characters (valid SHA 256).
* `timestamp` MUST be valid ISO 8601 UTC and end with `Z`.
* `created_at` if present MUST be valid ISO 8601 UTC and end with `Z`.
* `action_context` if present MUST be an object (not array, string, etc.).
* `action_context` MUST have at most 50 top level keys.
* `action_context` serialized size MUST NOT exceed 4096 bytes.
* Total payload serialized size SHOULD NOT exceed 8192 bytes.
* `action_context` SHOULD NOT contain PII. Implementations SHOULD scan for common PII patterns (email addresses, government ID numbers).
* Payload SHOULD NOT contain floating point numbers.
* `decision` if present MUST be `acknowledged` or `declined`.
* `issuer` if present MUST be an HTTPS origin (MUST begin with `https://`).
* `terms_type` if present MUST be a non-empty string. Implementations MUST NOT reject receipts whose `terms_type` value is not in the recommended list in Section 3a.1.
* `terms_service` if present MUST be a non-empty string.
* `terms_version` if present MUST be a non-empty string.

## 11. Extensibility

`action_context` is the primary extension point.

To avoid ecosystem fragmentation, this specification reserves the `ors` key inside `action_context`. If present, `action_context.ors` MUST be an object. Keys under `action_context.ors` are intended for interoperable extensions defined by this specification or future versions.

### 11.1 Reserved extension namespaces

**`ors.chain`** — Multi-agent workflow chaining. See Section 3d.

**`ors.commitments`** — Hash commitments for governance-grade provenance. If present, it is an object with the following fields:

```json
{
  "ors": {
    "commitments": {
      "tool_id": "provider.api.call",
      "args_hash": "<64 hex sha256>",
      "pre_state_hash": "<64 hex sha256>",
      "post_state_hash": "<64 hex sha256>",
      "policy_hash": "<64 hex sha256>"
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tool_id` | string | Identifier of the tool or operation being invoked. |
| `args_hash` | string (hex) | SHA 256 hash of the canonical representation of the tool arguments. |
| `pre_state_hash` | string (hex) | SHA 256 hash of a canonical representation of relevant system state before the action. |
| `post_state_hash` | string (hex) | SHA 256 hash of a canonical representation of relevant system state after the action. Used for post-hoc verification. |
| `policy_hash` | string (hex) | SHA 256 hash of the full policy document in effect, allowing verifiers to confirm policy content without fetching `terms_url`. |

Verifiers using `ors.commitments` SHOULD verify each hash independently using the same canonicalization and hashing conventions applied to the receipt payload (SHA 256, lowercase hex). The commitment fields are informational within the receipt; enforcement is an application-layer responsibility.

**`ors.anchor`** — Reference to an append-only transparency or Merkle anchoring record. If present, it is an object with the following fields:

```json
{
  "ors": {
    "anchor": {
      "type": "merkle",
      "root_hash": "<64 hex sha256>",
      "tree_size": 12345,
      "leaf_index": 42,
      "inclusion_proof": ["<base64url>", "<base64url>"],
      "anchor_uri": "https://transparency.example/log/",
      "anchored_at": "2026-04-01T12:05:00.000Z"
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Anchoring mechanism type. `merkle` indicates a binary Merkle tree inclusion proof. |
| `root_hash` | string (hex) | Yes | SHA 256 root hash of the Merkle tree at the time of anchoring. Lowercase hex, 64 characters. |
| `tree_size` | integer | Yes | Number of leaves in the tree at the time of anchoring. |
| `leaf_index` | integer | No | Zero-based index of this receipt's leaf in the tree. |
| `inclusion_proof` | array of base64url strings | No | Ordered sibling hashes forming the Merkle inclusion proof path from leaf to root. Each element is base64url-encoded without padding. |
| `anchor_uri` | string (HTTPS URL) | No | URL where the anchor record or transparency log entry can be independently verified. |
| `anchored_at` | string (ISO 8601) | No | UTC timestamp when the receipt was included in the anchoring batch. Ends with `Z`. |

**Verification procedure for `ors.anchor`:** A verifier wishing to confirm Merkle inclusion SHOULD:

1. Compute the leaf value as `SHA256("ORS_LEAF_V1" || canonical_hash_bytes)`, where `canonical_hash_bytes` is the raw 32-byte SHA 256 hash corresponding to the receipt's `canonical_hash` field, and `||` denotes concatenation.
2. Iteratively compute parent nodes by applying the proof path: for each sibling hash in `inclusion_proof`, concatenate `(left, right)` according to the positional ordering implied by `leaf_index` and the proof depth, then hash the concatenation.
3. Confirm the recomputed root matches `root_hash`.
4. Optionally fetch `anchor_uri` to verify that `root_hash` is published at the transparency log or anchoring service.

The `leaf_index` is used to determine left-right sibling ordering at each proof step. Specifically, if `leaf_index >> depth` is even, the sibling is on the right; if odd, the sibling is on the left.

**`ors.zk_proof`** — Reference to a zero-knowledge proof artifact attesting that this receipt or its associated authorization satisfies defined governance constraints. If present, it is an object with the following fields:

```json
{
  "ors": {
    "zk_proof": {
      "system": "groth16",
      "circuit_id": "ors-budget-compliance-v1",
      "statement_hash": "<64 hex sha256>",
      "proof_hash": "<64 hex sha256>",
      "public_inputs_hash": "<64 hex sha256>",
      "proof_uri": "https://proofs.example/receipts/550e8400",
      "verified_at": "2026-04-01T12:05:00.000Z"
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `system` | string | Yes | Proof system used. Recommended values: `groth16`, `plonk`, `stark`. |
| `circuit_id` | string | No | Identifier of the circuit or constraint system used to generate the proof. Allows verifiers to locate the correct verifying key. |
| `statement_hash` | string (hex) | Yes | SHA 256 hash of the canonical proof statement (the predicate being proved). Lowercase hex, 64 characters. |
| `proof_hash` | string (hex) | Yes | SHA 256 hash of the proof artifact bytes. Allows verifiers to confirm integrity of the fetched proof. Lowercase hex, 64 characters. |
| `public_inputs_hash` | string (hex) | No | SHA 256 hash of the serialized public inputs to the proof circuit. Lowercase hex, 64 characters. |
| `proof_uri` | string (HTTPS URL) | No | URL where the proof artifact can be fetched for verification. |
| `verified_at` | string (ISO 8601) | No | UTC timestamp when the proof was last verified by the issuer. Ends with `Z`. |

**Verification procedure for `ors.zk_proof`:** A verifier wishing to confirm the zero-knowledge proof SHOULD:

1. Fetch the proof artifact from `proof_uri`.
2. Confirm `SHA256(proof_bytes) == proof_hash` to verify proof integrity.
3. Locate the verifying key for the circuit identified by `circuit_id` and `system`.
4. Verify the proof against the public inputs. The public inputs MUST include at minimum the receipt's `canonical_hash` as a public input, so that the proof is bound to this specific receipt and cannot be replayed against a different one.
5. Optionally confirm `SHA256(canonical_public_inputs) == public_inputs_hash`.

Implementations that include `ors.zk_proof` SHOULD ensure the proof's public inputs include `canonical_hash` so that the proof cannot be detached from the receipt and presented as proof of compliance for a different action.

**`ors.mandate`** — Hash-anchored reference to a separately-signed OpenTerms Mandate commitment that authorized this action. The four-member shape and meaning are fixed by the OpenTerms Mandate Workstream 1 commitment specification, Section 6.1. The extension is optional and additive: a receipt with no `action_context.ors.mandate` member is a valid receipt and is unaffected. If present, it sits alongside the other reserved namespaces (`ors.chain`, `ors.commitments`, `ors.anchor`, `ors.zk_proof`) and is an object with the following fields:

```json
{
  "ors": {
    "mandate": {
      "mandate_id": "0190f8a0-1c2d-7e3f-8a4b-5c6d7e8f9a0b",
      "mandate_hash": "bd35514c5b99857e95abfee2dff847b314d6f71ab2ed65ffb493413ccf74444c",
      "scope_snapshot": {
        "action": "purchase",
        "domain": "supplier-a.com",
        "spend": { "currency": "USD", "amount": 120000 }
      },
      "chain_depth": 0
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mandate_id` | string | Yes | The `mandate_id` of the mandate commitment that authorized this action. |
| `mandate_hash` | string (hex) | Yes | Lowercase 64-character hex SHA-256 of the canonical mandate commitment bytes — the same digest defined in the W1 commitment specification, Section 5, in hex rather than raw form. This is the cryptographic binding from the receipt to the commitment: a verifier holding the commitment recomputes its canonical form, hashes it, and confirms equality with this value, which proves the receipt references exactly this commitment and not an altered one. |
| `scope_snapshot` | object | Yes | Compact record of the scope axes the recorded action actually consumed, sufficient for a verifier to check scope compliance from the receipt alone without fetching the full commitment. Its members are `action` (string, the action type performed), `domain` (string, the domain interacted with), and `spend` (object with `currency` and an integer `amount` in minor units), each present only if the action consumed that axis. A snapshot with no consumed axes is the empty object `{}`. |
| `chain_depth` | integer | Yes; value `0` | Sub-delegation depth of the mandate. In v1, with no sub-delegation, this value MUST be `0`. The member is present so that a verifier can detect, in a later version, whether chain-walking is required. |

A verifier MUST NOT treat the presence of `action_context.ors.mandate`, or the ORS receipt signature's coverage of the `mandate_id` and `mandate_hash` values inside it, as proof that the referenced mandate commitment is valid, that it is authentic, or that the principal authorized anything. The ORS receipt signature commits only to which mandate identifier and which mandate hash this receipt records; it does not commit to the mandate's contents, its signature, its validity window, or the principal's grant of authority. Confirming mandate authenticity requires separately verifying the mandate commitment's own Ed25519 signature per the OpenTerms Mandate specification — it cannot be inferred from the receipt signature alone.

A v1 `action_context.ors.mandate` extension MUST contain only the four defined members — `mandate_id`, `mandate_hash`, `scope_snapshot`, and `chain_depth`. An extension carrying any other key at the top level of the extension object is invalid, and a verifier MUST treat it as a verification failure. This rule is what reserves the namespace against fields that look authoritative (for example, a fabricated `chain_material`, `utilization_ref`, `principal_override`, or `expiry`) being smuggled into the extension before they are defined.

When `scope_snapshot` is present, its members MUST be typed as follows: `action`, when present, MUST be a string; `domain`, when present, MUST be a string; `spend`, when present, MUST be an object whose `currency` is a string and whose `amount` is an integer in minor units (a JSON integer, not a string or floating-point number). The three axes remain individually optional — each is present only if the action consumed that axis, and a `scope_snapshot` with no consumed axes is the empty object `{}` — but when an axis is present its type is fixed.

**`scope_snapshot` completeness.** Beyond axis typing, the `scope_snapshot` is subject to a completeness rule when a verifier claims the `mandate-bound-and-verified` posture defined in Section 8. For that posture, every scope axis that the verified mandate commitment actually constrains MUST have a corresponding entry in the receipt's `scope_snapshot`. If the mandate constrains an axis — for example, `scope.spend` caps the spend in a given currency, `scope.domains` enumerates the permitted domains, or `scope.actions` enumerates the permitted action types — and `scope_snapshot` omits the matching axis entry, the verifier MUST treat this as a verification failure and MUST NOT report `mandate-bound-and-verified`. A snapshot whose well-typed axes pass containment is not sufficient on its own; the snapshot must also be complete with respect to what the mandate constrains, so a verifier cannot pass a containment check by silently leaving out the axis that would have failed.

The completeness requirement is scoped to mandate-constrained axes. An axis that the mandate does NOT constrain need not appear in `scope_snapshot`; unconstrained axes remain individually optional, and a `scope_snapshot` with no consumed axes is still the empty object `{}` when the mandate constrains no axes. The completeness rule binds only to the axes the verified mandate actually carries as constraints.

This specification states the completeness principle; it does not state the reconciliation procedure — how a verifier proves an axis is complete and reconciles the consumed-scope claim against receipt evidence (for example, `scope_snapshot.spend.amount` against `amount_charged`, or `scope_snapshot.domain` against the effective action domain). The authoritative procedure is the OpenTerms Mandate Workstream 1 commitment specification, Section 7, and is referenced here rather than restated.

`mandate_id` is a string. UUID version 7 is RECOMMENDED, because its time-ordered prefix gives commitments a natural chronological sort; this matches the recommendation in the OpenTerms Mandate Workstream 1 commitment specification, Section 2, where the commitment's `mandate_id` is originally defined. This is a SHOULD-level recommendation in ORS v0.3, not a MUST: a published spec's identifier rule is expensive to loosen later and comparatively cheap to tighten later, so v0.3 keeps the looser direction reversible. An implementation MAY apply stricter local validation of `mandate_id` — for example, rejecting non-UUID strings, or requiring UUID version 7 specifically — and doing so is conformant with this specification. A conformant implementation MAY therefore be more restrictive than v0.3 requires; it MUST NOT be more permissive than the typing rules above.

`chain_material` and `utilization_ref` are not v1 members of this extension and MUST NOT appear. They are reserved for the OpenTerms Mandate Workstream 1E (sub-delegation) and Workstream 4 (utilization reference) respectively and will be specified in a later ORS version.

**Signing boundary.** The `ors.mandate` extension is a hash-anchored reference to a separately-signed artifact. The mandate commitment carries its own Ed25519 signature, produced under its own domain-separation prefix `OTMANDATE-v0.1\x00`, which is deliberately distinct from the ORS receipt signing prefix (`ORSv0.1\x00`, Section 6). The ORS receipt signature does not sign, validate, or vouch for the mandate. What the receipt signature does cover is the binding itself: because `ors.mandate` lives inside `action_context`, the values `mandate_id` and `mandate_hash` are part of the canonicalized signed payload (Section 4), and so the receipt issuer's signature commits to which mandate this receipt is bound to. The receipt's signature is not a substitute for verifying the mandate.

**Verification procedure for `ors.mandate`.** Verifying the receipt itself follows Section 8 unchanged; this extension does not alter that procedure. Beyond that baseline, the normative force of the binding-verification steps depends on what the verifier intends to claim.

A verifier that claims the *mandate-bound-and-verified* posture defined in Section 8 MUST perform every one of the following checks; a verifier that performs fewer of them MUST NOT report `mandate-bound-and-verified` and MUST instead report only `receipt-valid` (or an implementation-specific unverified status) for the binding:

1. Verify the ORS receipt under Section 8. The receipt MUST verify before the binding is meaningful.
2. Retrieve the mandate commitment named by `mandate_id` — from local cache, from the agent, or from a registration API. The procedure is offline once the commitment is held.
3. Canonicalize the commitment per the W1 commitment specification, Section 4, compute SHA-256, and confirm the lowercase hex digest equals `mandate_hash`. On any mismatch the binding is broken and the verifier MUST report a verification failure.
4. Verify the mandate commitment's own Ed25519 signature under its `OTMANDATE-v0.1\x00` domain prefix, per the W1 commitment specification, Section 5.
5. Confirm the mandate's validity window covers the receipt's `timestamp`, the mandate's `agent.agent_id` equals the receipt's `agent_id`, and the `scope_snapshot` falls within the mandate's `scope`.

A verifier that does not claim the `mandate-bound-and-verified` posture — for example, a tool performing optional, informational inspection of the binding without making an authorization decision — SHOULD perform the same steps where it can, and MUST NOT report `mandate-bound-and-verified` if it skips any of them. Partial inspection is permitted only on the `receipt-valid` (or implementation-specific unverified-binding) path. The threshold for the verified posture is all-or-nothing: a verifier that performs four of the five steps and reports `mandate-bound-and-verified` would let the skipped check pass vacuously, which is the failure mode this rule closes.

An implementation that supports only the `receipt-valid` posture is fully conformant with this specification. The `mandate-bound-and-verified` posture is an added capability that a verifier MAY offer; it is not a barrier to conformance. Early and partial implementations — those that have not yet wired up mandate-commitment retrieval, the commitment-signature check, or scope reconciliation — are explicitly expected, and the `receipt-valid` path is the home for them. Implementations are encouraged to add `mandate-bound-and-verified` support when they are ready; until then, reporting `receipt-valid` honestly and refusing to report the verified posture is the correct behavior.

The authoritative definition of this procedure is the W1 commitment specification, Section 7; it is referenced here rather than restated. ORS verifiers that do not consume `ors.mandate` are unaffected.

A worked example of a mandate-bound receipt is provided as `examples/mandate_bound_receipt.json` in this repository. It carries the `ors.mandate` extension at `action_context.ors.mandate` with the W1 Section 6.2 values verbatim, surrounded by an otherwise ordinary v0.3 receipt envelope.

**Verification posture.** A relying party that requires a mandate MUST NOT accept a receipt with no `action_context.ors.mandate` extension as a substitute for one whose binding has been verified. The two postures a relying party can demand — *receipt-valid* and *mandate-bound-and-verified* — and the requirement that mandate-required relying parties reject unbound receipts are defined normatively in Section 8 under "Verification postures."

### 11.2 JSON-LD compatibility

ORS receipts are plain JSON and do not include a `@context` field in the signed payload. Implementations that need JSON-LD compatibility for semantic web tooling MAY add a `@context` field to the receipt envelope after the signature has been computed, provided they do not include it in the canonicalized payload. Verifiers MUST ignore `@context` when recomputing the canonical hash.

A compatible JSON-LD context for ORS receipts MAY be published at `https://openterms.io/ns/ors/v0.3/context.jsonld`. This is informational and not required for conformance.

## 12. Security considerations

* Signing keys MUST remain secret. Only public keys are distributed via JWKS.
* Receipts are not encrypted. All fields are plaintext. Do not include secrets, tokens, or PII.
* `terms_hash` binds the receipt to an immutable policy document snapshot. Verifiers can confirm the terms document has not changed since the receipt was issued by re-hashing the document at `terms_url`.
* Receipts are append only. Once issued, they cannot be modified or revoked.
* **Replay:** If a receipt is intended to authorize only one request, use `request_binding` and optionally `expires_at`. Without request binding, replay resistance is an application level responsibility.
* **Context shifting:** If `provider` is not in the signed payload, a receipt can be presented to a provider other than the one it was intended for. Include `provider` in the payload when provider binding matters, or enforce provider binding out of band.
* **Refusal integrity:** Refusal receipts (`decision: "declined"`) bind to the same `terms_hash` as acknowledgement receipts, ensuring the decline happened under a specific policy version.
* Verifiers SHOULD use HTTPS for JWKS endpoints.
* Timestamp skew: verifiers SHOULD allow a small clock skew window. Recommended: 5 minutes.
* Verifiers SHOULD cache JWKS keys locally to avoid fetching on every verification.
* **Policy classification fields (`terms_type`, `terms_service`, `terms_version`):** These fields are signed and tamper-evident, but they are self-asserted by the issuer. Verifiers SHOULD NOT treat these fields as independently verified facts about the policy document's content or classification without additional out-of-band verification.

## Appendix A. Schema version history

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-02 | Initial release. Terms as first policy type. Signed envelope fields (receipt_id, amount_charged, created_at). Domain separated Ed25519 signatures. Optional provider binding, request binding, decision, chain fields, extension namespaces. |
| 0.2 | 2026-04 | Added optional `terms_type`, `terms_service`, `terms_version` payload fields for policy classification. Added `model_training` to `action_type` enum. Promoted `ors.anchor` and `ors.zk_proof` extension namespaces to normative descriptions with verification procedures. Added JSON-LD compatibility note (Section 11.2). Domain separation prefix unchanged; v0.1 verification tooling remains compatible. |
| 0.3 | 2026-05 | Promoted the `ors.mandate` extension namespace to a normative, optional extension under Section 11.1, with the four-member shape (`mandate_id`, `mandate_hash`, `scope_snapshot`, `chain_depth`) defined by the OpenTerms Mandate Workstream 1 commitment specification, Section 6. Added the signing-boundary statement and the verifier-side reference to the W1 verification procedure. Added Appendix D: Migration guide from v0.2 to v0.3. Core receipt format, canonicalization, hashing, and signing are unchanged; v0.1 and v0.2 receipts remain valid v0.3 receipts and v0.1/v0.2 verification tooling continues to verify v0.3 receipts that do not consume the new extension. |

## Appendix B. Canonicalization test vectors

Implementations MUST produce identical canonical JSON and SHA 256 hashes for these inputs. Any divergence indicates a canonicalization bug.

### Vector 1: Empty object

Input:
```json
{}
```

Canonical JSON:
```
{}
```

SHA 256: `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`

### Vector 2: Single field

Input:
```json
{
  "agent_id": "test"
}
```

Canonical JSON:
```
{"agent_id":"test"}
```

SHA 256: `b39da5a32bdcb9db8522b35e35a1cbe778add6d2c38e4e06f73ba5fc7e787b0f`

### Vector 3: Key sorting

Input:
```json
{
  "z": 1,
  "a": 2,
  "m": 3
}
```

Canonical JSON:
```
{"a":2,"m":3,"z":1}
```

SHA 256: `ebba85cfdc0a724b6cc327ecc545faeb38b9fe02eca603b430eb872f5cf75370`

### Vector 4: Null stripping

Input:
```json
{
  "keep": "yes",
  "remove": null,
  "also_keep": 0
}
```

Canonical JSON:
```
{"also_keep":0,"keep":"yes"}
```

SHA 256: `86ce4829dedbfd52caba57d01e174b09ebd0fb208e834c1a03d53ce17c41cb27`

### Vector 5: Nested key sorting

Input:
```json
{
  "outer": {
    "z_inner": 1,
    "a_inner": 2
  },
  "alpha": "first"
}
```

Canonical JSON:
```
{"alpha":"first","outer":{"a_inner":2,"z_inner":1}}
```

SHA 256: `1104756fd1871c899738458b3901f52c371d40f84df184cb180020f9daa0dae8`

### Vector 6: Array order preserved (not sorted)

Input:
```json
{
  "items": ["cherry", "apple", "banana"]
}
```

Canonical JSON:
```
{"items":["cherry","apple","banana"]}
```

SHA 256: `be6e07c10acac4b2efde23a707d610987187891a592c7ac0e9bf87e051aed91c`

### Vector 7: Nested null stripping

Input:
```json
{
  "a": {
    "b": null,
    "c": "keep"
  },
  "d": null
}
```

Canonical JSON:
```
{"a":{"c":"keep"}}
```

SHA 256: `07be2d06df5c92a98f246dd1081d302ff033865cd1779bc681e34eea4f27f362`

### Vector 8: Booleans and integers

Input:
```json
{
  "active": true,
  "count": 42,
  "disabled": false
}
```

Canonical JSON:
```
{"active":true,"count":42,"disabled":false}
```

SHA 256: `a3231349942960a33fe10a786e2d6a316a53ba78840b555197822bdc44b26ede`

### Vector 9: Unicode preservation

Input:
```json
{
  "name": "café",
  "city": "東京"
}
```

Canonical JSON:
```
{"city":"東京","name":"café"}
```

SHA 256: `d1770062ec7e67f8a0bc88436d78d1deef491d23a35895353567960821bbabe2`

### Vector 10: Empty nested structures

Input:
```json
{
  "empty_obj": {},
  "empty_arr": [],
  "val": "x"
}
```

Canonical JSON:
```
{"empty_arr":[],"empty_obj":{},"val":"x"}
```

SHA 256: `f3c22e5ce7ed875bd8f652e1f9b22c1413d4adb44c3eee9399d00f384202db93`

### Vector 11: Minimal receipt payload (with signed envelope fields)

Input:
```json
{
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "agent-test",
  "action_type": "api_call",
  "terms_url": "https://example.com/terms",
  "terms_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "timestamp": "2026-02-18T12:00:00.000Z",
  "pricing_version": "2025-01",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440010",
  "amount_charged": 1000,
  "created_at": "2026-02-18T12:00:00.100Z"
}
```

Canonical JSON:
```
{"action_type":"api_call","agent_id":"agent-test","amount_charged":1000,"created_at":"2026-02-18T12:00:00.100Z","pricing_version":"2025-01","receipt_id":"550e8400-e29b-41d4-a716-446655440010","terms_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","terms_url":"https://example.com/terms","timestamp":"2026-02-18T12:00:00.000Z","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}
```

SHA 256: `d45c27f864cee471b9cf6fbd8e60c051ca69d36ecd7403a76b52d5946f3836eb`

### Vector 12: Receipt payload with action_context

Input:
```json
{
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "agent-test",
  "action_type": "data_access",
  "terms_url": "https://example.com/terms",
  "terms_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "timestamp": "2026-02-18T12:05:00.000Z",
  "pricing_version": "2025-01",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440011",
  "amount_charged": 0,
  "created_at": "2026-02-18T12:05:00.050Z",
  "action_context": {
    "model": "gpt-4",
    "tokens": 500
  }
}
```

Canonical JSON:
```
{"action_context":{"model":"gpt-4","tokens":500},"action_type":"data_access","agent_id":"agent-test","amount_charged":0,"created_at":"2026-02-18T12:05:00.050Z","pricing_version":"2025-01","receipt_id":"550e8400-e29b-41d4-a716-446655440011","terms_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","terms_url":"https://example.com/terms","timestamp":"2026-02-18T12:05:00.000Z","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}
```

SHA 256: `fb8d7798be17bbc6496cf5035a2c114e6cb78a1886e27a84616077e53767b852`

### Vector 13: Receipt with policy classification fields (new in v0.2)

Input:
```json
{
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "agent-test",
  "action_type": "api_call",
  "terms_url": "https://openai.com/policies/privacy-policy",
  "terms_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "timestamp": "2026-04-01T12:00:00.000Z",
  "pricing_version": "2025-01",
  "terms_type": "Privacy Policy",
  "terms_service": "openai",
  "terms_version": "2024-01-15",
  "receipt_id": "550e8400-e29b-41d4-a716-446655440012",
  "amount_charged": 0,
  "created_at": "2026-04-01T12:00:00.050Z"
}
```

Canonical JSON:
```
{"action_type":"api_call","agent_id":"agent-test","amount_charged":0,"created_at":"2026-04-01T12:00:00.050Z","pricing_version":"2025-01","receipt_id":"550e8400-e29b-41d4-a716-446655440012","terms_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","terms_service":"openai","terms_type":"Privacy Policy","terms_url":"https://openai.com/policies/privacy-policy","terms_version":"2024-01-15","timestamp":"2026-04-01T12:00:00.000Z","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}
```

SHA 256: `f4e650a6787986385b09b5e5e0507f45a1a0d25a5d1c2513fd74572876b55ade`

## Appendix C. Migration guide: v0.1 to v0.2

**For receipt issuers:**

v0.2 is fully backward compatible with v0.1. No changes are required for existing issuers. To adopt v0.2 features:

1. Optionally add `terms_type`, `terms_service`, and/or `terms_version` to receipt payloads where policy classification is useful.
2. Update `ors_version` to `"0.2"` in new receipts when using v0.2 features.
3. If using `model_training` as an action type, ensure the new enum value is supported in your validation layer.

**For verifiers:**

Existing v0.1 verification code will correctly verify v0.2 receipts that add only the new optional fields. The canonicalization, hashing, and signing algorithm is unchanged. The domain separation prefix `ORSv0.1\x00` is retained in v0.2 to preserve this compatibility.

Verifiers that wish to consume `terms_type`, `terms_service`, or `terms_version` should add these fields to their signed-field extraction step in the VERIFY algorithm (Section 8, Step 1). Fields that are absent from a receipt are excluded from canonicalization by the null-stripping rule and do not affect verification.

**For `ors.anchor` and `ors.zk_proof` users:**

The v0.1 `ors.anchor` and `ors.zk_proof` stubs in `action_context` remain the correct placement. v0.2 adds normative field definitions and verification procedures. Existing implementations using the stub structure are compatible; add the new required fields (`type`, `root_hash`, `tree_size` for anchor; `system`, `statement_hash`, `proof_hash` for zk_proof) to become conformant.

## Appendix D. Migration guide: v0.2 to v0.3

v0.3 is fully backward compatible with v0.2 and v0.1. The core receipt format — required fields, canonicalization, hashing, signing, and the domain separation prefix `ORSv0.1\x00` — is unchanged. v0.3 documents the `ors.mandate` extension as a normative, optional extension namespace. **No change is required of any existing receipt issuer, verifier, or stored receipt.**

**For receipt issuers:**

No change is required. To adopt v0.3's new extension where it is useful:

1. Optionally attach the `ors.mandate` extension to `action_context.ors.mandate` on receipts that record an action authorized by an OpenTerms Mandate commitment. The four-member shape is fixed by the OpenTerms Mandate Workstream 1 commitment specification, Section 6.1, and is documented in Section 11.1 of this specification.
2. Optionally update `ors_version` to `"0.3"` in new receipts when adopting v0.3 features.
3. The receipt's signature does not sign the mandate. The mandate commitment carries its own Ed25519 signature under a distinct domain-separation prefix; the receipt signature covers the binding values `mandate_id` and `mandate_hash` (because they sit inside `action_context`) but is not a substitute for verifying the mandate.

**For verifiers:**

Existing v0.1 and v0.2 verification code will correctly verify v0.3 receipts. The canonicalization, hashing, and signing algorithm is unchanged. A verifier that does not consume `ors.mandate` ignores the extension as freeform `action_context` content and is unaffected.

Verifiers that wish to check mandate bindings follow the procedure summarized in Section 11.1 and defined authoritatively in the W1 commitment specification, Section 7: confirm the receipt, retrieve the mandate commitment, recompute its canonical hash and compare to `mandate_hash`, verify the commitment's own signature, and check the validity window, agent join, and scope containment. This is a separate procedure on a separately-signed artifact; it does not modify ORS receipt verification.

**For `ors.mandate` users carried forward from external practice:**

Receipts that already carry `action_context.ors.mandate` populated against the W1 commitment specification, Section 6, are already conformant under v0.3 with no field-level change. v0.3 documents the placement and shape that those receipts have been using.
