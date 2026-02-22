# Open Receipt Specification (ORS) v0.1

## 1. Introduction

An ORS receipt is a cryptographically signed record proving an AI agent acknowledged a specific policy before taking an action. In v0.1, the standardized policy type is a terms document referenced by URL and content hash. The format is designed to accommodate future policy types (safety policies, budget constraints, data residency rules, model usage constraints, tool permission frameworks) without schema changes.

ORS is a portable data format and a verification algorithm. It is not a network protocol, not a policy engine, and not a billing system. Implementations may add policy evaluation, payment settlement, and provider verification flows, but those are outside the core format.

Design goals:

* Portable across vendors and deployments.
* Verifiable by any third party using public keys.
* Tamper evident through canonicalization, hashing, and signing.
* Small enough to implement in one afternoon, with clear extension seams for richer provenance.

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

## 3. Receipt Schema

The receipt has two parts: the payload and the envelope.

### 3a. Payload fields (canonicalized and signed)

#### Required fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `workspace_id` | string (UUID v4) | Yes | Identifier for the workspace or organization issuing the receipt. |
| `agent_id` | string | Yes | Identifier for the AI agent taking the action. |
| `action_type` | string (enum) | Yes | One of: `api_call`, `data_access`, `purchase`, `custom`. |
| `terms_url` | string (URL) | Yes | URL of the terms document being acknowledged. MUST be HTTP or HTTPS. |
| `terms_hash` | string (hex) | Yes | SHA 256 hash of the terms document content. Lowercase hex, exactly 64 characters. |
| `timestamp` | string (ISO 8601) | Yes | When the agent requested the receipt. MUST be UTC, MUST end with `Z`. Format: `YYYY-MM-DDTHH:MM:SS.sssZ`. |
| `pricing_version` | string | Yes | Version identifier for the pricing schedule. Example: `2025-01`. |

#### Optional fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action_context` | object | No | Freeform metadata about the action. Max 50 keys, max 4 KB serialized. MUST NOT contain PII. |
| `ors_version` | string | No | ORS format version identifier. If present, value SHOULD be `0.1`. |
| `issuer` | string (HTTPS origin) | No | Issuer identifier for JWKS discovery. Example: `https://issuer.example`. MUST be HTTPS. If present, it is signed. |
| `provider` | object | No | Optional provider identity binding. If present, it is signed. See Section 3a.1. |
| `decision` | string (enum) | No | `acknowledged` or `declined`. If omitted, default is `acknowledged`. |
| `request_binding` | object | No | Optional binding to a specific provider challenge or request commitment. If present, it is signed. See Section 3a.2. |

#### 3a.1 Provider object

If `provider` is present in the payload:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `origin` | string (HTTPS origin) | Yes | Provider HTTPS origin. Format: `https://{host}` or `https://{host}:{port}`. See normalization rules below. |
| `provider_id` | string | No | Provider identifier used by the issuer or provider. |

Security note: If `provider` is not included in the signed payload, a receipt can be context shifted, meaning it can be presented to a different provider than the one it was intended for. Self describing receipts (those with `provider` in the signed payload) offer stronger provenance. Verifiers SHOULD prefer them when available.

Provider origin normalization: To prevent canonicalization mismatches, `provider.origin` MUST be an HTTPS origin in the format `https://{host}` or `https://{host}:{port}`. Host MUST be lowercase. Default port (443) MUST be omitted. No trailing slash. No path. Examples: `https://api.example.com` (correct), `https://API.EXAMPLE.COM` (incorrect, not lowercase), `https://api.example.com/` (incorrect, trailing slash), `api.example.com` (incorrect, no scheme).

#### 3a.2 Request binding object

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

Tradeoff note: Request binding is optional in v0.1, but SHOULD be used for any action where replay creates material risk. Without request binding, receipts can be cached and reused, which simplifies integration but does not guarantee replay resistance. With request binding, the provider must supply a challenge nonce or the agent must commit to a request hash, which adds coupling but provides stronger proof that a receipt was minted for a specific request.

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

### 3d. Chain fields (future extension)

Chain fields are defined for interoperability but are not required in v0.1. In v0.1 they SHOULD be placed inside `action_context` under the reserved `ors.chain` namespace.

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

Canonicalization applies to all signed fields: the payload fields from Section 3a and the signed envelope fields from Section 3b (receipt_id, amount_charged, created_at). Signature metadata fields from Section 3c (canonical_hash, signature, key_id) MUST NOT be included, because they are outputs of the signing process itself.

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

Input (keys unordered, action_context is null):

```json
{
  "terms_url": "https://api.example.com/tos",
  "agent_id": "my-agent",
  "action_type": "api_call",
  "workspace_id": "550e8400-e29b-41d4-a716-446655440000",
  "terms_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "timestamp": "2026-02-18T12:00:00.000Z",
  "pricing_version": "2025-01",
  "action_context": null
}
```

Canonical output (action_context stripped because null, keys sorted):

```
{"action_type":"api_call","agent_id":"my-agent","pricing_version":"2025-01","terms_hash":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2","terms_url":"https://api.example.com/tos","timestamp":"2026-02-18T12:00:00.000Z","workspace_id":"550e8400-e29b-41d4-a716-446655440000"}
```

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

Domain separation prevents ORS signatures from being valid in other protocols that also sign raw SHA 256 hashes. This is a standard cryptographic best practice.

**Critical implementation note:** The signature is over `ORSv0.1\x00` concatenated with the raw hash bytes, not the hex encoded string. Implementations that omit the domain prefix or sign the hex string will produce signatures that cannot be verified.

## 7. Public key distribution

Issuers MUST publish public signing keys so any verifier can validate receipts.

### 7.1 JWKS endpoint

* Path: `/.well-known/jwks.json`
* Format: JSON Web Key Set (RFC 7517)
* Each key MUST be an OKP (Octet Key Pair) with curve Ed25519
* Issuers SHOULD set Cache Control. Recommended: `public, max-age=86400`.

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

1. Agent includes `X-Openterms-Receipt: {hash}` in its API request.
2. Provider extracts the hash.
3. Provider calls `GET {issuer_url}/v1/receipts/verify/{hash}`.
4. If the response indicates `valid: true`, serve the request.
5. If invalid or missing, reject with 403.

## 10. Validation rules

Implementations SHOULD enforce:

* `action_type` MUST be one of: `api_call`, `data_access`, `purchase`, `custom`.
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

## 11. Extensibility

`action_context` is the primary extension point.

To avoid ecosystem fragmentation, this specification reserves the `ors` key inside `action_context`. If present, `action_context.ors` MUST be an object. Keys under `action_context.ors` are intended for interoperable extensions defined by this specification or future versions.

### 11.1 Reserved extension namespaces

The following extension objects under `action_context.ors` are defined for forward compatibility. They are **informational in v0.1** and not required for conformance. Implementations MAY include them. Future versions of this specification may promote some to normative status.

**`ors.chain`** — Multi agent workflow chaining. See Section 3c.

**`ors.commitments`** — Hash commitments for governance grade provenance. May include:

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

**`ors.anchor`** — References to append only transparency or Merkle anchoring mechanisms. May include:

```json
{
  "ors": {
    "anchor": {
      "type": "merkle",
      "root_hash": "<64 hex sha256>",
      "tree_size": 12345,
      "inclusion_proof": ["<base64url>"],
      "anchor_uri": "https://transparency.example/log/"
    }
  }
}
```

**`ors.zk_proof`** — References to zero knowledge proof artifacts. May include:

```json
{
  "ors": {
    "zk_proof": {
      "system": "groth16",
      "statement_hash": "<64 hex sha256>",
      "proof_hash": "<64 hex sha256>",
      "proof_uri": "https://proofs.example/"
    }
  }
}
```

These extensions are designed to be composable. A single receipt MAY include chain, commitments, anchor, and zk_proof simultaneously.

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

## Appendix A. Schema version history

| Version | Date | Changes |
|---------|------|---------|
| 0.1 | 2026-02 | Initial release. Terms as first policy type. Signed envelope fields (receipt_id, amount_charged, created_at). Domain separated Ed25519 signatures. Optional provider binding, request binding, decision, chain fields, extension namespaces. |

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
