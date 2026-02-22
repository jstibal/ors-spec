# Open Receipt Specification (ORS)

A portable format for cryptographic agent policy acknowledgement receipts. A receipt is a signed record proving an AI agent acknowledged a specific policy before taking an action.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Specification

**[ORS-v0.1.md](ORS-v0.1.md)** — The full specification. Covers receipt schema, canonicalization (RFC 8785), Ed25519 signing, JWKS key distribution, verification algorithm, HTTP header conventions, and extension namespaces.

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

The `examples/` directory contains 9 annotated receipt files demonstrating different features:

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

Example canonical hashes are computed from the actual payload fields. Signatures are illustrative since no private key is distributed.

## Reference Implementation

[Openterms MCP server](https://github.com/jstibal/openterms-mcp) — open source (Apache 2.0), implements ORS v0.1 receipt issuance and verification.

## Feedback

Please use [GitHub Issues](https://github.com/jstibal/ors-spec/issues) for questions, suggestions, and spec feedback.

## License

Apache 2.0. See [LICENSE](LICENSE).

Copyright 2026 Staticlabs Inc.
