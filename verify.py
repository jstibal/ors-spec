#!/usr/bin/env python3
"""
ORS receipt verifier.

Verifies an Open Receipt Specification (ORS) v0.1 receipt by:
  1. Recomputing the canonical hash from payload fields
  2. Comparing against the receipt's canonical_hash
  3. Verifying the Ed25519 signature using a JWKS source

JWKS can be provided as:
  --jwks URL       (fetches from HTTPS endpoint)
  --jwks-file PATH (reads from local file)

If neither is provided and the receipt payload includes "issuer",
the verifier attempts discovery using {issuer}/.well-known/jwks.json

Requires: Python 3.10+, cryptography library (pip install cryptography)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.request
from typing import Any, Dict, Optional, Tuple


# -------------------------------------------------------------------
# Base64url helpers (RFC 4648 Section 5, no padding)
# -------------------------------------------------------------------

def b64url_decode(data: str) -> bytes:
    pad_len = (-len(data)) % 4
    return base64.urlsafe_b64decode((data + "=" * pad_len).encode("ascii"))


# -------------------------------------------------------------------
# Canonicalization (ORS v0.1, based on RFC 8785)
# -------------------------------------------------------------------

# Domain separation prefix (ORS v0.1)
DOMAIN_SEPARATOR = b"ORSv0.1\x00"

PAYLOAD_KEYS_REQUIRED = [
    "workspace_id",
    "agent_id",
    "action_type",
    "terms_url",
    "terms_hash",
    "timestamp",
    "pricing_version",
]

# Signed envelope fields (ORS v0.1: these are canonicalized and signed)
PAYLOAD_KEYS_SIGNED_ENVELOPE = [
    "receipt_id",
    "amount_charged",
    "created_at",
]

PAYLOAD_KEYS_OPTIONAL = [
    "action_context",
    "ors_version",
    "issuer",
    "provider",
    "decision",
    "request_binding",
]


def strip_nulls(obj: Any) -> Any:
    """Recursively remove keys whose value is None from dicts."""
    if isinstance(obj, dict):
        return {k: strip_nulls(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [strip_nulls(v) for v in obj]
    return obj


def build_payload(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract the payload object from a receipt envelope.
    Includes required fields, signed envelope fields, and optional fields.
    """
    payload: Dict[str, Any] = {}
    for k in PAYLOAD_KEYS_REQUIRED:
        if k not in receipt:
            raise ValueError(f"Missing required payload field: {k}")
        payload[k] = receipt[k]
    for k in PAYLOAD_KEYS_SIGNED_ENVELOPE:
        if k not in receipt:
            raise ValueError(f"Missing required signed envelope field: {k}")
        payload[k] = receipt[k]
    for k in PAYLOAD_KEYS_OPTIONAL:
        if k in receipt and receipt[k] is not None:
            payload[k] = receipt[k]
    return payload


def canonicalize(payload: Dict[str, Any]) -> bytes:
    """
    ORS canonicalization:
      1. Strip nulls recursively
      2. Sort keys lexicographically at every nesting level
      3. Compact JSON, UTF-8, no unnecessary unicode escaping
    """
    cleaned = strip_nulls(payload)
    canonical_str = json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_str.encode("utf-8")


# -------------------------------------------------------------------
# JWKS handling
# -------------------------------------------------------------------

def load_jwks_from_url(url: str) -> Dict[str, Any]:
    """Fetch JWKS from an HTTPS endpoint."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_jwks_from_file(path: str) -> Dict[str, Any]:
    """Load JWKS from a local JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any]:
    """Find a JWK by key ID."""
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            return k
    raise ValueError(f"Key not found in JWKS: {kid}")


# -------------------------------------------------------------------
# Ed25519 verification
# -------------------------------------------------------------------

def ed25519_verify(public_key_bytes: bytes, hash_bytes: bytes, signature: bytes) -> bool:
    """
    Verify an Ed25519 signature with ORS domain separation.

    message = DOMAIN_SEPARATOR + hash_bytes (40 bytes total)
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise RuntimeError(
            "The 'cryptography' library is required for Ed25519 verification. "
            "Install with: pip install cryptography"
        )

    if len(public_key_bytes) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(public_key_bytes)}")
    if len(signature) != 64:
        raise ValueError(f"Signature must be 64 bytes, got {len(signature)}")

    pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    message = DOMAIN_SEPARATOR + hash_bytes
    try:
        pk.verify(signature, message)
        return True
    except Exception:
        return False


# -------------------------------------------------------------------
# Validation helpers
# -------------------------------------------------------------------

def is_hex64(s: str) -> bool:
    """Check if a string is exactly 64 lowercase hex characters."""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def validate_envelope(receipt: Dict[str, Any]) -> None:
    """Validate that required envelope fields are present and well formed."""
    # Signature metadata (not signed, but required in envelope)
    for f in ["canonical_hash", "signature", "key_id"]:
        if f not in receipt:
            raise ValueError(f"Missing required signature metadata field: {f}")

    # Signed envelope fields (also required)
    for f in ["receipt_id", "amount_charged", "created_at"]:
        if f not in receipt:
            raise ValueError(f"Missing required signed envelope field: {f}")

    if not is_hex64(receipt["canonical_hash"]):
        raise ValueError("canonical_hash must be 64 lowercase hex characters")


def validate_payload(payload: Dict[str, Any]) -> None:
    """Validate payload field values."""
    valid_actions = ("api_call", "data_access", "purchase", "custom")
    if payload["action_type"] not in valid_actions:
        raise ValueError(f"action_type must be one of: {', '.join(valid_actions)}")

    url = payload["terms_url"]
    if not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("terms_url must start with http:// or https://")

    if not is_hex64(payload["terms_hash"]):
        raise ValueError("terms_hash must be 64 lowercase hex characters")

    if "decision" in payload and payload["decision"] not in ("acknowledged", "declined"):
        raise ValueError("decision must be 'acknowledged' or 'declined'")

    if "action_context" in payload and not isinstance(payload["action_context"], dict):
        raise ValueError("action_context must be an object")

    if "issuer" in payload:
        issuer = payload["issuer"]
        if not isinstance(issuer, str) or not issuer.startswith("https://"):
            raise ValueError("issuer must be an HTTPS origin")


# -------------------------------------------------------------------
# Main verification
# -------------------------------------------------------------------

def verify_receipt(
    receipt: Dict[str, Any],
    jwks_url: Optional[str] = None,
    jwks_file: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify an ORS receipt per Section 8 of the specification.

    Returns (is_valid, details_dict).
    """
    # Step 0: Validate structure
    validate_envelope(receipt)
    payload = build_payload(receipt)
    validate_payload(payload)

    # Step 1-2: Canonicalize
    canonical_bytes = canonicalize(payload)

    # Step 3: Hash
    hash_bytes = hashlib.sha256(canonical_bytes).digest()
    hash_hex = hash_bytes.hex()

    # Step 4: Compare
    if hash_hex != receipt["canonical_hash"]:
        return False, {
            "valid": False,
            "error": "HASH_MISMATCH",
            "expected": receipt["canonical_hash"],
            "computed": hash_hex,
        }

    # Step 5: Load JWKS
    jwks_source = None
    if jwks_file:
        jwks = load_jwks_from_file(jwks_file)
        jwks_source = jwks_file
    elif jwks_url:
        jwks = load_jwks_from_url(jwks_url)
        jwks_source = jwks_url
    else:
        issuer = payload.get("issuer")
        if issuer:
            derived_url = issuer.rstrip("/") + "/.well-known/jwks.json"
            # Safety: issuer discovery fetches a URL from receipt data.
            # In high assurance contexts, use an explicit --jwks URL instead.
            print(
                f"Note: Deriving JWKS URL from receipt issuer field: {derived_url}",
                file=sys.stderr,
            )
            jwks = load_jwks_from_url(derived_url)
            jwks_source = derived_url
        else:
            raise ValueError(
                "No JWKS source. Provide --jwks URL, --jwks-file PATH, "
                "or include 'issuer' in the receipt payload."
            )

    jwk = find_jwk(jwks, receipt["key_id"])

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return False, {
            "valid": False,
            "error": "UNSUPPORTED_KEY_TYPE",
            "detail": f"Expected OKP/Ed25519, got {jwk.get('kty')}/{jwk.get('crv')}",
            "jwks_source": jwks_source,
        }

    # Step 6: Verify signature
    pub_bytes = b64url_decode(jwk["x"])
    sig_bytes = b64url_decode(receipt["signature"])

    if not ed25519_verify(pub_bytes, hash_bytes, sig_bytes):
        return False, {
            "valid": False,
            "error": "INVALID_SIGNATURE",
            "jwks_source": jwks_source,
        }

    # Step 7: Valid
    result = {
        "valid": True,
        "receipt_id": receipt.get("receipt_id"),
        "canonical_hash": hash_hex,
        "key_id": receipt["key_id"],
        "jwks_source": jwks_source,
    }

    if "decision" in payload:
        result["decision"] = payload["decision"]

    return True, result


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify an ORS (Open Receipt Specification) v0.1 receipt.",
        epilog="Example: python verify.py receipt.json --jwks https://openterms.com/.well-known/jwks.json",
    )
    parser.add_argument("receipt_json", help="Path to an ORS receipt JSON file")
    parser.add_argument(
        "--jwks", dest="jwks_url",
        help="JWKS URL (e.g., https://issuer.example/.well-known/jwks.json)",
    )
    parser.add_argument(
        "--jwks-file", dest="jwks_file",
        help="Path to a local JWKS JSON file",
    )

    args = parser.parse_args()

    if not os.path.exists(args.receipt_json):
        print(f"File not found: {args.receipt_json}", file=sys.stderr)
        return 2

    with open(args.receipt_json, "r", encoding="utf-8") as f:
        receipt = json.load(f)

    try:
        valid, details = verify_receipt(receipt, args.jwks_url, args.jwks_file)
    except ValueError as e:
        print(json.dumps({"valid": False, "error": str(e)}, indent=2))
        return 1
    except Exception as e:
        print(json.dumps({"valid": False, "error": f"Unexpected error: {e}"}, indent=2))
        return 1

    print(json.dumps(details, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
