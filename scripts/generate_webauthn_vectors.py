#!/usr/bin/env python3
"""
Generate ES256 / EC2-P256 WebAuthn test vectors for the Rust verifier in
crates/secrt-server/src/domain/webauthn.rs.

CRUCIAL: This script must NOT share code, types, or framing logic with the
Rust verifier. Its job is to be an INDEPENDENT reference implementation built
straight from the spec text, so two unrelated codebases agreeing on the same
bytes is the actual correctness signal. Self-consistency between the Rust
helper and the Rust verifier proves nothing.

Crypto primitives come from `cryptography` (pyca/cryptography). All WebAuthn
framing (COSE_Key CBOR, authenticatorData layout, clientDataJSON, signed
bytes ordering) is hand-assembled from the spec. Each assembly step cites
the spec section in a comment, so a reviewer can audit framing without
trusting any library.

Output: spec/v1/webauthn.vectors.json. Re-run only when the spec or the
verifier's contract changes — the file is committed for stable test runs.

Setup:
    python3 -m venv .venv-fixtures
    .venv-fixtures/bin/pip install cryptography
    .venv-fixtures/bin/python scripts/generate_webauthn_vectors.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# ── Constants ──────────────────────────────────────────────────────────
# WebAuthn flag bits (W3C WebAuthn §6.1)
FLAG_UP = 0x01  # User Present
FLAG_UV = 0x04  # User Verified
FLAG_AT = 0x40  # Attested credential data present (registration only)

# COSE labels (RFC 9052 §7.1, §13.1.1)
COSE_KTY = 1
COSE_ALG = 3
COSE_EC2_CRV = -1
COSE_EC2_X = -2
COSE_EC2_Y = -3
COSE_KTY_EC2 = 2
COSE_ALG_ES256 = -7
COSE_CRV_P256 = 1
COSE_CRV_P384 = 2  # used for the negative "wrong curve" vector

# Test environment — matches the Rust test_config and the typical RP setup
RP_ID = "secrt.is"
ORIGIN = "https://secrt.is"
AAGUID_ZERO = bytes(16)  # synced-passkey authenticators commonly emit zero AAGUID


# ── Encoding helpers ────────────────────────────────────────────────────

def b64u(data: bytes) -> str:
    """base64url-no-pad. Used everywhere in the WebAuthn wire format."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def cbor_uint(value: int) -> bytes:
    """RFC 8949 §3.1: unsigned int (major type 0)."""
    if value < 0:
        raise ValueError("not unsigned")
    if value < 24:
        return bytes([value])
    if value < 256:
        return bytes([0x18, value])
    if value < 65536:
        return bytes([0x19]) + value.to_bytes(2, "big")
    raise ValueError("too large for our needs")


def cbor_negint(value: int) -> bytes:
    """RFC 8949 §3.1: negative int (major type 1). value must be < 0."""
    if value >= 0:
        raise ValueError("not negative")
    n = -1 - value  # encoded value is -1 - actual
    if n < 24:
        return bytes([0x20 | n])
    if n < 256:
        return bytes([0x38, n])
    raise ValueError("too small for our needs")


def cbor_int(value: int) -> bytes:
    return cbor_uint(value) if value >= 0 else cbor_negint(value)


def cbor_bstr(data: bytes) -> bytes:
    """RFC 8949 §3.1: byte string (major type 2)."""
    n = len(data)
    if n < 24:
        head = bytes([0x40 | n])
    elif n < 256:
        head = bytes([0x58, n])
    elif n < 65536:
        head = bytes([0x59]) + n.to_bytes(2, "big")
    else:
        raise ValueError("too large")
    return head + data


def cbor_map(pairs: list[tuple[bytes, bytes]]) -> bytes:
    """RFC 8949 §3.1: map (major type 5). pairs are pre-encoded CBOR (key, value)."""
    n = len(pairs)
    if n < 24:
        head = bytes([0xa0 | n])
    elif n < 256:
        head = bytes([0xb8, n])
    else:
        raise ValueError("too large")
    body = b"".join(k + v for (k, v) in pairs)
    return head + body


# ── COSE_Key construction (RFC 9052 §7) ─────────────────────────────────

def cose_key_ec2_p256(x: bytes, y: bytes) -> bytes:
    """
    Build a COSE_Key for an EC2 P-256 ES256 public key.
    RFC 9052 §7.1 + §13.1.1. Canonical CBOR map of:
        {1: 2, 3: -7, -1: 1, -2: <x>, -3: <y>}
    """
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coords must be 32 bytes")
    return cbor_map([
        (cbor_int(COSE_KTY), cbor_int(COSE_KTY_EC2)),    # kty = EC2
        (cbor_int(COSE_ALG), cbor_int(COSE_ALG_ES256)),  # alg = ES256 (-7)
        (cbor_int(COSE_EC2_CRV), cbor_int(COSE_CRV_P256)),  # crv = P-256
        (cbor_int(COSE_EC2_X), cbor_bstr(x)),            # x
        (cbor_int(COSE_EC2_Y), cbor_bstr(y)),            # y
    ])


def cose_key_ec2_p384_wrong(x: bytes, y: bytes) -> bytes:
    """Negative fixture: claims P-384 (crv=2). Verifier must reject."""
    return cbor_map([
        (cbor_int(COSE_KTY), cbor_int(COSE_KTY_EC2)),
        (cbor_int(COSE_ALG), cbor_int(COSE_ALG_ES256)),
        (cbor_int(COSE_EC2_CRV), cbor_int(COSE_CRV_P384)),  # wrong curve
        (cbor_int(COSE_EC2_X), cbor_bstr(x)),
        (cbor_int(COSE_EC2_Y), cbor_bstr(y)),
    ])


# ── authenticatorData construction (W3C WebAuthn §6.1) ──────────────────

def rp_id_hash(rp_id: str) -> bytes:
    """SHA-256 of the RP ID (W3C WebAuthn §6.1, rpIdHash field)."""
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def authenticator_data_login(rp_id: str, flags: int, sign_count: int) -> bytes:
    """
    W3C WebAuthn §6.1, layout for a login (no attested credential data):
        rpIdHash (32) || flags (1) || signCount (4 BE)
    """
    out = bytearray()
    out += rp_id_hash(rp_id)                      # 32 bytes
    out += bytes([flags & 0xFF])                  # 1 byte
    out += sign_count.to_bytes(4, "big")          # 4 bytes
    assert len(out) == 37
    return bytes(out)


def authenticator_data_register(
    rp_id: str,
    flags: int,
    sign_count: int,
    aaguid: bytes,
    credential_id: bytes,
    cose_pubkey: bytes,
) -> bytes:
    """
    W3C WebAuthn §6.1 + §6.5.4, layout for registration with attested
    credential data (sets the AT flag):
        rpIdHash (32) || flags (1) || signCount (4 BE)
        || aaguid (16) || credIdLen (2 BE) || credentialId
        || credentialPublicKey (CBOR-encoded COSE_Key)
    """
    if len(aaguid) != 16:
        raise ValueError("aaguid must be 16 bytes")
    out = bytearray()
    out += rp_id_hash(rp_id)
    out += bytes([(flags | FLAG_AT) & 0xFF])
    out += sign_count.to_bytes(4, "big")
    out += aaguid
    out += len(credential_id).to_bytes(2, "big")
    out += credential_id
    out += cose_pubkey
    return bytes(out)


# ── clientDataJSON construction (W3C WebAuthn §5.10.1) ─────────────────

def client_data_json(type_: str, challenge: bytes, origin: str) -> bytes:
    """
    W3C WebAuthn §5.10.1. The 'challenge' field is the base64url-no-pad
    encoding of the raw challenge bytes.

    NB: Real-world clientDataJSON is whatever bytes the user-agent serializes
    — field order, escaping, and whitespace can vary between browsers. Our
    verifier MUST NOT canonicalize: it parses the literal bytes the browser
    sent. For our fixtures we use Python json with no extra whitespace, sorted
    keys, which produces a stable serialization for reproducible vectors.
    """
    obj = {
        "type": type_,
        "challenge": b64u(challenge),
        "origin": origin,
    }
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


# ── ECDSA signing (W3C WebAuthn §6.5.6) ────────────────────────────────

def sign_assertion(
    private_key: EllipticCurvePrivateKey,
    authenticator_data: bytes,
    client_data: bytes,
) -> bytes:
    """
    W3C WebAuthn §6.5.6: signature is over `authenticatorData || SHA-256(clientDataJSON)`.
    For COSE alg -7 (ES256) the signature carried on the wire is the ASN.1
    DER-encoded ECDSA signature. (`cryptography` returns DER directly.)
    """
    cdh = hashlib.sha256(client_data).digest()
    msg = authenticator_data + cdh
    return private_key.sign(msg, ec.ECDSA(hashes.SHA256()))


# ── Vector building blocks ─────────────────────────────────────────────

@dataclass
class Vector:
    name: str
    kind: str  # "register" | "verify"
    notes: str
    inputs: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)


def public_xy(priv: EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
    """Extract the 32-byte X and Y coordinates from a P-256 private key."""
    nums = priv.public_key().public_numbers()
    return (nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))


def sec1_uncompressed(x: bytes, y: bytes) -> bytes:
    """SEC1 §2.3.3 uncompressed point: 0x04 || X || Y. This is the canonical
    public-key representation the Rust verifier stores after parsing a COSE_Key."""
    return b"\x04" + x + y


# ── Vector generators ──────────────────────────────────────────────────

def make_register_happy() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    cose = cose_key_ec2_p256(x, y)
    cred_id = os.urandom(16)
    challenge = os.urandom(32)
    auth = authenticator_data_register(
        RP_ID, FLAG_UP | FLAG_UV, 0, AAGUID_ZERO, cred_id, cose,
    )
    cdj = client_data_json("webauthn.create", challenge, ORIGIN)
    return Vector(
        name="register_happy",
        kind="register",
        notes="Happy-path registration: AT|UP|UV flags set, sign_count=0, "
              "valid EC2 P-256 COSE_Key. Verifier must extract credential_id "
              "and the SEC1-uncompressed pubkey, accept rpIdHash, accept the "
              "challenge from clientDataJSON, and return the parsed credential.",
        inputs={
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
        },
        expected={
            "ok": True,
            "credential_id_b64u": b64u(cred_id),
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "sign_count": 0,
        },
    )


def make_login_happy() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 1)
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_happy",
        kind="verify",
        notes="Happy-path assertion. UP|UV set, sign_count=1 > stored 0, "
              "valid signature over authenticatorData||SHA256(clientDataJSON).",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": True, "new_sign_count": 1},
    )


def make_bad_rp_id_hash() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    # Build valid auth_data, then corrupt the first 32 bytes (rpIdHash).
    auth = bytearray(authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 1))
    auth[0:32] = hashlib.sha256(b"evil.example").digest()
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = sign_assertion(priv, bytes(auth), cdj)
    return Vector(
        name="login_bad_rp_id_hash",
        kind="verify",
        notes="rpIdHash does not match the expected RP ID. Signature is "
              "still self-consistent (signed over the corrupted auth_data), "
              "so this catches verifiers that skip the rpIdHash check.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(bytes(auth)),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": False, "error": "RpIdHashMismatch"},
    )


def make_up_flag_clear() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    auth = authenticator_data_login(RP_ID, FLAG_UV, 1)  # no UP
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_up_flag_clear",
        kind="verify",
        notes="UP (User Present) bit cleared. WebAuthn requires UP=1 for any "
              "user-initiated assertion. Verifier must reject.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": False, "error": "UserPresentFlagNotSet"},
    )


def make_sign_count_zero_synced_passkey() -> Vector:
    """Synced-passkey authenticators (Apple iCloud Keychain, etc.) emit
    sign_count=0 on every assertion. The verifier must accept this even
    when the stored count is positive, and must NOT regress the stored
    value back to 0."""
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 0)  # sign_count=0
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_sign_count_zero_synced_passkey",
        kind="verify",
        notes="Counter-less authenticator (sign_count=0 on the wire) with a "
              "stored count of 7. Verifier MUST accept and persist max(7, 0) "
              "= 7 — the stored value can't regress, but the assertion is "
              "valid. Without this carveout, every iCloud Keychain login "
              "after the first would 401 in production.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 7,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": True, "new_sign_count": 7},
    )


def make_sign_count_regression() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    # New sign_count = 5, but stored is 10. Cloned-authenticator signal.
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 5)
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_sign_count_regression",
        kind="verify",
        notes="sign_count moved BACKWARDS (new=5, stored=10). WebAuthn §6.1.1 "
              "requires the verifier to treat this as a cloned-authenticator "
              "signal and refuse the assertion. Some implementations only warn "
              "when stored > 0 and incoming = 0; this fixture is unambiguous.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 10,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": False, "error": "SignCountRegressed"},
    )


def make_signature_tamper() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 1)
    cdj = client_data_json("webauthn.get", challenge, ORIGIN)
    sig = bytearray(sign_assertion(priv, auth, cdj))
    sig[-1] ^= 0x01  # flip a bit in the last byte
    return Vector(
        name="login_signature_tamper",
        kind="verify",
        notes="Final byte of the signature flipped. ring's verifier must "
              "reject. (Note: ECDSA DER's malleability surfaces as InvalidSignature.)",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(bytes(sig)),
        },
        expected={"ok": False, "error": "InvalidSignature"},
    )


def make_bad_challenge() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    real_challenge = os.urandom(32)
    other_challenge = os.urandom(32)  # what the server actually issued
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 1)
    cdj = client_data_json("webauthn.get", real_challenge, ORIGIN)
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_bad_challenge",
        kind="verify",
        notes="clientDataJSON.challenge does not match the server's expected "
              "challenge. Signature is self-consistent. Catches replay attempts.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(other_challenge),  # mismatch
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": False, "error": "ChallengeMismatch"},
    )


def make_bad_origin() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    challenge = os.urandom(32)
    auth = authenticator_data_login(RP_ID, FLAG_UP | FLAG_UV, 1)
    # Origin in clientDataJSON is evil.example, but server expects secrt.is.
    cdj = client_data_json("webauthn.get", challenge, "https://evil.example")
    sig = sign_assertion(priv, auth, cdj)
    return Vector(
        name="login_bad_origin",
        kind="verify",
        notes="clientDataJSON.origin does not match the expected origin. "
              "Catches the cross-site authenticator-relay scenario.",
        inputs={
            "stored_pubkey_b64u": b64u(sec1_uncompressed(x, y)),
            "stored_sign_count": 0,
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
            "signature_b64u": b64u(sig),
        },
        expected={"ok": False, "error": "OriginMismatch"},
    )


def make_register_wrong_curve() -> Vector:
    priv = ec.generate_private_key(ec.SECP256R1())
    x, y = public_xy(priv)
    cose = cose_key_ec2_p384_wrong(x, y)  # claims P-384 in the COSE_Key
    cred_id = os.urandom(16)
    challenge = os.urandom(32)
    auth = authenticator_data_register(
        RP_ID, FLAG_UP | FLAG_UV, 0, AAGUID_ZERO, cred_id, cose,
    )
    cdj = client_data_json("webauthn.create", challenge, ORIGIN)
    return Vector(
        name="register_wrong_curve",
        kind="register",
        notes="COSE_Key declares crv=P-384, which we do not support. The "
              "verifier must reject without trying to interpret the bytes "
              "as a P-256 key.",
        inputs={
            "rp_id": RP_ID,
            "origin": ORIGIN,
            "expected_challenge_b64u": b64u(challenge),
            "authenticator_data_b64u": b64u(auth),
            "client_data_json_b64u": b64u(cdj),
        },
        expected={"ok": False, "error": "UnsupportedCoseAlgorithm"},
    )


# ── Main ────────────────────────────────────────────────────────────────

def main() -> int:
    here = Path(__file__).resolve().parent
    out_path = here.parent / "spec" / "v1" / "webauthn.vectors.json"

    vectors = [
        make_register_happy(),
        make_register_wrong_curve(),
        make_login_happy(),
        make_bad_rp_id_hash(),
        make_up_flag_clear(),
        make_sign_count_regression(),
        make_sign_count_zero_synced_passkey(),
        make_signature_tamper(),
        make_bad_challenge(),
        make_bad_origin(),
    ]

    payload = {
        "version": 1,
        "comment": (
            "ES256 / EC2-P256 WebAuthn test vectors. Generated by an "
            "INDEPENDENT implementation (Python pyca/cryptography for ECDSA "
            "primitives + hand-assembled WebAuthn framing per W3C WebAuthn "
            "and RFC 9052). Used to verify the Rust verifier in "
            "crates/secrt-server/src/domain/webauthn.rs against the spec, "
            "not against itself. Regenerate with "
            "`scripts/generate_webauthn_vectors.py`."
        ),
        "vectors": [
            {
                "name": v.name,
                "kind": v.kind,
                "notes": v.notes,
                "inputs": v.inputs,
                "expected": v.expected,
            }
            for v in vectors
        ],
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out_path} with {len(vectors)} vectors:")
    for v in vectors:
        print(f"  - {v.name} ({v.kind})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
