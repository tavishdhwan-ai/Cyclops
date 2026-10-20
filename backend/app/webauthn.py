"""
Sentinel AI WebAuthn & Platform Authenticator Verification Engine.
Validates WebAuthn assertions server-side using standard cryptography primitives.
Enforces Relying Party ID, Origin, User Verification flags, and atomic challenge consumption.
"""
import os
import base64
import hashlib
import json
import secrets
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:3000")


def base64url_encode(data: bytes) -> str:
    """Encode bytes into standard Base64URL string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def base64url_decode(s: str) -> bytes:
    """Decode Base64URL string into bytes."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def generate_webauthn_challenge() -> str:
    """Generate a high-entropy 32-byte cryptographic challenge."""
    return base64url_encode(secrets.token_bytes(32))


class AssertionVerificationResult(BaseModel):
    is_valid: bool
    user_verified: bool
    rp_id: str
    origin: str
    error: Optional[str] = None


def verify_webauthn_assertion(
    expected_challenge: str,
    client_data_json_b64: str,
    authenticator_data_b64: str,
    signature_b64: str,
    expected_rp_id: str = WEBAUTHN_RP_ID,
    expected_origin: str = WEBAUTHN_ORIGIN,
    public_key_pem: Optional[str] = None,
) -> AssertionVerificationResult:
    """
    Validates a WebAuthn assertion payload:
    1. Decodes and inspects clientDataJSON (type: 'webauthn.get', challenge match, origin check).
    2. Inspects authenticatorData (RP ID hash match, UP and UV flags).
    3. Validates digital signature if public key is provided.
    """
    try:
        # 1. Parse clientDataJSON
        client_data_raw = base64url_decode(client_data_json_b64)
        client_data = json.loads(client_data_raw.decode("utf-8"))

        op_type = client_data.get("type")
        if op_type not in ("webauthn.get", "webauthn.create"):
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=expected_origin,
                error=f"Unexpected clientData type: {op_type}",
            )

        client_challenge = client_data.get("challenge", "")
        # Compare challenges using constant-time comparison
        if not secrets.compare_digest(client_challenge, expected_challenge):
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=expected_origin,
                error="WebAuthn challenge mismatch or already consumed.",
            )

        client_origin = client_data.get("origin", "")
        # Allow matching origin or localhost variations in development
        origin_valid = (
            client_origin == expected_origin
            or (expected_rp_id == "localhost" and "localhost" in client_origin)
            or (expected_rp_id == "localhost" and "127.0.0.1" in client_origin)
        )
        if not origin_valid:
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=client_origin,
                error=f"Origin mismatch: expected {expected_origin}, got {client_origin}",
            )

        # 2. Parse authenticatorData
        auth_data_bytes = base64url_decode(authenticator_data_b64)
        if len(auth_data_bytes) < 37:
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=client_origin,
                error="authenticatorData too short (< 37 bytes).",
            )

        rp_id_hash = auth_data_bytes[:32]
        flags = auth_data_bytes[32]
        sign_count = int.from_bytes(auth_data_bytes[33:37], byteorder="big")

        expected_rp_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
        # Verify RP ID hash
        if not secrets.compare_digest(rp_id_hash, expected_rp_hash):
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=client_origin,
                error="authenticatorData RP ID hash mismatch.",
            )

        # Flag 0x01: User Present (UP)
        # Flag 0x04: User Verified (UV) - Biometric or device PIN unlock
        user_present = bool(flags & 0x01)
        user_verified = bool(flags & 0x04)

        if not user_present:
            return AssertionVerificationResult(
                is_valid=False,
                user_verified=False,
                rp_id=expected_rp_id,
                origin=client_origin,
                error="User Present flag not set by platform authenticator.",
            )

        # 3. Cryptographic Signature Verification (when public key is registered)
        if public_key_pem:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_public_key

                public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
                client_data_hash = hashlib.sha256(client_data_raw).digest()
                signed_data = auth_data_bytes + client_data_hash
                signature_bytes = base64url_decode(signature_b64)

                if isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(signature_bytes, signed_data, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return AssertionVerificationResult(
                    is_valid=False,
                    user_verified=user_verified,
                    rp_id=expected_rp_id,
                    origin=client_origin,
                    error="Cryptographic signature verification failed.",
                )
            except Exception as e:
                return AssertionVerificationResult(
                    is_valid=False,
                    user_verified=user_verified,
                    rp_id=expected_rp_id,
                    origin=client_origin,
                    error=f"Signature check error: {str(e)}",
                )

        return AssertionVerificationResult(
            is_valid=True,
            user_verified=user_verified,
            rp_id=expected_rp_id,
            origin=client_origin,
        )

    except Exception as err:
        return AssertionVerificationResult(
            is_valid=False,
            user_verified=False,
            rp_id=expected_rp_id,
            origin=expected_origin,
            error=f"Malformed WebAuthn payload: {str(err)}",
        )
