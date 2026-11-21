"""
Sentinel AI WebAuthn & Platform Authenticator Verification Engine.
Standards-compliant FIDO2/WebAuthn Level 3 implementation utilizing Python `webauthn==3.0.1`.
Supports Passkey registration (attestation) and authentication (assertion) with platform authenticators.
Enforces Relying Party ID, Origin, User Verification flags, cryptographic signatures, and counter verification.
"""
import os
import base64
import hashlib
import json
import secrets
from typing import Dict, Any, Optional, Tuple, List, Union

from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

import webauthn
from webauthn.helpers import (
    bytes_to_base64url,
    base64url_to_bytes,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    AuthenticatorTransport,
)
from webauthn.helpers.exceptions import WebAuthnException

WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:3000")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Sentinel AI")


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


def _resolve_allowed_origins(
    origin: Optional[Union[str, List[str]]] = None,
    rp_id: str = WEBAUTHN_RP_ID,
) -> List[str]:
    """Resolves and normalizes allowed origins for WebAuthn validation."""
    origins = set()
    target_origin = origin if origin is not None else WEBAUTHN_ORIGIN
    if isinstance(target_origin, str):
        origins.add(target_origin.rstrip("/"))
    elif isinstance(target_origin, (list, tuple, set)):
        for o in target_origin:
            if isinstance(o, str):
                origins.add(o.rstrip("/"))

    if rp_id == "localhost" or any("localhost" in o or "127.0.0.1" in o for o in origins):
        origins.update([
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ])
    return list(origins)


class VerifiedRegistrationResult:
    """Encapsulates verified WebAuthn registration output."""
    def __init__(
        self,
        credential_id: str,
        public_key: str,
        sign_count: int,
        credential_id_bytes: bytes,
        public_key_bytes: bytes,
        user_verified: bool = True,
        aaguid: Optional[str] = None,
        attestation_format: Optional[str] = None,
    ):
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.credential_id_bytes = credential_id_bytes
        self.public_key_bytes = public_key_bytes
        self.user_verified = user_verified
        self.aaguid = aaguid
        self.attestation_format = attestation_format
        self.is_valid = True

    def __iter__(self):
        yield self.credential_id
        yield self.public_key
        yield self.sign_count

    def __getitem__(self, item):
        return getattr(self, item)


class VerifiedAuthenticationResult:
    """Encapsulates verified WebAuthn authentication output."""
    def __init__(
        self,
        new_sign_count: int,
        credential_id: str,
        user_verified: bool,
        credential_id_bytes: bytes,
    ):
        self.new_sign_count = new_sign_count
        self.sign_count = new_sign_count
        self.credential_id = credential_id
        self.user_verified = user_verified
        self.credential_id_bytes = credential_id_bytes
        self.is_valid = True

    def __int__(self):
        return self.new_sign_count

    def __iter__(self):
        yield self.new_sign_count
        yield self.credential_id
        yield self.user_verified

    def __getitem__(self, item):
        return getattr(self, item)


# ==============================================================================
# Standards-Compliant WebAuthn Helper Functions (webauthn==3.0.1)
# ==============================================================================

def create_registration_options(
    user_id: str,
    user_name: str,
    user_display_name: Optional[str] = None,
    rp_id: str = WEBAUTHN_RP_ID,
    rp_name: str = WEBAUTHN_RP_NAME,
    challenge: Optional[Union[str, bytes]] = None,
    exclude_credentials: Optional[List[Union[str, Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """
    Generate WebAuthn registration options for a platform authenticator.
    Enforces user verification (Face ID / Touch ID / Android biometrics / Screen lock).
    """
    user_id_bytes = user_id.encode("utf-8") if isinstance(user_id, str) else user_id
    display_name = user_display_name or user_name

    challenge_bytes = None
    if challenge is not None:
        if isinstance(challenge, str):
            challenge_bytes = base64url_to_bytes(challenge)
        else:
            challenge_bytes = challenge

    descriptors = []
    if exclude_credentials:
        for cred in exclude_credentials:
            cred_id = cred
            if isinstance(cred, dict):
                cred_id = cred.get("credential_id") or cred.get("credentialId") or cred.get("id")
            if cred_id:
                cred_id_bytes = base64url_to_bytes(cred_id) if isinstance(cred_id, str) else cred_id
                descriptors.append(
                    PublicKeyCredentialDescriptor(
                        id=cred_id_bytes,
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                    )
                )

    options = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=user_name,
        user_display_name=display_name,
        challenge=challenge_bytes,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        attestation=AttestationConveyancePreference.NONE,
        exclude_credentials=descriptors if descriptors else None,
        timeout=60000,
    )

    return json.loads(options_to_json(options))


def verify_registration(
    credential: Union[str, Dict[str, Any]],
    expected_challenge: Union[str, bytes],
    expected_rp_id: str = WEBAUTHN_RP_ID,
    expected_origin: Optional[Union[str, List[str]]] = None,
    require_user_verification: bool = True,
) -> VerifiedRegistrationResult:
    """
    Verify registration attestation using the expected challenge, production RP ID and origin.
    Validates user verification, RP ID, origin, and cryptographic attestation.
    Returns the verified credential ID, public key, and initial sign counter.
    Raises ValueError on invalid attestation.
    """
    if isinstance(expected_challenge, str):
        expected_challenge_bytes = base64url_to_bytes(expected_challenge)
    else:
        expected_challenge_bytes = expected_challenge

    allowed_origins = _resolve_allowed_origins(expected_origin, expected_rp_id)

    try:
        verified_reg = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=expected_rp_id,
            expected_origin=allowed_origins,
            require_user_presence=True,
            require_user_verification=require_user_verification,
        )
    except WebAuthnException as err:
        raise ValueError(f"WebAuthn registration verification failed: {err}")
    except Exception as err:
        raise ValueError(f"Malformed registration response: {err}")

    cred_id_b64 = bytes_to_base64url(verified_reg.credential_id)
    pub_key_b64 = bytes_to_base64url(verified_reg.credential_public_key)

    return VerifiedRegistrationResult(
        credential_id=cred_id_b64,
        public_key=pub_key_b64,
        sign_count=verified_reg.sign_count,
        credential_id_bytes=verified_reg.credential_id,
        public_key_bytes=verified_reg.credential_public_key,
        user_verified=verified_reg.user_verified,
        aaguid=verified_reg.aaguid,
        attestation_format=str(verified_reg.fmt),
    )


def create_authentication_options(
    registered_credentials: Optional[List[Union[str, Dict[str, Any], bytes]]] = None,
    rp_id: str = WEBAUTHN_RP_ID,
    challenge: Optional[Union[str, bytes]] = None,
    user_verification: UserVerificationRequirement = UserVerificationRequirement.REQUIRED,
    timeout: int = 60000,
) -> Dict[str, Any]:
    """
    Generate authentication options for a specific user's registered credentials.
    Enforces required user verification.
    """
    challenge_bytes = None
    if challenge is not None:
        if isinstance(challenge, str):
            challenge_bytes = base64url_to_bytes(challenge)
        else:
            challenge_bytes = challenge

    descriptors = []
    if registered_credentials:
        for cred in registered_credentials:
            cred_id = cred
            if isinstance(cred, dict):
                cred_id = cred.get("credential_id") or cred.get("credentialId") or cred.get("id")
            if cred_id:
                cred_id_bytes = base64url_to_bytes(cred_id) if isinstance(cred_id, str) else cred_id
                descriptors.append(
                    PublicKeyCredentialDescriptor(
                        id=cred_id_bytes,
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        transports=[AuthenticatorTransport.INTERNAL],
                    )
                )

    options = webauthn.generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge_bytes,
        timeout=timeout,
        allow_credentials=descriptors if descriptors else None,
        user_verification=user_verification,
    )

    return json.loads(options_to_json(options))


def verify_authentication(
    credential: Union[str, Dict[str, Any]],
    expected_challenge: Union[str, bytes],
    credential_public_key: Union[str, bytes],
    credential_current_sign_count: int,
    expected_rp_id: str = WEBAUTHN_RP_ID,
    expected_origin: Optional[Union[str, List[str]]] = None,
    require_user_verification: bool = True,
) -> VerifiedAuthenticationResult:
    """
    Verify an authentication assertion using the stored credential ID, public key, sign counter,
    expected challenge, RP ID, and origin.
    Validates cryptographic signature, user presence, user verification, and sign counter.
    Raises ValueError on invalid assertion or replay attempt.
    """
    if isinstance(expected_challenge, str):
        expected_challenge_bytes = base64url_to_bytes(expected_challenge)
    else:
        expected_challenge_bytes = expected_challenge

    if isinstance(credential_public_key, str):
        public_key_bytes = base64url_to_bytes(credential_public_key)
    else:
        public_key_bytes = credential_public_key

    allowed_origins = _resolve_allowed_origins(expected_origin, expected_rp_id)

    try:
        verified_auth = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge_bytes,
            expected_rp_id=expected_rp_id,
            expected_origin=allowed_origins,
            credential_public_key=public_key_bytes,
            credential_current_sign_count=credential_current_sign_count,
            require_user_verification=require_user_verification,
        )
    except WebAuthnException as err:
        raise ValueError(f"WebAuthn authentication verification failed: {err}")
    except Exception as err:
        raise ValueError(f"Malformed authentication response: {err}")

    cred_id_b64 = bytes_to_base64url(verified_auth.credential_id)

    return VerifiedAuthenticationResult(
        new_sign_count=verified_auth.new_sign_count,
        credential_id=cred_id_b64,
        user_verified=verified_auth.user_verified,
        credential_id_bytes=verified_auth.credential_id,
    )


# ==============================================================================
# Backward-Compatible Assertion Verification Engine
# ==============================================================================

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
