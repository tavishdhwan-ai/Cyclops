"""
Authenticated Encryption Utility for Cyclops Gmail OAuth Credentials.

Uses AES-256-GCM (AEAD) from the maintained Python `cryptography` library,
with per-encryption 96-bit CSPRNG nonces and Authenticated Associated Data (AAD)
cryptographically binding ciphertexts to the owning Cyclops user ID and purpose.

Supports key rotation via versioned ciphertext prefixes (`v1:`) and optional
comma-separated previous decryption keys in `GMAIL_TOKEN_ENCRYPTION_PREVIOUS_KEYS`.
Never falls back to hardcoded secrets or client secrets.
"""
import os
import base64
import binascii
import secrets
from typing import List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


KEY_ENV_VAR = "GMAIL_TOKEN_ENCRYPTION_KEY"
PREVIOUS_KEYS_ENV_VAR = "GMAIL_TOKEN_ENCRYPTION_PREVIOUS_KEYS"
CLIENT_SECRET_ENV_VAR = "GOOGLE_GMAIL_CLIENT_SECRET"
CIPHERTEXT_PREFIX = "v1:"
NONCE_BYTES = 12
KEY_BYTES = 32


class GmailCryptoError(Exception):
    """Base error for Gmail credential cryptography."""


class GmailConfigurationError(GmailCryptoError):
    """Raised when Gmail encryption or OAuth configuration is missing or invalid."""


class GmailDecryptionError(GmailCryptoError):
    """Raised when ciphertext fails authentication tag verification or decoding."""


def _decode_aes256_key(raw_key: str, var_name: str = KEY_ENV_VAR) -> bytes:
    """
    Validates and decodes a 32-byte key from URL-safe base64, standard base64,
    or 64-character hex string. Fails strictly if malformed or wrong length.
    """
    if not raw_key or not isinstance(raw_key, str):
        raise GmailConfigurationError(f"{var_name} is missing.")

    cleaned = raw_key.strip()
    if not cleaned:
        raise GmailConfigurationError(f"{var_name} is empty.")

    # Never allow Google client secret to be reused as encryption key
    client_secret = os.getenv(CLIENT_SECRET_ENV_VAR, "").strip()
    if client_secret and secrets.compare_digest(cleaned, client_secret):
        raise GmailConfigurationError(
            f"{var_name} must be an independent cryptographic key, never {CLIENT_SECRET_ENV_VAR}."
        )

    decoded: bytes | None = None

    # 1. Try 64-char hex
    if len(cleaned) == 64:
        try:
            decoded = bytes.fromhex(cleaned)
        except ValueError:
            decoded = None

    # 2. Try URL-safe or standard base64 (44 chars with padding or 43 without)
    if decoded is None:
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        except (ValueError, binascii.Error, UnicodeEncodeError):
            try:
                decoded = base64.b64decode(padded.encode("ascii"), validate=True)
            except (ValueError, binascii.Error, UnicodeEncodeError):
                decoded = None

    if decoded is None or len(decoded) != KEY_BYTES:
        raise GmailConfigurationError(
            f"{var_name} is invalid: must decode to exactly {KEY_BYTES} bytes (256 bits)."
        )

    return decoded


def get_primary_encryption_key() -> bytes:
    """Loads and validates the primary AES-256-GCM encryption key from environment."""
    raw = os.getenv(KEY_ENV_VAR, "").strip()
    if not raw:
        raise GmailConfigurationError(f"{KEY_ENV_VAR} is not configured.")
    return _decode_aes256_key(raw, KEY_ENV_VAR)


def get_all_decryption_keys() -> List[bytes]:
    """
    Returns [primary_key, *previous_keys] for zero-downtime key rotation.
    Any invalid entries raise GmailConfigurationError.
    """
    keys = [get_primary_encryption_key()]
    prev_raw = os.getenv(PREVIOUS_KEYS_ENV_VAR, "").strip()
    if prev_raw:
        for item in prev_raw.split(","):
            candidate = item.strip()
            if candidate:
                keys.append(_decode_aes256_key(candidate, PREVIOUS_KEYS_ENV_VAR))
    return keys


def validate_encryption_key_configured() -> Tuple[bool, str | None]:
    """Non-throwing check for whether the encryption key is present and valid."""
    try:
        get_all_decryption_keys()
        return True, None
    except GmailConfigurationError as exc:
        return False, str(exc)


def _build_aad(user_id: str, purpose: str) -> bytes:
    """Constructs domain-separated AAD binding ciphertext to user_id and token purpose."""
    if not user_id or not purpose:
        raise GmailCryptoError("Both user_id and purpose are required for authenticated encryption.")
    return f"cyclops:gmail:{purpose}:{user_id}".encode("utf-8")


def encrypt_secret(plaintext: str, user_id: str, purpose: str = "refresh_token") -> str:
    """
    Encrypts a secret string using AES-256-GCM with a fresh 96-bit random nonce
    and authenticated associated data bound to `user_id` and `purpose`.
    Returns versioned string `v1:<urlsafe_b64(nonce + ciphertext + tag)>`.
    """
    if not plaintext or not isinstance(plaintext, str):
        raise GmailCryptoError("Plaintext secret must be a non-empty string.")

    key = get_primary_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_BYTES)
    aad = _build_aad(user_id, purpose)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    blob = base64.urlsafe_b64encode(nonce + ct).decode("ascii")
    return f"{CIPHERTEXT_PREFIX}{blob}"


def decrypt_secret(token_ciphertext: str, user_id: str, purpose: str = "refresh_token") -> str:
    """
    Decrypts and verifies an AES-256-GCM ciphertext against `user_id` and `purpose`.
    Supports decrypting with previous keys during key rotation.
    """
    if not token_ciphertext or not isinstance(token_ciphertext, str):
        raise GmailDecryptionError("Encrypted secret payload is empty.")

    if not token_ciphertext.startswith(CIPHERTEXT_PREFIX):
        raise GmailDecryptionError("Unsupported ciphertext version format.")

    payload_b64 = token_ciphertext[len(CIPHERTEXT_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise GmailDecryptionError("Malformed ciphertext encoding.") from exc

    if len(raw) <= NONCE_BYTES + 16:
        raise GmailDecryptionError("Ciphertext payload is truncated.")

    nonce = raw[:NONCE_BYTES]
    ct = raw[NONCE_BYTES:]
    aad = _build_aad(user_id, purpose)

    keys = get_all_decryption_keys()
    for key in keys:
        try:
            plaintext_bytes = AESGCM(key).decrypt(nonce, ct, aad)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag:
            continue

    raise GmailDecryptionError("Failed to verify ciphertext integrity or key mismatch.")
