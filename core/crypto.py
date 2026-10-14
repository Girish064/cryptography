"""AgentShield V3 — Cryptographic Operations & Key Management.

Provides high-performance, battle-tested Ed25519 signature generation and
verification, supporting URL-safe Base64 and Hex encodings for transparent
transport across CLI, REST APIs, and offline verification tools.
"""

from __future__ import annotations

import base64
import os
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

PrivateKeyType = Union[ed25519.Ed25519PrivateKey, str, bytes]
PublicKeyType = Union[ed25519.Ed25519PublicKey, str, bytes]


def generate_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair and return (private_key_b64, public_key_b64)."""
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return (private_key_to_b64(priv_key), public_key_to_b64(pub_key))


def private_key_to_b64(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Export raw 32-byte Ed25519 private key as a URL-safe Base64 string."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_key_to_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    """Export raw 32-byte Ed25519 public key as a URL-safe Base64 string."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def private_key_from_b64(b64_str: str) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from URL-safe or standard Base64 string."""
    padding = "=" * ((4 - len(b64_str) % 4) % 4)
    raw = base64.urlsafe_b64decode(b64_str + padding)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_b64(b64_str: str) -> ed25519.Ed25519PublicKey:
    """Load an Ed25519 public key from URL-safe or standard Base64 string."""
    padding = "=" * ((4 - len(b64_str) % 4) % 4)
    raw = base64.urlsafe_b64decode(b64_str + padding)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def _coerce_private_key(key: PrivateKeyType) -> ed25519.Ed25519PrivateKey:
    """Convert supported private key representations into Ed25519PrivateKey."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key
    if isinstance(key, bytes):
        if len(key) == 32:
            return ed25519.Ed25519PrivateKey.from_private_bytes(key)
        key = key.decode("utf-8")
    if isinstance(key, str):
        # Try hex if 64 characters
        if len(key) == 64:
            try:
                return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key))
            except ValueError:
                pass
        return private_key_from_b64(key)
    raise TypeError(f"Unsupported private key type: {type(key)}")


def _coerce_public_key(key: PublicKeyType) -> ed25519.Ed25519PublicKey:
    """Convert supported public key representations into Ed25519PublicKey."""
    if isinstance(key, ed25519.Ed25519PublicKey):
        return key
    if isinstance(key, bytes):
        if len(key) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(key)
        key = key.decode("utf-8")
    if isinstance(key, str):
        if len(key) == 64:
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
            except ValueError:
                pass
        return public_key_from_b64(key)
    raise TypeError(f"Unsupported public key type: {type(key)}")


def sign(message: Union[bytes, str], private_key: PrivateKeyType) -> str:
    """Cryptographically sign a message with an Ed25519 private key.

    Returns the signature as a URL-safe Base64 string without trailing '=' padding.
    """
    msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
    priv_key_obj = _coerce_private_key(private_key)
    signature_bytes = priv_key_obj.sign(msg_bytes)
    return base64.urlsafe_b64encode(signature_bytes).decode("ascii").rstrip("=")


def verify(signature: Union[str, bytes], message: Union[bytes, str], public_key: PublicKeyType) -> bool:
    """Verify an Ed25519 signature over a message using a public key.

    Returns True if mathematically valid; False if forged, altered, or malformed.
    """
    try:
        msg_bytes = message.encode("utf-8") if isinstance(message, str) else message
        pub_key_obj = _coerce_public_key(public_key)

        if isinstance(signature, str):
            padding = "=" * ((4 - len(signature) % 4) % 4)
            sig_bytes = base64.urlsafe_b64decode(signature + padding)
        else:
            sig_bytes = signature

        pub_key_obj.verify(sig_bytes, msg_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_keypair_from_env(
    priv_var: str = "AGENTSHIELD_PRIVATE_KEY",
    pub_var: str = "AGENTSHIELD_PUBLIC_KEY",
) -> tuple[str, str] | None:
    """Load base64-encoded keypair from environment variables if present."""
    priv = os.environ.get(priv_var)
    pub = os.environ.get(pub_var)
    if priv and pub:
        return (priv.strip(), pub.strip())
    return None
