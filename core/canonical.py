"""AgentShield V3 — Deterministic Canonical Action Representation & Hashing.

Ensures that identical semantic actions produce identical canonical bytes and
cryptographic hashes regardless of JSON key ordering, formatting, or platform.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any, Mapping

ACTION_DOMAIN_PREFIX: bytes = b"AGENTSHIELD-V3-ACTION\x00"


def _normalize_obj(obj: Any) -> Any:
    """Recursively normalize data structure for deterministic serialization.

    - Strings are normalized to Unicode Normalization Form C (NFC).
    - Mappings/Dicts have their keys normalized to NFC and sorted.
    - Iterables (lists/tuples) have their elements normalized.
    """
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    elif isinstance(obj, Mapping):
        # Recursively normalize keys and values, sorting keys
        return {
            unicodedata.normalize("NFC", str(k)): _normalize_obj(v)
            for k, v in sorted(obj.items(), key=lambda item: unicodedata.normalize("NFC", str(item[0])))
        }
    elif isinstance(obj, (list, tuple)):
        return [_normalize_obj(item) for item in obj]
    elif hasattr(obj, "model_dump") and callable(obj.model_dump):
        # Support Pydantic v2 models directly
        return _normalize_obj(obj.model_dump())
    elif hasattr(obj, "dict") and callable(obj.dict):
        # Support Pydantic v1 models
        return _normalize_obj(obj.dict())
    return obj


def canonicalize(data: Any) -> bytes:
    """Produce deterministic, whitespace-free canonical UTF-8 bytes from any data structure.

    Guarantees:
    - Identical key/value content in different dictionary insertion order produces the exact same bytes.
    - No extraneous whitespace (compact separators ',' and ':').
    - Unicode NFC normalization applied across all string keys and values.
    """
    normalized = _normalize_obj(data)
    canonical_json_str = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_json_str.encode("utf-8")


def hash_action(action: Any) -> str:
    """Calculate the deterministic SHA-256 action digest with domain separation.

    Digest = SHA256(b"AGENTSHIELD-V3-ACTION\x00" + canonical_bytes)
    Returns a 64-character lowercase hexadecimal string.
    """
    canonical_bytes = canonicalize(action)
    hasher = hashlib.sha256()
    hasher.update(ACTION_DOMAIN_PREFIX)
    hasher.update(canonical_bytes)
    return hasher.hexdigest()
