"""Helpers for turning raw event strings into typed, validated fields.

All helpers return None for absent or malformed input rather than guessing.
"""

from __future__ import annotations

import re

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = {"SHA256": 64, "SHA1": 40, "MD5": 32, "IMPHASH": 32}


def to_int(value: str | None) -> int | None:
    """Parse decimal or 0x-prefixed hex integers (Security log uses hex PIDs)."""
    if value is None:
        return None
    text = value.strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def parse_hashes(value: str | None) -> dict[str, str]:
    """Parse Sysmon's ``SHA1=..,MD5=..,SHA256=..,IMPHASH=..`` field.

    Only well-formed hex digests of the expected length are kept.
    """
    result: dict[str, str] = {}
    if not value:
        return result
    for part in value.split(","):
        algo, sep, digest = part.partition("=")
        algo = algo.strip().upper()
        digest = digest.strip()
        if sep and algo in _HASH_LENGTHS and len(digest) == _HASH_LENGTHS[algo] and _HEX.match(digest):
            result[algo] = digest.lower()
    return result


def clean(value: str | None) -> str | None:
    """Treat Sysmon's '-' placeholder and blank strings as absent."""
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in ("", "-") else stripped
