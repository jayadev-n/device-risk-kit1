"""
Device ID Hash Generator.
Produces deterministic SHA-256 device identifier based on network and browser attributes.
"""
import hashlib
from typing import Optional, Dict, Any


def generate_device_id(
    ip: Optional[str],
    user_agent: Optional[str],
    accept_language: Optional[str],
    extra_attributes: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a deterministic SHA-256 hex digest identifying a client device.

    Args:
        ip: Remote client IP address.
        user_agent: HTTP User-Agent header string.
        accept_language: HTTP Accept-Language header string.
        extra_attributes: Optional dictionary of client attributes (e.g. canvas hash, screen resolution).

    Returns:
        Hex-encoded SHA-256 digest string (64 characters).
    """
    clean_ip = (ip or "").strip()
    clean_ua = (user_agent or "").strip()
    clean_lang = (accept_language or "").strip()

    fingerprint_parts = [
        f"ip:{clean_ip}",
        f"ua:{clean_ua}",
        f"lang:{clean_lang}",
    ]

    if extra_attributes and isinstance(extra_attributes, dict):
        # Sort keys deterministically
        for key in sorted(extra_attributes.keys()):
            val = extra_attributes[key]
            if val is not None:
                fingerprint_parts.append(f"{key}:{str(val).strip()}")

    raw_signature = "|".join(fingerprint_parts)
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()
