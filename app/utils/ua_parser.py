"""
User-Agent Parser.
Extracts structured browser, OS, and device metadata from raw User-Agent strings.
"""
from typing import Optional, Dict, Any
import user_agents


def parse_user_agent(raw_user_agent: Optional[str]) -> Dict[str, Any]:
    """
    Parse a raw User-Agent string into a structured metadata dictionary.

    Args:
        raw_user_agent: Raw User-Agent string from HTTP headers.

    Returns:
        Structured dictionary containing parsed browser, OS, device info, and flags.
    """
    safe_ua = (raw_user_agent or "").strip()

    if not safe_ua:
        return {
            "browser": {
                "family": "Other",
                "version": "",
                "major": None,
                "minor": None,
            },
            "os": {
                "family": "Other",
                "version": "",
                "major": None,
                "minor": None,
            },
            "device": {
                "family": "Other",
                "brand": None,
                "model": None,
            },
            "is_bot": False,
            "is_mobile": False,
            "is_tablet": False,
            "is_pc": False,
            "is_touch_capable": False,
            "raw_user_agent": "",
        }

    parsed = user_agents.parse(safe_ua)

    browser_major = None
    if parsed.browser.version and len(parsed.browser.version) > 0:
        try:
            browser_major = int(parsed.browser.version[0])
        except (ValueError, TypeError):
            browser_major = None

    os_major = None
    if parsed.os.version and len(parsed.os.version) > 0:
        try:
            os_major = int(parsed.os.version[0])
        except (ValueError, TypeError):
            os_major = None

    return {
        "browser": {
            "family": parsed.browser.family or "Other",
            "version": parsed.browser.version_string or "",
            "major": browser_major,
            "minor": parsed.browser.version[1] if len(parsed.browser.version) > 1 else None,
        },
        "os": {
            "family": parsed.os.family or "Other",
            "version": parsed.os.version_string or "",
            "major": os_major,
            "minor": parsed.os.version[1] if len(parsed.os.version) > 1 else None,
        },
        "device": {
            "family": parsed.device.family or "Other",
            "brand": parsed.device.brand,
            "model": parsed.device.model,
        },
        "is_bot": bool(parsed.is_bot),
        "is_mobile": bool(parsed.is_mobile),
        "is_tablet": bool(parsed.is_tablet),
        "is_pc": bool(parsed.is_pc),
        "is_touch_capable": bool(parsed.is_touch_capable),
        "raw_user_agent": safe_ua,
    }
