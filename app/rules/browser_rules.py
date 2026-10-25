"""
Browser Anomaly Detection Rules.
Evaluates:
- Rule HC124: Outdated browser version
- Rule HC114: Unpopular or unknown user agent
"""
from typing import Dict, Any, Tuple

# Outdated browser major version thresholds
# Browsers with major versions strictly lower than these thresholds are flagged
MINIMUM_SUPPORTED_VERSIONS = {
    "chrome": 80,
    "chromium": 80,
    "firefox": 75,
    "safari": 13,
    "mobile safari": 13,
    "edge": 80,
    "opera": 65,
    "opera mobile": 65,
}

# Common recognized legitimate browser families
COMMON_BROWSER_FAMILIES = {
    "chrome",
    "chromium",
    "firefox",
    "safari",
    "mobile safari",
    "edge",
    "opera",
    "opera mobile",
    "samsung internet",
    "android",
    "uc browser",
    "yandex browser",
    "brave",
    "vivaldi",
}


def evaluate_hc124_outdated_browser(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC124: Check if browser major version is outdated (e.g., Chrome < 80, Firefox < 75).

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    browser_info = parsed_ua.get("browser", {})
    family = (browser_info.get("family") or "").strip().lower()
    major_version = browser_info.get("major")

    # Flag Internet Explorer explicitly as obsolete
    if "ie" in family or "internet explorer" in family:
        return True, f"Obsolete/unsupported browser detected: '{browser_info.get('family')} {browser_info.get('version')}'."

    # Check known browser threshold
    if family in MINIMUM_SUPPORTED_VERSIONS:
        threshold = MINIMUM_SUPPORTED_VERSIONS[family]
        if major_version is not None and major_version < threshold:
            return True, (
                f"Browser version is outdated: {browser_info.get('family')} {major_version} "
                f"(minimum recommended: {threshold})."
            )

    return False, ""


def evaluate_hc114_unknown_user_agent(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC114: Check if the user agent is unpopular, unknown, or missing.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    clean_ua = (raw_ua or "").strip()

    if not clean_ua:
        return True, "User-Agent header is missing or empty."

    # Unusually short UA strings are typically crafted or minimal clients
    if len(clean_ua) < 10:
        return True, f"Suspiciously short or generic User-Agent: '{clean_ua}'."

    browser_family = (parsed_ua.get("browser", {}).get("family") or "").strip().lower()

    if browser_family in ("other", "unknown", ""):
        return True, f"Unrecognized or unknown browser family: '{parsed_ua.get('browser', {}).get('family')}'."

    if browser_family not in COMMON_BROWSER_FAMILIES and not parsed_ua.get("is_bot", False):
        return True, f"Uncommon or unpopular browser family: '{parsed_ua.get('browser', {}).get('family')}'."

    return False, ""
