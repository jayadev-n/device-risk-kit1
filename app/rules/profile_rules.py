"""
Advanced Browser Profile Anomaly Detection Rules.
Evaluates:
- HC125: Suspicious browser profile - Spoofing
- HC121: Suspicious browser profile - High risk
- HC120: Suspicious browser profile - Medium risk
- HC118: Suspicious browser profile - Privacy extension
- HC116: Suspicious browser profile - Privacy browser
- HC115: Suspicious browser profile - Potential fraud browser
"""
from typing import Dict, Any, Tuple

# Known privacy-focused browser families
PRIVACY_BROWSERS = {
    "tor browser",
    "brave",
    "epic privacy browser",
    "duckduckgo",
    "mullvad browser",
}

# Anti-detect / fraud browser signatures in UA strings
FRAUD_BROWSER_SIGNATURES = [
    "antidetect",
    "linken sphere",
    "gologin",
    "indigo browser",
    "sessionbox",
    "multilogin",
    "adspower",
    "kameleo",
    "dolphin anty",
    "octo browser",
    "incogniton",
    "x-browser",
    "undetectable",
]

# Privacy extension indicators in headers or missing attributes
PRIVACY_EXTENSION_INDICATORS = [
    "x-do-not-track",
    "dnt",
]

# Headers that legitimate browsers virtually always send
EXPECTED_BROWSER_HEADERS = [
    "accept",
    "accept-language",
    "accept-encoding",
]

# Medium risk: some but not all expected headers missing
# High risk: multiple suspicious signals combined


def evaluate_hc125_spoofing(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC125: Detect OS/platform spoofing — UA says one OS but platform hints say another.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    ua_os = (parsed_ua.get("os", {}).get("family") or "").lower()

    # Check sec-ch-ua-platform header vs parsed OS
    platform_hint = (lower_headers.get("sec-ch-ua-platform") or "").strip().strip('"').lower()
    if platform_hint:
        if "windows" in ua_os and "windows" not in platform_hint:
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"Sec-CH-UA-Platform is '{platform_hint}'."
            )
        if "mac" in ua_os and "mac" not in platform_hint and "macos" not in platform_hint:
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"Sec-CH-UA-Platform is '{platform_hint}'."
            )
        if "linux" in ua_os and "linux" not in platform_hint and "android" not in platform_hint:
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"Sec-CH-UA-Platform is '{platform_hint}'."
            )

    # Check sec-ch-ua-mobile vs device type
    mobile_hint = lower_headers.get("sec-ch-ua-mobile", "")
    is_mobile_ua = parsed_ua.get("is_mobile", False)
    if mobile_hint == "?0" and is_mobile_ua:
        return True, "UA reports mobile device but Sec-CH-UA-Mobile indicates desktop."
    if mobile_hint == "?1" and parsed_ua.get("is_pc", False):
        return True, "UA reports desktop but Sec-CH-UA-Mobile indicates mobile."

    js_platform = (lower_headers.get("x-fp-platform") or "").lower()
    if js_platform:
        if "mac" in ua_os and "win" in js_platform:
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"navigator.platform is '{js_platform}'."
            )
        if "windows" in ua_os and "mac" in js_platform:
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"navigator.platform is '{js_platform}'."
            )
        if ("linux" in ua_os or "ubuntu" in ua_os) and ("win" in js_platform or "mac" in js_platform):
            return True, (
                f"OS spoofing detected: UA reports '{ua_os}' but "
                f"navigator.platform is '{js_platform}'."
            )

    return False, ""


def evaluate_hc121_high_risk_profile(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC121: Multiple simultaneous browser anomaly signals detected — high-risk profile.

    Triggers when 3+ suspicious signals are detected simultaneously.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    signals = []

    # Missing accept header
    if not lower_headers.get("accept"):
        signals.append("missing Accept header")

    # Missing accept-language
    if not lower_headers.get("accept-language"):
        signals.append("missing Accept-Language header")

    # Missing accept-encoding
    if not lower_headers.get("accept-encoding"):
        signals.append("missing Accept-Encoding header")

    # Unknown browser family
    family = (parsed_ua.get("browser", {}).get("family") or "").lower()
    if family in ("other", "unknown", ""):
        signals.append("unrecognized browser family")

    # Very short or missing UA
    if not raw_ua or len(raw_ua) < 20:
        signals.append("suspiciously short/missing User-Agent")

    # No referer (not critical alone, but adds to risk profile)
    if not lower_headers.get("referer") and not lower_headers.get("origin"):
        signals.append("no Referer or Origin header")

    if len(signals) >= 3:
        return True, f"High-risk browser profile: multiple anomalies detected — {'; '.join(signals)}."

    return False, ""


def evaluate_hc120_medium_risk_profile(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC120: Minor header inconsistencies — medium-risk browser profile.

    Triggers when exactly 1–2 suspicious signals are detected (not enough for high risk).

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    signals = []

    if not lower_headers.get("accept"):
        signals.append("missing Accept header")

    if not lower_headers.get("accept-language"):
        signals.append("missing Accept-Language header")

    if not lower_headers.get("accept-encoding"):
        signals.append("missing Accept-Encoding header")

    family = (parsed_ua.get("browser", {}).get("family") or "").lower()
    if family in ("other", "unknown", ""):
        signals.append("unrecognized browser family")

    if not raw_ua or len(raw_ua) < 20:
        signals.append("suspiciously short/missing User-Agent")

    # Medium risk: exactly 1 or 2 signals (high risk handles 3+)
    if 1 <= len(signals) <= 2:
        return True, f"Medium-risk browser profile: minor anomalies — {'; '.join(signals)}."

    return False, ""


def evaluate_hc118_privacy_extension(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC118: Privacy extension detected — blocking telemetry signals.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # DNT header is a classic privacy extension indicator
    if lower_headers.get("dnt") == "1":
        return True, "Do-Not-Track (DNT: 1) header present — privacy extension likely active."

    # GPC (Global Privacy Control) header
    if lower_headers.get("sec-gpc") == "1":
        return True, "Global Privacy Control (Sec-GPC: 1) header present — privacy extension active."

    return False, ""


def evaluate_hc116_privacy_browser(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC116: Privacy-focused browser detected (Tor, Brave, etc.).

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    browser_family = (parsed_ua.get("browser", {}).get("family") or "").lower()

    for pb in PRIVACY_BROWSERS:
        if pb in browser_family:
            return True, f"Privacy-focused browser detected: '{parsed_ua.get('browser', {}).get('family')}'."

    # Check UA string for Tor signatures
    ua_lower = (raw_ua or "").lower()
    if "tor" in ua_lower and "browser" in ua_lower:
        return True, "Tor Browser signature detected in User-Agent string."

    return False, ""


def evaluate_hc115_fraud_browser(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC115: Anti-detect or fingerprint-spoofing browser detected.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    ua_lower = (raw_ua or "").lower()

    for sig in FRAUD_BROWSER_SIGNATURES:
        if sig in ua_lower:
            return True, f"Potential fraud/anti-detect browser signature detected: '{sig}'."

    lower_headers = {k.lower(): v for k, v in headers.items()}
    antidetect = (lower_headers.get("x-antidetect") or "").strip().lower()
    if lower_headers.get("x-browser-fingerprint") or antidetect in ("true", "1", "yes", "detected"):
        return True, "Anti-detect browser custom header detected."

    canvas_noise = (lower_headers.get("x-fp-canvas-noise") or "").strip().lower()
    hw_raw = (lower_headers.get("x-fp-hardware-concurrency") or "").strip()
    hw_fake = False
    try:
        hw_value = int(hw_raw)
        hw_fake = hw_value in (0, 1) or hw_value >= 128
    except (ValueError, TypeError):
        hw_fake = False

    if canvas_noise in ("true", "1", "yes", "patched", "randomized") and hw_fake:
        return True, "Anti-detect profile: randomized canvas hash combined with fake hardware concurrency."
    if canvas_noise in ("true", "1", "yes", "patched", "randomized"):
        return True, "Canvas fingerprint appears patched or randomized by an anti-detect browser."

    return False, ""
