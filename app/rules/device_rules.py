"""
Device & Environment Signal Detection Rules.
Evaluates:
- HC113: Unpopular device screen resolution
- HC110: Customer's mobile device is rooted
- HC109: Customer's mobile device is jailbroken
- HC108: Customer's mobile device is an emulator
- HC100: Timezone mismatch (IP vs device)
- HC102: Cookies not enabled
- HC101: More than 2 different IP addresses via WebRTC
- HC126: More than 1 user with same device fingerprint
"""
from typing import Dict, Any, Tuple

# Common legitimate screen resolutions (width x height strings)
COMMON_RESOLUTIONS = {
    # Desktop
    "1920x1080", "1366x768", "1440x900", "1280x800", "1280x1024",
    "1600x900", "1024x768", "2560x1440", "3840x2160", "1920x1200",
    "1680x1050", "1360x768", "2560x1080", "1280x720", "1920x1440",
    "2048x1152", "1400x1050", "1600x1024", "1152x864", "1024x600",
    # Mobile / Tablet
    "375x667", "414x896", "390x844", "393x852", "412x915",
    "360x800", "360x780", "375x812", "414x736", "360x640",
    "768x1024", "820x1180", "800x1280", "1024x1366", "800x600",
    "1280x800", "600x1024",
}

# Known Android emulator screen resolutions
EMULATOR_RESOLUTIONS = {
    "1080x1920", "1440x2960", "1080x2340",  # common emulator defaults
    "1111x333",  # headless emulator artifact
    "0x0",       # JS unavailable / headless
}

# Emulator-specific UA keywords
EMULATOR_UA_KEYWORDS = [
    "android emulator",
    "sdk_gphone",
    "sdk_gphone64",
    "generic_x86",
    "bluestacks",
    "nox",
    "memu",
    "ldplayer",
    "genymotion",
    "android sdk built for x86",
    "emulator",
]

# Jailbreak indicators in device info
JAILBREAK_INDICATORS = [
    "cydia",
    "substrate",
    "jailbroken",
    "unc0ver",
    "checkra1n",
    "electra",
    "meridian",
]

# Root indicators for Android
ROOT_INDICATORS = [
    "supersu",
    "magisk",
    "su binary",
    "rooted",
    "busybox",
    "kingroot",
    "towelroot",
]


def evaluate_hc113_screen_resolution(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC113: Unusual, zero, or non-standard screen resolution detected.

    Looks for screen_resolution in the x-fp-* custom headers or client-hints.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    resolution = (
        lower_headers.get("x-fp-screen-resolution")
        or lower_headers.get("x-screen-resolution")
        or lower_headers.get("x-resolution")
        or ""
    ).strip()

    if not resolution:
        return False, ""  # Can't evaluate without data

    if resolution == "0x0":
        return True, "Screen resolution reported as 0x0 — likely headless or JS unavailable."

    if resolution == "1111x333" or resolution in EMULATOR_RESOLUTIONS:
        return True, f"Screen resolution '{resolution}' matches an anomalous or emulator viewport."

    # Check for very unusual aspect ratios or tiny dimensions
    try:
        parts = resolution.lower().replace(" ", "").split("x")
        if len(parts) == 2:
            w, h = int(parts[0]), int(parts[1])
            if w < 100 or h < 100:
                return True, f"Extremely small screen resolution: '{resolution}'."
            if w > 7680 or h > 4320:
                return True, f"Unrealistically large screen resolution: '{resolution}'."
    except (ValueError, TypeError):
        return True, f"Malformed screen resolution value: '{resolution}'."

    return False, ""


def evaluate_hc110_rooted_device(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC110: Android device appears to be rooted.

    Looks for root indicators in custom fingerprint headers or UA string.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    device_signal = (
        lower_headers.get("x-fp-device-security")
        or lower_headers.get("x-device-security")
        or lower_headers.get("x-fp-root")
        or ""
    ).lower()

    for indicator in ROOT_INDICATORS:
        if indicator in device_signal:
            return True, f"Root indicator detected in device security signal: '{indicator}'."

    # UA string may also leak root info in some SDK implementations
    ua_lower = (raw_ua or "").lower()
    for indicator in ROOT_INDICATORS:
        if indicator in ua_lower:
            return True, f"Root indicator detected in User-Agent: '{indicator}'."

    # Check explicit header flag
    if lower_headers.get("x-fp-is-rooted") in ("true", "1", "yes"):
        return True, "Device explicitly reported as rooted via fingerprint header."

    return False, ""


def evaluate_hc109_jailbroken_device(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC109: iOS device appears to be jailbroken.

    Looks for jailbreak indicators in custom fingerprint headers or UA string.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    device_signal = (
        lower_headers.get("x-fp-device-security")
        or lower_headers.get("x-device-security")
        or lower_headers.get("x-fp-jailbreak")
        or ""
    ).lower()

    for indicator in JAILBREAK_INDICATORS:
        if indicator in device_signal:
            return True, f"Jailbreak indicator detected in device security signal: '{indicator}'."

    # Check explicit header flag
    if lower_headers.get("x-fp-is-jailbroken") in ("true", "1", "yes"):
        return True, "Device explicitly reported as jailbroken via fingerprint header."

    return False, ""


def evaluate_hc108_emulator(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC108: Device appears to be an Android/iOS emulator.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Check explicit emulator flag
    if lower_headers.get("x-fp-is-emulator") in ("true", "1", "yes"):
        return True, "Device explicitly reported as emulator via fingerprint header."

    ua_lower = (raw_ua or "").lower()
    for keyword in EMULATOR_UA_KEYWORDS:
        if keyword in ua_lower:
            return True, f"Emulator keyword detected in User-Agent: '{keyword}'."

    js_platform = (
        lower_headers.get("x-fp-platform")
        or lower_headers.get("x-fp-cpu-arch")
        or ""
    ).lower()
    mobile_ua = parsed_ua.get("is_mobile") or any(
        token in ua_lower for token in ("iphone", "ipad", "android", "mobile")
    )
    desktop_arch = any(
        token in js_platform
        for token in ("win32", "win64", "x86_64", "x86-64", "macintel", "linux x86")
    )
    if mobile_ua and desktop_arch:
        return True, (
            "Mobile user-agent is running on desktop architecture "
            f"({js_platform or 'x86_64'}) — likely an emulated iPhone/Android session."
        )

    return False, ""


def evaluate_hc100_timezone_mismatch(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC100: Device timezone does not match IP geolocation timezone.

    Looks for timezone info sent via custom fingerprint headers.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    device_tz = (
        lower_headers.get("x-fp-timezone")
        or lower_headers.get("x-timezone")
        or ""
    ).strip()

    ip_tz = (
        lower_headers.get("x-ip-timezone")
        or lower_headers.get("x-geoip-timezone")
        or ""
    ).strip()

    if not device_tz or not ip_tz:
        return False, ""  # Can't compare without both values

    # Normalize: strip common prefixes and compare region
    def region(tz: str) -> str:
        # e.g. "America/New_York" -> "America", "UTC+5:30" -> "UTC+5:30"
        parts = tz.replace("_", " ").split("/")
        return parts[0].strip().lower()

    if region(device_tz) != region(ip_tz):
        return True, (
            f"Timezone mismatch: device reports '{device_tz}' but "
            f"IP geolocation indicates '{ip_tz}'."
        )

    return False, ""


def evaluate_hc102_cookies_disabled(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC102: Client browser has cookies disabled.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    cookies_enabled = lower_headers.get("x-fp-cookies-enabled") or lower_headers.get("x-cookies-enabled")
    if cookies_enabled is not None:
        if cookies_enabled.lower() in ("false", "0", "no"):
            return True, "Client reported cookies as disabled via fingerprint header."

    return False, ""


def evaluate_hc101_webrtc_multiple_ips(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC101: More than 2 different IPs detected via WebRTC leak.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    webrtc_ips_raw = (
        lower_headers.get("x-fp-webrtc-ips")
        or lower_headers.get("x-webrtc-ips")
        or ""
    ).strip()

    if not webrtc_ips_raw:
        return False, ""

    ips = [ip.strip() for ip in webrtc_ips_raw.split(",") if ip.strip()]
    unique_ips = set(ips)

    if len(unique_ips) > 2:
        return True, (
            f"WebRTC IP leak detected: {len(unique_ips)} unique IPs found "
            f"({', '.join(list(unique_ips)[:4])}{'...' if len(unique_ips) > 4 else ''}) — "
            "indicates proxy or VPN usage."
        )

    return False, ""


def evaluate_hc126_shared_device_fingerprint(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC126: Same device fingerprint shared by multiple distinct users.

    This is typically evaluated using a backend database lookup. Here we
    check for an explicit signal sent in the request header by the client SDK.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    shared_users_raw = (
        lower_headers.get("x-fp-shared-user-count")
        or lower_headers.get("x-shared-device-count")
        or ""
    ).strip()

    if shared_users_raw:
        try:
            count = int(shared_users_raw)
            if count >= 6:
                return True, (
                    f"Device fingerprint is shared by {count} distinct user accounts "
                    "in the last 30 days."
                )
        except ValueError:
            pass

    return False, ""
