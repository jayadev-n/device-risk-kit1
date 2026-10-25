"""
Observational / Behavioral Signal Detection Rules.
Evaluates rules that rely on client-side signals sent via custom headers:
- HC133: Dynamic Component Blocked (canvas/WebGL failure)
- HC134: Customer is using Proxy/VPN
- HC135: Click automator installed
- HC136: Screen mirrored to additional display
- HC137: Remote desktop software in use
- HC138: Phone screen captured during transaction (iOS)
- HC139: User on phone call during transaction
- HC140: Device connected to PC via USB
"""
from typing import Dict, Any, Tuple

# Known datacenter/VPN ASN prefixes or org name keywords
VPN_ORG_KEYWORDS = [
    "vpn", "proxy", "datacenter", "hosting", "cloud", "server",
    "digitalocean", "linode", "vultr", "amazon", "google cloud",
    "microsoft azure", "ovh", "hetzner", "nordvpn", "expressvpn",
    "mullvad", "surfshark", "private internet access", "pia",
    "tor exit", "anonymizer",
]


def _get_flag(headers_lower: dict, *keys: str) -> str:
    """Return the first non-empty value among the given header keys."""
    for key in keys:
        val = headers_lower.get(key, "").strip().lower()
        if val:
            return val
    return ""


def evaluate_hc133_dynamic_component_blocked(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC133: Canvas/WebGL dynamic fingerprinting components were blocked or unavailable.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-canvas-blocked", "x-canvas-blocked", "x-fp-webgl-blocked")
    if flag in ("true", "1", "yes", "blocked"):
        return True, "Canvas or WebGL dynamic component was blocked — client-side fingerprinting unavailable."

    canvas_hash = (lower_headers.get("x-fp-canvas-hash") or "").strip()
    if canvas_hash in ("unavailable", "blocked", "error", "null", "none"):
        return True, f"Canvas hash reported as '{canvas_hash}' — dynamic JS component blocked."

    return False, ""


def evaluate_hc134_vpn_proxy(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC134: Client IP belongs to a known VPN, proxy, or datacenter provider.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # Explicit VPN flag from enrichment layer
    is_vpn = _get_flag(lower_headers, "x-fp-is-vpn", "x-is-vpn", "x-fp-vpn-detected")
    if is_vpn in ("true", "1", "yes"):
        return True, "IP identified as VPN/proxy/datacenter via enrichment flag."

    is_proxy = _get_flag(lower_headers, "x-fp-is-proxy", "x-is-proxy")
    if is_proxy in ("true", "1", "yes"):
        return True, "IP identified as proxy/anonymizer via enrichment flag."

    # Check ASN org name for VPN keywords
    isp_org = (lower_headers.get("x-fp-isp") or lower_headers.get("x-isp") or "").lower()
    for keyword in VPN_ORG_KEYWORDS:
        if keyword in isp_org:
            return True, f"ISP/ASN organization '{isp_org}' matches known VPN/datacenter provider."

    # Check for common proxy forwarding headers that real proxies add
    if lower_headers.get("via") and "proxy" in lower_headers.get("via", "").lower():
        return True, "HTTP Via header indicates request passed through a proxy."

    return False, ""


def evaluate_hc135_click_automator(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC135: Click automation script or bot extension detected.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-click-automator", "x-click-automator", "x-fp-automation-detected")
    if flag in ("true", "1", "yes", "detected"):
        return True, "Click automator or DOM automation script detected on page."

    click_trusted = _get_flag(lower_headers, "x-fp-click-trusted", "x-click-trusted")
    if click_trusted in ("false", "0", "no"):
        return True, "Synthetic mouse/click event detected (isTrusted == false)."

    return False, ""


def evaluate_hc136_screen_mirrored(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC136: Screen is being mirrored to an additional external display.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-screen-mirrored", "x-screen-mirrored", "x-fp-multi-display")
    if flag in ("true", "1", "yes", "active"):
        return True, "Screen mirroring or external display capture session is active."

    # Check number of screens reported
    screen_count_raw = lower_headers.get("x-fp-screen-count") or lower_headers.get("x-screen-count") or ""
    try:
        count = int(screen_count_raw.strip())
        if count > 1:
            return True, f"Multiple displays detected: {count} screens active — possible screen mirroring."
    except (ValueError, TypeError):
        pass

    return False, ""


def evaluate_hc137_remote_desktop(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC137: Remote desktop software (AnyDesk, TeamViewer, RDP) detected.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-remote-desktop", "x-remote-desktop", "x-fp-rdp-detected")
    if flag in ("true", "1", "yes", "active", "detected"):
        return True, "Remote desktop software (AnyDesk/TeamViewer/RDP) session detected."

    # Check for specific RDP software header
    rdp_tool = (lower_headers.get("x-fp-remote-tool") or "").lower()
    if rdp_tool:
        return True, f"Remote access tool detected: '{rdp_tool}'."

    return False, ""


def evaluate_hc138_screen_recording(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC138: Screen recording or broadcast active on mobile device (iOS).

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-screen-recording", "x-screen-recording", "x-fp-screen-capture")
    if flag in ("true", "1", "yes", "active"):
        return True, "Active screen recording or broadcast detected on mobile device."

    return False, ""


def evaluate_hc139_active_phone_call(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC139: User is on an active phone call during the transaction.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-phone-call", "x-phone-call-active", "x-fp-call-state")
    if flag in ("true", "1", "yes", "active", "in_call"):
        return True, "User is on an active phone call during payment execution."

    return False, ""


def evaluate_hc140_usb_connected(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC140: Mobile device is connected to a PC via USB (tethering or debug mode).

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    flag = _get_flag(lower_headers, "x-fp-usb-connected", "x-usb-debug", "x-fp-adb-enabled")
    if flag in ("true", "1", "yes", "active", "enabled"):
        return True, "Mobile device is USB-tethered or in ADB debug mode."

    return False, ""


def evaluate_hc141_headless_chrome(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC141: Unmasked headless Chrome (navigator.webdriver == true).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    webdriver = _get_flag(lower_headers, "x-fp-webdriver", "x-webdriver-present")
    if webdriver in ("true", "1", "yes"):
        return True, "navigator.webdriver is true — unmasked headless or WebDriver session."

    ua_lower = (raw_ua or "").lower()
    if "headlesschrome" in ua_lower or "headless chrome" in ua_lower:
        return True, "User-Agent identifies HeadlessChrome."
    if "headless" in ua_lower and "chrome" in ua_lower:
        return True, "Headless Chrome token present in User-Agent."

    return False, ""


def evaluate_hc142_stealth_headless(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC142: Automation flag hidden, but cursor telemetry is empty.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    hidden = _get_flag(lower_headers, "x-fp-webdriver-hidden", "x-webdriver-hidden")
    mouse_raw = (lower_headers.get("x-fp-mouse-movement") or "").strip()
    try:
        mouse_samples = int(mouse_raw)
    except (ValueError, TypeError):
        mouse_samples = None

    if hidden in ("true", "1", "yes") and mouse_samples == 0:
        return True, "WebDriver flag is spoofed/hidden and zero mouse movement was recorded."

    return False, ""


def evaluate_hc143_tor_exit(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC143: Traffic originates from a known Tor exit node.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if _get_flag(lower_headers, "x-fp-is-tor", "x-is-tor") in ("true", "1", "yes"):
        return True, "Client IP identified as a Tor onion router exit node."

    isp_org = (lower_headers.get("x-fp-isp") or lower_headers.get("x-isp") or "").lower()
    if "tor exit" in isp_org or isp_org == "tor":
        return True, "ISP/ASN organization matches a Tor exit node."

    ua_lower = (raw_ua or "").lower()
    if "tor browser" in ua_lower or "(tor)" in ua_lower:
        return True, "Tor Browser signature present on an anonymizing exit path."

    return False, ""
