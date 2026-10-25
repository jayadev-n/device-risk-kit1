"""
Rule evaluators and registry for Device Fingerprint Risk Engine.
"""
from typing import Dict, Any, Callable, Tuple

# Existing evaluators
from .bot_rules import evaluate_hc117_bot_profile
from .header_rules import evaluate_hc106_missing_headers
from .browser_rules import evaluate_hc124_outdated_browser, evaluate_hc114_unknown_user_agent

# Browser age evaluators
from .browser_age_rules import (
    evaluate_hc123_browser_age_2_5_years,
    evaluate_hc122_browser_age_1_2_years,
)

# Advanced browser profile evaluators
from .profile_rules import (
    evaluate_hc125_spoofing,
    evaluate_hc121_high_risk_profile,
    evaluate_hc120_medium_risk_profile,
    evaluate_hc118_privacy_extension,
    evaluate_hc116_privacy_browser,
    evaluate_hc115_fraud_browser,
)

# Device & environment evaluators
from .device_rules import (
    evaluate_hc113_screen_resolution,
    evaluate_hc110_rooted_device,
    evaluate_hc109_jailbroken_device,
    evaluate_hc108_emulator,
    evaluate_hc100_timezone_mismatch,
    evaluate_hc102_cookies_disabled,
    evaluate_hc101_webrtc_multiple_ips,
    evaluate_hc126_shared_device_fingerprint,
)

# Observational / behavioral signal evaluators
from .signal_rules import (
    evaluate_hc133_dynamic_component_blocked,
    evaluate_hc134_vpn_proxy,
    evaluate_hc135_click_automator,
    evaluate_hc136_screen_mirrored,
    evaluate_hc137_remote_desktop,
    evaluate_hc138_screen_recording,
    evaluate_hc139_active_phone_call,
    evaluate_hc140_usb_connected,
    evaluate_hc141_headless_chrome,
    evaluate_hc142_stealth_headless,
    evaluate_hc143_tor_exit,
)

# Complete rule evaluator registry — maps rule ID -> evaluator function
RULE_EVALUATORS: Dict[str, Callable[[Dict[str, str], Dict[str, Any], str], Tuple[bool, str]]] = {
    # Bot & automation detection
    "HC117": evaluate_hc117_bot_profile,

    # Header checks
    "HC106": evaluate_hc106_missing_headers,

    # Browser version checks
    "HC124": evaluate_hc124_outdated_browser,
    "HC123": evaluate_hc123_browser_age_2_5_years,
    "HC122": evaluate_hc122_browser_age_1_2_years,

    # Browser identity
    "HC114": evaluate_hc114_unknown_user_agent,

    # Browser profile anomalies
    "HC125": evaluate_hc125_spoofing,
    "HC121": evaluate_hc121_high_risk_profile,
    "HC120": evaluate_hc120_medium_risk_profile,
    "HC118": evaluate_hc118_privacy_extension,
    "HC116": evaluate_hc116_privacy_browser,
    "HC115": evaluate_hc115_fraud_browser,

    # Device hardware checks
    "HC113": evaluate_hc113_screen_resolution,
    "HC110": evaluate_hc110_rooted_device,
    "HC109": evaluate_hc109_jailbroken_device,
    "HC108": evaluate_hc108_emulator,

    # Environment & context checks
    "HC100": evaluate_hc100_timezone_mismatch,
    "HC102": evaluate_hc102_cookies_disabled,
    "HC101": evaluate_hc101_webrtc_multiple_ips,
    "HC126": evaluate_hc126_shared_device_fingerprint,

    # Observational / behavioral signals
    "HC133": evaluate_hc133_dynamic_component_blocked,
    "HC134": evaluate_hc134_vpn_proxy,
    "HC135": evaluate_hc135_click_automator,
    "HC136": evaluate_hc136_screen_mirrored,
    "HC137": evaluate_hc137_remote_desktop,
    "HC138": evaluate_hc138_screen_recording,
    "HC139": evaluate_hc139_active_phone_call,
    "HC140": evaluate_hc140_usb_connected,
    "HC141": evaluate_hc141_headless_chrome,
    "HC142": evaluate_hc142_stealth_headless,
    "HC143": evaluate_hc143_tor_exit,
}

__all__ = [
    "RULE_EVALUATORS",
]
