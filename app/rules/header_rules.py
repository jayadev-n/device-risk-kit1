"""
Header Anomaly Detection Rules.
Evaluates Rule HC106: Missing standard browser headers.
"""
from typing import Dict, Any, Tuple


def evaluate_hc106_missing_headers(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC106: Check if standard browser headers like Accept-Language or Accept-Encoding are missing.

    Legitimate modern web browsers consistently send headers such as Accept-Language and Accept-Encoding.
    Their absence indicates automated scripts, minimal HTTP libraries, or header tampering.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing_headers = []

    if not lower_headers.get("accept-language"):
        missing_headers.append("Accept-Language")

    if not lower_headers.get("accept-encoding"):
        missing_headers.append("Accept-Encoding")

    if missing_headers:
        return True, f"Request missing expected standard browser header(s): {', '.join(missing_headers)}."

    return False, ""
