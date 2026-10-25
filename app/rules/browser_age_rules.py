"""
Browser Version Age Detection Rules.
Evaluates:
- HC123: Browser version age is between 2-5 years
- HC122: Browser version age is between 1-2 years
"""
from typing import Dict, Any, Tuple

# Approximate release years for major browser versions
# Maps (browser_family_lower, major_version) -> release_year estimate
# We use Chrome as reference; other browsers scale similarly
CHROME_RELEASE_YEARS = {
    120: 2023, 119: 2023, 118: 2023, 117: 2023, 116: 2023,
    115: 2023, 114: 2023, 113: 2023, 112: 2023, 111: 2023,
    110: 2023, 109: 2023, 108: 2022, 107: 2022, 106: 2022,
    105: 2022, 104: 2022, 103: 2022, 102: 2022, 101: 2022,
    100: 2022, 99: 2022, 98: 2022, 97: 2022, 96: 2021,
    95: 2021, 94: 2021, 93: 2021, 92: 2021, 91: 2021,
    90: 2021, 89: 2021, 88: 2021, 87: 2020, 86: 2020,
    85: 2020, 84: 2020, 83: 2020, 81: 2020, 80: 2020,
}

FIREFOX_RELEASE_YEARS = {
    120: 2023, 119: 2023, 118: 2023, 117: 2023, 116: 2023,
    115: 2023, 114: 2023, 113: 2023, 112: 2023, 111: 2023,
    110: 2023, 109: 2023, 108: 2022, 107: 2022, 106: 2022,
    105: 2022, 104: 2022, 103: 2022, 102: 2022, 101: 2022,
    100: 2022, 99: 2022, 98: 2022, 97: 2022, 96: 2022,
    95: 2021, 94: 2021, 93: 2021, 92: 2021, 91: 2021,
    90: 2021, 89: 2021, 88: 2021, 87: 2021, 86: 2021,
    85: 2021, 84: 2020, 83: 2020, 82: 2020, 81: 2020,
    80: 2020, 79: 2020, 78: 2020, 77: 2020, 76: 2020, 75: 2020,
}

CURRENT_YEAR = 2026


def _estimate_browser_release_year(family: str, major: int) -> int:
    """Estimate the release year for a given browser family and major version."""
    family_lower = family.lower()
    if "chrome" in family_lower or "chromium" in family_lower or "edge" in family_lower:
        return CHROME_RELEASE_YEARS.get(major, 2019 if major < 80 else 2022)
    elif "firefox" in family_lower:
        return FIREFOX_RELEASE_YEARS.get(major, 2019 if major < 75 else 2022)
    elif "safari" in family_lower:
        # Safari major version roughly maps: 13=2019, 14=2020, 15=2021, 16=2022, 17=2023
        if major >= 17:
            return 2023
        elif major >= 16:
            return 2022
        elif major >= 15:
            return 2021
        elif major >= 14:
            return 2020
        else:
            return 2019
    return 2022  # Default — assume reasonably recent


def evaluate_hc123_browser_age_2_5_years(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC123: Browser version is 2–5 years old.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    browser_info = parsed_ua.get("browser", {})
    family = (browser_info.get("family") or "").strip()
    major = browser_info.get("major")

    if not family or family.lower() in ("other", "unknown", "") or major is None:
        return False, ""

    try:
        major_int = int(major)
    except (ValueError, TypeError):
        return False, ""

    release_year = _estimate_browser_release_year(family, major_int)
    age_years = CURRENT_YEAR - release_year

    if 2 <= age_years <= 5:
        return True, (
            f"Browser version is {age_years} years old: {family} {major} "
            f"(estimated release: {release_year})."
        )

    return False, ""


def evaluate_hc122_browser_age_1_2_years(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC122: Browser version is 1–2 years old.

    Args:
        headers: HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    browser_info = parsed_ua.get("browser", {})
    family = (browser_info.get("family") or "").strip()
    major = browser_info.get("major")

    if not family or family.lower() in ("other", "unknown", "") or major is None:
        return False, ""

    try:
        major_int = int(major)
    except (ValueError, TypeError):
        return False, ""

    release_year = _estimate_browser_release_year(family, major_int)
    age_years = CURRENT_YEAR - release_year

    if 1 <= age_years < 2:
        return True, (
            f"Browser version is moderately old: {family} {major} "
            f"(estimated release: {release_year}, ~{age_years} year old)."
        )

    return False, ""
