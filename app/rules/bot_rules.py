"""
Bot & Automated Tool Detection Rules.
Evaluates Rule HC117: Suspicious browser profile - Bots or Postman.
"""
from typing import Dict, Any, Tuple

# Suspicious keywords indicative of automated tools, headless browsers, or HTTP libraries
SUSPICIOUS_BOT_KEYWORDS = [
    "postman",
    "curl",
    "python",
    "headless",
    "selenium",
    "puppeteer",
    "playwright",
    "phantomjs",
    "wget",
    "httpclient",
    "scrapy",
    "urllib",
    "aiohttp",
    "requests",
    "axios",
    "go-http-client",
    "bot",
    "crawl",
    "spider",
    "slurp",
    "headlesschrome",
]


def evaluate_hc117_bot_profile(
    headers: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str
) -> Tuple[bool, str]:
    """
    HC117: Check if the request originates from an automated client, bot, or tool like Postman/cURL.

    Args:
        headers: Case-insensitive or normalized HTTP headers dictionary.
        parsed_ua: Metadata parsed by parse_user_agent.
        raw_ua: Raw User-Agent string.

    Returns:
        Tuple of (triggered: bool, reason: str).
    """
    # 1. Check if user_agents library flagged it as a bot
    if parsed_ua.get("is_bot", False):
        return True, "User-Agent explicitly identified as bot/crawler by parser."

    ua_lower = (raw_ua or "").lower()

    # 2. Check for suspicious keywords in User-Agent string
    for keyword in SUSPICIOUS_BOT_KEYWORDS:
        if keyword in ua_lower:
            return True, f"User-Agent contains suspicious automation/client keyword: '{keyword}'."

    # 3. Check for specific automation headers (e.g. Postman-Token, Selenium webdriver, etc.)
    # Normalize header keys to lowercase for robust lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if "postman-token" in lower_headers:
        return True, "Request contains 'Postman-Token' header."

    if lower_headers.get("x-headless-browser") or lower_headers.get("x-puppeteer"):
        return True, "Request contains headless automation header."

    return False, ""
