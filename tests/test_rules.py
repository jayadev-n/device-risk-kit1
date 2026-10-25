import pytest
from app.utils.ua_parser import parse_user_agent
from app.rules.bot_rules import evaluate_hc117_bot_profile
from app.rules.header_rules import evaluate_hc106_missing_headers
from app.rules.browser_rules import evaluate_hc124_outdated_browser, evaluate_hc114_unknown_user_agent


def test_hc117_bot_triggers():
    # Test Postman UA
    ua = "PostmanRuntime/7.32.3"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc117_bot_profile({}, parsed, ua)
    assert trig is True
    assert "postman" in reason.lower()

    # Test curl UA
    ua = "curl/7.88.1"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc117_bot_profile({}, parsed, ua)
    assert trig is True
    assert "curl" in reason.lower()

    # Test python requests UA
    ua = "python-requests/2.31.0"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc117_bot_profile({}, parsed, ua)
    assert trig is True
    assert "python" in reason.lower()

    # Test Postman-Token header with regular UA
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc117_bot_profile({"Postman-Token": "12345"}, parsed, ua)
    assert trig is True
    assert "postman-token" in reason.lower()


def test_hc117_clean_browser():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    parsed = parse_user_agent(ua)
    trig, _ = evaluate_hc117_bot_profile({}, parsed, ua)
    assert trig is False


def test_hc106_missing_headers():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    parsed = parse_user_agent(ua)

    # Missing both Accept-Language and Accept-Encoding
    trig, reason = evaluate_hc106_missing_headers({}, parsed, ua)
    assert trig is True
    assert "Accept-Language" in reason
    assert "Accept-Encoding" in reason

    # Missing only Accept-Encoding
    trig, reason = evaluate_hc106_missing_headers({"Accept-Language": "en-US"}, parsed, ua)
    assert trig is True
    assert "Accept-Encoding" in reason

    # All headers present (case-insensitive test)
    trig, _ = evaluate_hc106_missing_headers({
        "accept-language": "en-US,en;q=0.9",
        "ACCEPT-ENCODING": "gzip, deflate, br"
    }, parsed, ua)
    assert trig is False


def test_hc124_outdated_browser():
    # Outdated Chrome (< 80)
    ua_old_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/70.0.3538.77 Safari/537.36"
    parsed_old = parse_user_agent(ua_old_chrome)
    trig, reason = evaluate_hc124_outdated_browser({}, parsed_old, ua_old_chrome)
    assert trig is True
    assert "70" in reason

    # Modern Chrome (>= 80)
    ua_modern_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    parsed_modern = parse_user_agent(ua_modern_chrome)
    trig, _ = evaluate_hc124_outdated_browser({}, parsed_modern, ua_modern_chrome)
    assert trig is False

    # Outdated Firefox (< 75)
    ua_old_ff = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0"
    parsed_ff = parse_user_agent(ua_old_ff)
    trig, reason = evaluate_hc124_outdated_browser({}, parsed_ff, ua_old_ff)
    assert trig is True
    assert "68" in reason


def test_hc114_unknown_user_agent():
    # Missing / empty UA
    trig, reason = evaluate_hc114_unknown_user_agent({}, parse_user_agent(""), "")
    assert trig is True
    assert "missing" in reason.lower()

    # Short generic UA
    trig, reason = evaluate_hc114_unknown_user_agent({}, parse_user_agent("test"), "test")
    assert trig is True

    # Standard browser UA should NOT trigger HC114
    ua_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    trig, _ = evaluate_hc114_unknown_user_agent({}, parse_user_agent(ua_chrome), ua_chrome)
    assert trig is False


def test_hc141_headless_webdriver():
    from app.rules.signal_rules import evaluate_hc141_headless_chrome

    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/122.0.0.0 Safari/537.36"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc141_headless_chrome({"X-Fp-Webdriver": "true"}, parsed, ua)
    assert trig is True
    assert "webdriver" in reason.lower() or "headless" in reason.lower()


def test_hc142_hidden_webdriver_zero_mouse():
    from app.rules.signal_rules import evaluate_hc142_stealth_headless

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc142_stealth_headless(
        {"X-Fp-Webdriver-Hidden": "true", "X-Fp-Mouse-Movement": "0"},
        parsed,
        ua,
    )
    assert trig is True
    assert "mouse" in reason.lower() or "webdriver" in reason.lower()


def test_hc143_tor_exit():
    from app.rules.signal_rules import evaluate_hc143_tor_exit

    ua = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
    parsed = parse_user_agent(ua)
    trig, reason = evaluate_hc143_tor_exit({"X-Fp-Is-Tor": "true"}, parsed, ua)
    assert trig is True
    assert "tor" in reason.lower()
