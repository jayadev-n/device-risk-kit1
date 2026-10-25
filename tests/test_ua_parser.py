import pytest
from app.utils.ua_parser import parse_user_agent


def test_parse_chrome_ua():
    ua_str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    parsed = parse_user_agent(ua_str)

    assert parsed["browser"]["family"] == "Chrome"
    assert parsed["browser"]["major"] == 120
    assert parsed["os"]["family"] == "Windows"
    assert parsed["is_bot"] is False
    assert parsed["is_pc"] is True


def test_parse_firefox_ua():
    ua_str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
    parsed = parse_user_agent(ua_str)

    assert parsed["browser"]["family"] == "Firefox"
    assert parsed["browser"]["major"] == 115
    assert parsed["is_bot"] is False


def test_parse_bot_ua():
    ua_str = "Googlebot/2.1 (+http://www.google.com/bot.html)"
    parsed = parse_user_agent(ua_str)

    assert parsed["is_bot"] is True


def test_parse_empty_ua():
    parsed = parse_user_agent("")
    assert parsed["browser"]["family"] == "Other"
    assert parsed["browser"]["major"] is None
    assert parsed["raw_user_agent"] == ""

    parsed_none = parse_user_agent(None)
    assert parsed_none["browser"]["family"] == "Other"
