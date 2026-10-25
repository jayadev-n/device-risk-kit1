import pytest
from app.utils.hash_generator import generate_device_id


def test_hash_generator_deterministic():
    ip = "192.168.1.100"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    lang = "en-US,en;q=0.9"

    hash1 = generate_device_id(ip, ua, lang)
    hash2 = generate_device_id(ip, ua, lang)

    assert len(hash1) == 64
    assert hash1 == hash2


def test_hash_generator_different_inputs():
    ip1 = "192.168.1.100"
    ip2 = "192.168.1.101"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    lang = "en-US,en;q=0.9"

    hash1 = generate_device_id(ip1, ua, lang)
    hash2 = generate_device_id(ip2, ua, lang)

    assert hash1 != hash2


def test_hash_generator_with_extra_attributes():
    ip = "192.168.1.100"
    ua = "Mozilla/5.0"
    lang = "en-US"

    hash_no_extra = generate_device_id(ip, ua, lang)
    hash_with_canvas1 = generate_device_id(ip, ua, lang, {"canvas": "canvas_123", "screen": "1080p"})
    hash_with_canvas2 = generate_device_id(ip, ua, lang, {"screen": "1080p", "canvas": "canvas_123"})

    assert hash_no_extra != hash_with_canvas1
    # Order of dictionary keys shouldn't affect deterministic hash
    assert hash_with_canvas1 == hash_with_canvas2


def test_hash_generator_handles_none():
    res = generate_device_id(None, None, None)
    assert isinstance(res, str)
    assert len(res) == 64
