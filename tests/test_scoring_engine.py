import pytest
from app.services.scoring_engine import ScoringEngine, evaluate_risk


def test_scoring_engine_clean_request():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
    }
    result = evaluate_risk(headers=headers, ip="192.168.1.50")

    assert result["risk_score"] == 0
    assert result["risk_severity"] == "LOW"
    assert result["recommended_action"] == "ALLOW"
    assert len(result["triggered_rules"]) == 0
    assert result["parsed_metadata"]["browser"]["family"] == "Chrome"
    assert len(result["device_id"]) == 64


def test_evaluated_rules_include_details():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
    }
    result = evaluate_risk(
        headers=headers,
        ip="192.168.1.50",
        client_payload={"timezone": "Asia/Calcutta", "screen_resolution": "1920x1080", "platform": "Win32"}
    )
    evaluated = {r["id"]: r for r in result["evaluated_rules"]}
    assert evaluated["HC117"]["details"]["Detected Bot Class"] == "Standard Web Browser"
    assert evaluated["HC106"]["details"]["Header Evaluation"] == "Standard Headers Present"
    assert "User Agent String" in evaluated["HC117"]["details"]
    assert evaluated["HC113"]["details"]["Screen Viewport"] == "1920x1080"
    assert evaluated["HC100"]["details"]["Browser Timezone"] == "Asia/Calcutta"
    for rule in result["evaluated_rules"]:
        assert isinstance(rule.get("details"), dict)
        assert len(rule["details"]) >= 2


def test_new_threat_scenarios_from_payload():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept": "text/html",
    }

    tz = evaluate_risk(
        headers=headers,
        ip="1.2.3.4",
        client_payload={"timezone": "America/New_York", "ip_timezone": "Asia/Kolkata"},
    )
    assert any(r["id"] == "HC100" and r["status"] == "triggered" for r in tz["evaluated_rules"])

    screen = evaluate_risk(
        headers=headers,
        ip="1.2.3.4",
        client_payload={"screen_resolution": "1111x333"},
    )
    assert any(r["id"] == "HC113" and r["status"] == "triggered" for r in screen["evaluated_rules"])

    stealth = evaluate_risk(
        headers=headers,
        ip="1.2.3.4",
        client_payload={"webdriver_hidden": True, "mouse_movement": 0},
    )
    assert any(r["id"] == "HC142" and r["status"] == "triggered" for r in stealth["evaluated_rules"])

    ids = {r["id"] for r in stealth["evaluated_rules"]}
    assert {"HC141", "HC142", "HC143"}.issubset(ids)
    assert all(r["status"] != "not_evaluated" for r in stealth["evaluated_rules"] if r["id"] in {"HC141", "HC142", "HC143"})


def test_scoring_engine_medium_risk():
    # Outdated Chrome 70 (+8) with headers present
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/70.0.3538.77 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
    }
    result = evaluate_risk(headers=headers, ip="192.168.1.50")

    assert result["risk_score"] == 8
    assert result["risk_severity"] == "MEDIUM"
    assert result["recommended_action"] == "CAPTCHA / MFA"
    assert len(result["triggered_rules"]) == 1
    assert result["triggered_rules"][0]["id"] == "HC124"


def test_scoring_engine_high_risk_bot():
    # Postman UA (+12) and missing headers (+2) = 14
    headers = {
        "User-Agent": "PostmanRuntime/7.36.0",
        "Postman-Token": "test-token"
    }
    result = evaluate_risk(headers=headers, ip="10.0.0.1")

    assert result["risk_score"] >= 12
    assert result["risk_severity"] == "HIGH"
    assert result["recommended_action"] == "BLOCK / CHALLENGE"
    rule_ids = [r["id"] for r in result["triggered_rules"]]
    assert "HC117" in rule_ids


def test_severity_and_action_mapping():
    engine = ScoringEngine()

    low = engine.calculate_severity_and_action(0)
    assert low["risk_severity"] == "LOW"
    assert low["recommended_action"] == "ALLOW"

    low_edge = engine.calculate_severity_and_action(4)
    assert low_edge["risk_severity"] == "LOW"

    med_start = engine.calculate_severity_and_action(5)
    assert med_start["risk_severity"] == "MEDIUM"
    assert med_start["recommended_action"] == "CAPTCHA / MFA"

    med_end = engine.calculate_severity_and_action(11)
    assert med_end["risk_severity"] == "MEDIUM"

    high = engine.calculate_severity_and_action(12)
    assert high["risk_severity"] == "HIGH"
    assert high["recommended_action"] == "BLOCK / CHALLENGE"

    high_large = engine.calculate_severity_and_action(24)
    assert high_large["risk_severity"] == "HIGH"
