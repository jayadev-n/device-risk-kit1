import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as client:
        yield client


def test_health_check_endpoint(client):
    response = client.get("/api/v1/fingerprint/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "device-fingerprint-engine"


def test_get_rules_endpoint(client):
    response = client.get("/api/v1/fingerprint/rules")
    assert response.status_code == 200
    data = response.get_json()
    assert "rules" in data
    assert len(data["rules"]) >= 4
    rule_ids = [r["id"] for r in data["rules"]]
    assert "HC117" in rule_ids
    assert "HC106" in rule_ids
    assert "HC124" in rule_ids
    assert "HC114" in rule_ids


def test_score_clean_browser(client):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
    }
    response = client.post(
        "/api/v1/fingerprint/score",
        headers=headers,
        json={"screen_resolution": "1920x1080", "canvas_hash": "canvas_12345"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["risk_score"] == 0
    assert data["risk_severity"] == "LOW"
    assert data["recommended_action"] == "ALLOW"
    assert len(data["device_id"]) == 64
    assert data["client_payload"]["canvas_hash"] == "canvas_12345"


def test_score_postman_bot(client):
    headers = {
        "User-Agent": "PostmanRuntime/7.36.0",
        "Postman-Token": "test-uuid"
    }
    response = client.post("/api/v1/fingerprint/score", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["risk_severity"] == "HIGH"
    assert data["recommended_action"] == "BLOCK / CHALLENGE"
    assert data["risk_score"] >= 12


def test_score_outdated_browser(client):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/72.0.3626.121 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br"
    }
    response = client.post("/api/v1/fingerprint/score", headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["risk_score"] == 8
    assert data["risk_severity"] == "MEDIUM"
    assert data["recommended_action"] == "CAPTCHA / MFA"


def test_score_get_method_instructions(client):
    response = client.get("/api/v1/fingerprint/score")
    assert response.status_code == 200
    data = response.get_json()
    assert "POST" in data["message"]


def test_web_ui_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Device Fingerprinting &amp; Risk Scoring Engine" in response.data or b"Device Fingerprinting & Risk Scoring Engine" in response.data
