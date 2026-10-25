"""
Score Controller.
Provides REST API endpoints for device fingerprinting and risk assessment.
"""
from flask import Blueprint, request, jsonify, Response
from typing import Tuple

from app.services.scoring_engine import evaluate_risk, get_scoring_engine

score_bp = Blueprint("score_bp", __name__)


def _extract_client_ip() -> str:
    """Extract client IP address considering proxy headers."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # First IP in the list represents the original client
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@score_bp.route("/api/v1/fingerprint/score", methods=["POST", "GET"])
def score_device() -> Tuple[Response, int]:
    """
    POST /api/v1/fingerprint/score
    Scores an incoming request, calculates risk points, severity, and recommended action.
    Supports payload metadata from browser clients (canvas, screen resolution, etc.)
    and header inspection.
    """
    if request.method == "GET":
        # Helpful payload information for GET requests
        return jsonify({
            "message": "Send a POST request to this endpoint to evaluate device fingerprint and risk score.",
            "endpoint": "/api/v1/fingerprint/score",
            "method": "POST",
            "sample_body": {
                "screen_resolution": "1920x1080",
                "canvas_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timezone": "America/New_York",
                "color_depth": 24
            }
        }), 200

    # Extract JSON body if supplied
    body = request.get_json(silent=True) or {}

    # Extract request headers
    request_headers = dict(request.headers)

    # Support testing or gateway proxy overrides via request body
    if "headers" in body and isinstance(body["headers"], dict):
        request_headers.update(body["headers"])

    if "user_agent" in body and body["user_agent"]:
        request_headers["User-Agent"] = body["user_agent"]

    # Extract client IP
    client_ip = body.get("ip") or _extract_client_ip()

    # Isolate additional client-side fingerprint attributes
    client_payload = {
        k: v for k, v in body.items()
        if k not in ("headers", "user_agent", "ip")
    }

    try:
        assessment = evaluate_risk(
            headers=request_headers,
            ip=client_ip,
            client_payload=client_payload if client_payload else None
        )
        return jsonify(assessment), 200
    except Exception as e:
        return jsonify({
            "error": "Failed to process fingerprint risk assessment",
            "details": str(e)
        }), 500


@score_bp.route("/api/v1/fingerprint/rules", methods=["GET"])
def get_rules() -> Tuple[Response, int]:
    """
    GET /api/v1/fingerprint/rules
    Returns active rules configuration and scoring thresholds.
    """
    engine = get_scoring_engine()
    return jsonify({
        "rules": engine.get_configured_rules(),
        "thresholds": engine.rules_config.get("thresholds", {}),
        "actions": engine.rules_config.get("actions", {})
    }), 200


@score_bp.route("/api/v1/fingerprint/health", methods=["GET"])
def health_check() -> Tuple[Response, int]:
    """
    GET /api/v1/fingerprint/health
    Liveness and health check endpoint.
    """
    return jsonify({
        "status": "healthy",
        "service": "device-fingerprint-engine",
        "version": "1.0.0"
    }), 200
