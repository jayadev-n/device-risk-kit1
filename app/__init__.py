"""
Application Factory for Device Fingerprinting and Risk Scoring Engine.
"""
import os
from flask import Flask, render_template_string
from typing import Optional, Dict, Any

from app.controllers.score_controller import score_bp

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_demo_html() -> str:
    """Load dashboard HTML from external file to avoid Python string escaping issues."""
    html_path = os.path.join(_HERE, "_demo_ui.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard not found. Ensure app/_demo_ui.html exists.</h1>"


def create_app(config_override: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Application factory pattern for Flask app initialization.

    Args:
        config_override: Optional configuration dictionary.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    app.config["JSON_SORT_KEYS"] = False
    app.config["RESTFUL_JSON"] = {"indent": 2}

    if config_override:
        app.config.update(config_override)

    @app.after_request
    def apply_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, Accept, Accept-Language, "
            "Accept-Encoding, User-Agent, X-Forwarded-For"
        )
        return response

    app.register_blueprint(score_bp)

    @app.route("/", methods=["GET"])
    def index():
        demo_html = _load_demo_html()
        return render_template_string(demo_html)

    return app
