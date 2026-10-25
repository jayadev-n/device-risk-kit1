"""
Application Entry Point for Device Fingerprinting & Risk Scoring Engine.
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "t")

    print("=" * 60)
    print("  [*] Device Fingerprinting & Risk Scoring Engine")
    print(f"  Running on: http://{host}:{port}")
    print(f"  Scoring API: http://{host}:{port}/api/v1/fingerprint/score")
    print(f"  Rules Info:  http://{host}:{port}/api/v1/fingerprint/rules")
    print("=" * 60)

    app.run(host=host, port=port, debug=debug)
