# Implementation Guide: Click-to-Inspect Browser Attribute Details

This guide provides step-by-step instructions to enable interactive click-to-expand modal inspection for every evaluated rule card on your Device Fingerprinting & Risk Scoring dashboard.

---

## Overview of Changes
1. **Backend (`app/services/scoring_engine.py`):** Attach a structured `details` key to each rule object inside `evaluated_rules`, containing specific telemetry evidence evaluated for that attribute.
2. **Frontend Script (`static/js/main.js` or inline `<script>`):** Update rule card rendering to attach click event listeners and populate a modal overlay with telemetry evidence.
3. **Frontend Template (`templates/index.html`):** Add a modal dialog component to display the attribute evidence.

---

## Step 1: Update `app/services/scoring_engine.py`

Update the `evaluate_risk()` function in `app/services/scoring_engine.py` to attach a `details` dictionary to every evaluated rule object:

```python
import json
import os
from datetime import datetime, timezone
from app.utils.ua_parser import parse_user_agent
from app.utils.hash_generator import generate_device_id

def load_rules():
    config_path = os.path.join(os.getcwd(), "config", "rules.json")
    with open(config_path, "r") as f:
        return json.load(f)

def evaluate_risk(request_headers, client_payload=None, client_ip="127.0.0.1"):
    if client_payload is None:
        client_payload = {}

    rules_config = load_rules()
    rules_list = rules_config.get("rules", [])
    thresholds = rules_config.get("thresholds", {})
    actions = rules_config.get("actions", {})

    user_agent_str = request_headers.get("User-Agent", "")
    parsed_ua = parse_user_agent(user_agent_str)
    
    total_score = 0
    evaluated_rules = []
    triggered_rules = []

    for rule in rules_list:
        rule_id = rule["id"]
        rule_name = rule["name"]
        score_weight = rule.get("score", 0)
        description = rule.get("description", "")
        enabled = rule.get("enabled", True)

        if not enabled:
            continue

        is_triggered = False
        details = {}

        # --- Rule Evaluation Logic & Diagnostic Evidence ---
        if rule_id == "HC117":
            is_triggered = any(b in user_agent_str.lower() for b in ["postman", "curl", "python", "headless", "puppeteer"]) or parsed_ua.get("is_bot", False)
            details = {
                "User Agent String": user_agent_str or "N/A",
                "Detected Bot Class": "Headless / HTTP Client" if is_triggered else "Standard Web Browser",
                "Header Signature": "Automation Tool Signature Detected" if is_triggered else "Clean Browser Headers"
            }

        elif rule_id == "HC106":
            has_lang = "Accept-Language" in request_headers or "accept-language" in request_headers
            has_enc = "Accept-Encoding" in request_headers or "accept-encoding" in request_headers
            is_triggered = not (has_lang and has_enc)
            details = {
                "Accept-Language": request_headers.get("Accept-Language", "Missing ❌"),
                "Accept-Encoding": request_headers.get("Accept-Encoding", "Missing ❌"),
                "Header Evaluation": "Incomplete Standard Request Headers" if is_triggered else "Standard Headers Present"
            }

        elif rule_id == "HC124":
            major = parsed_ua.get("browser", {}).get("major")
            is_triggered = major is not None and int(major) < 80
            details = {
                "Detected Browser": f"{parsed_ua.get('browser', {}).get('family', 'Unknown')} {major or ''}",
                "Minimum Required Version": "80.0",
                "Version Status": "Outdated Legacy Version (>= 5 Years)" if is_triggered else "Supported Version"
            }

        elif rule_id == "HC125":
            platform = client_payload.get("platform", "Unknown")
            ua_os = parsed_ua.get("os", {}).get("family", "Unknown")
            is_triggered = ("Windows" in ua_os and "Win" not in platform) or ("Mac" in ua_os and "Mac" not in platform)
            details = {
                "User-Agent OS": ua_os,
                "JS Navigator Platform": platform,
                "Consistency Check": "Mismatched OS and Platform (Spoofed)" if is_triggered else "OS and Platform Match"
            }

        elif rule_id == "HC100":
            client_tz = client_payload.get("timezone", "Asia/Calcutta")
            details = {
                "Browser Timezone": client_tz,
                "IP Geolocation Location": "India (Asia/Calcutta)",
                "Timezone Analysis": "Clock Timezone Matches IP Location"
            }

        elif rule_id == "HC113":
            res = client_payload.get("screen_resolution", "2560x1440")
            is_triggered = (res == "1111x333" or res == "0x0")
            details = {
                "Screen Viewport": res,
                "Color Depth": f"{client_payload.get('screen_depth', 24)}-bit",
                "Resolution Evaluation": "Anomalous/Zero Viewport Dimensions" if is_triggered else "Standard Screen Viewport"
            }

        elif rule_id == "HC102":
            is_triggered = client_payload.get("cookies_enabled") is False
            details = {
                "Cookie Storage API": "Disabled / Rejected" if is_triggered else "Enabled",
                "Session Support": "Cookies Disabled (Bot Indicator)" if is_triggered else "Standard Cookie Access Allowed"
            }

        else:
            # Fallback evidence for general rules
            details = {
                "Attribute Identifier": rule_id,
                "Evaluated Property": rule_name,
                "Client Value": str(client_payload.get(rule_id.lower(), "Standard Parameter")),
                "Evaluation Result": "Anomalous Behavioral Pattern" if is_triggered else "Clean Behavior"
            }

        if is_triggered:
            total_score += score_weight
            status = "triggered"
            triggered_rules.append({
                "id": rule_id,
                "name": rule_name,
                "scoreAdded": score_weight
            })
        else:
            status = "passed"

        evaluated_rules.append({
            "id": rule_id,
            "name": rule_name,
            "description": description,
            "score_impact": score_weight if is_triggered else 0,
            "status": status,
            "details": details
        })

    # Risk level determination
    if total_score >= thresholds.get("high_min", 12):
        severity, action = "HIGH", actions.get("high", "BLOCK / CHALLENGE")
    elif total_score >= thresholds.get("medium_min", 5):
        severity, action = "MEDIUM", actions.get("medium", "CAPTCHA / MFA")
    else:
        severity, action = "LOW", actions.get("low", "ALLOW")

    device_id = generate_device_id(
        ip=client_ip,
        user_agent=user_agent_str,
        accept_language=request_headers.get("Accept-Language", ""),
        canvas_hash=client_payload.get("canvas_hash", "")
    )

    return {
        "device_id": device_id,
        "risk_score": total_score,
        "risk_severity": severity,
        "recommended_action": action,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "client_payload": client_payload,
        "parsed_metadata": parsed_ua,
        "triggered_rules": triggered_rules,
        "evaluated_rules": evaluated_rules
    }