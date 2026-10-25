"""
Scoring Engine Service.
Loads rules configuration, evaluates incoming requests against rules,
aggregates risk points, and produces risk assessment and recommended actions.
"""
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from app.utils.ua_parser import parse_user_agent
from app.utils.hash_generator import generate_device_id
from app.rules import RULE_EVALUATORS

DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "rules.json"
)


class ScoringEngine:
    """
    Device Fingerprinting and Risk Scoring Engine.
    """

    def __init__(self, rules_config_path: Optional[str] = None):
        self.rules_config_path = rules_config_path or DEFAULT_RULES_PATH
        self.rules_config = self._load_rules_config()

    def _load_rules_config(self) -> Dict[str, Any]:
        """
        Load rule definitions and point weights from JSON config file.
        Falls back to default built-in configuration if file is unavailable.
        """
        if os.path.exists(self.rules_config_path):
            try:
                with open(self.rules_config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                # Fallback to built-in defaults if loading fails
                print(f"Warning: Failed to parse rules config at {self.rules_config_path}: {e}")

        # Built-in fallback
        return {
            "rules": [
                {
                    "id": "HC117",
                    "name": "Suspicious browser profile - Bots or Postman",
                    "score": 12,
                    "enabled": True,
                    "description": "Bots or Postman profile detection."
                },
                {
                    "id": "HC106",
                    "name": "Missing standard browser headers",
                    "score": 2,
                    "enabled": True,
                    "description": "Missing Accept-Language or Accept-Encoding."
                },
                {
                    "id": "HC124",
                    "name": "Outdated browser version",
                    "score": 8,
                    "enabled": True,
                    "description": "Outdated major browser version."
                },
                {
                    "id": "HC114",
                    "name": "Unpopular or unknown user agent",
                    "score": 2,
                    "enabled": True,
                    "description": "Unrecognized or unknown UA."
                }
            ],
            "thresholds": {
                "low_max": 4,
                "medium_min": 5,
                "medium_max": 11,
                "high_min": 12
            },
            "actions": {
                "low": "ALLOW",
                "medium": "CAPTCHA / MFA",
                "high": "BLOCK / CHALLENGE"
            }
        }

    def reload_rules(self) -> None:
        """Reload configuration from disk."""
        self.rules_config = self._load_rules_config()

    def get_configured_rules(self) -> List[Dict[str, Any]]:
        """Return list of configured rules."""
        return self.rules_config.get("rules", [])

    def calculate_severity_and_action(self, score: int) -> Dict[str, str]:
        """
        Map cumulative risk score to threat severity level and recommended action.

        - Score < 5: LOW risk, Action: ALLOW
        - Score 5–11: MEDIUM risk, Action: CAPTCHA / MFA
        - Score >= 12: HIGH risk, Action: BLOCK / CHALLENGE
        """
        thresholds = self.rules_config.get("thresholds", {})
        actions = self.rules_config.get("actions", {})

        low_max = thresholds.get("low_max", 4)
        medium_max = thresholds.get("medium_max", 11)

        if score <= low_max:
            return {
                "risk_severity": "LOW",
                "recommended_action": actions.get("low", "ALLOW")
            }
        elif score <= medium_max:
            return {
                "risk_severity": "MEDIUM",
                "recommended_action": actions.get("medium", "CAPTCHA / MFA")
            }
        else:
            return {
                "risk_severity": "HIGH",
                "recommended_action": actions.get("high", "BLOCK / CHALLENGE")
            }

    def evaluate(
        self,
        headers: Dict[str, str],
        ip: Optional[str] = None,
        client_payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate an incoming HTTP request for risk and device fingerprinting.

        Args:
            headers: HTTP request headers dictionary.
            ip: Client IP address.
            client_payload: Optional JSON body payload from client (e.g. canvas, screen).

        Returns:
            Structured risk assessment dictionary.
        """
        # Extract relevant headers in a case-insensitive manner, then overlay
        # JSON client telemetry as x-fp-* signals so rule evaluators can see it.
        headers_normalized = {str(k): str(v) for k, v in headers.items()}
        headers_normalized = _inject_client_signals(headers_normalized, client_payload or {})
        headers_lower = {k.lower(): v for k, v in headers_normalized.items()}

        raw_ua = headers_lower.get("user-agent", "")
        accept_lang = headers_lower.get("accept-language", "")

        # 1. Parse User-Agent
        parsed_ua = parse_user_agent(raw_ua)

        # 2. Generate Device ID
        device_id = generate_device_id(
            ip=ip,
            user_agent=raw_ua,
            accept_language=accept_lang,
            extra_attributes=client_payload
        )

        # 3. Evaluate Rules
        triggered_rules = []
        evaluated_rules = []
        total_score = 0

        rules_list = self.rules_config.get("rules", [])
        for rule_meta in rules_list:
            rule_id = rule_meta.get("id")
            is_enabled = rule_meta.get("enabled", True)
            rule_score = rule_meta.get("score", 0)
            rule_name = rule_meta.get("name", rule_id)
            rule_description = rule_meta.get("description", "")

            if not is_enabled:
                continue

            evaluator = RULE_EVALUATORS.get(rule_id)
            if not evaluator:
                # Rule is configured but no evaluator is wired up yet —
                # surface it in the dashboard as "not_evaluated"
                evaluated_rules.append({
                    "id": rule_id,
                    "name": rule_name,
                    "status": "not_evaluated",
                    "score_impact": 0,
                    "description": rule_description,
                    "details": _build_rule_details(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        headers=headers_normalized,
                        headers_lower=headers_lower,
                        parsed_ua=parsed_ua,
                        raw_ua=raw_ua,
                        client_payload=client_payload or {},
                        triggered=False,
                    ),
                })
                continue

            triggered, reason = evaluator(headers_normalized, parsed_ua, raw_ua)

            # Build per-rule telemetry evidence for the click-to-inspect modal
            details = _build_rule_details(
                rule_id=rule_id,
                rule_name=rule_name,
                headers=headers_normalized,
                headers_lower=headers_lower,
                parsed_ua=parsed_ua,
                raw_ua=raw_ua,
                client_payload=client_payload or {},
                triggered=triggered,
            )

            if triggered:
                total_score += rule_score
                triggered_rules.append({
                    "id": rule_id,
                    "name": rule_name,
                    "score": rule_score,
                    "reason": reason
                })
                evaluated_rules.append({
                    "id": rule_id,
                    "name": rule_name,
                    "status": "triggered",
                    "score_impact": rule_score,
                    "description": reason or rule_description,
                    "details": details,
                })
            else:
                evaluated_rules.append({
                    "id": rule_id,
                    "name": rule_name,
                    "status": "passed",
                    "score_impact": 0,
                    "description": rule_description,
                    "details": details,
                })


        # 4. Map Risk Severity and Action
        decision = self.calculate_severity_and_action(total_score)

        # 5. Metadata
        parsed_metadata = {
            "ip": ip or "unknown",
            "browser": parsed_ua["browser"],
            "os": parsed_ua["os"],
            "device": parsed_ua["device"],
            "is_bot": parsed_ua["is_bot"],
            "is_mobile": parsed_ua["is_mobile"],
            "is_tablet": parsed_ua["is_tablet"],
            "is_pc": parsed_ua["is_pc"],
            "raw_user_agent": raw_ua,
        }

        return {
            "device_id": device_id,
            "risk_score": total_score,
            "risk_severity": decision["risk_severity"],
            "recommended_action": decision["recommended_action"],
            "triggered_rules": triggered_rules,
            "evaluated_rules": evaluated_rules,
            "parsed_metadata": parsed_metadata,
            "client_payload": client_payload or {},
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }


PAYLOAD_HEADER_MAP = {
    "timezone": "X-Fp-Timezone",
    "ip_timezone": "X-Ip-Timezone",
    "screen_resolution": "X-Fp-Screen-Resolution",
    "platform": "X-Fp-Platform",
    "canvas_hash": "X-Fp-Canvas-Hash",
    "cookies_enabled": "X-Fp-Cookies-Enabled",
    "webdriver": "X-Fp-Webdriver",
    "webdriver_hidden": "X-Fp-Webdriver-Hidden",
    "mouse_movement": "X-Fp-Mouse-Movement",
    "click_trusted": "X-Fp-Click-Trusted",
    "hardware_concurrency": "X-Fp-Hardware-Concurrency",
    "webrtc_ips": "X-Fp-Webrtc-Ips",
    "is_tor": "X-Fp-Is-Tor",
    "is_vpn": "X-Fp-Is-Vpn",
    "remote_desktop": "X-Fp-Remote-Desktop",
    "remote_tool": "X-Fp-Remote-Tool",
    "shared_user_count": "X-Fp-Shared-User-Count",
    "is_emulator": "X-Fp-Is-Emulator",
    "canvas_blocked": "X-Fp-Canvas-Blocked",
    "cpu_arch": "X-Fp-Cpu-Arch",
    "antidetect": "X-Antidetect",
    "canvas_noise": "X-Fp-Canvas-Noise",
}


def _inject_client_signals(headers: Dict[str, str], payload: Dict[str, Any]) -> Dict[str, str]:
    """Copy client JSON attributes onto fingerprint headers used by evaluators."""
    if not payload:
        return headers

    merged = dict(headers)
    existing_lower = {k.lower() for k in merged}
    for key, header_name in PAYLOAD_HEADER_MAP.items():
        if key not in payload or payload[key] is None:
            continue
        if header_name.lower() in existing_lower:
            continue
        value = payload[key]
        if isinstance(value, bool):
            encoded = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            encoded = ",".join(str(item) for item in value)
        else:
            encoded = str(value)
        merged[header_name] = encoded
        existing_lower.add(header_name.lower())
    return merged


def _header_value(headers: Dict[str, str], headers_lower: Dict[str, str], name: str, missing: str = "Missing ❌") -> str:
    """Return a header value using original or lowercase lookup."""
    if name in headers and headers[name]:
        return headers[name]
    lower = name.lower()
    if lower in headers_lower and headers_lower[lower]:
        return headers_lower[lower]
    return missing


def _build_rule_details(
    rule_id: str,
    rule_name: str,
    headers: Dict[str, str],
    headers_lower: Dict[str, str],
    parsed_ua: Dict[str, Any],
    raw_ua: str,
    client_payload: Dict[str, Any],
    triggered: bool,
) -> Dict[str, str]:
    """
    Attach structured telemetry evidence for each evaluated rule.
    Used by the dashboard click-to-inspect modal.
    """
    user_agent_str = raw_ua or ""
    payload = client_payload or {}

    if rule_id == "HC117":
        return {
            "User Agent String": user_agent_str or "N/A",
            "Detected Bot Class": "Headless / HTTP Client" if triggered else "Standard Web Browser",
            "Header Signature": "Automation Tool Signature Detected" if triggered else "Clean Browser Headers",
        }

    if rule_id == "HC106":
        return {
            "Accept-Language": _header_value(headers, headers_lower, "Accept-Language"),
            "Accept-Encoding": _header_value(headers, headers_lower, "Accept-Encoding"),
            "Header Evaluation": "Incomplete Standard Request Headers" if triggered else "Standard Headers Present",
        }

    if rule_id == "HC124":
        major = parsed_ua.get("browser", {}).get("major")
        return {
            "Detected Browser": f"{parsed_ua.get('browser', {}).get('family', 'Unknown')} {major or ''}".strip(),
            "Minimum Required Version": "80.0",
            "Version Status": "Outdated Legacy Version (>= 5 Years)" if triggered else "Supported Version",
        }

    if rule_id == "HC125":
        platform = payload.get("platform", "Unknown")
        ua_os = parsed_ua.get("os", {}).get("family", "Unknown")
        return {
            "User-Agent OS": ua_os,
            "JS Navigator Platform": platform,
            "Consistency Check": "Mismatched OS and Platform (Spoofed)" if triggered else "OS and Platform Match",
        }

    if rule_id == "HC100":
        client_tz = payload.get("timezone") or headers_lower.get("x-fp-timezone") or "N/A"
        ip_tz = payload.get("ip_timezone") or headers_lower.get("x-ip-timezone") or "Unknown (no geo lookup)"
        return {
            "Browser Timezone": str(client_tz),
            "IP Geolocation Location": str(ip_tz),
            "Timezone Analysis": "Clock Timezone Mismatch vs IP Location" if triggered else "Clock Timezone Matches IP Location",
        }

    if rule_id == "HC108":
        return {
            "User-Agent Device": "Mobile" if parsed_ua.get("is_mobile") else parsed_ua.get("device", {}).get("family", "Unknown"),
            "JS Platform / Arch": str(payload.get("platform") or headers_lower.get("x-fp-platform") or "N/A"),
            "Emulation Check": "Mobile UA on desktop architecture" if triggered else "Device class matches platform",
        }

    if rule_id == "HC113":
        res = payload.get("screen_resolution") or headers_lower.get("x-fp-screen-resolution") or "N/A"
        return {
            "Screen Viewport": str(res),
            "Color Depth": f"{payload.get('screen_depth', 24)}-bit",
            "Resolution Evaluation": "Anomalous/Zero Viewport Dimensions" if triggered else "Standard Screen Viewport",
        }

    if rule_id == "HC115":
        return {
            "Canvas Hash": str(payload.get("canvas_hash") or headers_lower.get("x-fp-canvas-hash") or "N/A"),
            "Hardware Concurrency": str(payload.get("hardware_concurrency") or headers_lower.get("x-fp-hardware-concurrency") or "N/A"),
            "Anti-Detect Check": "Patched canvas or fake hardware profile" if triggered else "Native canvas/hardware signature",
        }

    if rule_id == "HC102":
        return {
            "Cookie Storage API": "Disabled / Rejected" if triggered else "Enabled",
            "Session Support": "Cookies Disabled (Bot Indicator)" if triggered else "Standard Cookie Access Allowed",
        }

    if rule_id == "HC126":
        return {
            "Shared Account Count": str(payload.get("shared_user_count") or headers_lower.get("x-fp-shared-user-count") or "1"),
            "Velocity Check": "6+ accounts on one hardware ID" if triggered else "Normal account-to-device mapping",
        }

    if rule_id == "HC135":
        return {
            "Click isTrusted": str(payload.get("click_trusted") if "click_trusted" in payload else headers_lower.get("x-fp-click-trusted", "true")),
            "Event Source": "Synthetic JavaScript event" if triggered else "Trusted user input",
        }

    if rule_id == "HC137":
        return {
            "Remote Desktop Flag": str(payload.get("remote_desktop") or headers_lower.get("x-fp-remote-desktop") or "false"),
            "Remote Tool": str(payload.get("remote_tool") or headers_lower.get("x-fp-remote-tool") or "none"),
            "Session Check": "RDP / AnyDesk / TeamViewer detected" if triggered else "Local interactive session",
        }

    if rule_id == "HC141":
        return {
            "navigator.webdriver": str(payload.get("webdriver") if "webdriver" in payload else headers_lower.get("x-fp-webdriver", "false")),
            "User Agent String": user_agent_str or "N/A",
            "Headless Check": "Unmasked headless Chrome / WebDriver" if triggered else "No webdriver automation flag",
        }

    if rule_id == "HC142":
        return {
            "WebDriver Hidden": str(payload.get("webdriver_hidden") if "webdriver_hidden" in payload else headers_lower.get("x-fp-webdriver-hidden", "false")),
            "Mouse Movement Samples": str(payload.get("mouse_movement") if "mouse_movement" in payload else headers_lower.get("x-fp-mouse-movement", "N/A")),
            "Stealth Check": "Automation hidden with zero cursor telemetry" if triggered else "Pointer activity consistent with a human session",
        }

    if rule_id == "HC143":
        return {
            "Tor Signal": str(payload.get("is_tor") if "is_tor" in payload else headers_lower.get("x-fp-is-tor", "false")),
            "User Agent String": user_agent_str or "N/A",
            "Exit Node Check": "Known Tor onion router exit node" if triggered else "Not a Tor exit path",
        }

    return {
        "Attribute Identifier": rule_id,
        "Evaluated Property": rule_name,
        "Client Value": str(payload.get(rule_id.lower(), "Standard Parameter")),
        "Evaluation Result": "Anomalous Behavioral Pattern" if triggered else "Clean Behavior",
    }


# Singleton instance for general use
_engine_instance = None


def get_scoring_engine() -> ScoringEngine:
    """Get or create singleton ScoringEngine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ScoringEngine()
    return _engine_instance


def evaluate_risk(
    headers: Dict[str, str],
    ip: Optional[str] = None,
    client_payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to evaluate risk using the default engine instance.
    """
    return get_scoring_engine().evaluate(headers, ip, client_payload)
