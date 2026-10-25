# UI Feature Request: Visual Status Highlighting for Rule Engine Dashboard

## Objective
Upgrade the frontend dashboard UI for the Device Fingerprinting & Risk Scoring Engine to visually differentiate between:
1. **Triggered/Suspicious Rules (Red/Amber Alert State)**: Rules that matched negative criteria (e.g., Bot detected, missing headers, outdated browser) and added risk score points.
2. **Passed/Clean Criteria (Green Check State)**: Rules that were evaluated and successfully passed cleanly (e.g., User is NOT a bot, headers are intact, browser is up to date).

## Functional Requirements

### 1. Updated Rule Evaluation Payload Format
Ensure the API response payload includes a complete list of evaluated rules with their evaluation status (`passed` vs `triggered`):

```json
"evaluated_rules": [
  {
    "id": "HC117",
    "name": "Suspicious browser profile - Bots and automation",
    "status": "triggered", // or "passed"
    "score_impact": 12,
    "description": "Detected Postman/automated client header."
  },
  {
    "id": "HC106",
    "name": "Missing device details / headers",
    "status": "passed",
    "score_impact": 0,
    "description": "All standard HTTP headers (Accept-Language, Accept-Encoding) present."
  }
]