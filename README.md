# 🛡️ Device Fingerprinting & Risk Scoring Engine

A modular, production-ready Flask REST API that performs **Device Fingerprinting** and **Risk Scoring** based on incoming HTTP request headers, browser telemetry, and behavioral heuristics.

---

## 📌 Architecture & Data Flow

```text
+-------------------------------------------------------------------------------+
|                                CLIENT LAYER                                   |
|                                                                               |
|   +------------------------------------+----------------------------------+   |
|   |         Postman / API Client       |      Web Browser Client Script   |   |
|   |   (Sends User-Agent, IP, Headers)  |     (Sends Canvas, Screen, etc)  |   |
|   +-----------------+------------------+------------------+---------------+   |
+---------------------|-------------------------------------|-------------------+
                      |                                     |
                      +------------------+------------------+
                                         | HTTP POST
                                         v
+-------------------------------------------------------------------------------+
|                            FLASK BACKEND ENGINE                               |
|                                                                               |
|  1. Score Controller  ──────>  Captures HTTP Headers & Request Metadata       |
|                                                                               |
|  2. UA Parser & Hash  ──────>  Parses OS/Browser & Generates SHA-256 Device ID |
|                                                                               |
|  3. Rule Engine       ──────>  Executes Bot, Header, and Browser Checks       |
|                                                                               |
|  4. Scoring Module    ──────>  Sums Points & Calculates Risk Severity         |
+----------------------------------------+--------------------------------------+
                                         |
                                         v
+-------------------------------------------------------------------------------+
|                          JSON RISK ASSESSMENT OUTPUT                          |
|   • Device ID Hash      • Risk Score       • Severity (LOW/MED/HIGH)          |
|   • Parsed Metadata     • Triggered Rules  • Recommended Action               |
+-------------------------------------------------------------------------------+
```

---

## 📂 Project Structure

```text
device-fingerprint-engine/
│
├── config/
│   └── rules.json              # Configurable rule set and point weights
│
├── app/
│   ├── __init__.py             # Flask app factory & interactive web UI demo
│   ├── controllers/
│   │   ├── __init__.py
│   │   └── score_controller.py # REST endpoints (POST /api/v1/fingerprint/score)
│   │
│   ├── rules/
│   │   ├── __init__.py         # Evaluator registry
│   │   ├── bot_rules.py        # HC117: Postman/cURL/Bot/Automation checks
│   │   ├── header_rules.py     # HC106: Missing browser headers checks
│   │   └── browser_rules.py    # HC114 & HC124: Outdated & unknown UAs
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   └── scoring_engine.py   # Aggregation, severity mapping & device ID
│   │
│   └── utils/
│       ├── __init__.py
│       ├── ua_parser.py        # User-agent metadata parser
│       └── hash_generator.py   # Deterministic SHA-256 device ID generator
│
├── tests/                      # Automated test suite (Pytest)
├── run.py                      # Application entry point
├── requirements.txt            # Python dependencies
├── ARCHITECTURE.md             # System architecture specification
├── prompt.md                   # Project requirements specification
└── README.md                   # Documentation & Postman Guide
```

---

## ⚙️ Configured Threat Rules

Defined in [`config/rules.json`](config/rules.json):

| Rule ID | Rule Name | Score Impact | Trigger Conditions |
|---|---|:---:|---|
| **`HC117`** | Suspicious browser profile - Bots or Postman | **+12 pts** | User-Agent contains `postman`, `curl`, `python`, `headless`, `selenium`, `puppeteer`, etc., `is_bot` flag is `true`, or contains `Postman-Token` header. |
| **`HC124`** | Outdated browser version | **+8 pts** | Major version below supported threshold (e.g. Chrome < 80, Firefox < 75, Safari < 13) or obsolete browsers like IE. |
| **`HC106`** | Missing standard browser headers | **+2 pts** | Absence of standard modern browser headers: `Accept-Language` or `Accept-Encoding`. |
| **`HC114`** | Unpopular or unknown user agent | **+2 pts** | Empty/missing UA, short generic UA string, or unknown browser family. |

### Severity & Recommended Actions Matrix

| Cumulative Score | Threat Severity | Recommended Action |
|---|---|---|
| **Score < 5** | `LOW` | **`ALLOW`** |
| **Score 5 – 11** | `MEDIUM` | **`CAPTCHA / MFA`** |
| **Score >= 12** | `HIGH` | **`BLOCK / CHALLENGE`** |

---

## 🚀 Installation & Quickstart

### Prerequisites
- Python 3.9+
- Pip

### 1. Clone & Setup Environment
```bash
# Navigate to the project root
cd device-fingerprint-engine

# Optional: Create a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Server
```bash
python run.py
```
The server starts at `http://localhost:5000`.

- **Web Dashboard & Interactive Client:** `http://localhost:5000/`
- **Scoring API Endpoint:** `POST http://localhost:5000/api/v1/fingerprint/score`
- **Active Rules Configuration:** `GET http://localhost:5000/api/v1/fingerprint/rules`
- **Health Check:** `GET http://localhost:5000/api/v1/fingerprint/health`

---

## 🧪 Postman & cURL Usage Guide

### Scenario 1: Clean Legitimate Browser (LOW Risk -> ALLOW)

**cURL Request:**
```bash
curl -X POST http://localhost:5000/api/v1/fingerprint/score \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -d '{
    "screen_resolution": "1920x1080",
    "canvas_hash": "canvas_a9f82c",
    "timezone": "America/New_York"
  }'
```

**Expected JSON Response (HTTP 200):**
```json
{
  "device_id": "7f8b9264c9bb457e5b61e2760a92d47155d045d44d41e7cb7678d91c78de38a3",
  "risk_score": 0,
  "risk_severity": "LOW",
  "recommended_action": "ALLOW",
  "triggered_rules": [],
  "parsed_metadata": {
    "ip": "127.0.0.1",
    "browser": {
      "family": "Chrome",
      "major": 122,
      "minor": "0",
      "version": "122.0.0.0"
    },
    "os": {
      "family": "Windows",
      "major": 10,
      "minor": null,
      "version": "10"
    },
    "device": {
      "brand": null,
      "family": "Other",
      "model": null
    },
    "is_bot": false,
    "is_mobile": false,
    "is_pc": true,
    "is_tablet": false,
    "raw_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
  },
  "client_payload": {
    "canvas_hash": "canvas_a9f82c",
    "screen_resolution": "1920x1080",
    "timezone": "America/New_York"
  },
  "evaluated_at": "2026-10-16T15:20:00.000000+00:00"
}
```

---

### Scenario 2: Outdated Browser (MEDIUM Risk -> CAPTCHA / MFA)

Triggers `HC124` (+8 points) and `HC106` (+2 points if missing Accept-Language):

**cURL Request:**
```bash
curl -X POST http://localhost:5000/api/v1/fingerprint/score \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br"
```

**Expected JSON Response (HTTP 200):**
```json
{
  "device_id": "b0a24f0c978438171d93cefa5c26b9a9bf4da2b7a977227d8ce6b09bb99540b9",
  "risk_score": 8,
  "risk_severity": "MEDIUM",
  "recommended_action": "CAPTCHA / MFA",
  "triggered_rules": [
    {
      "id": "HC124",
      "name": "Outdated browser version",
      "score": 8,
      "reason": "Browser version is outdated: Chrome 70 (minimum recommended: 80)."
    }
  ],
  "parsed_metadata": {
    "ip": "127.0.0.1",
    "browser": {
      "family": "Chrome",
      "major": 70,
      "minor": "0",
      "version": "70.0.3538.77"
    },
    "os": {
      "family": "Windows",
      "major": 10,
      "minor": null,
      "version": "10"
    },
    "is_bot": false,
    "is_pc": true
  }
}
```

---

### Scenario 3: Automated Bot or Postman Request (HIGH Risk -> BLOCK / CHALLENGE)

Triggers `HC117` (+12 points) and `HC106` (+2 points):

**Postman / cURL Request:**
```bash
curl -X POST http://localhost:5000/api/v1/fingerprint/score \
  -H "User-Agent: PostmanRuntime/7.36.0" \
  -H "Postman-Token: 62bf19b4-b033-4f9e-8761-123456789abc"
```

**Expected JSON Response (HTTP 200):**
```json
{
  "device_id": "4b2e8fa4429e7ecba0bc8b671a539da60ca64024c0d12ce17b2b291db7c73b0d",
  "risk_score": 14,
  "risk_severity": "HIGH",
  "recommended_action": "BLOCK / CHALLENGE",
  "triggered_rules": [
    {
      "id": "HC117",
      "name": "Suspicious browser profile - Bots or Postman",
      "score": 12,
      "reason": "User-Agent contains suspicious automation/client keyword: 'postman'."
    },
    {
      "id": "HC106",
      "name": "Missing standard browser headers",
      "score": 2,
      "reason": "Request missing expected standard browser header(s): Accept-Language, Accept-Encoding."
    }
  ],
  "parsed_metadata": {
    "ip": "127.0.0.1",
    "browser": {
      "family": "Other",
      "major": null,
      "version": ""
    },
    "is_bot": false
  }
}
```

---

## 🧪 Running Automated Tests

Run all unit and integration tests with `pytest`:

```bash
python -m pytest tests/ -v
```
