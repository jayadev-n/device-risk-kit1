# Project Generation Prompt: Device Fingerprinting & Risk Scoring Engine

## Context & Goal
You are an expert Python and cybersecurity engineer. Build a production-ready, modular Flask API that performs **Device Fingerprinting and Risk Scoring** based on incoming HTTP request headers and attributes. 

The engine inspects requests (e.g., from Postman, cURL, or web browsers), matches them against configurable risk detection rules, calculates a cumulative risk score, assigns a threat severity level (LOW, MEDIUM, HIGH), and recommends an action (ALLOW, CAPTCHA/MFA, BLOCK/CHALLENGE).

## Technology Stack
- **Language:** Python 3.9+
- **Framework:** Flask (REST API)
- **User-Agent Parsing:** `user-agents` library
- **Configuration & Storage:** JSON-based rules configuration (`config/rules.json`)
- **Hashing & Crypto:** Python standard library (`hashlib`)

## Project Structure
Generate the complete project following this structure:

device-fingerprint-engine/
│
├── config/
│   └── rules.json              # Configurable rule set and point weights
│
├── app/
│   ├── __init__.py             # Flask app factory initialization
│   ├── controllers/
│   │   ├── __init__.py
│   │   └── score_controller.py # POST endpoint for scoring
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── bot_rules.py        # HC117: Postman/cURL/Bot checks
│   │   ├── header_rules.py     # HC106: Missing browser headers
│   │   └── browser_rules.py    # HC114, HC124: Outdated & unknown UAs
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   └── scoring_engine.py   # Rule evaluation and score aggregation
│   │
│   └── utils/
│       ├── __init__.py
│       ├── ua_parser.py        # User-agent metadata parser
│       └── hash_generator.py   # Device ID hash calculation
│
├── run.py                      # Application entry point
├── requirements.txt            # Python dependencies
└── README.md                   # Setup and Postman usage documentation

## Implementation Requirements

### 1. `config/rules.json`
Define the following rules with ID, descriptive name, score impact, and enabled flag:
- **HC117**: "Suspicious browser profile - Bots or Postman" (Score: +12)
- **HC106**: "Missing standard browser headers" (Score: +2)
- **HC124**: "Outdated browser version" (Score: +8)
- **HC114**: "Unpopular or unknown user agent" (Score: +2)

### 2. `app/utils/hash_generator.py`
Create a function `generate_device_id(ip, user_agent, accept_language)` that returns a deterministic `SHA-256` string identifying the device.

### 3. `app/rules/`
- **`bot_rules.py`**: Check if UA contains keywords like `postman`, `curl`, `python`, `headless`, `selenium`, `puppeteer`, or if `is_bot` flag is true.
- **`header_rules.py`**: Check if standard headers like `Accept-Language` or `Accept-Encoding` are missing.
- **`browser_rules.py`**: Check if browser major version is outdated (e.g., Chrome < 80, Firefox < 75) or if UA family is unknown/other.

### 4. `app/services/scoring_engine.py`
- Parse the User-Agent using `user_agents`.
- Execute all enabled rules.
- Calculate total points.
- Map total score to Risk Level & Action:
  - **Score < 5:** `LOW` risk, Action: `ALLOW`
  - **Score 5–11:** `MEDIUM` risk, Action: `CAPTCHA / MFA`
  - **Score >= 12:** `HIGH` risk, Action: `BLOCK / CHALLENGE`
- Return structured response dictionary.

### 5. `app/controllers/score_controller.py`
Expose a POST endpoint `/api/v1/fingerprint/score`.
- Read headers, remote IP, and request body.
- Call `evaluate_risk()` from the scoring engine.
- Return JSON with 200 OK status.

## Instructions
Write fully implemented, clean, PEP-8 compliant code for every file specified above. Do not use placeholders or incomplete functions.