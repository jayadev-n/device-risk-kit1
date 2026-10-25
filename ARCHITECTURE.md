# Device Fingerprinting & Risk Scoring Engine — Architecture Specification

## Overview
This document outlines the architectural blueprint, data flow, and evaluation logic for the Device Fingerprinting & Risk Scoring Engine.

---

## System Architecture & Data Flow

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