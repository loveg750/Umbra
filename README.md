# Umbra | Trident Division  
**Blacksite Threat Intelligence & Detection Agent**

Umbra is a blacksite-style SOC intelligence agent built as part of an AI Agents capstone project.  
She ingests security logs, runs a hybrid detection pipeline (rules + anomaly scoring), and presents alerts with an adaptive persona that responds differently to the Creator versus other operators.

> **Key idea:** Umbra behaves like a mini SOC analyst inside a dashboard — correlating signals, scoring risk, and narrating what she sees.

---

## 🔍 Use Case

Modern environments generate huge volumes of logs across authentication, endpoints, network, and exfiltration surfaces.  
Security teams struggle to:

- Quickly spot meaningful patterns
- Understand *why* a sequence of events looks suspicious
- Prioritize which events to investigate first

**Umbra** is designed as an intelligent assistant that:

- **Ingests CSV log exports** (simulating SIEM data)
- **Detects known patterns** using a rule engine
- **Scores unknown or weird behavior** using an anomaly engine
- **Explains alerts in human language** through a persona layer

The capstone version runs as a **Streamlit app** but is designed so it can be extended into a real-time service later.

---

## ✨ Core Features

- **Multi-log support**
  - `auth` – login events, MFA anomalies, brute-force patterns  
  - `network` – beaconing, rare domains, DNS tunneling hints  
  - `exfil` – large archive creation, cloud uploads, USB copy patterns  
  - `endpoint` – suspicious processes, privilege escalation, credential access

- **Rule-based Detection Engine**
  - Loads JSON rule packs from the `rules/` folder
  - Each rule defines conditions, severity, and optional MITRE mappings
  - Produces structured `Incident` objects when rules match log records

- **Anomaly / Zero-Day Engine**
  - Adds a behavior layer on top of rules
  - Scores each record (0–100) based on:
    - exploit / crash language
    - exfil-style activity
    - C2 / beaconing indicators
    - credential access signals
    - behavioral deviation fields
  - Outputs:
    - `score` (0–100)
    - `risk_level` (low / medium / high / critical)
    - `tags` (e.g., `zero_day_suspect`, `exfil_suspect`)
    - `signals` explaining *why* the activity looks risky

- **Alert Builder**
  - Merges rule-based incidents + anomaly results into a single **alert object**
  - Standard format includes:
    - top-level severity + title + summary
    - rule block (id, name, MITRE)
    - anomaly block (score, risk, tags, signals)
    - context block (original record, host, user)

- **Umbra Persona (Creator vs Agent)**
  - Umbra adapts based on operator identity:
    - If codename matches the Creator (e.g. `"Trident"`), Umbra enters **Creator / “God Mode”** (visual + language changes).
    - All other users are treated as **Blacksite Agents** with high-level access.
  - Persona middleware:
    - Generates a short “voice line” per alert based on severity + anomaly tags.
    - Example:  
      *“This is deliberate, not accidental. Someone is probing your defenses.  
      This pattern does not exist in my memory. Treat it as a potential zero-day.”*

- **Streamlit Blacksite UI**
  - Dark, minimal dashboard
  - Sidebar: operator codename (Creator/Agent detection)
  - Header: title, mode pill, welcome line
  - Controls: log type selection + CSV upload + “Analyze with Umbra” button
  - Summary metrics: count of Critical / High / Medium / Low alerts
  - Alert cards with:
    - severity badge
    - risk level
    - rule id
    - persona voice line
    - summary + expandable details (signals, MITRE, raw record)

---

## 🏗️ Architecture Overview

**High-level flow:**

1. **Input**: User selects log type and uploads a CSV.
2. **Detection Engine** (`detection_engine.py`):
   - Loads JSON rules from `rules/`
   - Scans each record for rule matches
   - Emits `Incident` objects
3. **Anomaly Engine** (`anomaly_engine.py`):
   - Analyzes each underlying record
   - Produces `AnomalyResult` (score, risk, tags, signals)
4. **Alert Builder** (`alert_builder.py`):
   - Combines `Incident` + `AnomalyResult`
   - Creates a normalized alert dict for the UI
5. **Persona Middleware** (`persona_middleware.py`):
   - Uses operator context (Creator vs Agent)
   - Attaches Umbra’s voice line + operator metadata to each alert
6. **UI** (`Umbra.py`):
   - Renders dashboard, summary metrics, and alert cards

---

## 📁 Project Structure

```text
Umbra/
├── Umbra.py                 # Streamlit UI / main app
├── detection_engine.py      # Rule engine & incident generation
├── anomaly_engine.py        # Anomaly / zero-day scoring engine
├── alert_builder.py         # Combines incidents + anomaly into alerts
├── persona_middleware.py    # Persona logic (Creator vs Agent)
├── rules/
│   ├── auth_rules.json      # Auth-related detection rules
│   ├── network_rules.json   # Network-related rules
│   ├── exfiltration_rules.json
│   └── endpoint_rules.json
└── sample_logs/ (optional)  # Example CSV logs for testing
