# InsightOps – AI-Driven SOC Intelligence

```
 ___           _       _     ___            
|_ _|_ __  ___(_) __ _| |__ / _ \ _ __  ___ 
 | || '_ \/ __| |/ _` | '_ \ | | | '_ \/ __|
 | || | | \__ \ | (_| | | | | |_| | |_) \__ \
|___|_| |_|___/_|\__, |_| |_|\___/| .__/|___/
                  |___/             |_|      
```

**InsightOps is a **SOC-assist (not SOC-automation)** intelligence engine that correlates security alerts, assigns deterministic risk scores, maps MITRE ATT&CK techniques, and generates analyst-ready incident narratives - all without ML, black boxes, or automated response.**

---

## 📌 Project Overview

**InsightOps** is an enterprise-grade, **AI-assisted Security Operations Center (SOC) intelligence platform** designed to mirror **real-world SOC workflows**, not academic simulations.

Unlike typical student projects that stop at log ingestion or isolated detections, InsightOps implements a full SOC-style detection-to-incident pipeline, including:

- A realistic **Active Directory–based SOC lab** (Windows + Linux)
- **Centralized SIEM monitoring** using Splunk as the detection backbone
- **Detection engineering aligned with MITRE ATT&CK**, not signature-based alerts
- An external **AI-driven intelligence layer** that correlates alerts, assigns deterministic risk scores, and generates analyst-readable incident context

InsightOps is **intentionally SOC-assist only**.
It augments human analysts by prioritizing, correlating, and explaining security signals — it does not perform automated response or remediation, avoiding the operational risks of premature automation.

To support analyst workflows, InsightOps also includes **Splunk dashboards** that provide:

- A **real-time incident triage queue** for Tier-1 / Tier-2 analysts
- A SOC-wide **incident overview** showing risk distribution and active MITRE techniques

These dashboards are visualization-only and do not mutate system state, preserving **auditability and decision integrity**.

InsightOps focuses on **operational correctness, explainability, and SOC maturity** rather than feature count or automation hype.

---

## 🎯 Target Roles

This project is designed to demonstrate readiness for:

- SOC Analyst (Tier 1 / Tier 2)
- Blue Team Engineer
- Detection Engineer (Junior)
- SIEM / SOC Automation Engineer
- Entry-level DFIR roles

---

## 🧱 System Architecture (High-Level)

InsightOps follows a **three-layer SOC architecture**:

### 🔹 Layer 1 — SOC Infrastructure & Telemetry Foundation
- Fedora Linux host running **Splunk Enterprise (bare metal)**
- KVM/QEMU–based virtualized lab
- Active Directory (Windows Server 2019, Domain Functional Level 2016)
- Windows 10 and Ubuntu domain-joined endpoints
- Kali Linux internal attacker (non-domain)
- Centralized log collection via Splunk Universal Forwarder

### 🔹 Layer 2 — AI-Driven SOC Intelligence Engine (Core Contribution)
- External Python-based AI engine
- Pulls alerts from Splunk via REST API
- Performs:
  - Contextual risk scoring (0–100)
  - Multi-stage attack correlation
  - Incident construction
  - Explainable intelligence generation
- Writes enriched incidents back to Splunk using HEC (`ai_soc` index)

---

## 📸 Execution & Detection Gallery

InsightOps in action during live attack simulations (Kali Linux + Splunk side-by-side).

### 1. Multi-Stage Attack Correlation (Incident Triage Queue)
The triage queue showing AI-correlated incidents. Notice the deterministic risk capping at 100 (CRITICAL) for multi-stage chains involving lateral movement and credential dumping.
![Incident Triage Queue](docs/Images_Proof/Screenshot_20260228_223232.png)
![Incident Triage Queue](docs/Images_Proof/Screenshot_20260228_223222.png)

### 2. Live Simulation: Kerberoasting Attack vs SOC Overview
Attacker executing `GetUserSPNs.py` against the AD environment while the AI engine aggregates alerts and updates the SOC situational awareness overview.
![Kerberoasting Execution](docs/Images_Proof/Screenshot_20260227_043645.png)

### 3. Live Simulation: SSH Password Spraying vs SOC Overview
Attacker spraying SSH credentials against the Linux Ubuntu host. The AI engine maps the behavior directly to MITRE T1110.003 and escalates risk.
![SSH Spraying Execution](docs/Images_Proof/Screenshot_20260228_210806.png)

---

## 🌐 Lab Network Design

| Component | Network |
|--------|--------|
| Internal SOC / AD LAN | `10.10.10.0/24` |
| NAT / Internet | `192.168.122.0/24` |

### Key Systems
- **Fedora Host / Splunk and  (AI Engine Host)** → `10.10.10.1`
- **DC01 (Windows Server 2019)** → `10.10.10.10`
- **Windows 10 Client** → `10.10.10.30`
- **Ubuntu Client** → `10.10.10.20`
- **Kali (Attacker)** → `10.10.10.50`

Dual-NIC architecture enables realistic east–west traffic monitoring and internal attack simulation.

---

## 🏗️ Architecture

```
Splunk (index=main)
    │
    ▼  REST API :8089
┌───────────────────────────────────────────────────┐
│  ai-engine/main.py                                │
│                                                   │
│  0. run_signal_health_check()                     │
│  1. fetch_alerts()         ← splunk_client.py     │
│  2. calculate_risk_score() ← risk_scorer.py       │
│  3. correlate_incidents()  ← incident_builder.py  │
│  4. apply_correlation_bonuses() ← bonus_engine.py │
│  5. explain_incident()     ← explainer.py         │
│  6. write_incident_to_hec()← hec_writer.py        │
└───────────────────────────────────────────────────┘
    │
    ▼  HEC :8088
Splunk (index=ai_soc)
```

---

## 📁 Project Structure

```
InsightOps/
├── ai-engine/
│   ├── main.py                       Pipeline orchestrator (~155 lines)
│   ├── correlation/
│   │   ├── bonus_engine.py           Attack chain bonuses + weight loading
│   │   └── incident_builder.py       Alert → incident grouping
│   ├── explainability/
│   │   └── explainer.py              MITRE mapping, summaries, investigation steps
│   ├── health/
│   │   └── signal_health.py          Telemetry freshness check (pre-pipeline)
│   ├── ingestion/
│   │   ├── splunk_client.py          Alert fetch + classification
│   │   └── hec_writer.py            Write enriched incidents to Splunk HEC
│   └── scoring/
│       └── risk_scorer.py            4-factor weighted risk scoring
├── tests/                            77 unit tests (pytest), no Splunk required
├── config/
│   ├── splunk.yaml                   Connection details (no credentials)
│   └── weights.yaml                  Static scoring weights
├── splunk/
│   └── detections/
│       └── savedsearches.conf        Raw SPL for all 14 detection rules
├── docs/
│   ├── Lessons_Learned.md            15 lessons from building this project
│   └── DASHBOARDS.md                 Splunk dashboard XML definitions
├── .env.example                      Credential template
├── .gitignore
├── pytest.ini
└── requirements.txt
```

---

## ⚙️ Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure credentials

```bash
cp .env.example .env
# Edit .env and fill in your real values:
#   export SPLUNK_USERNAME=...
#   export SPLUNK_PASSWORD=...
#   export SPLUNK_HEC_TOKEN=...
source .env
```

### 3. Configure connection

Edit `config/splunk.yaml`:
```yaml
splunk_host: 10.10.10.1
management_port: 8089
hec_port: 8088
ai_soc_index: ai_soc
```

---

## 🚀 Running

```bash
# Dry-run (no writes to Splunk)
source .env
python ai-engine/main.py --dry-run

# Full pipeline (writes enriched incidents to Splunk HEC)
python ai-engine/main.py
```

**Expected output (dry-run):**
```
INFO  Dry run enabled: no data will be sent to Splunk
--- Signal Health Check ---
[OK] linux_secure: last event 2 minutes ago
⚠️  wineventlog:security: no events in last 12 minutes
[OK] alert:InsightOps*: last event 1 minute ago
---------------------------
INFO  Fetching alerts from Splunk
INFO  Scored 4 alerts
INFO  Correlated 2 incidents
INFO  Wrote incident af3c… to Splunk HEC
```

---

## 🔍 Detection Coverage

| Alert | Platform | MITRE | Severity |
|---|---|---|---|
| Password Spraying | Windows / Linux | T1110.003 | HIGH |
| SSH Brute Force | Linux | T1110.001 | LOW |
| Kerberoasting | Windows | T1558.003 | CRITICAL |
| Lateral Movement | Windows | T1021 | HIGH |
| Lateral Movement (SSH) | Linux | T1021.004 | HIGH |
| Privilege Escalation | Windows | T1068 | CRITICAL |
| Privilege Escalation (sudo/SUID) | Linux | T1548.003 | CRITICAL |
| Persistence | Windows | T1547 | CRITICAL |
| Persistence (cron) | Linux | T1053.003 | CRITICAL |
| Credential Dumping | Windows / Linux | T1003 | CRITICAL |
| Ransomware Pre-Impact | Windows / Linux | T1490 | CRITICAL |

> [!NOTE] 
> The raw Splunk SPL (Search Processing Language) logic behind these alerts is stored in [`splunk/detections/savedsearches.conf`](splunk/detections/savedsearches.conf).

---

## 📊 Risk Scoring

```
risk_score = normalize(
    severity       × w_base_severity      +
    host_criticality × w_host_criticality +
    user_privilege × w_user_privilege     +
    event_frequency × w_behavioral_frequency
) + correlation_bonus   →   capped at 100
```

Weights are loaded from `config/weights.yaml`. Defaults:

```yaml
base_severity: 1.0
host_criticality: 1.0
user_privilege: 1.0
behavioral_frequency: 1.0
correlation_bonus: 15.0
```

### Correlation Bonus Stacking

| Chain | Bonus |
|---|---|
| Any Password Spraying | +0.5× bonus |
| PS → Kerberoasting | +1× bonus |
| Cred Access → Privilege Escalation | +1× bonus |
| Priv-Esc → Persistence | +1× bonus |
| Any Lateral Movement (Linux) | +1× bonus (amplified if cred access present) |
| Any Credential Dumping | +1× bonus |
| Pre-Ransomware after PE/Persistence/LM | +100 (capped to 100) |

---

## 🧠 Explainability Output

Every incident written to Splunk includes:

```json
{
  "incident_id": "af3c89d1-...",
  "risk_score": 87.5,
  "plain_english_summary": "A 3-alert chain on dc01...",
  "mitre_techniques": [
    {"technique_id": "T1110.003", "technique_name": "Brute Force: Password Spraying"},
    {"technique_id": "T1558.003", "technique_name": "Steal or Forge Kerberos Tickets"}
  ],
  "risk_score_explanation": "Score elevated by correlation bonus of 30.0...",
  "investigation_steps": [
    "Review failed authentication events for dc01...",
    "Check for suspicious Kerberos ticket requests..."
  ]
}
```

---

## 🩺 Signal Health Check

Runs before every pipeline execution. Queries Splunk for latest event time across:

| Signal | Filter |
|---|---|
| `linux_secure` | `sourcetype=linux_secure` |
| `wineventlog:security` | `sourcetype=wineventlog:security` |
| `alert:InsightOps*` | `source="alert:InsightOps*"` |

Warns if any signal has no events in the last 10 minutes. Uses a 15s timeout per query. Fully fail-safe — never blocks the pipeline.

---

## 🧪 Tests

```bash
pytest tests/ -v
```

```
77 passed in 0.17s
```

No Splunk connection required. Tests cover:
- `test_risk_scorer.py` — scoring formula, caps, breakdown keys
- `test_bonus_engine.py` — all bonus rules, stacking, ransomware cap
- `test_incident_builder.py` — grouping, time windows, schema
- `test_explainer.py` — MITRE classification correctness, investigation steps
- `test_splunk_client.py` — all 14 alert classifiers, user field extraction

---

## 🎓 Academic Context

Built as a **6th-semester B.Tech (CSE – Cybersecurity)** Portfolio project. Demonstrates real SIEM integration, Windows + Linux kill-chain coverage, and production-grade SOC engineering practices well beyond typical academic scope.

---

## Final Note

InsightOps is not a tool that "detects attacks."

It is a system that **protects analyst decision integrity**.
