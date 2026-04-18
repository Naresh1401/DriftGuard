# DriftGuard

**Human-state drift detection for cybersecurity.** DriftGuard detects the organizational behavioral patterns — fatigue, overconfidence, hurry, quiet fear, hoarding, and compliance theater — that precede security breaches by days or weeks.

> *"Every cybersecurity breach has a human-state precursor. Current tools catch the breach. We catch the precursor."*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![Node 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org)

---

## One-Click Setup

### Option 1: Docker (recommended)

```bash
git clone https://github.com/user/DriftGuard.git
cd DriftGuard
./setup.sh
```

This starts the full stack: frontend, backend API, PostgreSQL, Grafana, and Prometheus.

| Service | URL |
|---------|-----|
| Frontend | http://localhost |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Grafana | http://localhost:3001 (admin / driftguard) |
| Prometheus | http://localhost:9090 |

### Option 2: Local Development

```bash
git clone https://github.com/user/DriftGuard.git
cd DriftGuard
./setup.sh local
```

This creates a Python venv, installs Node modules, and starts both dev servers:

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

### Option 3: Manual Setup

```bash
# Backend
cd DriftGuard/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd DriftGuard/frontend
npm install && npm run dev
```

---

## What It Does

Current cybersecurity tools detect breaches at **Stage 4–5** — behavior and system impact. Nobody reads **Stage 1–2** — the human-state drift that precedes the breach:

| Drift Pattern | What It Detects |
|---------------|----------------|
| **Fatigue** | Sustained workload reducing vigilance — the person isn't negligent, they're exhausted |
| **Overconfidence** | Accumulated expertise bypassing safety protocols |
| **Hurry** | Deadline pressure compressing validation into formality |
| **Quiet Fear** | Known issues going unreported because speaking up feels unsafe |
| **Hoarding** | Access and authority accumulating beyond role requirements |
| **Compliance Theater** | High audit scores coexisting with elevated breach indicators |

Each pattern maps to **NIST SP 800-53** controls:

| Control | Title | Vulnerable Patterns |
|---------|-------|-------------------|
| AC-2 | Account Management | Overconfidence, Hoarding |
| AU-6 | Audit Review | Fatigue, Compliance Theater |
| IR-6 | Incident Reporting | Quiet Fear, Hurry |
| CA-7 | Continuous Monitoring | Fatigue, Compliance Theater, Hurry |
| AT-2 | Awareness Training | Compliance Theater |

---

## Architecture

```
Signals → Ingestion → Temporal Weighting → 6 Pattern Agents → Aggregation → Alerts
              ↓                                                       ↓
        PII Anonymization                                    NI Calibration
        (ethical guardrail)                                  (response delivery)
```

**8-node LangGraph pipeline** with per-pattern detection agents, fan-out/fan-in orchestration, and NLI classification (DeBERTa-v3 + rule-based fallback).

### Three Layers

| Layer | Name | Function |
|-------|------|----------|
| **Layer 3** | AI Detection | NLI classification, temporal weighting, multi-agent orchestration |
| **Layer 2** | EI Revelation | Early warning engine, severity scoring, alert generation |
| **Layer 1** | NI Calibration | Nature's Intelligence response delivery (content owned by framework team) |

---

## Integration Connectors

DriftGuard integrates with existing SIEM and EDR stacks — it doesn't replace your current tools, it adds the human layer they're architecturally blind to.

| Connector | Platform | Protocol |
|-----------|----------|----------|
| Splunk | Splunk Enterprise/Cloud | REST API |
| Sentinel | Microsoft Sentinel | Azure Log Analytics KQL |
| CloudTrail | AWS | boto3 SDK |
| Google Workspace | Google Admin | Reports API |
| Epic EMR | Epic EHR | FHIR R4 AuditEvent |

### Universal SDK

Any application can connect via the SDK or webhook API:

**Python:**
```python
from sdk.client import DriftGuardClient

client = DriftGuardClient(
    api_url="http://localhost:8000",
    app_name="my-app",
    domain="enterprise"
)
client.send_signal("access_log", "auth-service", {"login_count": 150})
```

**Webhook:**
```bash
curl -X POST http://localhost:8000/api/v1/integrations/webhook \
  -H "Content-Type: application/json" \
  -d '{"event_type": "security_alert", "source_app": "my-siem", "payload": {"severity": "high"}}'
```

---

## Domain Adapters

Pre-built YAML configurations for 6 industry verticals:

- **Healthcare** — HIPAA/HITECH, Epic EMR integration, clinical signal mapping
- **Finance** — SOX/PCI DSS, trading desk monitoring, audit resistance detection
- **Government** — FedRAMP/FISMA, clearance-aware thresholds
- **Retail** — PCI DSS, seasonal pattern awareness
- **Education** — FERPA, research data protection, IRB compliance
- **Enterprise** — General NIST CSF / ISO 27001 alignment

Add your own by uploading a YAML configuration file through the API or dashboard.

---

## Ethical Boundaries (non-negotiable)

These are hard-coded in the system — not configurable, not bypassable:

- **No individual profiling** — detections are organizational-level only
- **PII anonymized at ingestion** — employee identifiers hashed before storage or classification
- **180-day maximum data retention** — hard-coded, cannot be extended
- **Human review for Critical alerts** — no automated escalation without human approval
- **Confidence + explanation required** — no alert without both
- **Immutable audit trail** — every action logged, no modification or deletion possible
- **Permanent ethical banner** — every screen displays the constraint notice

---

## Project Structure

```
DriftGuard/
├── backend/
│   ├── main.py                    # FastAPI entry point
│   ├── config/settings.py         # Pydantic Settings
│   ├── models/                    # Data models
│   ├── core/
│   │   ├── drift_patterns.py      # 6 drift pattern definitions
│   │   ├── nist_mapping.py        # NIST SP 800-53 mappings
│   │   ├── severity.py            # Severity scoring
│   │   └── ethical_guardrails.py  # PII anonymization & guardrails
│   ├── pipeline/
│   │   ├── orchestrator.py        # LangGraph state graph
│   │   ├── classifier.py          # NLI + rule-based classification
│   │   ├── agents/                # Per-pattern detection agents
│   │   └── signal_ingestion.py    # Signal intake & anonymization
│   ├── calibration/
│   │   ├── content_api.py         # NI response library
│   │   ├── rag_retrieval.py       # FAISS/Qdrant vector search
│   │   └── delivery.py            # Multi-channel delivery
│   ├── integrations/              # SIEM/EDR/EMR connectors
│   ├── sdk/                       # Python & TypeScript SDK
│   └── api/routes/                # REST API endpoints
├── frontend/                      # React + TypeScript + Tailwind
├── ni_content/                    # NI calibration responses
├── monitoring/                    # Grafana, Prometheus, OTel
├── docker-compose.yml
├── setup.sh                       # One-click setup script
└── LICENSE                        # MIT
```

---

## Testing

```bash
cd DriftGuard/backend
source venv/bin/activate
pytest -v
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Key areas:

- **NI Response Library** — Write calibration responses (no code required)
- **Domain Configs** — Add YAML configs for new industries
- **Integration Connectors** — Add SIEM/EDR platform connectors
- **Test Coverage** — Expand the test suite

---

## Research Foundation

Based on the research papers included in this repository:

- *"Beyond the Breach: A Three-Layer Architecture for Human-State Drift Detection in Cybersecurity"*
- *"The Human Firewall: Detecting Behavioral Drift Before the Breach"*

---

## Team

- **Naresh Sampangi** — Engineering
- **Sumeet Agarwal** — Senior AI Engineer
- **Dr. Anil K. Agarwal** — Clinical Seat + Healthcare Market

---

## License

[MIT](LICENSE) — use it, fork it, build on it.
