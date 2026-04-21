# DriftGuard — Technical Architecture (v2.0)

## Overview

DriftGuard is a cybersecurity breach-prevention platform that detects **organizational drift patterns** (fatigue, overconfidence, hurry, quiet-fear, hoarding, compliance theater) before they become breaches, then calibrates teams with NI (Narrative Intelligence) guidance.

v2.0 adds a **Predictive Breach Probability Engine** that transforms DriftGuard from a detection system into a forecasting system.

---

## High-Level Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      Frontend (React 19 / Vite)            │
│   Dashboard · AlertCenter · LiveScanner · Calibration      │
│   Governance · Reports · ThreatIntel · RiskForecast (v2)   │
└──────────────────────────┬─────────────────────────────────┘
                           │  HTTPS + JWT
┌──────────────────────────▼─────────────────────────────────┐
│                   FastAPI Backend (Python 3.11)            │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  Routers: /auth /signals /alerts /calibration       │  │
│   │           /reports /risk-forecast (v2) /scanner …   │  │
│   └─────────────────────────────────────────────────────┘  │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  Pipeline: 8-node LangGraph orchestrator            │  │
│   │  ingestion → classification → severity → weighting  │  │
│   │  → correlation → alerting → calibration → delivery  │  │
│   └─────────────────────────────────────────────────────┘  │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  Engine: EarlyWarning + Risk Forecast               │  │
│   │  · Drift pattern detector                           │  │
│   │  · NIST SP 800-53 mapper                            │  │
│   │  · Predictive breach probability (v2)               │  │
│   └─────────────────────────────────────────────────────┘  │
└──────────────────────────┬─────────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
       SQLite (dev)                 Integrations
     PostgreSQL (prod-ready)    Splunk · Sentinel · CloudTrail
                                Epic EMR · Google Workspace
```

---

## Risk Forecast Engine (v2)

The v2 predictive engine produces a **breach probability percentage** over a configurable time horizon (7-180 days).

### Composite Formula

For a given domain $d$ and horizon $H$ days:

$$
P_{\text{breach}}(d, H) = \min\!\left(0.95,\; B_H + (1 - B_H)\cdot M \cdot 0.85\right)
$$

where:

- $B_H = 1 - (1 - B_d)^{H/365}$ — horizon-scaled domain baseline
- $M = 1 - e^{-k\cdot R}$ — saturating drift modifier (bounded 0-1)
- $R = 0.6 \cdot R_\text{patterns} + 0.4 \cdot R_\text{NIST}$ — composite risk score
- $k = 0.45$ — saturation rate

### Pattern Risk

$$
R_\text{patterns} = \sum_{a \in \text{alerts}} \sum_{p \in a.\text{patterns}} \frac{s_a}{5} \cdot c_a \cdot w_p \cdot e^{-\ln 2 \cdot \Delta t_a / 14}
$$

- $s_a$ = alert severity (1-5)
- $c_a$ = alert confidence (0-1)
- $w_p$ = research-derived pattern weight (Hurry=1.55, Fatigue=1.45, QuietFear=1.40, ...)
- 14-day temporal half-life (recent signals dominate)

### NIST Risk

For each unique NIST control $c$ with occurrence count $n_c$:

$$
R_\text{NIST} = \sum_c \frac{C_c}{10} \cdot \min\!\left(1, \frac{\ln(1+n_c)}{\ln 10}\right)
$$

where $C_c$ is the control criticality (AC-2=9.5, AU-6=8.8, IR-6=8.5, ...).

### Domain Baselines

Calibrated from IBM Cost of a Data Breach 2024:

| Domain | Annual baseline |
| --- | --- |
| Healthcare | 32% |
| Finance | 24% |
| Government | 21% |
| Retail | 20% |
| Enterprise | 18% |
| Education | 16% |

### API Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/risk-forecast/` | Cross-domain risk overview |
| `GET` | `/api/v1/risk-forecast/{domain}` | Full forecast with components & top contributors |
| `GET` | `/api/v1/risk-forecast/{domain}/trend?days=N` | N-day historical probability trend |

All require JWT auth.

---

## Security Model

- **Authentication**: JWT (HS256), 24-hour tokens
- **Password hashing**: bcrypt (passlib 4.0.1)
- **Authorization**: role-based (admin, ciso, compliance_officer, ni_architect, viewer)
- **Transport**: HTTPS-only in production (Strict-Transport-Security headers)
- **Headers**: X-Content-Type-Options, X-Frame-Options: DENY, X-XSS-Protection
- **CORS**: Whitelisted origins via settings

---

## Deployment Topology

- **Production API**: Render (https://driftguard-api-mbdj.onrender.com)
- **Build**: Docker (Dockerfile.backend) · requirements-deploy.txt
- **Database**: SQLite (aiosqlite) — PostgreSQL-ready via SQLAlchemy
- **Lifespan**: auto-seeds 5 demo accounts on startup for consistent E2E access
- **Health check**: `/api/v1/health` — DB, apps, integration endpoints

---

## Testing

- 92 backend pytest cases (API, drift patterns, guardrails, pipeline, severity)
- Frontend: TypeScript strict mode, Vite build
- E2E: role-login smoke tests on every commit
