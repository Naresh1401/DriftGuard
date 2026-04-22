# DriftGuard — End-to-End Guide

How to use the platform from scratch, how it collects data, and how it mitigates breaches across **AI** and **classical cybersecurity** surfaces.

---

## Part 1 — From scratch: get to a working dashboard

### 1.1 Three ways to start

| You are… | Do this |
|---|---|
| **Just trying it out** | Use the hosted demo (Section 1.2) |
| **An engineer / contributor** | Run it locally (Section 1.3) |
| **A security team going to prod** | Self-host with Docker (Section 1.4) |

### 1.2 Hosted demo (zero install, ~30 seconds)
1. Open the dashboard URL (Vercel-hosted frontend, talks to `https://driftguard-api-mbdj.onrender.com`).
2. Log in with a seeded account — password is `Test1234!` for all of:
   - `admin@driftguard.com`
   - `ciso@driftguard.com`
   - `compliance_officer@driftguard.com`
   - `ni_architect@driftguard.com`
   - `viewer@driftguard.com`
3. You land on the AI Breach page. Click **Run demo scan** → see 7 patterns, audit chain head, real-time anomaly stream tick every 5s.

### 1.3 Local dev (full source, two terminals)
```bash
git clone https://github.com/Naresh1401/DriftGuard.git
cd DriftGuard

# ── Terminal 1: backend
cd backend
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# ── Terminal 2: frontend
cd frontend
npm install
npm run dev    # http://localhost:3000
```
- Open <http://localhost:3000>, log in with a seeded account above.
- Swagger lives at <http://localhost:8000/docs>.
- Run tests: `cd backend && pytest -q` (currently **156/156 passing**).

### 1.4 Self-host (Docker, on-prem / air-gapped)
```bash
docker compose up -d     # backend + frontend + nginx + monitoring
# UI:  http://localhost
# API: http://localhost:8000/api/v1
```
Files: [docker-compose.yml](docker-compose.yml), [nginx.conf](nginx.conf), [Dockerfile.backend](Dockerfile.backend), [Dockerfile.frontend](Dockerfile.frontend). Configure secrets in `.env` (JWT secret, DB URL, integration tokens).

### 1.5 First-run walkthrough on the dashboard

Once you're logged in:

1. **Overview** → headline risk score, 24h forecast sparkline, active patterns count.
2. **AI Breach** → the seven patterns (Shadow AI, Prompt Injection, Non-Human Identity Misuse, Model/Data Poisoning, Sleeper-Agent Backdoor, AI Social Engineering, Agent Sprawl), each tied to OWASP LLM ID + NIST AI RMF function. Buttons:
   - **Mint anchor** — seal the current audit chain head
   - **Verify** — verify a single anchor
   - **Verify all** — walk the full anchor history
3. **Drift Map** → human-state behavioural drift heatmap (the original DriftGuard product surface).
4. **Domains** → switch profile (general, healthcare/Epic, finance, etc.) — adapter configs in [backend/domain/configs/](backend/domain/configs).
5. **Integrations** → connect CloudTrail / Splunk / Sentinel / Workspace / Epic.
6. **Reports** → generate a NIST AI RMF / SOC 2 evidence pack (PDF + JSON receipts).
7. **Calibration** → tune confidence threshold (default 0.70 → human review required below this).
8. **Governance** → approval gates, ethical guardrails, escalation chains.

---

## Part 2 — How DriftGuard collects data

DriftGuard never invents data. Every claim it makes traces back to a normalized **signal** ingested through one of four explicit paths.

```
┌──────────────────────────────────────────────────────────────────┐
│                     Source systems                               │
│ CloudTrail • Splunk • Sentinel • Google Workspace • Epic EMR • …│
└──────────────────────────────────────────────────────────────────┘
        │              │              │              │
        ▼              ▼              ▼              ▼
   Adapter         Adapter        Adapter       Adapter
 (cloudtrail.py) (splunk.py)  (sentinel.py)  (epic_emr.py)
        │              │              │              │
        └──────────────┴──────┬───────┴──────────────┘
                              ▼
                ┌───────────────────────────┐
                │  Normalized AISignal      │  (also accepts SDK + REST)
                │  actor_id, action,        │
                │  destination, tokens,     │
                │  approved_by_human, …     │
                └───────────────┬───────────┘
                                ▼
                ┌────────────────────────────────────────┐
                │  POST /api/v1/ai-breach/scan           │
                │  → AIBreachDetector.detect_all()       │
                │  → aggregate_risk()                    │
                │  → AuditChain.append (tamper-evident)  │
                │  → AgentQuarantine.record              │
                │  → RealtimeAnalyzer.observe (z-score)  │
                │  → RiskForecaster.add (EWMA)           │
                └────────────────────────────────────────┘
                                │
            ┌───────────────────┼─────────────────────┐
            ▼                   ▼                     ▼
    Audit chain (JSONL)   SSE /stream         Operator UI
    + cryptographic       (tick + anomaly)    + reports
    anchors
```

### 2.1 The four ingestion paths

| Path | Endpoint / Module | Use when… |
|---|---|---|
| **Batch scan** | `POST /api/v1/ai-breach/scan` | You have a list of telemetry events to score |
| **Single sample** | `POST /api/v1/ai-breach/ingest` | Your upstream already produced a risk score |
| **SDK** (Python / TS) | [backend/sdk/client.py](backend/sdk/client.py), [backend/sdk/driftguard-sdk.ts](backend/sdk/driftguard-sdk.ts) | You're embedding from a service / app |
| **Adapter pull** | [backend/integrations/](backend/integrations) | A SaaS source (CloudTrail, Splunk, Sentinel, Workspace, Epic) — adapter normalizes and forwards |

### 2.2 What a signal contains

From [backend/engine/ai_breach_detector.py](backend/engine/ai_breach_detector.py):
```python
AISignal(
  actor_type: 'agent' | 'human' | 'service',
  actor_id: str,                 # eg. agent-prod-1, user-42, svc-cron
  model_id, model_version,       # which LLM produced the output (if any)
  action: str,                   # eg. 'tool_call:send_email', 'http_post'
  tool_name, destination,        # eg. 'api.openai.com', internal route
  prompt_size_tokens, output_size_tokens,
  contains_instruction_tokens: bool,   # heuristic for prompt injection
  decision_latency_ms,
  approved_by_human: bool | None,      # human-in-the-loop attestation
  metadata: dict,                # adapter-specific extras
)
```

### 2.3 What persists vs. what stays in memory

| Data | Storage | Lifetime |
|---|---|---|
| Audit chain | JSONL append-only at `backend/data/ai_breach_audit.jsonl` | Forever (tamper-evident) |
| Anchors | JSON files in `backend/data/anchors/` | Forever |
| Quarantine | JSON snapshot at `backend/data/quarantine.json` (atomic write) | Forever, restart-safe |
| Realtime per-actor windows | In-process (RealtimeAnalyzer) | 60-min TTL, drops on restart |
| Forecaster history | In-process (RiskForecaster) | 24h, drops on restart |
| User accounts | SQL via SQLAlchemy ([backend/db/database.py](backend/db/database.py)) | Persistent |

By design, the **chain is the system of record**; everything else is operational telemetry that can be replayed.

---

## Part 3 — How DriftGuard detects + mitigates AI breaches

### 3.1 The seven AI breach patterns

Defined in [backend/core/ai_drift_patterns.py](backend/core/ai_drift_patterns.py); each is mapped to OWASP LLM Top-10 + NIST AI RMF function + plain-language summary + mitigation playbook.

| Pattern | OWASP | NIST RMF | What it catches |
|---|---|---|---|
| Shadow AI Adoption | LLM06 | GOVERN | Unsanctioned LLM use (humans → public LLMs with sensitive data) |
| Prompt Injection of Agentic AI | LLM01 | MEASURE | Instruction tokens in untrusted inputs flowing to an agent |
| Non-Human Identity Misuse | LLM08 | MANAGE | Service / agent credentials acting outside their playbook |
| Model or Data Poisoning | LLM03 | MEASURE | Training-data anomalies, output distribution shift |
| Sleeper-Agent Backdoor | LLM05 | MAP | Trigger-conditioned malicious behaviour after long dormancy |
| AI-Augmented Social Engineering | LLM09 | MEASURE | LLM-crafted spear phishing, voice clones |
| Agent Sprawl / Unauthorized Action | LLM07 | GOVERN | Agents performing actions outside approved scopes |

### 3.2 Detection pipeline (per scan)

1. **Normalize** signals → `AISignal` (Section 2.2).
2. **Classify** — `AIBreachDetector.detect_all(signals)` runs all seven detectors. Each returns an `AIBreachDetection` with `confidence`, `severity`, `risk_score = confidence * base_severity`, `reasoning`, and the `signal_ids` it cites.
3. **Human-in-the-loop gate** — any detection with `confidence < 0.70` is marked `requires_human_review = True`. The system never auto-acts on low-confidence findings.
4. **Aggregate** — `aggregate_risk(detections)` returns the rolled-up alert level + active patterns count.
5. **Forecast** — `RiskForecaster.add(now, score)` updates the 24h EWMA + 95% upper band.
6. **Record (tamper-evident)** — every detection is appended to the audit chain (Part 4).
7. **Quarantine check** — `AgentQuarantine.record(det)` accumulates per-actor risk over a 60-min window; if the sum crosses 120 (≈2 Critical findings), the actor is quarantined (informational flag — not a kill switch).
8. **Realtime z-score** — `RealtimeAnalyzer.observe(actor, max_risk)` flags `|z| ≥ 2.5` as a live anomaly (see App. N).
9. **Broadcast** — SSE `/stream` pushes a `tick` every 5s and a separate `anomaly` event per new flag.

### 3.3 Mitigation playbooks

Each pattern ships with a structured playbook ([backend/core/ai_breach_playbooks.py](backend/core/ai_breach_playbooks.py)) that the dashboard surfaces inline:
- **Containment** steps (eg. "rotate the agent's API key", "freeze the model deployment")
- **Investigation** queries (eg. "list all `/v1/messages` calls from this agent in the last 24h")
- **Eradication** actions (eg. "remove the poisoned training shard, retrain from snapshot N-1")
- **Recovery** acceptance criteria (eg. "z-score returns below 1.5 for 2h")
- **Lessons** template for the post-incident report

The playbook is referenced by `mitigation_repo_path` so SOC tooling can deep-link to the runbook.

### 3.4 Governance gates (`backend/governance/approval_gates.py`)

Critical actions require an approval gate. A gate has an explicit allow-list of roles (`admin`, `ciso`, `compliance_officer`), a quorum, and an audit trail. Until the gate clears, the action is blocked. Examples:
- Releasing an actor from quarantine
- Lowering the global confidence threshold
- Deleting historical evidence

---

## Part 4 — How DriftGuard mitigates classical cybersecurity breaches

The same pipeline doubles as a cybersecurity audit + response surface. Three mechanisms combine.

### 4.1 Tamper-evident audit chain

Every detection becomes an entry in a hash-chained append-only log ([backend/engine/ai_breach_governance.py](backend/engine/ai_breach_governance.py)).

- **Entry hash** = `sha256(prev_hash || canonical_json(payload))`
- **Anchor** = `sha256(length || head_hash || timestamp || prev_anchor_id)` — periodically minted, chained to the previous anchor
- **Per-entry receipt** (App. M) — operators can hand any auditor a single receipt and they can verify it offline with no live access (`POST /audit/entry/verify`)
- **Whole-chain verify** (`GET /audit/verify`) — confirms `intact`, returns current `length` + `head`
- **Anchor walk** (`GET /audit/anchors`) — verifies the full anchor history; returns `valid`, `count`, and `broken_at` if anything was tampered

This gives you a forensic chain-of-custody for **every** alert, satisfying SOC 2 CC7, ISO 27001 A.12.4, and NIST 800-53 AU-2 / AU-9.

### 4.2 Real-time per-actor anomaly layer (App. N)

The `RealtimeAnalyzer` watches risk *trajectory*, not just thresholds. A burst of medium-severity findings from one actor will trip an anomaly even if no single finding is Critical — exactly the behavioural drift NIST AI RMF MEASURE-2.7 expects to be continuously monitored.

```bash
# Push a sample (after JWT login)
curl -sf -X POST $API/ai-breach/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"actor_id":"agent-prod-1","risk_score":87.0}'

# Subscribe to live events
curl -sN $API/ai-breach/stream
# event: hello
# event: tick    { ... realtime stats ... }
# event: anomaly { actor_id, z, baseline_mean, reason, ... }
```

### 4.3 Containment via Quarantine + Approval Gates

When the per-actor 60-min sum crosses the threshold, the actor is **quarantined**:
- Visible at `GET /api/v1/ai-breach/quarantine`
- Persisted atomically (`os.replace`) so it survives restart
- Release requires `POST /quarantine/release` from a role allowed by an approval gate (audit-trailed)
- Status broadcast on SSE so SOC dashboards react instantly

Quarantine is **informational by design** — DriftGuard surfaces the recommendation; the SOAR / orchestration layer decides whether to disable a key, isolate a host, or page on-call. This keeps DriftGuard inside the `MEASURE` + `MANAGE` lanes of NIST AI RMF and avoids the "auto-firewall ate production" anti-pattern.

### 4.4 Compliance evidence

The `Reports` page assembles:
- All detections in a date range (with their citing signals)
- The corresponding chain entries + receipts
- The latest anchor (with its hash)
- Forecast trend + anomalies fired
- Playbook references actually invoked

…into a single auditor-ready PDF + machine-verifiable JSON bundle.

---

## Part 5 — End-to-end worked example

**Scenario:** an agent named `agent-acme-1` starts exfiltrating tokens to `api.openai.com` after a prompt-injection in a customer support ticket.

```bash
API=https://driftguard-api-mbdj.onrender.com/api/v1

# 1. Auth
TOKEN=$(curl -s -X POST $API/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@driftguard.com","password":"Test1234!"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. Send a batch of 5 signals from the agent
curl -sf -X POST $API/ai-breach/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "signals": [
      {"actor_id":"agent-acme-1","action":"tool_call:read_ticket",
       "destination":"crm.acme.internal","contains_instruction_tokens":true,
       "output_size_tokens":1200},
      {"actor_id":"agent-acme-1","action":"tool_call:send_email",
       "destination":"api.openai.com","approved_by_human":false,
       "output_size_tokens":8000},
      {"actor_id":"agent-acme-1","action":"tool_call:send_email",
       "destination":"api.openai.com","approved_by_human":false,
       "output_size_tokens":12000}
    ]}'
# → detections include LLM01 prompt injection + LLM06 shadow AI;
#   risk_score ~85; audit.appended=2; head=abc123…;
#   realtime.anomalies_triggered=[{actor_id:"agent-acme-1", z:6.7, ...}]

# 3. Watch live SSE
curl -sN $API/ai-breach/stream
# event: anomaly { actor_id:"agent-acme-1", risk_score:85.0,
#                  baseline_mean:12.4, z:6.7, reason:"|z|=6.7 >= 2.5 ..." }

# 4. Check quarantine (after threshold crossed)
curl -sf -H "Authorization: Bearer $TOKEN" $API/ai-breach/quarantine
# → [{actor_id:"agent-acme-1", reason:"...", since:"2026-04-22T13:18:18Z"}]

# 5. Pull a chain receipt for the auditor
curl -sf $API/ai-breach/audit/entry/0 | tee receipt.json
# (offline, no network) verify it:
curl -sf -X POST $API/ai-breach/audit/entry/verify \
  -H 'Content-Type: application/json' -d @receipt.json
# → { "valid": true, "reason": "receipt hash recomputed" }

# 6. Mint and verify an anchor (seal the current chain head)
curl -sf -X POST $API/ai-breach/audit/anchor
curl -sf $API/ai-breach/audit/anchors
# → { count: 3, valid: true, broken_at: null }

# 7. After investigation, release the actor (requires admin role)
curl -sf -X POST $API/ai-breach/quarantine/release \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"actor_id":"agent-acme-1","reason":"key rotated, root cause fixed"}'
```

What just happened, end to end:
- Adapter or app pushed signals → detector classified two patterns → confidence ≥ 0.70 so no human review block → audit chain appended 2 entries (now hashed and tamper-evident) → realtime analyzer flagged a z-score anomaly → quarantine threshold crossed → SSE pushed an `anomaly` event → operator pulled a per-entry receipt → minted an anchor for the auditor → released the actor through a role-gated, audit-trailed action.

---

## Part 6 — Where to dig deeper

- **API reference** — Swagger at `/docs` (live in every deployment)
- **Architecture & every "honest gap"** — [BUSINESS_PLAN.md](BUSINESS_PLAN.md) appendices H → N
- **Pattern definitions** — [backend/core/ai_drift_patterns.py](backend/core/ai_drift_patterns.py)
- **Detection logic** — [backend/engine/ai_breach_detector.py](backend/engine/ai_breach_detector.py)
- **Audit chain + anchors + receipts** — [backend/engine/ai_breach_governance.py](backend/engine/ai_breach_governance.py)
- **Realtime analyzer** — [backend/engine/realtime_analyzer.py](backend/engine/realtime_analyzer.py)
- **Adapters** — [backend/integrations/](backend/integrations)
- **Approval gates** — [backend/governance/approval_gates.py](backend/governance/approval_gates.py)
- **Tests (run before you trust it)** — `cd backend && pytest -q` (156 currently green)
