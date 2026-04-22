# Using DriftGuard — Platforms & How-To

DriftGuard is a continuous AI-breach + human-state drift detection platform. This guide covers **where** you can use it and **how** to get going on each surface.

---

## 1. Supported platforms at a glance

| Platform | Audience | Access | Auth |
|---|---|---|---|
| Web dashboard (browser) | Operators, CISOs, compliance, NI architects, viewers | https://driftguard-api-mbdj.onrender.com (API) + Vercel-hosted UI | Email + password (JWT) |
| REST API (HTTPS) | Backend integrations, SOC pipelines, custom dashboards | `https://driftguard-api-mbdj.onrender.com/api/v1` | Bearer JWT |
| Server-Sent Events stream | NOC tickers, live wallboards, custom UIs | `GET /api/v1/ai-breach/stream` | Public (read-only) |
| Python SDK | Python services, Django/Flask/FastAPI apps, ML pipelines | `backend/sdk/client.py`, `backend/sdk/middleware.py` | API key / JWT |
| TypeScript / JS SDK | Node.js services, browser apps, edge functions | `backend/sdk/driftguard-sdk.ts` | API key / JWT |
| Local self-host (Docker) | On-prem, air-gapped, regulated industries | `docker compose up` | Configurable |
| Local dev (macOS / Linux / WSL) | Engineers, contributors | `uvicorn` + `vite` | Seeded local accounts |

---

## 2. Web dashboard (the fastest way in)

Works in any modern desktop browser (Chrome, Edge, Firefox, Safari).

### 2.1 Production
1. Open the deployed UI (Vercel) — the frontend is wired to call the Render-hosted API at `https://driftguard-api-mbdj.onrender.com`.
2. Log in with your seeded credentials.
3. Land on the AI Breach page → see live patterns, audit chain head, quarantine status, real-time anomaly stream.

### 2.2 Local
```bash
# Backend
cd DriftGuard/backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000

# Frontend (separate terminal)
cd DriftGuard/frontend
npm install   # first time only
npm run dev   # serves http://localhost:3000
```
Open <http://localhost:3000>. Default seeded accounts (password `Test1234!`):
- `admin@driftguard.com` (admin)
- `ciso@driftguard.com` (CISO)
- `compliance_officer@driftguard.com` (compliance)
- `ni_architect@driftguard.com` (architect)
- `viewer@driftguard.com` (read-only)

---

## 3. REST API (any language, any platform)

Base URL (prod): `https://driftguard-api-mbdj.onrender.com/api/v1`

### 3.1 Auth — get a token
```bash
curl -s -X POST https://driftguard-api-mbdj.onrender.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@driftguard.com","password":"Test1234!"}'
# → { "access_token": "<JWT>", "role":"admin", ... }
```

### 3.2 Core endpoints
| Endpoint | Purpose |
|---|---|
| `GET  /ai-breach/patterns` | The 7 AI breach pattern definitions |
| `POST /ai-breach/scan` | Run all detectors over a batch of signals |
| `POST /ai-breach/ingest` | Push a single `(actor_id, risk_score)` sample to the realtime analyzer |
| `GET  /ai-breach/actors` | Top-movers snapshot |
| `GET  /ai-breach/actors/{id}/trajectory` | Per-actor rolling window + baseline |
| `GET  /ai-breach/anomalies?limit=50` | Most recent z-score anomalies |
| `GET  /ai-breach/stream` | SSE: `tick` every 5s, `anomaly` on new events |
| `POST /ai-breach/audit/anchor` | Mint cryptographic chain anchor |
| `GET  /ai-breach/audit/verify` | Whole-chain integrity check |
| `GET  /ai-breach/audit/entry/{i}` | Per-entry receipt |
| `GET  /ai-breach/quarantine` | Currently quarantined actors |

### 3.3 Example: end-to-end real-time
```bash
TOKEN=$(curl -s -X POST .../auth/login -d '...' | jq -r .access_token)

# Push a sample
curl -sf -X POST .../ai-breach/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"actor_id":"agent-prod-1","risk_score":87.0}'

# Subscribe to live anomaly stream
curl -sN .../ai-breach/stream
```

---

## 4. Python SDK

Install (from repo): `pip install -e DriftGuard/backend`

```python
from sdk.client import DriftGuardClient

client = DriftGuardClient(
    base_url="https://driftguard-api-mbdj.onrender.com/api/v1",
    api_key="<JWT or API key>",
)

# Push a real-time sample
verdict = client.ingest(actor_id="agent-prod-1", risk_score=87.0)
if verdict["anomaly"]:
    alert(verdict)

# Drop into Django/Flask/FastAPI request middleware
from sdk.middleware import DriftGuardMiddleware
app.add_middleware(DriftGuardMiddleware, client=client)
```

---

## 5. TypeScript / JavaScript SDK

For Node.js services, Vercel/Cloudflare/Edge functions, browser apps.

```ts
import { DriftGuardClient } from "./driftguard-sdk";

const dg = new DriftGuardClient({
  baseUrl: "https://driftguard-api-mbdj.onrender.com/api/v1",
  apiKey: process.env.DRIFTGUARD_API_KEY!,
});

await dg.ingest({ actorId: "user-42", riskScore: 92.0 });

// Live SSE in the browser
const es = new EventSource(`${dg.baseUrl}/ai-breach/stream`);
es.addEventListener("anomaly", (e) => console.warn(JSON.parse(e.data)));
```

---

## 6. Self-host with Docker (on-prem / air-gapped)

```bash
git clone https://github.com/Naresh1401/DriftGuard.git
cd DriftGuard
docker compose up -d        # backend + frontend + nginx
# UI:  http://localhost:80
# API: http://localhost:8000/api/v1
```

Compose file: [docker-compose.yml](DriftGuard/docker-compose.yml). Nginx terminates TLS via [nginx.conf](DriftGuard/nginx.conf). Configure secrets in `.env` (JWT secret, DB URL, integration tokens).

Other deployment targets shipped in-tree:
- **Render** — [render.yaml](DriftGuard/render.yaml)
- **Fly.io** — [fly.toml](DriftGuard/fly.toml)
- **Railway** — [railway.toml](DriftGuard/railway.toml)
- **Vercel** (frontend) — [vercel.json](DriftGuard/vercel.json)

---

## 7. Integrations (real production data sources)

Adapters live in [backend/integrations/](DriftGuard/backend/integrations):
- AWS CloudTrail — `cloudtrail.py`
- Splunk — `splunk.py`
- Microsoft Sentinel — `sentinel.py`
- Google Workspace — `google_workspace.py`
- Epic EMR (healthcare) — `epic_emr.py`

Each adapter normalizes its source into `AISignal` and routes through `POST /ai-breach/scan`, which then feeds the audit chain, quarantine, and realtime analyzer in one call.

---

## 8. Operating system / environment matrix

| OS | Web | REST | SDK (Python) | SDK (TS) | Self-host (Docker) | Local dev |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| macOS 12+ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Linux (Ubuntu 22.04+, RHEL 9+) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windows 10/11 (native) | ✅ | ✅ | ✅ | ✅ | ✅ (Docker Desktop) | ✅ |
| Windows + WSL2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| iOS / Android (browser) | ✅ (read-only UI) | ✅ | — | — | — | — |

Requirements:
- Python **3.11+** for the backend (3.10 not supported — uses 3.11 stdlib)
- Node **18+** for the frontend / TS SDK
- Docker **24+** for self-host

---

## 9. Quick decision tree

- **I want to look at the dashboard** → use the web UI (Section 2).
- **I want to push events from my service** → REST `/ai-breach/ingest` or SDK (Section 3 / 4 / 5).
- **I want a live wallboard** → subscribe to SSE `/ai-breach/stream` (Section 3.3).
- **I need on-prem / air-gapped** → Docker self-host (Section 6).
- **I need to wire CloudTrail / Splunk / Sentinel / Workspace / Epic** → adapter in `backend/integrations/` (Section 7).
- **I'm a contributor** → local dev (Section 2.2) + run `pytest` in `backend/`.

---

## 10. Support & next steps

- API reference: served live at `https://driftguard-api-mbdj.onrender.com/docs` (FastAPI Swagger)
- Architecture & governance details: [BUSINESS_PLAN.md](BUSINESS_PLAN.md), Appendices H–N
- Contribution guide: [CONTRIBUTING.md](DriftGuard/CONTRIBUTING.md)
- License: [LICENSE](DriftGuard/LICENSE)
