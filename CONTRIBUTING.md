# Contributing to DriftGuard

Thank you for your interest in contributing to DriftGuard! This project detects human-state drift patterns that precede cybersecurity breaches.

## Quick Start for Contributors

```bash
git clone https://github.com/YOUR_USERNAME/DriftGuard.git
cd DriftGuard
./setup.sh local
```

## Development Workflow

### Backend (Python/FastAPI)

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000
```

### Frontend (React/TypeScript)

```bash
cd frontend
npm run dev
```

### Running Tests

```bash
cd backend
source venv/bin/activate
pytest
```

## Project Structure

- `backend/` — FastAPI application, AI pipeline, integrations
- `frontend/` — React + TypeScript + Tailwind dashboard
- `ni_content/` — NI calibration response library (placeholders)
- `monitoring/` — Grafana, Prometheus, OpenTelemetry configs

## Contribution Areas

### High Impact

- **NI Response Library** — Write calibration responses for drift patterns (no code required)
- **Domain Configs** — Add YAML configs for new industry verticals
- **Integration Connectors** — Add connectors for new SIEM/EDR platforms
- **Tests** — Expand test coverage

### Architecture

- **Pipeline Agents** — Improve drift pattern detection accuracy
- **RAG Retrieval** — Enhance calibration response matching
- **Frontend Pages** — Build out dashboard visualizations

## Code Standards

- Python: Follow existing patterns, type hints encouraged
- TypeScript: Strict mode, functional components
- All drift detection must be **organizational-level** — never individual profiling
- Every alert must include confidence score + plain language explanation

## Ethical Guidelines

DriftGuard has non-negotiable ethical boundaries hard-coded into the system:

1. **No individual profiling** — detections are organizational-level only
2. **PII anonymization** — employee identifiers are hashed at ingestion
3. **180-day max data retention** — hard-coded, not configurable
4. **Human review for Critical alerts** — no automated escalation without human approval
5. **Immutable audit log** — all system actions are permanently recorded

Do not submit PRs that weaken these boundaries.

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Submit a PR with a clear description

## License

MIT — see [LICENSE](LICENSE)
