"""AI Breach API — endpoints for the AI-era breach surface.

Routes:
  GET  /api/v1/ai-breach/patterns           List the seven AI breach pattern definitions
  POST /api/v1/ai-breach/scan               Run all detectors over a batch of signals
  POST /api/v1/ai-breach/risk               Single rolled-up risk score from signals
  GET  /api/v1/ai-breach/demo               Returns a deterministic demo result
                                            (useful for the dashboard preview)
"""
from __future__ import annotations

import asyncio
import json as _json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.ai_drift_patterns import (
    AI_BREACH_PATTERNS,
    AIBreachPatternType,
    all_ai_patterns,
)
from core.ai_breach_playbooks import (
    PLAYBOOKS,
    all_playbooks,
    get_playbook,
    playbook_to_dict,
)
from engine.ai_breach_detector import (
    AIBreachDetector,
    AISignal,
    aggregate_risk,
)
from engine.ai_breach_advanced import (
    CrossDriftCorrelator,
    HumanDriftEvent,
    RiskForecaster,
)
from engine.ai_breach_governance import (
    AgentQuarantine,
    AuditChain,
)
from engine.realtime_analyzer import RealtimeAnalyzer
from engine.embed_layer import (
    APPROVED,
    ApprovalWorkflow,
    EventCollector,
    PENDING,
    REJECTED,
    RecommendationEngine,
)


router = APIRouter(prefix="/ai-breach", tags=["AI Breach"])

# Module-level forecaster — keeps a 24h rolling buffer per process.
# In a multi-worker deployment this would move to Redis; for the demo
# and the current single-worker Render service this is sufficient.
_FORECASTER = RiskForecaster()

# Append-only audit chain of every detection produced via /scan.
# Used by /audit/* endpoints to expose tamper-evident evidence to auditors.
# Persisted as JSON-Lines so the chain survives process restarts; the file
# is read-only in operational practice (everything is replayed at boot).
_AUDIT_PATH = os.environ.get(
    "DRIFTGUARD_AUDIT_PATH",
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "data" / "ai_breach_audit.jsonl"),
)
_ANCHOR_DIR = os.environ.get(
    "DRIFTGUARD_ANCHOR_DIR",
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "data" / "anchors"),
)
_QUARANTINE_PATH = os.environ.get(
    "DRIFTGUARD_QUARANTINE_PATH",
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "data" / "quarantine.json"),
)
_AUDIT_CHAIN = AuditChain(storage_path=_AUDIT_PATH)

# Per-actor risk circuit breaker. Threshold tuned so that two Critical
# detections (~70 each) inside the window will trip quarantine.
_QUARANTINE = AgentQuarantine(
    threshold=120.0, window_minutes=60, storage_path=_QUARANTINE_PATH
)

# Real-time per-actor risk trajectory + z-score anomaly detector.
# Stateful across requests within a single process. Fed by /scan and
# the new /ingest endpoint, drained by /actors, /anomalies, and the
# SSE /stream channel (see Appendix N).
_REALTIME = RealtimeAnalyzer()

# Embed-layer state (see Appendix O):
#   * RecommendationEngine — turns detections into structured suggestions
#   * ApprovalWorkflow      — durable, role-gated approval queue
_RECOMMENDER = RecommendationEngine()
_APPROVALS_PATH = os.environ.get(
    "DRIFTGUARD_APPROVALS_PATH",
    str(__import__("pathlib").Path(__file__).resolve().parents[2] / "data" / "approvals.json"),
)
_APPROVALS = ApprovalWorkflow(storage_path=_APPROVALS_PATH)


# ── Request / response schemas ───────────────────────

class AISignalIn(BaseModel):
    actor_type: str = "agent"
    actor_id: str
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    action: str = ""
    tool_name: Optional[str] = None
    destination: Optional[str] = None
    prompt_size_tokens: Optional[int] = None
    output_size_tokens: Optional[int] = None
    contains_instruction_tokens: bool = False
    decision_latency_ms: Optional[int] = None
    approved_by_human: Optional[bool] = None
    timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    signals: List[AISignalIn]
    confidence_threshold: float = 0.70


# ── Endpoints ────────────────────────────────────────

@router.get("/patterns")
async def list_patterns() -> Dict[str, Any]:
    """Return the seven AI breach pattern definitions for UI rendering."""
    return {
        "count": len(AI_BREACH_PATTERNS),
        "patterns": [
            {
                "pattern": p.pattern_type.value,
                "display_name": p.display_name,
                "description": p.description,
                "owasp_llm_id": p.owasp_llm_id,
                "nist_ai_rmf_function": p.nist_ai_rmf_function,
                "nist_controls_at_risk": [c.value for c in p.nist_controls_at_risk],
                "signal_indicators": list(p.signal_indicators),
                "failure_modes": list(p.failure_modes),
                "plain_language_summary": p.plain_language_summary,
                "base_severity": p.base_severity,
                "mitigation_repo_path": p.mitigation_repo_path,
            }
            for p in all_ai_patterns()
        ],
    }


@router.post("/scan")
async def scan_signals(req: ScanRequest) -> Dict[str, Any]:
    """Run all AI breach detectors over a batch of signals."""
    if not req.signals:
        raise HTTPException(status_code=400, detail="signals must be non-empty")
    detector = AIBreachDetector(confidence_threshold=req.confidence_threshold)
    sigs = [
        AISignal(
            timestamp=s.timestamp or datetime.utcnow(),
            actor_type=s.actor_type,
            actor_id=s.actor_id,
            model_id=s.model_id,
            model_version=s.model_version,
            action=s.action,
            tool_name=s.tool_name,
            destination=s.destination,
            prompt_size_tokens=s.prompt_size_tokens,
            output_size_tokens=s.output_size_tokens,
            contains_instruction_tokens=s.contains_instruction_tokens,
            decision_latency_ms=s.decision_latency_ms,
            approved_by_human=s.approved_by_human,
            metadata=s.metadata,
        )
        for s in req.signals
    ]
    detections = detector.detect_all(sigs)
    agg = aggregate_risk(detections)
    _FORECASTER.add(datetime.utcnow(), agg["overall_risk_score"])
    # Append every detection to the tamper-evident chain and check for
    # actors that just crossed the per-actor risk budget.
    chain_entries = _AUDIT_CHAIN.append_detections(detections)
    new_quarantines: List[Dict[str, Any]] = []
    for det in detections:
        rec = _QUARANTINE.record(det)
        if rec is not None:
            new_quarantines.append(rec.to_dict())
    # Real-time per-actor trajectory: for every actor in the batch, score
    # the highest detection risk attributed to one of their signals (0.0
    # if no detection fired). The verdict is appended to the rolling
    # anomaly buffer so SSE subscribers see live z-score events.
    sig_to_actor = {str(s.id): s.actor_id for s in sigs}
    actor_max: Dict[str, float] = {a: 0.0 for a in {s.actor_id for s in sigs}}
    for d in detections:
        for sid in d.signal_ids:
            actor = sig_to_actor.get(str(sid))
            if actor is not None and d.risk_score > actor_max.get(actor, 0.0):
                actor_max[actor] = float(d.risk_score)
    realtime_verdicts = [
        _REALTIME.observe(actor, score) for actor, score in actor_max.items()
    ]
    new_anomalies = [v for v in realtime_verdicts if v.get("anomaly")]
    return {
        "scanned_signals": len(sigs),
        "detections": [d.to_dict() for d in detections],
        "aggregate": agg,
        "audit": {
            "appended": len(chain_entries),
            "head": _AUDIT_CHAIN.head(),
            "length": len(_AUDIT_CHAIN),
        },
        "quarantines_triggered": new_quarantines,
        "realtime": {
            "actors_observed": len(actor_max),
            "anomalies_triggered": new_anomalies,
        },
    }


@router.post("/risk")
async def risk_score(req: ScanRequest) -> Dict[str, Any]:
    """Return a single aggregated AI-breach risk view."""
    if not req.signals:
        raise HTTPException(status_code=400, detail="signals must be non-empty")
    detector = AIBreachDetector(confidence_threshold=req.confidence_threshold)
    sigs = [
        AISignal(
            timestamp=s.timestamp or datetime.utcnow(),
            actor_type=s.actor_type,
            actor_id=s.actor_id,
            model_id=s.model_id,
            model_version=s.model_version,
            action=s.action,
            tool_name=s.tool_name,
            destination=s.destination,
            prompt_size_tokens=s.prompt_size_tokens,
            output_size_tokens=s.output_size_tokens,
            contains_instruction_tokens=s.contains_instruction_tokens,
            decision_latency_ms=s.decision_latency_ms,
            approved_by_human=s.approved_by_human,
            metadata=s.metadata,
        )
        for s in req.signals
    ]
    return aggregate_risk(detector.detect_all(sigs))


@router.get("/demo")
async def demo() -> Dict[str, Any]:
    """Deterministic demo result so the dashboard can render without setup."""
    now = datetime.utcnow()
    sigs: List[AISignal] = []
    # shadow AI: 4 human → public LLM with large prompts
    for i in range(4):
        sigs.append(AISignal(
            timestamp=now - timedelta(minutes=i),
            actor_type="human",
            actor_id=f"user-{i}",
            destination="api.openai.com",
            prompt_size_tokens=900 + i * 50,
            action="http_post",
        ))
    # prompt injection: agent sees instruction tokens
    for i in range(3):
        sigs.append(AISignal(
            timestamp=now - timedelta(minutes=i),
            actor_type="agent",
            actor_id="ticket-bot",
            model_id="claude-opus",
            action=f"tool_call:{['send_email','read_db','update_record'][i]}",
            contains_instruction_tokens=True,
        ))
    # NHI misuse: 1 service token, many actions, two geos
    for i, act in enumerate(["read_s3", "write_s3", "list_users", "rotate_key", "decrypt", "assume_role"]):
        sigs.append(AISignal(
            timestamp=now - timedelta(minutes=i),
            actor_type="service",
            actor_id="ci-token-7",
            action=act,
            metadata={"geo": "us-east-1" if i % 2 == 0 else "ap-south-1"},
        ))
    # model poisoning: output size shifts
    for i in range(10):
        sigs.append(AISignal(
            timestamp=now - timedelta(minutes=10 - i),
            actor_type="agent",
            actor_id="risk-classifier",
            model_id="m-1",
            output_size_tokens=200 if i < 5 else 900,
            action="classify",
        ))
    # defender over-trust: 8 fast approvals
    for i in range(8):
        sigs.append(AISignal(
            timestamp=now - timedelta(seconds=30 * i),
            actor_type="human",
            actor_id="soc-analyst-3",
            action="triage_decision",
            decision_latency_ms=900 + i * 50,
            approved_by_human=True,
        ))
    detector = AIBreachDetector()
    return aggregate_risk(detector.detect_all(sigs))


# ── Advanced endpoints ───────────────────────────────

class HumanDriftIn(BaseModel):
    actor_id: str
    pattern: str
    timestamp: Optional[datetime] = None
    severity: int = 3


class CorrelateRequest(BaseModel):
    signals: List[AISignalIn]
    human_events: List[HumanDriftIn]
    window_minutes: int = 60


@router.get("/playbooks")
async def list_playbooks() -> Dict[str, Any]:
    """Return the auto-mitigation playbook for every AI breach pattern,
    including the MITRE ATLAS technique IDs each one maps to."""
    return {
        "count": len(PLAYBOOKS),
        "playbooks": [playbook_to_dict(pb) for pb in all_playbooks()],
    }


@router.get("/playbooks/{pattern}")
async def get_pattern_playbook(pattern: str) -> Dict[str, Any]:
    try:
        p = AIBreachPatternType(pattern)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=f"unknown pattern: {pattern}") from exc
    return playbook_to_dict(get_playbook(p))


@router.get("/forecast")
async def get_forecast() -> Dict[str, Any]:
    """24-hour rolling AI-breach risk forecast (EWMA + 95% band)."""
    out = _FORECASTER.to_dict()
    if out["samples"] == 0:
        # seed with a demo trace so dashboards never see an empty forecast
        now = datetime.utcnow()
        for i in range(24):
            _FORECASTER.add(now - timedelta(hours=24 - i), 30 + (i * 1.5) + (i % 3) * 4)
        out = _FORECASTER.to_dict()
        out["seeded"] = True
    return out


@router.post("/correlate")
async def correlate_with_human_drift(req: CorrelateRequest) -> Dict[str, Any]:
    """Surface AI breach detections that fired alongside human-drift events
    for the same actor — the most actionable kind of finding because both
    the human and the AI surface lit up at once."""
    if not req.signals:
        raise HTTPException(status_code=400, detail="signals must be non-empty")
    detector = AIBreachDetector()
    sigs = [
        AISignal(
            timestamp=s.timestamp or datetime.utcnow(),
            actor_type=s.actor_type,
            actor_id=s.actor_id,
            model_id=s.model_id,
            model_version=s.model_version,
            action=s.action,
            tool_name=s.tool_name,
            destination=s.destination,
            prompt_size_tokens=s.prompt_size_tokens,
            output_size_tokens=s.output_size_tokens,
            contains_instruction_tokens=s.contains_instruction_tokens,
            decision_latency_ms=s.decision_latency_ms,
            approved_by_human=s.approved_by_human,
            metadata=s.metadata,
        )
        for s in req.signals
    ]
    detections = detector.detect_all(sigs)
    human_events = [
        HumanDriftEvent(
            actor_id=h.actor_id,
            pattern=h.pattern,
            timestamp=h.timestamp or datetime.utcnow(),
            severity=h.severity,
        )
        for h in req.human_events
    ]
    correlator = CrossDriftCorrelator(window_minutes=req.window_minutes)
    findings = correlator.correlate(detections, human_events)
    return {
        "ai_detections": len(detections),
        "human_events": len(human_events),
        "cross_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


# ── Governance: tamper-evident audit chain ───────────

@router.get("/audit/chain")
async def audit_chain(limit: int = 50) -> Dict[str, Any]:
    """Return the most recent audit-chain entries (default last 50).

    Each entry is hash-linked to the prior one; integrity can be verified
    independently via /audit/verify.
    """
    if limit <= 0 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be in 1..1000")
    entries = _AUDIT_CHAIN.entries(limit=limit)
    return {
        "length": len(_AUDIT_CHAIN),
        "head": _AUDIT_CHAIN.head(),
        "returned": len(entries),
        "entries": [e.to_dict() for e in entries],
    }


@router.get("/audit/verify")
async def audit_verify() -> Dict[str, Any]:
    """Walk the chain and confirm every hash linkage is intact."""
    return _AUDIT_CHAIN.verify()


# ── Governance: agent quarantine / circuit breaker ───

@router.get("/quarantine")
async def quarantine_list() -> Dict[str, Any]:
    """List every actor currently quarantined by the AI-breach circuit breaker."""
    items = _QUARANTINE.list_quarantined()
    return {
        "count": len(items),
        "threshold": _QUARANTINE.threshold,
        "window_minutes": _QUARANTINE.window_minutes,
        "quarantined": items,
    }


@router.get("/quarantine/{actor_id}")
async def quarantine_status(actor_id: str) -> Dict[str, Any]:
    return _QUARANTINE.status(actor_id)


class ReleaseRequest(BaseModel):
    reason: str = ""


@router.post("/quarantine/{actor_id}/release")
async def quarantine_release(actor_id: str, req: ReleaseRequest) -> Dict[str, Any]:
    """Manually clear an actor's quarantine. The reason is logged to the
    audit chain so the override itself is tamper-evident."""
    existed = _QUARANTINE.release(actor_id)
    entry = _AUDIT_CHAIN.append({
        "event": "quarantine_release",
        "actor_id": actor_id,
        "reason": req.reason,
        "had_record": existed,
    })
    return {
        "released": existed,
        "actor_id": actor_id,
        "audit_entry_hash": entry.entry_hash,
    }


# ── Governance: external anchor snapshot ─────────────

@router.post("/audit/anchor")
async def audit_anchor() -> Dict[str, Any]:
    """Produce a portable snapshot of the current chain head (length, head,
    timestamp, anchor_id). The snapshot is also written to disk under the
    configured anchor directory so external systems (object-locked S3,
    customer git repo, public timestamp service) can publish it for
    independent tamper-evidence beyond the in-process chain."""
    return _AUDIT_CHAIN.anchor_snapshot(anchor_dir=_ANCHOR_DIR)


@router.post("/audit/anchor/verify")
async def audit_anchor_verify(anchor: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Verify an externally-published anchor doc against the live chain.

    Closes the loop on the anchor mechanism: a regulator, auditor, or the
    customer themselves can submit a previously-minted snapshot and learn
    whether the chain still extends from that point or has been truncated /
    reorged. See ``AuditChain.verify_anchor`` for the three checks performed.
    """
    return _AUDIT_CHAIN.verify_anchor(anchor)


@router.get("/audit/anchors")
async def audit_anchor_history() -> Dict[str, Any]:
    """Walk the anchor directory and verify the full anchors-of-anchors
    chain in one shot. See ``AuditChain.verify_anchor_history`` — proves
    each anchor is self-consistent, that the prev_anchor_id linkage is
    unbroken, and that every anchor still verifies against the live entry
    chain.
    """
    return _AUDIT_CHAIN.verify_anchor_history(_ANCHOR_DIR)


@router.get("/audit/entry/{index}")
async def audit_entry(index: int) -> Dict[str, Any]:
    """Return a single audit entry by chain index, plus a self-verification
    block. Lets a customer prove a specific detection was logged without
    needing to download the rest of the chain — they store the receipt at
    detection time and re-fetch this endpoint later to confirm the chain
    still holds the same entry at that index.
    """
    entry = _AUDIT_CHAIN.entry_at(index)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no entry at index {index}")
    receipt = entry.to_dict()
    return {
        "entry": receipt,
        "verification": _AUDIT_CHAIN.verify_entry_receipt(receipt),
    }


@router.post("/audit/entry/verify")
async def audit_entry_verify(entry: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Self-contained verification of a previously-issued entry receipt.
    Does not consult the live chain — proves only that the receipt is
    internally well-formed (the payload binding hash recomputes). To prove
    chain inclusion, separately ``GET /audit/entry/{index}`` and confirm
    the returned ``entry_hash`` matches the receipt's ``entry_hash``.
    """
    return _AUDIT_CHAIN.verify_entry_receipt(entry)


# ── Real-time per-actor analytics (Appendix N) ───────

class IngestRequest(BaseModel):
    """Lightweight per-actor risk sample for systems that have already
    computed a score upstream (a SOC pipeline, a sidecar, an SDK)."""
    actor_id: str
    risk_score: float
    timestamp: Optional[datetime] = None


@router.post("/ingest")
async def ingest_realtime(req: IngestRequest) -> Dict[str, Any]:
    """Feed a single (actor, risk_score) sample into the realtime analyzer.

    Returns the z-score verdict for this sample. Anomalous samples
    (``|z| >= z_threshold``) are appended to the rolling anomaly buffer
    and broadcast on the SSE ``/stream`` channel. Use this when your
    upstream already produces risk scores and you only need the
    streaming anomaly layer.
    """
    return _REALTIME.observe(
        req.actor_id, req.risk_score, timestamp=req.timestamp
    )


@router.get("/actors")
async def list_actors() -> Dict[str, Any]:
    """Snapshot of every tracked actor with their latest risk + baseline.

    Sorted by latest_risk descending so the dashboard's "top movers"
    table is one fetch away.
    """
    rows = _REALTIME.actors()
    return {"count": len(rows), "actors": rows, "stats": _REALTIME.stats()}


@router.get("/actors/{actor_id}/trajectory")
async def actor_trajectory(actor_id: str) -> Dict[str, Any]:
    """Full rolling-window trajectory for a single actor: every sample
    plus the current baseline mean / stdev / z-threshold. Used by the
    operator UI for per-actor drill-downs."""
    traj = _REALTIME.trajectory(actor_id)
    if traj["samples"] == 0:
        raise HTTPException(
            status_code=404,
            detail=f"no samples observed for actor {actor_id!r}",
        )
    return traj


@router.get("/anomalies")
async def list_anomalies(limit: int = 50) -> Dict[str, Any]:
    """Most recent z-score anomalies (newest last). Bounded ring buffer;
    older anomalies fall off as new ones arrive. Backs the SSE replay-on-
    reconnect contract: any subscriber can re-fetch this to recover the
    last N events without a full chain scan."""
    items = _REALTIME.recent_anomalies(limit=max(1, min(int(limit), 200)))
    return {"count": len(items), "anomalies": items}


# ── Embed layer (Appendix O): collect → recommend → approve ──

class CollectRequest(BaseModel):
    """Free-form events from any embedding host (browser, mobile app,
    backend service, agent runtime). Each event is normalized into an
    ``AISignal`` and run through the same detector pipeline as ``/scan``.
    Pending recommendations are filed automatically on detection."""
    site_id: Optional[str] = None
    events: List[Dict[str, Any]]


@router.post("/collect")
async def collect(req: CollectRequest) -> Dict[str, Any]:
    """Generic event sink for embedded sites / apps / agents.

    Pipeline:
      1. Normalize each event → AISignal (EventCollector).
      2. Run the full detector + audit + quarantine + realtime pass.
      3. For each detection, build a Recommendation and submit it to
         the role-gated approval queue.
      4. Return detections + freshly-filed recommendations so the
         embedding can render a banner / toast immediately.
    """
    if not req.events:
        raise HTTPException(status_code=400, detail="events must be non-empty")
    sigs = EventCollector.normalize_batch(req.events)
    detector = AIBreachDetector(confidence_threshold=0.70)
    detections = detector.detect_all(sigs)
    agg = aggregate_risk(detections)
    _FORECASTER.add(datetime.utcnow(), agg["overall_risk_score"])
    _AUDIT_CHAIN.append_detections(detections)
    for det in detections:
        _QUARANTINE.record(det)
    sig_to_actor = {str(s.id): s.actor_id for s in sigs}
    actor_max: Dict[str, float] = {a: 0.0 for a in {s.actor_id for s in sigs}}
    for d in detections:
        for sid in d.signal_ids:
            actor = sig_to_actor.get(str(sid))
            if actor is not None and d.risk_score > actor_max.get(actor, 0.0):
                actor_max[actor] = float(d.risk_score)
    for actor, score in actor_max.items():
        _REALTIME.observe(actor, score)
    det_dicts = [d.to_dict() for d in detections]
    recs = _RECOMMENDER.build_many(det_dicts)
    submitted = _APPROVALS.submit_many(recs)
    return {
        "site_id": req.site_id,
        "ingested_events": len(sigs),
        "detections": det_dicts,
        "aggregate": agg,
        "recommendations_pending": submitted,
    }


@router.get("/recommendations")
async def list_recommendations(
    status: Optional[str] = None, limit: int = 100
) -> Dict[str, Any]:
    """List recommendations, optionally filtered by status.

    ``status`` is one of ``pending``, ``approved``, ``rejected``,
    ``expired``. Newest first, bounded by ``limit`` (max 500)."""
    if status is not None and status not in (PENDING, APPROVED, REJECTED, "expired"):
        raise HTTPException(status_code=400, detail=f"invalid status {status!r}")
    capped = max(1, min(int(limit), 500))
    items = _APPROVALS.list(status=status, limit=capped)
    return {
        "count": len(items),
        "recommendations": items,
        "stats": _APPROVALS.stats(),
    }


@router.get("/recommendations/{rec_id}")
async def get_recommendation(rec_id: str) -> Dict[str, Any]:
    item = _APPROVALS.get(rec_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"recommendation {rec_id} not found")
    return item


class DecisionRequest(BaseModel):
    """A signed decision on a pending recommendation. ``approver_role``
    is checked against the recommendation's ``required_approver_roles``
    list — wrong role → 403."""
    decision: str  # "approved" | "rejected"
    approver_id: str
    approver_role: str
    reason: str = ""


@router.post("/recommendations/{rec_id}/decide")
async def decide_recommendation(
    rec_id: str, req: DecisionRequest
) -> Dict[str, Any]:
    try:
        return _APPROVALS.decide(
            rec_id,
            decision=req.decision,
            approver_id=req.approver_id,
            approver_role=req.approver_role,
            reason=req.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/recommendations/log/decisions")
async def recommendations_decision_log(limit: int = 100) -> Dict[str, Any]:
    """Tamper-evident decision log for the approval queue. Bounded ring
    buffer; oldest entries fall off. Useful for SOC dashboards and
    SOC 2 CC1.3 segregation-of-duties audits."""
    capped = max(1, min(int(limit), 500))
    entries = _APPROVALS.decision_log(limit=capped)
    return {"count": len(entries), "entries": entries}


@router.get("/forecast/history")
async def forecast_history(limit: int = 288) -> Dict[str, Any]:
    """Return the recent risk-history buffer for sparkline / trend rendering.

    Stays bounded by the forecaster's own ``max_history`` (24h at 5-min
    cadence by default). Read-only; no state mutation.
    """
    capped = max(1, min(int(limit), _FORECASTER.max_history))
    history = _FORECASTER.history[-capped:]
    return {
        "samples": len(history),
        "alpha": _FORECASTER.alpha,
        "points": [
            {"ts": ts.isoformat() if hasattr(ts, "isoformat") else str(ts), "risk": round(float(v), 1)}
            for ts, v in history
        ],
    }


# ── Real-time SSE risk stream ────────────────────────

@router.get("/stream")
async def stream_risk():
    """Server-Sent Events stream of live AI-breach posture.

    Each event payload contains:
      - forecast EWMA + 95% upper band sample
      - audit chain head + length
      - quarantine count

    Clients (the dashboard, a SOC ticker, a NOC display) reconnect for free
    on disconnect — SSE handles the transport. The stream is read-only and
    requires no auth in the current deployment; production hardening would
    add the same Bearer check as the SDK's optional ``api_key``.
    """
    async def gen():
        # Initial hello event so subscribers know the channel is open.
        # Replays the most recent realtime stats so a fresh subscriber
        # has immediate context without polling /actors first.
        yield (
            "event: hello\n"
            f"data: {_json.dumps({'ok': True, 'realtime': _REALTIME.stats()})}\n\n"
        )
        # Cursor into the realtime anomaly buffer so we only emit deltas.
        last_emitted = len(_REALTIME.recent_anomalies(limit=1_000))
        while True:
            forecast = _FORECASTER.to_dict()
            sample = forecast.get("forecast", [])
            payload = {
                "ts": datetime.utcnow().isoformat(),
                "forecast": {
                    "ewma": forecast.get("current_ewma"),
                    "samples": forecast.get("samples"),
                    "next": sample[-1] if sample else None,
                },
                "audit": {
                    "length": len(_AUDIT_CHAIN),
                    "head": _AUDIT_CHAIN.head(),
                },
                "quarantine": {
                    "count": len(_QUARANTINE.list_quarantined()),
                    "threshold": _QUARANTINE.threshold,
                },
                "realtime": _REALTIME.stats(),
            }
            yield f"event: tick\ndata: {_json.dumps(payload, default=str)}\n\n"
            # Drain any anomalies that fired since the last tick and push
            # one ``anomaly`` event per new entry (newest last). The SSE
            # transport handles back-pressure; if a subscriber is slow,
            # the anomaly buffer keeps the most recent N regardless.
            current = _REALTIME.recent_anomalies(limit=1_000)
            new_count = len(current)
            if new_count > last_emitted:
                for verdict in current[last_emitted:]:
                    yield (
                        "event: anomaly\n"
                        f"data: {_json.dumps(verdict, default=str)}\n\n"
                    )
                last_emitted = new_count
            await asyncio.sleep(5)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
