"""AI Breach API — endpoints for the AI-era breach surface.

Routes:
  GET  /api/v1/ai-breach/patterns           List the seven AI breach pattern definitions
  POST /api/v1/ai-breach/scan               Run all detectors over a batch of signals
  POST /api/v1/ai-breach/risk               Single rolled-up risk score from signals
  GET  /api/v1/ai-breach/demo               Returns a deterministic demo result
                                            (useful for the dashboard preview)
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.ai_drift_patterns import (
    AI_BREACH_PATTERNS,
    AIBreachPatternType,
    all_ai_patterns,
)
from engine.ai_breach_detector import (
    AIBreachDetector,
    AISignal,
    aggregate_risk,
)


router = APIRouter(prefix="/ai-breach", tags=["AI Breach"])


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
    return {
        "scanned_signals": len(sigs),
        "detections": [d.to_dict() for d in detections],
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
