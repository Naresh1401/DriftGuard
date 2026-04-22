"""Tests for the advanced AI breach features: playbooks, forecast, correlation."""
from __future__ import annotations

from datetime import datetime, timedelta

from core.ai_drift_patterns import AIBreachPatternType
from core.ai_breach_playbooks import (
    PLAYBOOKS,
    all_playbooks,
    get_playbook,
    playbook_to_dict,
)
from engine.ai_breach_advanced import (
    CrossDriftCorrelator,
    HumanDriftEvent,
    RiskForecaster,
)
from engine.ai_breach_detector import (
    AIBreachDetection,
    AIBreachDetector,
    AISignal,
)


# ── Playbooks ────────────────────────────────────

def test_every_pattern_has_a_playbook():
    assert set(PLAYBOOKS.keys()) == set(AIBreachPatternType)


def test_each_playbook_has_at_least_one_step():
    for pb in all_playbooks():
        assert pb.immediate_steps
        assert pb.short_term_steps
        assert pb.long_term_steps
        assert pb.mitre_atlas_ids
        for s in pb.immediate_steps:
            assert s.action
            assert s.owner_role in {"security_engineer", "ciso", "ml_engineer", "compliance"}


def test_playbook_serialises():
    d = playbook_to_dict(get_playbook(AIBreachPatternType.SHADOW_AI))
    import json
    json.dumps(d)
    assert d["mitre_atlas_ids"]
    assert d["immediate_steps"][0]["order"] == 1


# ── Forecaster ──────────────────────────────────

def test_empty_forecaster_returns_empty():
    f = RiskForecaster()
    assert f.forecast() == []
    out = f.to_dict()
    assert out["samples"] == 0
    assert out["current_ewma"] == 0


def test_forecaster_clamps_and_smooths():
    f = RiskForecaster(alpha=0.3)
    now = datetime.utcnow()
    # spiky input
    for i, v in enumerate([10, 90, 20, 85, 30, 75, 40]):
        f.add(now - timedelta(minutes=10 * (7 - i)), v)
    pts = f.forecast(horizon_minutes=240, step_minutes=60)
    assert len(pts) == 4
    for p in pts:
        assert 0 <= p.lower_bound <= p.forecast <= p.upper_bound <= 100


def test_forecaster_max_history_trims():
    f = RiskForecaster(max_history=5)
    now = datetime.utcnow()
    for i in range(20):
        f.add(now + timedelta(minutes=i), float(i))
    assert len(f.history) == 5


# ── Cross-drift correlator ─────────────────────

def test_correlator_empty_inputs():
    c = CrossDriftCorrelator()
    assert c.correlate([], []) == []


def test_correlator_finds_overlap():
    now = datetime.utcnow()
    det = AIBreachDetection(
        pattern=AIBreachPatternType.PROMPT_INJECTION,
        confidence=0.85,
        severity=4,
        risk_score=70.0,
        reasoning="test",
        detected_at=now,
    )
    human = HumanDriftEvent(
        actor_id="user-123",
        pattern="BEHAVIORAL_VARIANCE",
        timestamp=now + timedelta(minutes=10),
        severity=3,
    )
    findings = CrossDriftCorrelator(window_minutes=60).correlate([det], [human])
    assert len(findings) == 1
    assert findings[0].combined_severity >= 4
    assert "rompt" in findings[0].reasoning.lower() or "injection" in findings[0].reasoning.lower()


def test_correlator_respects_window():
    now = datetime.utcnow()
    det = AIBreachDetection(detected_at=now)
    human = HumanDriftEvent(
        actor_id="u",
        pattern="X",
        timestamp=now + timedelta(hours=5),
    )
    assert CrossDriftCorrelator(window_minutes=60).correlate([det], [human]) == []


# ── End-to-end smoke ─────────────────────────────

def test_detector_feeds_forecaster():
    sigs = [
        AISignal(actor_type="agent", actor_id="bot", action="x",
                 contains_instruction_tokens=True)
        for _ in range(3)
    ]
    detections = AIBreachDetector().detect_all(sigs)
    overall = max((d.risk_score for d in detections), default=0.0)
    f = RiskForecaster()
    f.add(datetime.utcnow(), overall)
    assert f.to_dict()["samples"] == 1
