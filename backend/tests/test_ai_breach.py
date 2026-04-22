"""Tests for the AI breach detector and pattern registry."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from core.ai_drift_patterns import (
    AI_BREACH_PATTERNS,
    AIBreachPatternType,
    all_ai_patterns,
    patterns_for_owasp,
    patterns_for_nist_function,
)
from engine.ai_breach_detector import (
    AIBreachDetector,
    AISignal,
    aggregate_risk,
)


def test_seven_patterns_registered():
    assert len(AI_BREACH_PATTERNS) == 7
    assert {p for p in AIBreachPatternType} == set(AI_BREACH_PATTERNS.keys())


def test_each_pattern_has_owasp_and_nist():
    for p in all_ai_patterns():
        assert p.owasp_llm_id.startswith("LLM")
        assert p.nist_ai_rmf_function in {"GOVERN", "MAP", "MEASURE", "MANAGE"}
        assert 1 <= p.base_severity <= 5
        assert p.nist_controls_at_risk
        assert p.mitigation_repo_path


def test_patterns_for_owasp_lookup():
    assert patterns_for_owasp("LLM01")[0].pattern_type == AIBreachPatternType.PROMPT_INJECTION
    assert patterns_for_nist_function("govern")


def test_empty_signals_yields_empty():
    assert AIBreachDetector().detect_all([]) == []


def _now():
    return datetime.utcnow()


def test_shadow_ai_detection():
    sigs = [
        AISignal(
            actor_type="human",
            actor_id=f"u{i}",
            destination="api.openai.com",
            prompt_size_tokens=900,
            action="http_post",
        )
        for i in range(3)
    ]
    out = AIBreachDetector().detect_all(sigs)
    found = [d for d in out if d.pattern == AIBreachPatternType.SHADOW_AI]
    assert found, "shadow AI should fire on humans posting large prompts to public LLMs"
    assert found[0].confidence > 0.5


def test_prompt_injection_detection():
    sigs = [
        AISignal(actor_type="agent", actor_id="bot", action="tool_call:x",
                 contains_instruction_tokens=True)
        for _ in range(3)
    ]
    out = AIBreachDetector().detect_all(sigs)
    found = [d for d in out if d.pattern == AIBreachPatternType.PROMPT_INJECTION]
    assert found
    assert found[0].severity >= 3


def test_nhi_misuse_detection():
    sigs = [
        AISignal(actor_type="service", actor_id="tok-1", action=a, metadata={"geo": g})
        for a, g in [
            ("read_s3", "us"), ("write_s3", "us"), ("list_users", "ap"),
            ("rotate_key", "ap"), ("decrypt", "us"), ("assume_role", "us"),
        ]
    ]
    out = AIBreachDetector().detect_all(sigs)
    found = [d for d in out if d.pattern == AIBreachPatternType.NHI_MISUSE]
    assert found


def test_defender_over_trust_detection():
    sigs = [
        AISignal(actor_type="human", actor_id="soc",
                 action="triage_decision",
                 decision_latency_ms=800,
                 approved_by_human=True)
        for _ in range(10)
    ]
    out = AIBreachDetector().detect_all(sigs)
    found = [d for d in out if d.pattern == AIBreachPatternType.DEFENDER_OVER_TRUST]
    assert found
    assert found[0].risk_score > 0


def test_aggregate_risk_levels():
    # empty
    assert aggregate_risk([]) == {
        "overall_risk_score": 0.0,
        "alert_level": "Watch",
        "active_patterns": 0,
        "patterns": [],
    }
    # build a critical detection via shadow AI strong signal
    sigs = [
        AISignal(
            actor_type="human", actor_id=f"u{i}",
            destination="api.openai.com",
            prompt_size_tokens=2000,
            action="http_post",
        )
        for i in range(8)
    ]
    out = AIBreachDetector().detect_all(sigs)
    agg = aggregate_risk(out)
    assert agg["active_patterns"] >= 1
    assert agg["alert_level"] in {"Watch", "Warning", "Critical"}
    assert 0 <= agg["overall_risk_score"] <= 100


def test_detection_to_dict_is_json_safe():
    sigs = [
        AISignal(actor_type="agent", actor_id="bot", action="tool",
                 contains_instruction_tokens=True)
        for _ in range(2)
    ]
    detections = AIBreachDetector().detect_all(sigs)
    assert detections
    d = detections[0].to_dict()
    # all strings, ints, floats, lists — json-serialisable
    import json
    json.dumps(d)
    assert "owasp_llm_id" in d and "nist_ai_rmf_function" in d
