"""Tests for engine.ai_breach_governance — audit chain + agent quarantine."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from engine.ai_breach_governance import (
    AgentQuarantine,
    AuditChain,
    GENESIS_HASH,
    _canonical_json,
    _hash,
)
from engine.ai_breach_detector import AIBreachDetection
from core.ai_drift_patterns import AIBreachPatternType


# ── Audit chain ──────────────────────────────────────

def _det(actor_id: str, risk: float = 70.0, pattern=AIBreachPatternType.PROMPT_INJECTION):
    """Build a minimal AIBreachDetection that exposes actor_id via signal_ids."""
    d = AIBreachDetection(
        pattern=pattern,
        confidence=0.9,
        severity=4,
        risk_score=risk,
        reasoning="test",
        signal_ids=[uuid4()],
    )
    # Detector output doesn't carry actor_id directly; the quarantine
    # falls back to "signal:<first_id>". Tag it via dict-like access in tests
    # by monkey-patching an attribute.
    d.actor_id = actor_id  # type: ignore[attr-defined]
    return d


def test_chain_starts_empty():
    chain = AuditChain()
    assert len(chain) == 0
    assert chain.head() == GENESIS_HASH
    v = chain.verify()
    assert v == {"intact": True, "broken_at": -1, "length": 0, "head": GENESIS_HASH}


def test_chain_append_links_correctly():
    chain = AuditChain()
    e1 = chain.append({"event": "first", "n": 1})
    e2 = chain.append({"event": "second", "n": 2})
    assert e1.index == 0 and e2.index == 1
    assert e1.prev_hash == GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert chain.head() == e2.entry_hash
    assert len(chain) == 2


def test_chain_verify_detects_tamper():
    chain = AuditChain()
    chain.append({"event": "a"})
    e2 = chain.append({"event": "b"})
    # Mutate payload after the fact.
    e2.payload["event"] = "tampered"
    v = chain.verify()
    assert v["intact"] is False
    assert v["broken_at"] == 1


def test_chain_append_detections_uses_to_dict():
    chain = AuditChain()
    entries = chain.append_detections([_det("agent-1"), _det("agent-2")])
    assert len(entries) == 2
    assert chain.verify()["intact"] is True
    # Payload should include the structured detection fields.
    assert entries[0].payload["pattern"] == "Prompt_Injection"


def test_canonical_json_is_stable():
    a = {"b": 2, "a": 1, "c": [3, {"y": 5, "x": 4}]}
    b = {"c": [3, {"x": 4, "y": 5}], "a": 1, "b": 2}
    assert _canonical_json(a) == _canonical_json(b)
    assert _hash(GENESIS_HASH, _canonical_json(a)) == _hash(GENESIS_HASH, _canonical_json(b))


# ── Quarantine ───────────────────────────────────────

def test_quarantine_validates_inputs():
    with pytest.raises(ValueError):
        AgentQuarantine(threshold=0)
    with pytest.raises(ValueError):
        AgentQuarantine(window_minutes=0)


def test_quarantine_trips_on_threshold_cross():
    q = AgentQuarantine(threshold=100.0, window_minutes=60)
    # First detection: under threshold, no quarantine yet.
    rec1 = q.record(_det("agent-A", risk=60))
    assert rec1 is None
    # Second detection pushes the actor over the budget.
    rec2 = q.record(_det("agent-A", risk=50))
    assert rec2 is not None
    assert rec2.actor_id == "agent-A"
    assert rec2.cumulative_risk >= 100.0
    assert rec2.requires_human_review is True
    # Subsequent calls do not produce a *new* record (already quarantined).
    rec3 = q.record(_det("agent-A", risk=80))
    assert rec3 is None
    assert any(r["actor_id"] == "agent-A" for r in q.list_quarantined())


def test_quarantine_status_and_release():
    q = AgentQuarantine(threshold=50.0, window_minutes=60)
    q.record(_det("svc-7", risk=60))
    s = q.status("svc-7")
    assert s["quarantined"] is True
    assert s["record"]["actor_id"] == "svc-7"
    assert q.release("svc-7") is True
    s2 = q.status("svc-7")
    assert s2["quarantined"] is False
    # Releasing an unknown actor returns False without raising.
    assert q.release("nobody") is False


def test_quarantine_falls_back_to_signal_bucket_when_no_actor():
    q = AgentQuarantine(threshold=30.0, window_minutes=60)
    d = AIBreachDetection(
        pattern=AIBreachPatternType.SHADOW_AI,
        confidence=0.9,
        severity=4,
        risk_score=40.0,
        signal_ids=[uuid4()],
    )
    rec = q.record(d)
    assert rec is not None
    assert rec.actor_id.startswith("signal:")


# ── Persistence + anchor ─────────────────────────────

def test_chain_persistence_round_trip(tmp_path):
    path = tmp_path / "chain.jsonl"
    c1 = AuditChain(storage_path=str(path))
    c1.append({"event": "a", "n": 1})
    c1.append({"event": "b", "n": 2})
    head1 = c1.head()
    # Re-open: chain is replayed and verifies intact.
    c2 = AuditChain(storage_path=str(path))
    assert len(c2) == 2
    assert c2.head() == head1
    assert c2.verify() == {"intact": True, "broken_at": -1, "length": 2, "head": head1}


def test_anchor_snapshot_writes_file(tmp_path):
    chain = AuditChain()
    chain.append({"event": "x"})
    out = chain.anchor_snapshot(anchor_dir=str(tmp_path))
    assert out["length"] == 1
    assert out["head"] == chain.head()
    assert "anchor_id" in out and len(out["anchor_id"]) == 64
    files = list(tmp_path.glob("anchor-*.json"))
    assert len(files) == 1
    on_disk = files[0].read_text(encoding="utf-8")
    assert out["anchor_id"] in on_disk


def test_anchor_verify_against_live_chain():
    chain = AuditChain()
    chain.append({"event": "alpha"})
    chain.append({"event": "beta"})
    snap = chain.anchor_snapshot()
    res = chain.verify_anchor(snap)
    assert res["valid"] is True
    assert res["anchor_length"] == 2
    assert res["current_length"] == 2
    assert res["growth_since_anchor"] == 0
    # Chain grows: anchor still verifies and growth is reflected.
    chain.append({"event": "gamma"})
    res2 = chain.verify_anchor(snap)
    assert res2["valid"] is True
    assert res2["growth_since_anchor"] == 1


def test_anchor_verify_detects_tampered_anchor():
    chain = AuditChain()
    chain.append({"event": "x"})
    snap = chain.anchor_snapshot()
    forged = dict(snap)
    forged["head"] = "f" * 64  # rewrite head, leave anchor_id alone
    res = chain.verify_anchor(forged)
    assert res["valid"] is False
    assert "anchor_id" in res["reason"]


def test_anchor_verify_detects_truncation():
    chain_a = AuditChain()
    chain_a.append({"event": "x"})
    chain_a.append({"event": "y"})
    snap = chain_a.anchor_snapshot()
    # A different / truncated chain must fail verification.
    chain_b = AuditChain()
    res = chain_b.verify_anchor(snap)
    assert res["valid"] is False
    assert "truncated" in res["reason"].lower()


def test_anchor_verify_genesis():
    chain = AuditChain()
    snap = chain.anchor_snapshot()
    assert snap["length"] == 0
    res = chain.verify_anchor(snap)
    assert res["valid"] is True


def test_anchor_chain_links_prev_id(tmp_path):
    chain = AuditChain()
    chain.append({"event": "x"})
    a1 = chain.anchor_snapshot(anchor_dir=str(tmp_path))
    chain.append({"event": "y"})
    a2 = chain.anchor_snapshot(anchor_dir=str(tmp_path))
    # First anchor is genesis-linked, second links to first.
    assert a1["prev_anchor_id"] == "0" * 64
    assert a2["prev_anchor_id"] == a1["anchor_id"]
    # Both verify against the live chain.
    assert chain.verify_anchor(a1)["valid"] is True
    assert chain.verify_anchor(a2)["valid"] is True
    # Tampering with prev_anchor_id breaks self-consistency.
    forged = dict(a2)
    forged["prev_anchor_id"] = "1" * 64
    assert chain.verify_anchor(forged)["valid"] is False


def test_anchor_legacy_no_prev_field_still_verifies():
    """Anchors minted before the chaining upgrade must still verify."""
    import hashlib as _h
    chain = AuditChain()
    chain.append({"event": "x"})
    length = len(chain)
    head = chain.head()
    ts = "2026-04-22T00:00:00+00:00"
    legacy_id = _h.sha256(f"{length}|{head}|{ts}".encode()).hexdigest()
    legacy = {"length": length, "head": head, "timestamp": ts, "anchor_id": legacy_id}
    res = chain.verify_anchor(legacy)
    assert res["valid"] is True


def test_quarantine_persistence_round_trip(tmp_path):
    path = tmp_path / "quar.json"
    q1 = AgentQuarantine(threshold=10.0, window_minutes=5, storage_path=str(path))

    class _D:
        actor_id = "agent-42"
        risk_score = 50.0
        signal_ids = ["s1"]
        pattern = None

    rec = q1.record(_D())
    assert rec is not None
    assert rec.actor_id == "agent-42"

    # Re-open: quarantine status survives restart.
    q2 = AgentQuarantine(threshold=10.0, window_minutes=5, storage_path=str(path))
    status = q2.status("agent-42")
    assert status["quarantined"] is True
    assert status["record"]["actor_id"] == "agent-42"

    # Release persists too.
    assert q2.release("agent-42") is True
    q3 = AgentQuarantine(threshold=10.0, window_minutes=5, storage_path=str(path))
    assert q3.status("agent-42")["quarantined"] is False


def test_anchor_history_verifies_full_chain(tmp_path):
    chain = AuditChain()
    chain.append({"event": "a"})
    chain.anchor_snapshot(anchor_dir=str(tmp_path))
    chain.append({"event": "b"})
    chain.anchor_snapshot(anchor_dir=str(tmp_path))
    chain.append({"event": "c"})
    chain.anchor_snapshot(anchor_dir=str(tmp_path))
    res = chain.verify_anchor_history(str(tmp_path))
    assert res["count"] == 3
    assert res["valid"] is True
    assert res["broken_at"] == -1
    assert all(a["valid"] for a in res["anchors"])


def test_anchor_history_detects_broken_link(tmp_path):
    import json as _j
    chain = AuditChain()
    chain.append({"event": "a"})
    chain.anchor_snapshot(anchor_dir=str(tmp_path))
    chain.append({"event": "b"})
    chain.anchor_snapshot(anchor_dir=str(tmp_path))
    # Corrupt the second anchor's prev_anchor_id (and matching id) so the
    # individual file is internally consistent but the linkage is broken.
    files = sorted(tmp_path.glob("anchor-*.json"))
    raw = _j.loads(files[1].read_text(encoding="utf-8"))
    raw["prev_anchor_id"] = "1" * 64
    import hashlib as _h
    raw["anchor_id"] = _h.sha256(
        f"{raw['length']}|{raw['head']}|{raw['timestamp']}|{raw['prev_anchor_id']}".encode()
    ).hexdigest()
    files[1].write_text(_j.dumps(raw), encoding="utf-8")
    res = chain.verify_anchor_history(str(tmp_path))
    assert res["valid"] is False
    assert res["broken_at"] == 1
    assert "prev_anchor_id" in res["reason"]


def test_anchor_history_empty_dir(tmp_path):
    chain = AuditChain()
    res = chain.verify_anchor_history(str(tmp_path))
    assert res == {"count": 0, "valid": True, "broken_at": -1, "anchors": []}
