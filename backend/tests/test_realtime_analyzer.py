"""Tests for the realtime per-actor analyzer + its API wiring."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from main import app
from engine.realtime_analyzer import RealtimeAnalyzer


# ── Unit tests ───────────────────────────────────────

def test_warmup_no_baseline():
    a = RealtimeAnalyzer(baseline_min=5)
    v = a.observe("agent-1", 10.0)
    assert v["baseline_ready"] is False
    assert v["anomaly"] is False
    assert v["samples"] == 1


def test_baseline_fires_anomaly_on_spike():
    a = RealtimeAnalyzer(baseline_min=5, z_threshold=2.0)
    # Steady baseline at ~10
    for _ in range(8):
        a.observe("agent-1", 10.0 + (0.1 if _ % 2 else -0.1))
    spike = a.observe("agent-1", 95.0)
    assert spike["baseline_ready"] is True
    assert spike["anomaly"] is True
    assert spike["z"] is None or spike["z"] > 2.0


def test_no_anomaly_within_baseline():
    a = RealtimeAnalyzer(baseline_min=5, z_threshold=3.0)
    for _ in range(10):
        a.observe("agent-x", 50.0)
    # Same value as baseline: zero deviation → no anomaly
    v = a.observe("agent-x", 50.0)
    assert v["anomaly"] is False


def test_per_actor_isolation():
    a = RealtimeAnalyzer(baseline_min=4, z_threshold=2.0)
    for _ in range(6):
        a.observe("noisy", 80.0)
        a.observe("quiet", 5.0)
    # Quiet actor sees a spike; noisy actor sees its own baseline
    quiet_spike = a.observe("quiet", 90.0)
    noisy_normal = a.observe("noisy", 80.0)
    assert quiet_spike["anomaly"] is True
    assert noisy_normal["anomaly"] is False


def test_trajectory_and_actors_snapshot():
    a = RealtimeAnalyzer(baseline_min=3)
    for s in [10, 20, 30, 40]:
        a.observe("agent-A", float(s))
    a.observe("agent-B", 5.0)
    actors = a.actors()
    ids = {r["actor_id"] for r in actors}
    assert {"agent-A", "agent-B"} == ids
    traj = a.trajectory("agent-A")
    assert traj["samples"] == 4
    assert traj["points"][-1]["risk"] == 40.0
    assert traj["baseline_ready"] is True


def test_recent_anomalies_buffer_bounded():
    a = RealtimeAnalyzer(baseline_min=3, z_threshold=1.0, anomaly_buffer=5)
    for s in [1.0, 1.1, 0.9, 1.05]:
        a.observe("a", s)
    # Now 10 spikes
    for _ in range(10):
        a.observe("a", 100.0)
    items = a.recent_anomalies(limit=100)
    assert len(items) <= 5  # bounded by ring buffer


def test_ttl_evicts_old_samples():
    a = RealtimeAnalyzer(baseline_min=3, ttl_minutes=1)
    old = datetime.utcnow() - timedelta(minutes=5)
    a.observe("a", 10.0, timestamp=old)
    # Fresh sample — old one should be evicted before baseline forms
    v = a.observe("a", 11.0)
    assert v["samples"] == 1


# ── API integration ──────────────────────────────────

@pytest.fixture
def client():
    return TestClient(app)


def test_ingest_and_actors_endpoints(client):
    # Warm up baseline (default baseline_min=8 in module-level analyzer)
    for s in [10.0, 11.0, 9.5, 10.5, 10.2, 9.8, 10.1, 9.9, 10.3, 10.0]:
        r = client.post(
            "/api/v1/ai-breach/ingest",
            json={"actor_id": "rt-test-actor", "risk_score": s},
        )
        assert r.status_code == 200
    spike = client.post(
        "/api/v1/ai-breach/ingest",
        json={"actor_id": "rt-test-actor", "risk_score": 90.0},
    )
    assert spike.status_code == 200
    assert spike.json()["anomaly"] is True

    # Trajectory endpoint
    traj = client.get("/api/v1/ai-breach/actors/rt-test-actor/trajectory")
    assert traj.status_code == 200
    assert traj.json()["samples"] >= 7

    # 404 for unknown actor
    missing = client.get("/api/v1/ai-breach/actors/__nope__/trajectory")
    assert missing.status_code == 404

    # Anomalies endpoint contains our spike
    anom = client.get("/api/v1/ai-breach/anomalies?limit=50")
    assert anom.status_code == 200
    assert any(
        a["actor_id"] == "rt-test-actor" for a in anom.json()["anomalies"]
    )


def test_scan_emits_realtime_block(client):
    payload = {
        "signals": [
            {
                "actor_type": "agent",
                "actor_id": "scan-rt-1",
                "action": "tool_call:send_email",
                "destination": "external.example.com",
                "approved_by_human": False,
                "output_size_tokens": 5000,
            }
        ]
    }
    r = client.post("/api/v1/ai-breach/scan", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "realtime" in body
    assert body["realtime"]["actors_observed"] >= 1
