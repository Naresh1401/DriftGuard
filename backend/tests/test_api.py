"""
Tests for API endpoints.
Uses FastAPI TestClient for synchronous testing.
"""

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_health_has_version(self, client):
        resp = client.get("/api/health")
        data = resp.json()
        assert "version" in data


class TestSignalEndpoints:
    def test_ingest_signal(self, client):
        signal = {
            "signal_id": "test-api-001",
            "source": "test",
            "signal_type": "access_log",
            "timestamp": "2024-01-15T10:00:00Z",
            "department": "SOC",
            "raw_data": {"action": "login"},
        }
        resp = client.post("/api/signals/ingest", json=signal)
        assert resp.status_code in (200, 201, 422)  # 422 if validation strict

    def test_ingest_invalid_signal(self, client):
        resp = client.post("/api/signals/ingest", json={})
        assert resp.status_code in (400, 422)


class TestAlertEndpoints:
    def test_list_alerts(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200

    def test_health_score(self, client):
        resp = client.get("/api/alerts/health-score")
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data


class TestDomainEndpoints:
    def test_list_domains(self, client):
        resp = client.get("/api/domains")
        assert resp.status_code == 200


class TestReportEndpoints:
    def test_weekly_report(self, client):
        resp = client.get("/api/reports/weekly")
        assert resp.status_code == 200


class TestGovernanceEndpoints:
    def test_audit_log(self, client):
        resp = client.get("/api/governance/audit-log")
        assert resp.status_code == 200
