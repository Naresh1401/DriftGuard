"""
Tests for API endpoints.
Uses FastAPI TestClient for synchronous testing.
"""

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_health_has_version(self, client):
        resp = client.get("/api/v1/health")
        data = resp.json()
        assert "version" in data


class TestSignalEndpoints:
    def test_ingest_signal(self, client):
        signal = {
            "signal_type": "access_log",
            "source": "test",
            "timestamp": "2024-01-15T10:00:00Z",
            "data": {"action": "login"},
            "domain": "enterprise",
        }
        resp = client.post("/api/v1/signals/ingest", json=signal)
        assert resp.status_code in (200, 201, 422)

    def test_ingest_invalid_signal(self, client):
        resp = client.post("/api/v1/signals/ingest", json={})
        assert resp.status_code in (400, 422)


class TestAlertEndpoints:
    def test_list_alerts(self, client):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200


class TestDomainEndpoints:
    def test_list_domains(self, client):
        resp = client.get("/api/v1/domains")
        assert resp.status_code == 200


class TestReportEndpoints:
    def test_weekly_report(self, client):
        resp = client.get("/api/v1/reports/weekly-summary")
        assert resp.status_code == 200


class TestGovernanceEndpoints:
    def test_audit_log(self, client):
        resp = client.get("/api/v1/governance/audit-log")
        assert resp.status_code == 200
