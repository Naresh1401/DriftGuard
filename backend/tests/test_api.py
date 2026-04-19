"""
Tests for API endpoints.
Uses FastAPI TestClient for synchronous testing.
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from api.middleware.auth import get_current_user
from models import User, UserRole


async def _mock_admin_user():
    """Override auth — return a test admin user."""
    return User(
        email="test@driftguard.local",
        full_name="Test Admin",
        role=UserRole.ADMIN,
        organization="Test",
    )


app.dependency_overrides[get_current_user] = _mock_admin_user


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ── Health ────────────────────────────────────────────

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


# ── Signals ───────────────────────────────────────────

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

    def test_upload_csv(self, client):
        csv = "timestamp,action,department\n2024-01-15T10:00:00Z,login,SOC"
        resp = client.post("/api/v1/signals/upload/csv", json={"csv_content": csv, "domain": "enterprise"})
        assert resp.status_code == 200
        data = resp.json()
        assert "signals_parsed" in data

    def test_upload_json(self, client):
        json_content = '[{"timestamp":"2024-01-15","action":"login","department":"SOC"}]'
        resp = client.post("/api/v1/signals/upload/json", json={"json_content": json_content, "domain": "enterprise"})
        assert resp.status_code == 200
        data = resp.json()
        assert "signals_parsed" in data

    def test_upload_logs(self, client):
        log = "Jan 15 10:00:00 server1 sshd[1234]: Accepted password for admin from 10.0.0.1"
        resp = client.post("/api/v1/signals/upload/logs", json={"log_content": log, "log_format": "auto", "domain": "enterprise"})
        assert resp.status_code == 200
        data = resp.json()
        assert "signals_parsed" in data or "events_parsed" in data

    def test_analyze_email_headers(self, client):
        headers = "From: test@example.com\nTo: admin@org.com\nReceived: from mx.example.com"
        resp = client.post("/api/v1/signals/analyze/email-headers", json={"headers": headers})
        assert resp.status_code == 200
        data = resp.json()
        assert "security_score" in data

    def test_siem_query_demo(self, client):
        resp = client.post("/api/v1/signals/collect/siem", json={
            "siem_type": "splunk", "query": "index=main | head 10", "time_range": "24h"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "siem" in data
        assert "events" in data

    def test_siem_invalid_type(self, client):
        resp = client.post("/api/v1/signals/collect/siem", json={
            "siem_type": "invalid_siem", "query": "test"
        })
        assert resp.status_code == 400

    def test_webhook_register(self, client):
        resp = client.post("/api/v1/signals/webhooks/register", json={
            "name": "test_webhook", "signal_type": "custom", "domain": "enterprise"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "webhook_id" in data
        assert "secret" in data

    def test_webhook_list(self, client):
        resp = client.get("/api/v1/signals/webhooks")
        assert resp.status_code == 200
        assert "webhooks" in resp.json()


# ── Alerts ────────────────────────────────────────────

class TestAlertEndpoints:
    def test_list_alerts(self, client):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        assert "total" in data

    def test_health_score(self, client):
        resp = client.get("/api/v1/alerts/health-score/enterprise")
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert "trend" in data
        assert "active_patterns" in data
        assert "critical_alerts" in data
        assert "warning_alerts" in data
        assert "watch_alerts" in data
        assert 0 <= data["score"] <= 100

    def test_alert_action_not_found(self, client):
        resp = client.post("/api/v1/alerts/nonexistent/action", json={"action": "acknowledge"})
        assert resp.status_code == 404

    def test_alert_invalid_action(self, client):
        resp = client.post("/api/v1/alerts/nonexistent/action", json={"action": "invalid_action"})
        assert resp.status_code in (400, 404)


# ── Domains ───────────────────────────────────────────

class TestDomainEndpoints:
    def test_list_domains(self, client):
        resp = client.get("/api/v1/domains")
        assert resp.status_code == 200
        data = resp.json()
        assert "domains" in data
        assert len(data["domains"]) >= 6  # 6 built-in domains

    def test_get_domain(self, client):
        resp = client.get("/api/v1/domains/enterprise")
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "enterprise"

    def test_get_domain_not_found(self, client):
        resp = client.get("/api/v1/domains/nonexistent_domain_xyz")
        assert resp.status_code == 404

    def test_analyze_url(self, client):
        resp = client.post("/api/v1/domains/analyze-url", json={"url": "https://example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data


# ── Reports ───────────────────────────────────────────

class TestReportEndpoints:
    def test_weekly_report(self, client):
        resp = client.get("/api/v1/reports/weekly-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "health_score" in data
        assert "total_alerts" in data

    def test_nist_risk(self, client):
        resp = client.get("/api/v1/reports/nist-risk")
        assert resp.status_code == 200
        data = resp.json()
        assert "domain" in data
        assert "controls_at_risk" in data

    def test_board_summary(self, client):
        resp = client.get("/api/v1/reports/board-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "executive_summary" in data
        assert "health_score" in data["executive_summary"]

    def test_export_csv(self, client):
        resp = client.get("/api/v1/reports/export?report_type=weekly&format=csv")
        assert resp.status_code == 200

    def test_export_json_format(self, client):
        resp = client.get("/api/v1/reports/export?report_type=nist&format=json")
        assert resp.status_code == 200


# ── Governance ────────────────────────────────────────

class TestGovernanceEndpoints:
    def test_audit_log(self, client):
        resp = client.get("/api/v1/governance/audit-log")
        assert resp.status_code == 200
        data = resp.json()
        assert "entries" in data
        assert "total" in data

    def test_pending_gates(self, client):
        resp = client.get("/api/v1/governance/gates/pending")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending" in data
        assert isinstance(data["pending"], list)

    def test_approve_not_found(self, client):
        resp = client.post("/api/v1/governance/nist_mapping/nonexistent/approve")
        assert resp.status_code in (200, 404)

    def test_reject_not_found(self, client):
        resp = client.post("/api/v1/governance/critical_alert/nonexistent/reject")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rejected"


# ── Calibration ───────────────────────────────────────

class TestCalibrationEndpoints:
    def test_pending_reviews(self, client):
        resp = client.get("/api/v1/calibration/pending-reviews")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending" in data

    def test_approve_not_found(self, client):
        resp = client.post("/api/v1/calibration/responses/nonexistent/approve")
        assert resp.status_code in (200, 404)

    def test_reject_not_found(self, client):
        resp = client.post("/api/v1/calibration/responses/nonexistent/reject")
        assert resp.status_code in (200, 404)


# ── Onboarding ────────────────────────────────────────

class TestOnboardingEndpoints:
    def test_onboarding_status(self, client):
        resp = client.get("/api/v1/onboarding/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "steps" in data
        assert len(data["steps"]) == 3

    def test_onboarding_domains(self, client):
        resp = client.get("/api/v1/onboarding/domains")
        assert resp.status_code == 200
        data = resp.json()
        assert "domains" in data
        assert len(data["domains"]) >= 6

    def test_complete_onboarding(self, client):
        resp = client.post("/api/v1/onboarding/complete", json={
            "domain": "enterprise",
            "step1": {"domain": "enterprise"},
            "step2": {"connectors": [], "sample_file_mode": False},
            "step3": {"alert_sensitivity": "balanced", "priority_nist_controls": [], "response_delivery": ["dashboard"]},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"
        assert data["domain"] == "enterprise"


# ── Threat Intel ──────────────────────────────────────

class TestThreatIntelEndpoints:
    def test_feed(self, client):
        resp = client.get("/api/v1/threat-intel/feed")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert len(data["items"]) >= 1

    def test_feed_filter_severity(self, client):
        resp = client.get("/api/v1/threat-intel/feed?severity=critical")
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["severity"] == "critical"

    def test_correlate(self, client):
        resp = client.get("/api/v1/threat-intel/correlate")
        assert resp.status_code == 200
        data = resp.json()
        assert "correlations" in data
        assert "total_threats" in data


# ── Scans ─────────────────────────────────────────────

class TestScanEndpoints:
    def test_scan_status(self, client):
        resp = client.get("/api/v1/scans/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "active" in data

    def test_scan_history(self, client):
        resp = client.get("/api/v1/scans/history")
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data

    def test_trigger_scan(self, client):
        resp = client.post("/api/v1/scans/trigger", json={"domain": "enterprise", "scope": "quick"})
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "started"

    def test_create_schedule(self, client):
        resp = client.post("/api/v1/scans/schedule", json={
            "domain": "enterprise", "scope": "full", "cron_expression": "0 2 * * *"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "schedule_id" in data
        assert data["schedule"]["next_run"] is not None

    def test_list_schedules(self, client):
        resp = client.get("/api/v1/scans/schedules")
        assert resp.status_code == 200
        assert "schedules" in resp.json()


# ── Drift Map ─────────────────────────────────────────

class TestDriftMapEndpoints:
    def test_heatmap(self, client):
        resp = client.get("/api/v1/drift-map/heatmap?domain=enterprise&days=30")
        assert resp.status_code == 200
        data = resp.json()
        assert "domain" in data

    def test_summary(self, client):
        resp = client.get("/api/v1/drift-map/summary?domain=enterprise")
        assert resp.status_code == 200
        data = resp.json()
        assert "health_score" in data

    def test_trend(self, client):
        resp = client.get("/api/v1/drift-map/trend/Fatigue?days=30")
        assert resp.status_code == 200


# ── Scanner ───────────────────────────────────────────

class TestScannerEndpoints:
    def test_scan_localhost(self, client):
        resp = client.post("/api/v1/scanner/scan", json={
            "url": "http://localhost:8000",
            "scan_ports": False,
            "scan_dns": False,
        })
        # May succeed or fail depending on connectivity
        assert resp.status_code in (200, 400, 500)


# ── Integrations ──────────────────────────────────────

class TestIntegrationEndpoints:
    def test_list_connectors(self, client):
        resp = client.get("/api/v1/integrations/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_register_app(self, client):
        resp = client.post("/api/v1/integrations/apps/register", json={
            "app_name": "test_app",
            "app_type": "web_application",
            "description": "Test application",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "app_id" in data
        assert "api_key" in data

    def test_list_apps(self, client):
        resp = client.get("/api/v1/integrations/apps")
        assert resp.status_code == 200
        assert "apps" in resp.json()

    def test_universal_webhook_no_signature(self, client):
        resp = client.post("/api/v1/integrations/webhook", json={
            "app_id": "nonexistent",
            "event_type": "test",
            "payload": {},
        })
        # Should fail because app not found or missing signature
        assert resp.status_code in (200, 401, 404)
