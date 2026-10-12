"""
Tests for resolving and approving alerts in the early warning engine.
"""

from engine.early_warning import EarlyWarningEngine
from models import Alert, AlertLevel, AlertStatus


def _engine_with_alert(level: AlertLevel = AlertLevel.CRITICAL) -> tuple[EarlyWarningEngine, Alert]:
    engine = EarlyWarningEngine()
    alert = Alert(alert_level=level, drift_patterns=[], domain="enterprise")
    engine._active_alerts["enterprise"].append(alert)
    return engine, alert


class TestResolveAlert:
    def test_resolves_by_string_id(self):
        # The API passes the path parameter through as a string
        engine, alert = _engine_with_alert()
        resolved = engine.resolve_alert(str(alert.id), resolved_by="ciso@example.com")
        assert resolved is alert
        assert alert.status == AlertStatus.RESOLVED
        assert alert.resolved_at is not None
        assert alert.resolved_by == "ciso@example.com"

    def test_resolves_by_uuid(self):
        engine, alert = _engine_with_alert()
        assert engine.resolve_alert(alert.id, resolved_by="ciso@example.com") is alert

    def test_acted_upon(self):
        engine, alert = _engine_with_alert()
        engine.resolve_alert(str(alert.id), resolved_by="ciso@example.com", acted_upon=True)
        assert alert.status == AlertStatus.ACTED_UPON
        assert alert.acted_upon_at is not None

    def test_unknown_id(self):
        engine, _ = _engine_with_alert()
        assert engine.resolve_alert("not-an-alert", resolved_by="ciso@example.com") is None


class TestApproveCriticalAlert:
    def test_approves_by_string_id(self):
        engine, alert = _engine_with_alert(AlertLevel.CRITICAL)
        assert engine.approve_critical_alert(str(alert.id), approved_by="ciso@example.com") is alert
        assert alert.human_approved is True

    def test_non_critical_is_not_approved(self):
        engine, alert = _engine_with_alert(AlertLevel.WATCH)
        assert engine.approve_critical_alert(str(alert.id), approved_by="ciso@example.com") is alert
        assert alert.human_approved is False
