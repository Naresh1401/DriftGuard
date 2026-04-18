"""
Tests for ethical guardrails — the non-negotiable constraints.
These tests verify that ethical boundaries are enforced at system level.
"""

import pytest
from datetime import datetime, timezone
from core.ethical_guardrails import (
    anonymize_pii,
    validate_alert_transparency,
    enforce_critical_human_approval,
    validate_data_retention,
    validate_ni_response,
    ETHICAL_BANNER,
)
from models import Alert, AlertLevel, DriftPatternType, NISTControl


class TestAnonymizePII:
    def test_hashes_email(self):
        data = {"email": "john@example.com", "count": 5}
        result = anonymize_pii(data)
        assert result["email"] != "john@example.com"
        assert isinstance(result["email"], str)
        assert result["count"] == 5

    def test_hashes_name_fields(self):
        data = {"user_name": "Alice Smith", "department": "SOC"}
        result = anonymize_pii(data)
        assert result["user_name"] != "Alice Smith"
        assert result["department"] == "SOC"

    def test_nested_dict(self):
        data = {"outer": {"employee_id": "12345"}}
        result = anonymize_pii(data)
        assert result["outer"]["employee_id"] != "12345"

    def test_consistent_hashing(self):
        data1 = {"email": "test@test.com"}
        data2 = {"email": "test@test.com"}
        r1 = anonymize_pii(data1)
        r2 = anonymize_pii(data2)
        assert r1["email"] == r2["email"]

    def test_empty_dict(self):
        assert anonymize_pii({}) == {}


class TestAlertTransparency:
    def _make_alert(self, **kwargs) -> Alert:
        defaults = dict(
            alert_id="test-1",
            drift_pattern=DriftPatternType.FATIGUE,
            alert_level=AlertLevel.WATCH,
            severity=2,
            confidence=0.8,
            department="SOC",
            plain_language="Test explanation",
            nist_controls=[NISTControl.AU_6],
            recommended_action="Review cadence",
            timestamp=datetime.now(timezone.utc),
        )
        defaults.update(kwargs)
        return Alert(**defaults)

    def test_valid_alert_passes(self):
        alert = self._make_alert()
        assert validate_alert_transparency(alert) is True

    def test_missing_plain_language_fails(self):
        alert = self._make_alert(plain_language="")
        assert validate_alert_transparency(alert) is False

    def test_zero_confidence_fails(self):
        alert = self._make_alert(confidence=0.0)
        assert validate_alert_transparency(alert) is False


class TestCriticalHumanApproval:
    def test_critical_without_approval_raises(self):
        with pytest.raises(ValueError, match="[Cc]ritical"):
            enforce_critical_human_approval(
                alert_level=AlertLevel.CRITICAL,
                human_approved=False,
            )

    def test_critical_with_approval_passes(self):
        enforce_critical_human_approval(
            alert_level=AlertLevel.CRITICAL,
            human_approved=True,
        )

    def test_non_critical_doesnt_require_approval(self):
        enforce_critical_human_approval(
            alert_level=AlertLevel.WATCH,
            human_approved=False,
        )


class TestDataRetention:
    def test_within_limit_passes(self):
        assert validate_data_retention(180) is True
        assert validate_data_retention(90) is True
        assert validate_data_retention(1) is True

    def test_over_limit_fails(self):
        assert validate_data_retention(181) is False
        assert validate_data_retention(365) is False

    def test_zero_fails(self):
        assert validate_data_retention(0) is False


class TestNIResponseValidation:
    def test_valid_generic_response_passes(self):
        result = validate_ni_response(
            "The review cadence has exceeded sustainable rhythm. Reduce volume and rotate assignments."
        )
        assert result is True

    def test_individual_targeting_fails(self):
        result = validate_ni_response(
            "John Smith in the SOC team needs to improve his review performance."
        )
        assert result is False

    def test_empty_response_fails(self):
        result = validate_ni_response("")
        assert result is False


class TestEthicalBanner:
    def test_banner_exists(self):
        assert ETHICAL_BANNER
        assert "individual" in ETHICAL_BANNER.lower() or "profiled" in ETHICAL_BANNER.lower()
