"""
Tests for ethical guardrails — the non-negotiable constraints.
These tests verify that ethical boundaries are enforced at system level.
"""

import pytest
from core.ethical_guardrails import (
    anonymize_signal,
    validate_alert_transparency,
    require_human_approval_for_critical,
    validate_data_retention,
    validate_calibration_response,
    EthicalGuardrailViolation,
    ETHICAL_BANNER,
)


class TestAnonymizeSignal:
    def test_hashes_email(self):
        data = {"email": "john@example.com", "count": 5}
        result = anonymize_signal(data)
        assert result["email"] != "john@example.com"
        assert isinstance(result["email"], str)
        assert result["count"] == 5

    def test_hashes_name_fields(self):
        data = {"user_name": "Alice Smith", "department": "SOC"}
        result = anonymize_signal(data)
        assert "Alice Smith" not in str(result["user_name"])
        assert result["department"] == "SOC"

    def test_nested_dict(self):
        data = {"outer": {"employee_id": "12345"}}
        result = anonymize_signal(data)
        assert result["outer"]["employee_id"] != "12345"

    def test_consistent_hashing(self):
        data1 = {"email": "test@test.com"}
        data2 = {"email": "test@test.com"}
        r1 = anonymize_signal(data1)
        r2 = anonymize_signal(data2)
        assert r1["email"] == r2["email"]

    def test_empty_dict(self):
        assert anonymize_signal({}) == {}


class TestAlertTransparency:
    def test_valid_alert_passes(self):
        # Should not raise
        validate_alert_transparency(
            confidence=0.85,
            explanation="Fatigue pattern detected from review cadence decline",
            signals_summary="15 audit_review signals over 14 days",
        )

    def test_missing_explanation_raises(self):
        with pytest.raises(EthicalGuardrailViolation):
            validate_alert_transparency(
                confidence=0.85,
                explanation="",
                signals_summary="15 signals",
            )

    def test_invalid_confidence_raises(self):
        with pytest.raises(EthicalGuardrailViolation):
            validate_alert_transparency(
                confidence=1.5,
                explanation="Valid explanation for the alert",
                signals_summary="15 signals",
            )


class TestCriticalHumanApproval:
    def test_critical_without_approval_raises(self):
        with pytest.raises(EthicalGuardrailViolation):
            require_human_approval_for_critical(
                alert_level="Critical",
                human_approved=False,
            )

    def test_critical_with_approval_passes(self):
        require_human_approval_for_critical(
            alert_level="Critical",
            human_approved=True,
        )

    def test_non_critical_doesnt_require_approval(self):
        require_human_approval_for_critical(
            alert_level="Watch",
            human_approved=False,
        )


class TestDataRetention:
    def test_within_limit_returns_days(self):
        assert validate_data_retention(180) == 180
        assert validate_data_retention(90) == 90
        assert validate_data_retention(1) == 1

    def test_over_limit_raises(self):
        with pytest.raises(EthicalGuardrailViolation):
            validate_data_retention(181)

    def test_zero_raises(self):
        with pytest.raises(EthicalGuardrailViolation):
            validate_data_retention(0)


class TestCalibrationResponse:
    def test_valid_response_passes(self):
        is_valid, reason = validate_calibration_response(
            "The review cadence has exceeded sustainable rhythm. Reduce volume and rotate assignments."
        )
        assert is_valid is True
        assert reason is None

    def test_empty_response_fails(self):
        is_valid, reason = validate_calibration_response("")
        assert is_valid is False
        assert reason is not None


class TestEthicalBanner:
    def test_banner_exists(self):
        assert ETHICAL_BANNER
        assert "individual" in ETHICAL_BANNER.lower() or "profiled" in ETHICAL_BANNER.lower()
