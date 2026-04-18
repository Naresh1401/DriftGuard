"""
Tests for drift pattern definitions and NIST control mappings.
Verifies immutability and completeness of pattern definitions.
"""

import pytest
from core.drift_patterns import DRIFT_PATTERNS, DriftPatternDefinition
from core.nist_mapping import NIST_CONTROLS, NISTControlDefinition
from models import DriftPatternType, NISTControl


class TestDriftPatterns:
    def test_all_six_patterns_defined(self):
        expected = {
            DriftPatternType.FATIGUE, DriftPatternType.OVERCONFIDENCE,
            DriftPatternType.HURRY, DriftPatternType.QUIET_FEAR,
            DriftPatternType.HOARDING, DriftPatternType.COMPLIANCE_THEATER,
        }
        assert set(DRIFT_PATTERNS.keys()) == expected

    def test_each_pattern_has_required_fields(self):
        for key, pattern in DRIFT_PATTERNS.items():
            assert isinstance(pattern, DriftPatternDefinition), f"{key} is not DriftPatternDefinition"
            assert pattern.pattern_type == key
            assert len(pattern.signal_indicators) > 0, f"{key} has no signal indicators"
            assert len(pattern.cybersecurity_failure_modes) > 0, f"{key} has no failure modes"
            assert len(pattern.nist_controls_at_risk) > 0, f"{key} has no NIST controls"
            assert pattern.plain_language_summary, f"{key} has no plain language summary"

    def test_patterns_are_frozen(self):
        pattern = DRIFT_PATTERNS[DriftPatternType.FATIGUE]
        with pytest.raises((AttributeError, TypeError)):
            pattern.pattern_type = DriftPatternType.HURRY

    def test_fatigue_pattern_specifics(self):
        fatigue = DRIFT_PATTERNS[DriftPatternType.FATIGUE]
        assert NISTControl.AU_6 in fatigue.nist_controls_at_risk or NISTControl.CA_7 in fatigue.nist_controls_at_risk

    def test_compliance_theater_pattern_specifics(self):
        ct = DRIFT_PATTERNS[DriftPatternType.COMPLIANCE_THEATER]
        summary_lower = ct.plain_language_summary.lower()
        assert "complian" in summary_lower or "audit" in summary_lower or "security posture" in summary_lower


class TestNISTControls:
    def test_all_five_controls_defined(self):
        expected = {NISTControl.AC_2, NISTControl.AU_6, NISTControl.IR_6, NISTControl.CA_7, NISTControl.AT_2}
        assert set(NIST_CONTROLS.keys()) == expected

    def test_each_control_has_required_fields(self):
        for ctrl_key, ctrl in NIST_CONTROLS.items():
            assert isinstance(ctrl, NISTControlDefinition)
            assert ctrl.control_id == ctrl_key
            assert ctrl.title, f"{ctrl_key} has no title"
            assert len(ctrl.vulnerable_to) > 0, f"{ctrl_key} has no vulnerable patterns"

    def test_control_pattern_cross_reference(self):
        """Every pattern should map to at least one NIST control and vice versa."""
        all_pattern_controls: set = set()
        for pattern in DRIFT_PATTERNS.values():
            all_pattern_controls.update(pattern.nist_controls_at_risk)

        for ctrl_key in NIST_CONTROLS:
            assert ctrl_key in all_pattern_controls, f"Control {ctrl_key} not referenced by any pattern"
