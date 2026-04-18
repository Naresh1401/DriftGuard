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
        expected = {"Fatigue", "Overconfidence", "Hurry", "Quiet_Fear", "Hoarding", "Compliance_Theater"}
        assert set(DRIFT_PATTERNS.keys()) == expected

    def test_each_pattern_has_required_fields(self):
        for name, pattern in DRIFT_PATTERNS.items():
            assert isinstance(pattern, DriftPatternDefinition), f"{name} is not DriftPatternDefinition"
            assert pattern.name == name
            assert len(pattern.signal_indicators) > 0, f"{name} has no signal indicators"
            assert len(pattern.failure_modes) > 0, f"{name} has no failure modes"
            assert len(pattern.nist_controls) > 0, f"{name} has no NIST controls"
            assert pattern.plain_language_summary, f"{name} has no plain language summary"

    def test_patterns_are_frozen(self):
        pattern = DRIFT_PATTERNS["Fatigue"]
        with pytest.raises((AttributeError, TypeError)):
            pattern.name = "Modified"

    def test_fatigue_pattern_specifics(self):
        fatigue = DRIFT_PATTERNS["Fatigue"]
        assert "AU-6" in fatigue.nist_controls or "CA-7" in fatigue.nist_controls

    def test_compliance_theater_pattern_specifics(self):
        ct = DRIFT_PATTERNS["Compliance_Theater"]
        assert "compliance" in ct.plain_language_summary.lower() or "audit" in ct.plain_language_summary.lower()


class TestNISTControls:
    def test_all_five_controls_defined(self):
        expected = {"AC-2", "AU-6", "IR-6", "CA-7", "AT-2"}
        assert set(NIST_CONTROLS.keys()) == expected

    def test_each_control_has_required_fields(self):
        for ctrl_id, ctrl in NIST_CONTROLS.items():
            assert isinstance(ctrl, NISTControlDefinition)
            assert ctrl.control_id == ctrl_id
            assert ctrl.title, f"{ctrl_id} has no title"
            assert len(ctrl.vulnerable_patterns) > 0, f"{ctrl_id} has no vulnerable patterns"

    def test_control_pattern_cross_reference(self):
        """Every pattern should map to at least one NIST control and vice versa."""
        all_pattern_controls = set()
        for pattern in DRIFT_PATTERNS.values():
            all_pattern_controls.update(pattern.nist_controls)

        for ctrl_id in NIST_CONTROLS:
            assert ctrl_id in all_pattern_controls, f"Control {ctrl_id} not referenced by any pattern"
