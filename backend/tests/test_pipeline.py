"""
Tests for the signal ingestion pipeline and classifier.
"""

import pytest
from datetime import datetime, timezone
from pipeline.signal_ingestion import SignalIngestionEngine
from pipeline.classifier import DriftClassifier
from models import RawSignal


class TestSignalIngestion:
    def setup_method(self):
        self.engine = SignalIngestionEngine()

    def test_ingest_valid_signal(self):
        signal = RawSignal(
            signal_id="test-001",
            source="test",
            signal_type="access_log",
            timestamp=datetime.now(timezone.utc),
            department="SOC",
            raw_data={"action": "login", "result": "success"},
        )
        processed = self.engine.ingest(signal)
        assert processed is not None
        assert processed.signal_id == "test-001"

    def test_pii_anonymized_at_ingestion(self):
        signal = RawSignal(
            signal_id="test-002",
            source="test",
            signal_type="access_log",
            timestamp=datetime.now(timezone.utc),
            department="SOC",
            raw_data={
                "user_email": "john@example.com",
                "employee_name": "John Doe",
                "action": "login",
            },
        )
        processed = self.engine.ingest(signal)
        # PII fields should be hashed
        assert processed.anonymized_data.get("user_email") != "john@example.com"
        assert processed.anonymized_data.get("employee_name") != "John Doe"

    def test_ingest_multiple_signal_types(self):
        types = ["access_log", "audit_review", "incident_response",
                 "communication", "approval_workflow", "training_completion", "custom"]
        for st in types:
            signal = RawSignal(
                signal_id=f"test-{st}",
                source="test",
                signal_type=st,
                timestamp=datetime.now(timezone.utc),
                department="Test",
                raw_data={"type": st},
            )
            processed = self.engine.ingest(signal)
            assert processed is not None, f"Failed to ingest {st}"


class TestDriftClassifier:
    def setup_method(self):
        self.classifier = DriftClassifier()

    def test_classifier_initialization(self):
        assert self.classifier is not None

    def test_rule_based_fallback_fatigue(self):
        """Test that fatigue signals score on fatigue pattern."""
        features = {
            "signal_type": "audit_review",
            "frequency_deviation": 0.6,  # high deviation
            "time_pattern": "after_hours",
            "review_depth_indicator": 0.3,  # shallow reviews
        }
        scores = self.classifier.rule_based_score(features)
        assert "Fatigue" in scores
        assert scores["Fatigue"] > 0

    def test_rule_based_fallback_overconfidence(self):
        features = {
            "signal_type": "approval_workflow",
            "exception_rate": 0.25,
            "bypass_indicator": True,
        }
        scores = self.classifier.rule_based_score(features)
        assert "Overconfidence" in scores
        assert scores["Overconfidence"] > 0

    def test_confidence_threshold(self):
        """Below confidence threshold should flag for human review."""
        result = self.classifier.classify_with_confidence(
            {"signal_type": "custom", "ambiguous": True},
            min_confidence=0.70,
        )
        if result.confidence < 0.70:
            assert result.needs_human_review is True
