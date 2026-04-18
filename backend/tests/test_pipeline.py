"""
Tests for the signal ingestion pipeline and classifier.
"""

import pytest
from datetime import datetime, timezone
from pipeline.signal_ingestion import SignalIngestionEngine
from pipeline.classifier import DriftClassifier
from models import RawSignal, SignalType


class TestSignalIngestion:
    def setup_method(self):
        self.engine = SignalIngestionEngine()

    def test_ingest_valid_signal(self):
        signal = RawSignal(
            signal_type=SignalType.ACCESS_LOG,
            source="test",
            timestamp=datetime.now(timezone.utc),
            data={"action": "login", "result": "success"},
            domain="enterprise",
        )
        processed = self.engine.ingest(signal)
        assert processed is not None
        assert processed.raw_signal_id == signal.id

    def test_pii_anonymized_at_ingestion(self):
        signal = RawSignal(
            signal_type=SignalType.ACCESS_LOG,
            source="test",
            timestamp=datetime.now(timezone.utc),
            data={
                "user_email": "john@example.com",
                "employee_name": "John Doe",
                "action": "login",
            },
            domain="enterprise",
        )
        processed = self.engine.ingest(signal)
        assert processed.anonymized is True
        # PII fields should be hashed/redacted in features
        assert "john@example.com" not in str(processed.features)

    def test_ingest_multiple_signal_types(self):
        types = [
            SignalType.ACCESS_LOG, SignalType.AUDIT_REVIEW,
            SignalType.INCIDENT_RESPONSE, SignalType.COMMUNICATION,
            SignalType.APPROVAL_WORKFLOW, SignalType.TRAINING_COMPLETION,
            SignalType.CUSTOM,
        ]
        for st in types:
            signal = RawSignal(
                signal_type=st,
                source="test",
                timestamp=datetime.now(timezone.utc),
                data={"type": st.value},
                domain="enterprise",
            )
            processed = self.engine.ingest(signal)
            assert processed is not None, f"Failed to ingest {st}"


class TestDriftClassifier:
    def setup_method(self):
        self.classifier = DriftClassifier()

    def test_classifier_initialization(self):
        assert self.classifier is not None
        assert self.classifier._confidence_threshold == 0.70

    def test_classify_empty_signals(self):
        result = self.classifier.classify([])
        assert result == []

    def test_classify_returns_drift_classifications(self):
        """Classify a batch of signals and verify output structure."""
        from models import ProcessedSignal
        from uuid import uuid4

        signals = [
            ProcessedSignal(
                raw_signal_id=uuid4(),
                signal_type=SignalType.AUDIT_REVIEW,
                timestamp=datetime.now(timezone.utc),
                features={
                    "review_depth": 0.2,
                    "completion_rate": 0.95,
                    "variance": 0.05,
                },
            )
        ]
        results = self.classifier.classify(signals)
        # Should return a list of DriftClassification objects
        assert isinstance(results, list)
        for r in results:
            assert hasattr(r, "pattern")
            assert hasattr(r, "confidence")
            assert 0.0 <= r.confidence <= 1.0
            if r.confidence < 0.70:
                assert r.requires_human_review is True
