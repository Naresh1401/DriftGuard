"""
Tests for severity scoring and temporal weighting engine.
"""

import pytest
from datetime import datetime, timedelta, timezone
from core.severity import compute_temporal_weight, compute_severity, detect_acceleration
from pipeline.temporal_weighting import TemporalWeightingEngine
from models import Severity


class TestTemporalWeight:
    def test_recent_signals_high_weight(self):
        now = datetime.utcnow()
        timestamps = [now - timedelta(hours=i) for i in range(5)]
        weight = compute_temporal_weight(timestamps, lookback_days=14, half_life_days=3.0)
        assert weight > 3.0  # several recent signals should sum high

    def test_old_signals_low_weight(self):
        old = datetime.utcnow() - timedelta(days=60)
        timestamps = [old - timedelta(days=i) for i in range(5)]
        weight = compute_temporal_weight(timestamps, lookback_days=14)
        assert weight == 0.0  # all outside lookback

    def test_empty_timestamps(self):
        weight = compute_temporal_weight([], lookback_days=14)
        assert weight == 0.0


class TestComputeSeverity:
    def test_low_inputs_give_low_severity(self):
        sev = compute_severity(signal_count=1, temporal_weight=0.5, acceleration_ratio=0.5, confidence=0.3)
        assert sev in (Severity.MINIMAL, Severity.LOW)

    def test_high_inputs_give_high_severity(self):
        sev = compute_severity(signal_count=20, temporal_weight=8.0, acceleration_ratio=4.0, confidence=0.95)
        assert sev in (Severity.HIGH, Severity.CRITICAL)

    def test_returns_severity_enum(self):
        sev = compute_severity(signal_count=5, temporal_weight=2.0, acceleration_ratio=1.0, confidence=0.7)
        assert isinstance(sev, Severity)


class TestAccelerationDetection:
    def test_rising_trend(self):
        now = datetime.utcnow()
        # 5 in last 7 days, 1 in prior 7 days
        timestamps = [now - timedelta(days=i) for i in range(5)] + [now - timedelta(days=10)]
        is_accel, ratio = detect_acceleration(timestamps, window_days=7)
        assert is_accel is True
        assert ratio > 1.5

    def test_stable_trend(self):
        now = datetime.utcnow()
        # 3 in each window
        timestamps = (
            [now - timedelta(days=i) for i in range(3)] +
            [now - timedelta(days=7 + i) for i in range(3)]
        )
        is_accel, ratio = detect_acceleration(timestamps, window_days=7)
        assert is_accel is False

    def test_too_few_timestamps(self):
        is_accel, ratio = detect_acceleration([datetime.utcnow()])
        assert is_accel is False


class TestTemporalWeightingEngine:
    def test_engine_instantiation(self):
        engine = TemporalWeightingEngine()
        assert engine is not None
