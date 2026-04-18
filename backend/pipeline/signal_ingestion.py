"""Signal ingestion — entry point for all organizational signals.

Accepts any signal type through domain configuration.
Enforces anonymization at ingestion (ethical guardrail).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from core.ethical_guardrails import anonymize_signal
from models import ProcessedSignal, RawSignal, SignalType


class SignalIngestionEngine:
    """Ingest, anonymize, and normalize organizational signals."""

    def __init__(self, domain_config: Optional[Dict] = None):
        self._domain_config = domain_config or {}
        self._signal_buffer: List[ProcessedSignal] = []

    def ingest(self, raw: RawSignal) -> ProcessedSignal:
        """Process a single raw signal.

        1. Anonymize PII at ingestion (hard guardrail)
        2. Extract features for classification
        3. Return ProcessedSignal ready for the pipeline
        """
        # ETHICAL GUARDRAIL: anonymize before anything else
        clean_data = anonymize_signal(raw.data)

        features = self._extract_features(raw.signal_type, clean_data)
        team_id = clean_data.get("team_id") or clean_data.get("department")
        system_id = clean_data.get("system_id") or clean_data.get("system")

        processed = ProcessedSignal(
            id=uuid4(),
            raw_signal_id=raw.id,
            signal_type=raw.signal_type,
            timestamp=raw.timestamp,
            features=features,
            team_id=str(team_id) if team_id else None,
            system_id=str(system_id) if system_id else None,
            anonymized=True,
        )
        self._signal_buffer.append(processed)
        return processed

    def ingest_batch(self, signals: List[RawSignal]) -> List[ProcessedSignal]:
        return [self.ingest(s) for s in signals]

    def flush_buffer(self) -> List[ProcessedSignal]:
        buffered = self._signal_buffer[:]
        self._signal_buffer.clear()
        return buffered

    def _extract_features(
        self, signal_type: SignalType, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract classification-relevant features from signal data."""
        extractors = {
            SignalType.ACCESS_LOG: self._features_access_log,
            SignalType.AUDIT_REVIEW: self._features_audit_review,
            SignalType.INCIDENT_RESPONSE: self._features_incident_response,
            SignalType.COMMUNICATION: self._features_communication,
            SignalType.APPROVAL_WORKFLOW: self._features_approval_workflow,
            SignalType.TRAINING_COMPLETION: self._features_training,
            SignalType.CUSTOM: self._features_custom,
        }
        extractor = extractors.get(signal_type, self._features_custom)
        return extractor(data)

    # ── Feature extractors per signal type ───────────

    def _features_access_log(self, data: Dict) -> Dict:
        return {
            "access_frequency": data.get("access_count", 0),
            "unique_resources": data.get("unique_resources", 0),
            "after_hours_access": data.get("after_hours", False),
            "approval_chain_length": data.get("approval_chain_length", 1),
            "access_type": data.get("access_type", "read"),
            "role_match": data.get("role_match", True),
            "time_since_last_review": data.get("days_since_review", 0),
        }

    def _features_audit_review(self, data: Dict) -> Dict:
        return {
            "review_duration_seconds": data.get("review_duration", 0),
            "outcome_variance": data.get("outcome_variance", 0.0),
            "rubber_stamp_score": data.get("rubber_stamp_score", 0.0),
            "items_reviewed": data.get("items_reviewed", 0),
            "findings_ratio": data.get("findings_ratio", 0.0),
            "reviewer_count": data.get("reviewer_count", 1),
        }

    def _features_incident_response(self, data: Dict) -> Dict:
        return {
            "detection_to_action_hours": data.get("detection_to_action_hours", 0),
            "escalation_count": data.get("escalation_count", 0),
            "silence_duration_hours": data.get("silence_hours", 0),
            "severity_reported": data.get("severity", 0),
            "narrative_depth": data.get("narrative_word_count", 0),
            "follow_up_count": data.get("follow_up_count", 0),
        }

    def _features_communication(self, data: Dict) -> Dict:
        return {
            "escalation_chain_used": data.get("escalation_used", False),
            "reporting_frequency": data.get("report_count", 0),
            "informal_mentions": data.get("informal_mentions", 0),
            "formal_log_count": data.get("formal_logs", 0),
            "silence_periods_count": data.get("silence_periods", 0),
            "avg_response_time_hours": data.get("avg_response_hours", 0),
        }

    def _features_approval_workflow(self, data: Dict) -> Dict:
        return {
            "exception_requests": data.get("exception_count", 0),
            "bypass_events": data.get("bypass_count", 0),
            "single_approver": data.get("single_approver", False),
            "approval_window_hours": data.get("approval_window_hours", 24),
            "high_risk_action": data.get("high_risk", False),
            "compressed_window": data.get("approval_window_hours", 24) < 4,
        }

    def _features_training(self, data: Dict) -> Dict:
        return {
            "completion_rate": data.get("completion_rate", 0.0),
            "repeat_failures": data.get("repeat_failures", 0),
            "time_to_complete_hours": data.get("time_to_complete", 0),
            "behavioral_change_score": data.get("behavioral_change", 0.0),
            "days_overdue": data.get("days_overdue", 0),
            "avoidance_signals": data.get("avoidance_count", 0),
        }

    def _features_custom(self, data: Dict) -> Dict:
        # Pass through custom domain signal features
        return {k: v for k, v in data.items() if k not in {"team_id", "system_id", "department", "system"}}
