"""Transformer-based NLI classifier for drift pattern detection.

Uses cross-encoder NLI (DeBERTa-v3) to classify signals against
drift pattern hypotheses. The attention mechanism weights signals
differently across time — this is architecturally intentional.

Confidence scoring is built into every output.
Any signal with confidence < 0.70 routes to human review queue.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import numpy as np

from core.drift_patterns import DRIFT_PATTERNS, DriftPatternDefinition
from models import DriftClassification, DriftPatternType, NISTControl, ProcessedSignal, Severity


class DriftClassifier:
    """NLI-based drift pattern classifier with temporal weighting."""

    def __init__(
        self,
        model_name: str = "cross-encoder/nli-deberta-v3-base",
        confidence_threshold: float = 0.70,
    ):
        self._model_name = model_name
        self._confidence_threshold = confidence_threshold
        self._model = None
        self._hypothesis_templates = self._build_hypotheses()

    def _build_hypotheses(self) -> Dict[DriftPatternType, List[str]]:
        """Build NLI hypothesis templates from framework-team definitions."""
        templates: Dict[DriftPatternType, List[str]] = {}
        for pattern_type, defn in DRIFT_PATTERNS.items():
            templates[pattern_type] = [
                f"This signal indicates {indicator.lower()}."
                for indicator in defn.signal_indicators
            ]
        return templates

    def load_model(self) -> None:
        """Lazy-load the transformer model."""
        if self._model is not None:
            return
        try:
            from sentence_transformers import CrossEncoder
            self._model = CrossEncoder(self._model_name)
        except ImportError:
            # Fallback to rule-based classification if transformers unavailable
            self._model = None

    def classify(
        self,
        signals: List[ProcessedSignal],
        temporal_weights: Optional[Dict[str, float]] = None,
    ) -> List[DriftClassification]:
        """Classify a batch of signals against all six drift patterns.

        Returns a DriftClassification for each pattern that exceeds
        the minimum detection threshold.
        """
        if not signals:
            return []

        # Build feature summary from signals
        feature_summary = self._aggregate_features(signals)

        classifications: List[DriftClassification] = []
        for pattern_type, hypotheses in self._hypothesis_templates.items():
            confidence, reasoning = self._score_pattern(
                feature_summary, pattern_type, hypotheses, signals
            )

            if confidence < 0.15:
                continue  # Below noise floor

            t_weight = temporal_weights.get(pattern_type.value, 1.0) if temporal_weights else 1.0
            defn = DRIFT_PATTERNS[pattern_type]

            severity = self._compute_severity_from_features(
                feature_summary, pattern_type, confidence, t_weight
            )

            classification = DriftClassification(
                pattern=pattern_type,
                confidence=round(confidence, 4),
                severity=severity,
                signals_used=[s.id for s in signals],
                nist_controls_at_risk=list(defn.nist_controls_at_risk),
                temporal_weight=round(t_weight, 4),
                reasoning=reasoning,
                requires_human_review=confidence < self._confidence_threshold,
            )
            classifications.append(classification)

        return sorted(classifications, key=lambda c: c.confidence, reverse=True)

    def _score_pattern(
        self,
        features: Dict,
        pattern_type: DriftPatternType,
        hypotheses: List[str],
        signals: List[ProcessedSignal],
    ) -> Tuple[float, str]:
        """Score how well the aggregated features match a drift pattern.

        Uses NLI model if available, falls back to rule-based scoring.
        """
        if self._model is not None:
            return self._score_with_nli(features, hypotheses)
        return self._score_rule_based(features, pattern_type, signals)

    def _score_with_nli(
        self, features: Dict, hypotheses: List[str]
    ) -> Tuple[float, str]:
        """Score using cross-encoder NLI model."""
        premise = self._features_to_premise(features)
        pairs = [(premise, h) for h in hypotheses]
        scores = self._model.predict(pairs)

        # NLI models output [contradiction, neutral, entailment]
        if isinstance(scores[0], np.ndarray):
            # Multi-class output
            entailment_scores = [s[2] if len(s) > 2 else s[0] for s in scores]
        else:
            entailment_scores = list(scores)

        avg_score = float(np.mean(entailment_scores))
        max_idx = int(np.argmax(entailment_scores))
        top_hypothesis = hypotheses[max_idx]
        confidence = min(max(avg_score, 0.0), 1.0)

        reasoning = (
            f"NLI classification detected pattern alignment "
            f"(strongest signal: '{top_hypothesis}', "
            f"score: {entailment_scores[max_idx]:.3f})"
        )
        return confidence, reasoning

    def _score_rule_based(
        self,
        features: Dict,
        pattern_type: DriftPatternType,
        signals: List[ProcessedSignal],
    ) -> Tuple[float, str]:
        """Rule-based fallback scoring when NLI model is unavailable."""
        scorers = {
            DriftPatternType.FATIGUE: self._rule_fatigue,
            DriftPatternType.OVERCONFIDENCE: self._rule_overconfidence,
            DriftPatternType.HURRY: self._rule_hurry,
            DriftPatternType.QUIET_FEAR: self._rule_quiet_fear,
            DriftPatternType.HOARDING: self._rule_hoarding,
            DriftPatternType.COMPLIANCE_THEATER: self._rule_compliance_theater,
        }
        scorer = scorers.get(pattern_type, lambda f, s: (0.0, "No rule defined"))
        return scorer(features, signals)

    # ── Rule-based scorers ───────────────────────────

    def _rule_fatigue(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if f.get("rubber_stamp_score", 0) > 0.5:
            score += 0.3
            reasons.append("high rubber-stamp score in reviews")
        if f.get("outcome_variance", 1.0) < 0.1:
            score += 0.25
            reasons.append("near-zero variance in review outcomes")
        if f.get("review_duration_seconds", 300) < 30:
            score += 0.25
            reasons.append("extremely short review durations")
        if f.get("access_frequency", 0) > 50:
            score += 0.2
            reasons.append("high-volume access patterns")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    def _rule_overconfidence(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if f.get("bypass_events", 0) > 0:
            score += 0.35
            reasons.append(f"{f['bypass_events']} protocol bypass events")
        if f.get("exception_requests", 0) > 2:
            score += 0.25
            reasons.append(f"{f['exception_requests']} exception requests")
        if f.get("single_approver", False):
            score += 0.2
            reasons.append("single-approver decisions on high-risk actions")
        if f.get("informal_mentions", 0) > f.get("formal_log_count", 1):
            score += 0.2
            reasons.append("informal communications exceeding formal logs")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    def _rule_hurry(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if f.get("compressed_window", False):
            score += 0.35
            reasons.append("compressed approval windows detected")
        if f.get("approval_window_hours", 24) < 2:
            score += 0.25
            reasons.append(f"approval window only {f.get('approval_window_hours')}h")
        if f.get("narrative_depth", 100) < 20:
            score += 0.2
            reasons.append("minimal narrative in reports (rushed documentation)")
        if f.get("follow_up_count", 1) == 0:
            score += 0.2
            reasons.append("zero follow-ups after actions")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    def _rule_quiet_fear(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if f.get("silence_duration_hours", 0) > 48:
            score += 0.3
            reasons.append(f"{f['silence_duration_hours']}h silence in incident logs")
        if f.get("silence_periods_count", 0) > 2:
            score += 0.25
            reasons.append(f"{f['silence_periods_count']} unusual silence periods")
        if f.get("informal_mentions", 0) > 0 and f.get("formal_log_count", 0) == 0:
            score += 0.3
            reasons.append("informal concerns raised but never formally logged")
        if f.get("escalation_count", 0) == 0 and f.get("severity_reported", 0) > 2:
            score += 0.15
            reasons.append("significant severity with zero escalations")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    def _rule_hoarding(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if not f.get("role_match", True):
            score += 0.35
            reasons.append("access retained beyond role requirements")
        if f.get("time_since_last_review", 0) > 90:
            score += 0.25
            reasons.append(f"permissions not reviewed in {f['time_since_last_review']} days")
        if f.get("avg_response_time_hours", 0) > 72:
            score += 0.2
            reasons.append("slow response to audit requests (resistance signal)")
        if f.get("unique_resources", 0) > 20:
            score += 0.2
            reasons.append(f"access to {f['unique_resources']} unique resources")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    def _rule_compliance_theater(self, f: Dict, signals: List) -> Tuple[float, str]:
        score = 0.0
        reasons = []
        if f.get("completion_rate", 0) > 0.95 and f.get("behavioral_change_score", 1) < 0.2:
            score += 0.4
            reasons.append("near-perfect completion with no behavioral change")
        if f.get("findings_ratio", 0.5) < 0.05:
            score += 0.3
            reasons.append("audit findings ratio suspiciously low")
        if f.get("narrative_depth", 100) < 15:
            score += 0.15
            reasons.append("minimal narrative depth in incident reports")
        if f.get("outcome_variance", 0.5) < 0.05:
            score += 0.15
            reasons.append("zero variance in review outcomes (rubber-stamping)")
        return min(score, 1.0), "; ".join(reasons) if reasons else "Insufficient signals"

    # ── Helpers ──────────────────────────────────────

    def _aggregate_features(self, signals: List[ProcessedSignal]) -> Dict:
        """Merge features from multiple signals into a single feature dict."""
        merged: Dict = {}
        for signal in signals:
            for key, value in signal.features.items():
                if key not in merged:
                    merged[key] = value
                elif isinstance(value, (int, float)):
                    merged[key] = max(merged[key], value)
                elif isinstance(value, bool):
                    merged[key] = merged[key] or value
        return merged

    def _features_to_premise(self, features: Dict) -> str:
        """Convert feature dict to natural language premise for NLI."""
        parts = []
        for key, value in features.items():
            readable = key.replace("_", " ")
            if isinstance(value, bool):
                if value:
                    parts.append(f"{readable} was detected")
            elif isinstance(value, (int, float)):
                parts.append(f"{readable} is {value}")
            else:
                parts.append(f"{readable}: {value}")
        return ". ".join(parts) + "."

    def _compute_severity_from_features(
        self,
        features: Dict,
        pattern_type: DriftPatternType,
        confidence: float,
        temporal_weight: float,
    ) -> Severity:
        """Map features + confidence + temporal weight to severity 1-5."""
        signal_intensity = min(len(features) / 6.0, 1.0)

        raw = (
            0.30 * signal_intensity
            + 0.30 * confidence
            + 0.25 * min(temporal_weight / 5.0, 1.0)
            + 0.15 * (1.0 if pattern_type == DriftPatternType.COMPLIANCE_THEATER else 0.5)
        )

        if raw >= 0.80:
            return Severity.CRITICAL
        elif raw >= 0.60:
            return Severity.HIGH
        elif raw >= 0.40:
            return Severity.MODERATE
        elif raw >= 0.20:
            return Severity.LOW
        return Severity.MINIMAL
