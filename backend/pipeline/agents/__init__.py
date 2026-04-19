"""Drift pattern detection agents — one per pattern type.

Each agent is responsible for one drift pattern.
Agents are orchestrated by LangGraph.
"""
from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from core.drift_patterns import DRIFT_PATTERNS, DriftPatternDefinition
from models import (
    DriftClassification,
    DriftPatternType,
    ProcessedSignal,
    Severity,
)
from pipeline.classifier import DriftClassifier


def _merge_dicts(a: Dict, b: Dict) -> Dict:
    """Merge two dicts, keeping the latest non-empty value."""
    merged = {**a}
    for k, v in b.items():
        if v:  # only overwrite with non-empty values
            merged[k] = v
    return merged


def _keep_latest_str(a: str, b: str) -> str:
    return b if b else a


class AgentState(TypedDict, total=False):
    """Shared state passed between agents in the LangGraph pipeline.

    Uses TypedDict with Annotated reducers so LangGraph can properly
    handle concurrent writes from parallel agent fan-out.
    """
    signals: Annotated[List[ProcessedSignal], operator.add]
    temporal_weights: Annotated[Dict[str, float], _merge_dicts]
    acceleration_data: Annotated[Dict[str, Any], _merge_dicts]
    classifications: Annotated[List[DriftClassification], operator.add]
    team_id: Optional[str]
    system_id: Optional[str]
    domain: str
    errors: Annotated[List[str], operator.add]


class DriftPatternAgent:
    """Agent responsible for detecting a single drift pattern type."""

    def __init__(
        self,
        pattern_type: DriftPatternType,
        classifier: DriftClassifier,
    ):
        self.pattern_type = pattern_type
        self.definition: DriftPatternDefinition = DRIFT_PATTERNS[pattern_type]
        self._classifier = classifier

    @property
    def name(self) -> str:
        return f"{self.pattern_type.value}_agent"

    def analyze(self, state: AgentState) -> dict:
        """Analyze signals for this drift pattern.

        This is the function called by LangGraph for each agent node.
        Returns a partial state dict so LangGraph can merge via reducers.
        """
        signals = state.get("signals", [])
        temporal_weights = state.get("temporal_weights", {})
        acceleration_data = state.get("acceleration_data", {})

        relevant_signals = self._filter_relevant_signals(signals)

        if not relevant_signals:
            return {}  # no update

        classifications_out: List[DriftClassification] = []

        classifications = self._classifier.classify(
            signals=relevant_signals,
            temporal_weights=temporal_weights,
        )

        # Keep only the classification for our pattern type
        for cls in classifications:
            if cls.pattern == self.pattern_type:
                # Enrich with acceleration data
                accel = acceleration_data.get(self.pattern_type.value, (False, 0.0, ""))
                if accel and accel[0]:
                    cls.reasoning += f" | ACCELERATION: {accel[2]}"
                classifications_out.append(cls)
                break

        return {"classifications": classifications_out} if classifications_out else {}

    def _filter_relevant_signals(
        self, signals: List[ProcessedSignal]
    ) -> List[ProcessedSignal]:
        """Filter signals relevant to this drift pattern."""
        relevance_map = {
            DriftPatternType.FATIGUE: {"audit_review", "access_log"},
            DriftPatternType.OVERCONFIDENCE: {"approval_workflow", "access_log", "communication"},
            DriftPatternType.HURRY: {"approval_workflow", "incident_response", "audit_review"},
            DriftPatternType.QUIET_FEAR: {"incident_response", "communication"},
            DriftPatternType.HOARDING: {"access_log", "audit_review", "communication"},
            DriftPatternType.COMPLIANCE_THEATER: {"audit_review", "training_completion", "incident_response"},
        }
        relevant_types = relevance_map.get(self.pattern_type, set())

        filtered = [
            s for s in signals
            if s.signal_type.value in relevant_types or s.signal_type.value == "custom"
        ]
        return filtered if filtered else signals


# ── Specialized Agent Imports ────────────────────────

from pipeline.agents.fatigue import FatigueAgent
from pipeline.agents.overconfidence import OverconfidenceAgent
from pipeline.agents.hurry import HurryAgent
from pipeline.agents.quiet_fear import QuietFearAgent
from pipeline.agents.hoarding import HoardingAgent
from pipeline.agents.compliance_theater import ComplianceTheaterAgent

_AGENT_MAP: Dict[DriftPatternType, type] = {
    DriftPatternType.FATIGUE: FatigueAgent,
    DriftPatternType.OVERCONFIDENCE: OverconfidenceAgent,
    DriftPatternType.HURRY: HurryAgent,
    DriftPatternType.QUIET_FEAR: QuietFearAgent,
    DriftPatternType.HOARDING: HoardingAgent,
    DriftPatternType.COMPLIANCE_THEATER: ComplianceTheaterAgent,
}


# ── Agent Factory ────────────────────────────────────

def create_all_agents(classifier: DriftClassifier) -> Dict[DriftPatternType, DriftPatternAgent]:
    """Create one specialized agent per drift pattern type."""
    return {
        pattern_type: agent_cls(pattern_type, classifier)
        for pattern_type, agent_cls in _AGENT_MAP.items()
    }
