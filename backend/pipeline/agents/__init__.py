"""Drift pattern detection agents — one per pattern type.

Each agent is responsible for one drift pattern.
Agents are orchestrated by LangGraph.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.drift_patterns import DRIFT_PATTERNS, DriftPatternDefinition
from models import (
    DriftClassification,
    DriftPatternType,
    ProcessedSignal,
    Severity,
)
from pipeline.classifier import DriftClassifier


@dataclass
class AgentState:
    """Shared state passed between agents in the LangGraph pipeline."""
    signals: List[ProcessedSignal] = field(default_factory=list)
    temporal_weights: Dict[str, float] = field(default_factory=dict)
    acceleration_data: Dict[str, Any] = field(default_factory=dict)
    classifications: List[DriftClassification] = field(default_factory=list)
    team_id: Optional[str] = None
    system_id: Optional[str] = None
    domain: str = "enterprise"
    errors: List[str] = field(default_factory=list)


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

    def analyze(self, state: AgentState) -> AgentState:
        """Analyze signals for this drift pattern.

        This is the function called by LangGraph for each agent node.
        """
        relevant_signals = self._filter_relevant_signals(state.signals)

        if not relevant_signals:
            return state

        classifications = self._classifier.classify(
            signals=relevant_signals,
            temporal_weights=state.temporal_weights,
        )

        # Keep only the classification for our pattern type
        for cls in classifications:
            if cls.pattern == self.pattern_type:
                # Enrich with acceleration data
                accel = state.acceleration_data.get(self.pattern_type.value, (False, 0.0, ""))
                if accel and accel[0]:
                    cls.reasoning += f" | ACCELERATION: {accel[2]}"
                state.classifications.append(cls)
                break

        return state

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
