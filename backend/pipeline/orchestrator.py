"""
COMPONENT 1 — BEHAVIORAL SIGNAL PROCESSING PIPELINE
=====================================================
LangGraph multi-agent orchestrator.
Each agent handles one drift pattern type.
Pipeline: Ingest → Anonymize → Classify → Weight → Report
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from models import (
    AlertLevel,
    DriftClassification,
    DriftPatternType,
    DriftReport,
    ProcessedSignal,
    RawSignal,
    Severity,
)
from pipeline.agents import AgentState, DriftPatternAgent, create_all_agents
from pipeline.classifier import DriftClassifier
from pipeline.signal_ingestion import SignalIngestionEngine
from pipeline.temporal_weighting import TemporalWeightingEngine

logger = logging.getLogger(__name__)


class DriftGuardPipeline:
    """Main orchestration pipeline using LangGraph-style state graph.

    Pipeline sequence:
    1. Signal Ingestion (anonymize at ingestion)
    2. Temporal Weighting (exponential decay, acceleration detection)
    3. Parallel drift pattern agent analysis (6 agents)
    4. Classification aggregation
    5. Alert level determination
    6. Drift report generation
    """

    def __init__(
        self,
        domain_config: Optional[Dict] = None,
        confidence_threshold: float = 0.70,
    ):
        self._domain_config = domain_config or {}
        self._confidence_threshold = confidence_threshold

        # Core components
        self._ingestion = SignalIngestionEngine(domain_config)
        self._classifier = DriftClassifier(
            confidence_threshold=confidence_threshold,
        )
        self._temporal = TemporalWeightingEngine()
        self._agents = create_all_agents(self._classifier)

        # Build the state graph
        self._graph = self._build_graph()

    def _build_graph(self) -> "StateGraph":
        """Build the LangGraph-style state graph.

        Uses a simplified state graph pattern for environments
        where langgraph may not be installed.
        """
        try:
            return self._build_langgraph()
        except ImportError:
            logger.info("LangGraph not available, using built-in orchestration")
            return None

    def _build_langgraph(self):
        """Build actual LangGraph StateGraph."""
        from langgraph.graph import END, StateGraph

        graph = StateGraph(AgentState)

        # Add agent nodes
        for pattern_type, agent in self._agents.items():
            graph.add_node(agent.name, agent.analyze)

        # Add entry and aggregation nodes
        graph.add_node("ingest", self._ingest_node)
        graph.add_node("temporal_weight", self._temporal_weight_node)
        graph.add_node("aggregate", self._aggregate_node)

        # Set entry point
        graph.set_entry_point("ingest")

        # Ingest → temporal weighting
        graph.add_edge("ingest", "temporal_weight")

        # Temporal weighting → all agents (fan-out)
        for agent in self._agents.values():
            graph.add_edge("temporal_weight", agent.name)

        # All agents → aggregate (fan-in)
        for agent in self._agents.values():
            graph.add_edge(agent.name, "aggregate")

        # Aggregate → END
        graph.add_edge("aggregate", END)

        return graph.compile()

    async def process(
        self,
        signals: List[RawSignal],
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
        domain: str = "enterprise",
    ) -> DriftReport:
        """Process a batch of signals through the full pipeline."""
        # Step 1: Ingest and anonymize
        processed = self._ingestion.ingest_batch(signals)
        logger.info(f"Ingested {len(processed)} signals (anonymized)")

        # Step 2: Build initial state
        state = AgentState(
            signals=processed,
            team_id=team_id,
            system_id=system_id,
            domain=domain,
        )

        # Step 3: Run through graph or built-in orchestration
        if self._graph is not None:
            final_state = await self._run_langgraph(state)
        else:
            final_state = self._run_builtin(state)

        # Step 4: Generate drift report
        return self._generate_report(final_state)

    async def _run_langgraph(self, state: AgentState) -> AgentState:
        """Run through LangGraph state graph."""
        result = await self._graph.ainvoke(state)
        return result

    def _run_builtin(self, state: AgentState) -> AgentState:
        """Built-in sequential orchestration fallback."""
        # Ingest node
        state = self._ingest_node(state)

        # Temporal weighting
        state = self._temporal_weight_node(state)

        # Run all agents
        for agent in self._agents.values():
            state = agent.analyze(state)

        # Aggregate
        state = self._aggregate_node(state)

        return state

    def _ingest_node(self, state: AgentState) -> AgentState:
        """No-op here since ingestion already happened in process()."""
        return state

    def _temporal_weight_node(self, state: AgentState) -> AgentState:
        """Compute temporal weights and acceleration."""
        # Record signals for each potential pattern
        for pattern_type in DriftPatternType:
            self._temporal.record_signals(state.signals, pattern_type)

        state.temporal_weights = self._temporal.compute_weights(
            state.team_id, state.system_id
        )
        state.acceleration_data = self._temporal.detect_acceleration(
            state.team_id, state.system_id
        )
        return state

    def _aggregate_node(self, state: AgentState) -> AgentState:
        """Aggregate classifications from all agents.

        Remove duplicates, sort by confidence.
        """
        seen = set()
        unique: List[DriftClassification] = []
        for cls in state.classifications:
            if cls.pattern not in seen:
                seen.add(cls.pattern)
                unique.append(cls)
        state.classifications = sorted(unique, key=lambda c: c.confidence, reverse=True)
        return state

    def _generate_report(self, state: AgentState) -> DriftReport:
        """Generate the structured JSON drift report."""
        active = [c for c in state.classifications if c.confidence >= 0.15]
        alert_level = self._determine_alert_level(active)
        routing = self._determine_routing(alert_level, active)

        # Check acceleration
        any_acceleration = any(
            data[0] for data in state.acceleration_data.values()
            if isinstance(data, tuple)
        )
        accel_details = None
        if any_acceleration:
            accel_parts = [
                data[2] for data in state.acceleration_data.values()
                if isinstance(data, tuple) and data[0]
            ]
            accel_details = " | ".join(accel_parts)

        return DriftReport(
            id=uuid4(),
            timestamp=datetime.utcnow(),
            domain=state.domain,
            team_id=state.team_id,
            system_id=state.system_id,
            active_patterns=active,
            alert_level=alert_level,
            acceleration_detected=any_acceleration,
            acceleration_details=accel_details,
            routing_decision=routing,
        )

    def _determine_alert_level(
        self, classifications: List[DriftClassification]
    ) -> AlertLevel:
        """Determine alert level per early warning engine rules.

        Single pattern: Watch
        Two co-occurring: Warning
        Three+ or severity ≥ 4: Critical
        """
        if not classifications:
            return AlertLevel.WATCH

        active_count = len(classifications)
        max_severity = max((c.severity.value for c in classifications), default=1)

        # Critical: 3+ patterns or any single at severity 4+
        if active_count >= 3 or max_severity >= 4:
            return AlertLevel.CRITICAL

        # Warning: 2 patterns co-occurring OR any at severity 3
        if active_count >= 2 or max_severity >= 3:
            return AlertLevel.WARNING

        return AlertLevel.WATCH

    def _determine_routing(
        self,
        alert_level: AlertLevel,
        classifications: List[DriftClassification],
    ) -> str:
        """Determine routing decision based on alert level."""
        any_needs_review = any(c.requires_human_review for c in classifications)

        if alert_level == AlertLevel.CRITICAL:
            return "governance_review_required"
        elif alert_level == AlertLevel.WARNING:
            return "notify_compliance_officer"
        elif any_needs_review:
            return "human_review_queue"
        return "log_and_monitor"

    def get_temporal_engine(self) -> TemporalWeightingEngine:
        return self._temporal

    def get_classifier(self) -> DriftClassifier:
        return self._classifier
