"""
AI BREACH DETECTOR — heuristic detector for the seven AI-era breach classes.
============================================================================

Inputs: a list of `AISignal` records (lightweight schema below).
Outputs: per-pattern detections with confidence in [0,1] and severity.

Design principles:
  - Deterministic and explainable. No black-box model in the detector itself
    (per `core/ethical_guardrails.py` — DriftGuard is the auditor of AI,
    not another opaque AI).
  - Each detector produces a confidence score AND a short reasoning string
    so every alert can be traced back to the signal that caused it.
  - Confidence below 0.70 forces `requires_human_review = True`,
    matching the human-drift framework convention in `models/__init__.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import UUID, uuid4

from core.ai_drift_patterns import (
    AIBreachPatternType,
    AI_BREACH_PATTERNS,
    get_ai_pattern,
)


# ── Lightweight signal schema (independent of the human pipeline) ──

@dataclass
class AISignal:
    """A single AI-related telemetry event."""
    id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    actor_type: str = "agent"          # 'agent' | 'human' | 'service'
    actor_id: str = ""
    model_id: Optional[str] = None
    model_version: Optional[str] = None
    action: str = ""                   # eg. 'tool_call:send_email', 'http_post'
    tool_name: Optional[str] = None
    destination: Optional[str] = None  # eg. 'api.openai.com', internal route
    prompt_size_tokens: Optional[int] = None
    output_size_tokens: Optional[int] = None
    contains_instruction_tokens: bool = False
    decision_latency_ms: Optional[int] = None
    approved_by_human: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIBreachDetection:
    """Detector output."""
    id: UUID = field(default_factory=uuid4)
    pattern: AIBreachPatternType = AIBreachPatternType.SHADOW_AI
    confidence: float = 0.0
    severity: int = 1
    risk_score: float = 0.0  # confidence * base_severity, normalised 0-100
    reasoning: str = ""
    signal_ids: List[UUID] = field(default_factory=list)
    requires_human_review: bool = False
    detected_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        defn = get_ai_pattern(self.pattern)
        return {
            "id": str(self.id),
            "pattern": self.pattern.value,
            "display_name": defn.display_name,
            "owasp_llm_id": defn.owasp_llm_id,
            "nist_ai_rmf_function": defn.nist_ai_rmf_function,
            "nist_controls_at_risk": [c.value for c in defn.nist_controls_at_risk],
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "risk_score": round(self.risk_score, 1),
            "reasoning": self.reasoning,
            "plain_language_summary": defn.plain_language_summary,
            "mitigation_repo_path": defn.mitigation_repo_path,
            "signal_ids": [str(s) for s in self.signal_ids],
            "requires_human_review": self.requires_human_review,
            "detected_at": self.detected_at.isoformat(),
        }


# ── Known public LLM endpoints (extensible) ──────────
KNOWN_PUBLIC_LLM_HOSTS = {
    "api.openai.com", "chat.openai.com",
    "api.anthropic.com", "claude.ai",
    "generativelanguage.googleapis.com", "gemini.google.com",
    "api.mistral.ai", "api.together.xyz", "api.groq.com",
    "api.perplexity.ai", "api.cohere.ai",
}


class AIBreachDetector:
    """Run all seven AI-breach detectors over a batch of AISignal records."""

    def __init__(
        self,
        confidence_threshold: float = 0.70,
        public_llm_hosts: Optional[Iterable[str]] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.public_llm_hosts = set(public_llm_hosts or KNOWN_PUBLIC_LLM_HOSTS)

    def detect_all(self, signals: List[AISignal]) -> List[AIBreachDetection]:
        out: List[AIBreachDetection] = []
        if not signals:
            return out
        for fn in (
            self._detect_shadow_ai,
            self._detect_prompt_injection,
            self._detect_nhi_misuse,
            self._detect_model_poisoning,
            self._detect_sleeper_agent,
            self._detect_ai_social_engineering,
            self._detect_defender_over_trust,
        ):
            d = fn(signals)
            if d is not None:
                out.append(d)
        return out

    # ── 1. Shadow AI ────────────────────────────────
    def _detect_shadow_ai(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        humans_to_public = [
            s for s in signals
            if s.actor_type == "human"
            and s.destination
            and any(host in s.destination for host in self.public_llm_hosts)
        ]
        if not humans_to_public:
            return None
        large = [s for s in humans_to_public if (s.prompt_size_tokens or 0) > 500]
        ratio = len(large) / max(len(humans_to_public), 1)
        # confidence: presence of any traffic gives 0.55, large prompts push higher
        confidence = min(0.55 + 0.45 * ratio, 0.99)
        return self._build_detection(
            AIBreachPatternType.SHADOW_AI,
            confidence,
            humans_to_public,
            (
                f"{len(humans_to_public)} outbound calls from human actors to "
                f"public LLM endpoints; {len(large)} carried prompts > 500 tokens."
            ),
        )

    # ── 2. Prompt injection ─────────────────────────
    def _detect_prompt_injection(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        agent_signals = [s for s in signals if s.actor_type == "agent"]
        if not agent_signals:
            return None
        flagged = [s for s in agent_signals if s.contains_instruction_tokens]
        # action diversity per agent — sudden new actions are suspicious
        per_agent_actions: Dict[str, set] = {}
        for s in agent_signals:
            per_agent_actions.setdefault(s.actor_id, set()).add(s.action)
        wide_action_agents = [a for a, acts in per_agent_actions.items() if len(acts) >= 4]

        if not flagged and not wide_action_agents:
            return None
        confidence = 0.0
        if flagged:
            confidence += 0.55 + 0.4 * min(len(flagged) / max(len(agent_signals), 1), 1.0)
        if wide_action_agents:
            confidence += 0.15 * min(len(wide_action_agents) / max(len(per_agent_actions), 1), 1.0)
        confidence = min(confidence, 0.98)
        return self._build_detection(
            AIBreachPatternType.PROMPT_INJECTION,
            confidence,
            flagged or agent_signals[: min(5, len(agent_signals))],
            (
                f"{len(flagged)} agent events contained instruction-like tokens "
                f"in untrusted content; {len(wide_action_agents)} agents used "
                f">=4 distinct tool actions in this window."
            ),
        )

    # ── 3. Non-Human Identity Misuse ────────────────
    def _detect_nhi_misuse(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        nhi = [s for s in signals if s.actor_type in ("agent", "service")]
        if not nhi:
            return None
        # entitlement growth: count distinct actions per actor
        per_actor: Dict[str, set] = {}
        per_actor_geos: Dict[str, set] = {}
        for s in nhi:
            per_actor.setdefault(s.actor_id, set()).add(s.action)
            geo = s.metadata.get("geo") if isinstance(s.metadata, dict) else None
            if geo:
                per_actor_geos.setdefault(s.actor_id, set()).add(geo)
        wide_scope = [a for a, acts in per_actor.items() if len(acts) >= 6]
        roaming = [a for a, geos in per_actor_geos.items() if len(geos) >= 2]
        if not wide_scope and not roaming:
            return None
        confidence = 0.0
        if wide_scope:
            confidence += 0.5 + 0.35 * min(len(wide_scope) / max(len(per_actor), 1), 1.0)
        if roaming:
            confidence += 0.2 * min(len(roaming) / max(len(per_actor), 1), 1.0)
        confidence = min(confidence, 0.97)
        return self._build_detection(
            AIBreachPatternType.NHI_MISUSE,
            confidence,
            nhi[: min(10, len(nhi))],
            (
                f"{len(wide_scope)} non-human identities exercised >=6 distinct "
                f"actions; {len(roaming)} called from >=2 geographies in window."
            ),
        )

    # ── 4. Model / Data Poisoning ───────────────────
    def _detect_model_poisoning(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        model_outputs = [s for s in signals if s.model_id and s.output_size_tokens]
        if len(model_outputs) < 8:
            return None
        sizes = [s.output_size_tokens for s in model_outputs]
        m = mean(sizes)
        sd = pstdev(sizes) or 1.0
        # if recent half differs from earlier half by > 1.5 sd, flag drift
        half = len(model_outputs) // 2
        early = mean(sizes[:half])
        late = mean(sizes[half:])
        z = abs(late - early) / sd
        if z < 1.2:
            return None
        confidence = min(0.55 + 0.15 * z, 0.97)
        return self._build_detection(
            AIBreachPatternType.MODEL_POISONING,
            confidence,
            model_outputs[half:],
            (
                f"Output-size distribution shifted by {z:.2f} sigma between "
                f"early ({early:.0f} tokens) and late ({late:.0f} tokens) halves "
                f"of the window across {len({s.model_id for s in model_outputs})} models."
            ),
        )

    # ── 5. Sleeper-agent backdoor ───────────────────
    def _detect_sleeper_agent(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        # group by model_version; flag any version that produced outputs
        # heavily concentrated in a < 5-minute spike
        per_version: Dict[str, List[AISignal]] = {}
        for s in signals:
            if s.model_version:
                per_version.setdefault(s.model_version, []).append(s)
        suspicious_versions: List[str] = []
        evidence: List[AISignal] = []
        for ver, sigs in per_version.items():
            if len(sigs) < 5:
                continue
            sigs_sorted = sorted(sigs, key=lambda x: x.timestamp)
            window = timedelta(minutes=5)
            for i in range(len(sigs_sorted)):
                burst = [s for s in sigs_sorted[i:] if s.timestamp - sigs_sorted[i].timestamp <= window]
                if len(burst) / len(sigs_sorted) >= 0.7 and len(burst) >= 5:
                    suspicious_versions.append(ver)
                    evidence.extend(burst)
                    break
        if not suspicious_versions:
            return None
        confidence = min(0.6 + 0.1 * len(suspicious_versions), 0.95)
        return self._build_detection(
            AIBreachPatternType.SLEEPER_AGENT,
            confidence,
            evidence,
            (
                f"Model version(s) {suspicious_versions} produced >=70 percent of "
                f"output inside a 5-minute burst — consistent with a triggered "
                f"dormant pattern."
            ),
        )

    # ── 6. AI-augmented social engineering ──────────
    def _detect_ai_social_engineering(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        humans = [s for s in signals if s.actor_type == "human"]
        if not humans:
            return None
        # multi-channel pressure: same actor, >=3 distinct destinations within 10 min
        per_actor: Dict[str, List[AISignal]] = {}
        for s in humans:
            per_actor.setdefault(s.actor_id, []).append(s)
        flagged_actors: List[str] = []
        evidence: List[AISignal] = []
        for actor, sigs in per_actor.items():
            sigs_sorted = sorted(sigs, key=lambda x: x.timestamp)
            for i in range(len(sigs_sorted)):
                window = [s for s in sigs_sorted[i:] if s.timestamp - sigs_sorted[i].timestamp <= timedelta(minutes=10)]
                if len({s.destination for s in window if s.destination}) >= 3 and len(window) >= 3:
                    flagged_actors.append(actor)
                    evidence.extend(window)
                    break
        if not flagged_actors:
            return None
        confidence = min(0.55 + 0.15 * len(flagged_actors), 0.93)
        return self._build_detection(
            AIBreachPatternType.AI_SOCIAL_ENGINEERING,
            confidence,
            evidence,
            (
                f"{len(flagged_actors)} human actor(s) experienced multi-channel "
                f"contact (>=3 distinct destinations within 10 minutes)."
            ),
        )

    # ── 7. Defender-side AI over-trust ──────────────
    def _detect_defender_over_trust(self, signals: List[AISignal]) -> Optional[AIBreachDetection]:
        decisions = [s for s in signals if s.approved_by_human is not None and s.decision_latency_ms is not None]
        if len(decisions) < 5:
            return None
        approved = [s for s in decisions if s.approved_by_human]
        approval_rate = len(approved) / len(decisions)
        median_latency = sorted([s.decision_latency_ms for s in decisions])[len(decisions) // 2]
        suspicious = approval_rate >= 0.95 and median_latency <= 1500  # sub 1.5s
        if not suspicious:
            return None
        # confidence scales with how extreme both signals are
        confidence = min(0.55 + (approval_rate - 0.95) * 5 + (1500 - median_latency) / 5000, 0.95)
        confidence = max(0.55, confidence)
        return self._build_detection(
            AIBreachPatternType.DEFENDER_OVER_TRUST,
            confidence,
            decisions,
            (
                f"Human-approval rate of AI triage = {approval_rate:.0%} with "
                f"median decision latency = {median_latency} ms across "
                f"{len(decisions)} decisions — consistent with rubber-stamping."
            ),
        )

    # ── helpers ─────────────────────────────────────
    def _build_detection(
        self,
        pattern: AIBreachPatternType,
        confidence: float,
        evidence: List[AISignal],
        reasoning: str,
    ) -> AIBreachDetection:
        defn = get_ai_pattern(pattern)
        sev = defn.base_severity
        # severity scales with confidence in 1..5
        sev_effective = max(1, min(5, round(sev * confidence + 0.5)))
        risk_score = round(confidence * sev * 4, 1)  # 0..20 mapped to 0..100
        risk_score = min(risk_score * 5, 100.0)
        return AIBreachDetection(
            pattern=pattern,
            confidence=round(confidence, 3),
            severity=sev_effective,
            risk_score=risk_score,
            reasoning=reasoning,
            signal_ids=[s.id for s in evidence[:10]],
            requires_human_review=confidence < self.confidence_threshold,
        )


def aggregate_risk(detections: List[AIBreachDetection]) -> Dict[str, Any]:
    """Roll up to a single organisational AI-breach risk view."""
    if not detections:
        return {
            "overall_risk_score": 0.0,
            "alert_level": "Watch",
            "active_patterns": 0,
            "patterns": [],
        }
    overall = max(d.risk_score for d in detections)
    if overall >= 70:
        level = "Critical"
    elif overall >= 40:
        level = "Warning"
    else:
        level = "Watch"
    return {
        "overall_risk_score": overall,
        "alert_level": level,
        "active_patterns": len(detections),
        "patterns": [d.to_dict() for d in detections],
    }
