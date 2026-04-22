"""
AI-ERA DRIFT PATTERNS — sits ON TOP of the immutable 6 human-drift patterns.
============================================================================

Where `drift_patterns.py` covers the human-state breach surface, this module
covers the AI-replacement breach surface defined in BUSINESS_PLAN.md
Appendix F.2 (the seven AI-era breach classes).

The human framework is sacred and untouched. AI patterns are additive:
they extend the same probability + severity + NIST-mapping pipeline to
non-human identities and to the AI systems themselves.

Mappings:
  - NIST AI RMF 1.0 + Generative AI Profile (NIST AI 600-1, July 2024)
  - OWASP LLM Top 10 (2025 revision)
  - UK NCSC prompt-injection guidance (December 2025)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional, Tuple

from models import NISTControl


# ── Seven AI-era breach classes ──────────────────────
class AIBreachPatternType(str, Enum):
    SHADOW_AI = "Shadow_AI"
    PROMPT_INJECTION = "Prompt_Injection"
    NHI_MISUSE = "Non_Human_Identity_Misuse"
    MODEL_POISONING = "Model_Or_Data_Poisoning"
    SLEEPER_AGENT = "Sleeper_Agent_Backdoor"
    AI_SOCIAL_ENGINEERING = "AI_Augmented_Social_Engineering"
    DEFENDER_OVER_TRUST = "Defender_AI_Over_Trust"


@dataclass(frozen=True)
class AIBreachPatternDefinition:
    pattern_type: AIBreachPatternType
    display_name: str
    description: str
    owasp_llm_id: str               # eg. LLM01 prompt injection
    nist_ai_rmf_function: str       # GOVERN | MAP | MEASURE | MANAGE
    signal_indicators: Tuple[str, ...]
    failure_modes: Tuple[str, ...]
    nist_controls_at_risk: FrozenSet[NISTControl]
    plain_language_summary: str
    base_severity: int              # 1-5; multiplied by detector confidence
    mitigation_repo_path: str       # which DriftGuard module mitigates it


SHADOW_AI = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.SHADOW_AI,
    display_name="Shadow AI Adoption",
    description=(
        "Employees route sensitive data through unsanctioned AI tools "
        "(public LLMs, browser extensions, copilots) outside the governance "
        "perimeter. The data egress looks like ordinary HTTPS to the SIEM."
    ),
    owasp_llm_id="LLM06",
    nist_ai_rmf_function="GOVERN",
    signal_indicators=(
        "Outbound HTTPS to known LLM endpoints from non-AI teams",
        "Sudden spike in clipboard or file-upload size against AI domains",
        "Browser extension installs flagged as AI assistants",
        "Prompt-shaped payloads exceeding configured token thresholds",
    ),
    failure_modes=(
        "Confidential data leakage",
        "Regulatory breach (GDPR Art. 5, 32)",
        "Loss of audit trail for AI-assisted decisions",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AC_2, NISTControl.AU_6}),
    plain_language_summary=(
        "People are quietly using AI tools no-one approved. The data is "
        "leaving the building inside what looks like a normal web request."
    ),
    base_severity=4,
    mitigation_repo_path="backend/pipeline/signal_ingestion.py + backend/core/drift_patterns.py",
)

PROMPT_INJECTION = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.PROMPT_INJECTION,
    display_name="Prompt Injection of Agentic AI",
    description=(
        "Adversary embeds instructions inside content the AI agent later "
        "reads (email body, web page, ticket field, RAG document) so the "
        "agent executes attacker intent under a trusted service identity."
    ),
    owasp_llm_id="LLM01",
    nist_ai_rmf_function="MEASURE",
    signal_indicators=(
        "Agent action sequence diverges from established baseline",
        "Instruction-like tokens detected inside untrusted content fields",
        "Tool calls invoked in an order never seen for this agent",
        "Output references entities the agent has no read scope for",
    ),
    failure_modes=(
        "Unauthorised tool execution",
        "Privileged data exfiltration via trusted agent",
        "Cross-tenant data leakage",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AC_2, NISTControl.AU_6, NISTControl.IR_6}),
    plain_language_summary=(
        "An AI agent was tricked into following hidden instructions. "
        "It looked like normal automation because the agent's own account did it."
    ),
    base_severity=5,
    mitigation_repo_path="backend/core/ai_drift_patterns.py + backend/engine/ai_breach_detector.py",
)

NHI_MISUSE = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.NHI_MISUSE,
    display_name="Non-Human Identity Misuse",
    description=(
        "Service tokens, API keys and agent credentials accumulate "
        "entitlements no human reviews. When abused they bypass UEBA "
        "because there is no human baseline to deviate from."
    ),
    owasp_llm_id="LLM08",
    nist_ai_rmf_function="MANAGE",
    signal_indicators=(
        "Token age exceeds rotation policy",
        "Entitlement count grows monotonically without revocation",
        "Token used from new geography or new ASN",
        "Token invokes scopes never invoked in last 30 days",
    ),
    failure_modes=(
        "Silent privilege escalation",
        "Lateral movement via long-lived credential",
        "Forgotten-token data breach",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AC_2, NISTControl.CA_7}),
    plain_language_summary=(
        "An AI service account has been quietly collecting permissions. "
        "If it is ever compromised the blast radius is far larger than expected."
    ),
    base_severity=4,
    mitigation_repo_path="backend/core/ai_drift_patterns.py + backend/core/nist_mapping.py",
)

MODEL_POISONING = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.MODEL_POISONING,
    display_name="Model or Data Poisoning",
    description=(
        "Training data, fine-tuning corpus or RAG index is silently "
        "corrupted upstream so the model begins to favour attacker outputs."
    ),
    owasp_llm_id="LLM03",
    nist_ai_rmf_function="MEASURE",
    signal_indicators=(
        "Output distribution shift against approved calibration corpus",
        "Confidence inversion — high confidence on previously-uncertain inputs",
        "Recommendation drift toward a narrow set of entities",
        "Embedding-space anomaly in newly indexed documents",
    ),
    failure_modes=(
        "Biased automated decisions",
        "Attacker-favourable recommendations at scale",
        "Loss of decision auditability",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AU_6, NISTControl.CA_7, NISTControl.AT_2}),
    plain_language_summary=(
        "The AI is starting to give answers that drift away from the "
        "approved baseline. Something upstream has changed."
    ),
    base_severity=5,
    mitigation_repo_path="backend/pipeline/temporal_weighting.py + backend/calibration/rag_retrieval.py",
)

SLEEPER_AGENT = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.SLEEPER_AGENT,
    display_name="Sleeper-Agent Backdoor",
    description=(
        "A third-party model contains a dormant trigger that activates "
        "malicious behaviour after a date or specific input. Standard SFT "
        "and RLHF do not remove these (Anthropic, 2024)."
    ),
    owasp_llm_id="LLM05",
    nist_ai_rmf_function="MAP",
    signal_indicators=(
        "Sudden deviation from calibration baseline at a specific timestamp",
        "Output anomaly correlated with a specific input pattern",
        "Behaviour change concentrated in one model version or weight hash",
    ),
    failure_modes=(
        "Coordinated malicious output campaign",
        "Supply-chain compromise via untrusted model",
        "Long-dwell adversarial activity",
    ),
    nist_controls_at_risk=frozenset({NISTControl.IR_6, NISTControl.CA_7}),
    plain_language_summary=(
        "An AI model that behaved normally for months has suddenly changed. "
        "The trigger may have been a date or a specific phrase."
    ),
    base_severity=5,
    mitigation_repo_path="backend/engine/early_warning.py + backend/calibration/rag_retrieval.py",
)

AI_SOCIAL_ENGINEERING = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.AI_SOCIAL_ENGINEERING,
    display_name="AI-Augmented Social Engineering",
    description=(
        "Highly personalised voice or email impersonation generated by "
        "AI against the small surviving human team after AI-driven "
        "workforce reduction. Generic gateway filters do not catch it."
    ),
    owasp_llm_id="LLM09",
    nist_ai_rmf_function="MEASURE",
    signal_indicators=(
        "Unusual response time on out-of-pattern counterparty contact",
        "Voice-channel call from previously-unseen number to privileged role",
        "Email tone exactly matching known executive style but odd timing",
        "Multi-channel pressure pattern (email + voice + chat) inside a short window",
    ),
    failure_modes=(
        "Wire fraud via deepfake authorisation",
        "Credential disclosure under perceived legitimate request",
        "Reputational damage from impersonation",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AT_2, NISTControl.IR_6}),
    plain_language_summary=(
        "A human on the team is being targeted by an AI-crafted attack "
        "specifically tuned to their context. It will not look like a phish."
    ),
    base_severity=4,
    mitigation_repo_path="backend/core/ai_drift_patterns.py + backend/calibration/delivery.py",
)

DEFENDER_OVER_TRUST = AIBreachPatternDefinition(
    pattern_type=AIBreachPatternType.DEFENDER_OVER_TRUST,
    display_name="Defender-Side AI Over-Trust",
    description=(
        "SOC analysts auto-accept AI-generated triage decisions, closing "
        "real incidents as benign. The audit trail says 'analyst approved'."
    ),
    owasp_llm_id="LLM09",
    nist_ai_rmf_function="GOVERN",
    signal_indicators=(
        "Median analyst-decision time below the AI inference time",
        "Approval rate of AI suggestions exceeds 95 percent for sustained period",
        "Closed incidents lacking human-authored notes",
        "Declining mean alert investigation depth",
    ),
    failure_modes=(
        "False-negative incident closure",
        "Loss of human judgement signal",
        "Compliance breach when reviewer cannot explain decision",
    ),
    nist_controls_at_risk=frozenset({NISTControl.AU_6, NISTControl.AT_2, NISTControl.IR_6}),
    plain_language_summary=(
        "Your analysts are clicking accept on AI triage faster than the "
        "AI took to produce it. Real incidents will slip through."
    ),
    base_severity=4,
    mitigation_repo_path="backend/governance/approval_gates.py + backend/core/ethical_guardrails.py",
)


# ── Registry ─────────────────────────────────────────

AI_BREACH_PATTERNS: Dict[AIBreachPatternType, AIBreachPatternDefinition] = {
    AIBreachPatternType.SHADOW_AI: SHADOW_AI,
    AIBreachPatternType.PROMPT_INJECTION: PROMPT_INJECTION,
    AIBreachPatternType.NHI_MISUSE: NHI_MISUSE,
    AIBreachPatternType.MODEL_POISONING: MODEL_POISONING,
    AIBreachPatternType.SLEEPER_AGENT: SLEEPER_AGENT,
    AIBreachPatternType.AI_SOCIAL_ENGINEERING: AI_SOCIAL_ENGINEERING,
    AIBreachPatternType.DEFENDER_OVER_TRUST: DEFENDER_OVER_TRUST,
}


def get_ai_pattern(pattern_type: AIBreachPatternType) -> AIBreachPatternDefinition:
    return AI_BREACH_PATTERNS[pattern_type]


def all_ai_patterns() -> Tuple[AIBreachPatternDefinition, ...]:
    return tuple(AI_BREACH_PATTERNS.values())


def patterns_for_owasp(owasp_id: str) -> Tuple[AIBreachPatternDefinition, ...]:
    return tuple(p for p in AI_BREACH_PATTERNS.values() if p.owasp_llm_id == owasp_id)


def patterns_for_nist_function(fn: str) -> Tuple[AIBreachPatternDefinition, ...]:
    fn_upper = fn.upper()
    return tuple(p for p in AI_BREACH_PATTERNS.values() if p.nist_ai_rmf_function == fn_upper)
