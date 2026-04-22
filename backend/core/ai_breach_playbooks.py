"""
AI BREACH PLAYBOOKS & MITRE ATLAS mapping.
==========================================

Adds two advanced capabilities to the AI breach layer:

  1. MITRE ATLAS technique mapping — each of the seven patterns is
     mapped to one or more MITRE ATLAS adversarial-ML techniques
     (https://atlas.mitre.org). This complements the OWASP LLM Top 10
     mapping in `core/ai_drift_patterns.py`.

  2. Auto-mitigation playbooks — for each pattern we provide an
     ordered list of concrete, copy-pasteable response actions a
     human reviewer can execute. Playbooks are deterministic and
     vendor-agnostic; nothing here calls an LLM.

Sources:
  - MITRE ATLAS Matrix v4.7.0 (public)
  - OWASP LLM Top 10 (2025 revision) mitigation appendix
  - UK NCSC December 2025 prompt-injection guidance (mitigations section)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from core.ai_drift_patterns import AIBreachPatternType


@dataclass(frozen=True)
class PlaybookStep:
    order: int
    action: str
    owner_role: str  # 'security_engineer' | 'ciso' | 'ml_engineer' | 'compliance'
    automatable: bool


@dataclass(frozen=True)
class Playbook:
    pattern: AIBreachPatternType
    mitre_atlas_ids: Tuple[str, ...]  # eg ('AML.T0051', 'AML.T0040')
    immediate_steps: Tuple[PlaybookStep, ...]
    short_term_steps: Tuple[PlaybookStep, ...]
    long_term_steps: Tuple[PlaybookStep, ...]
    expected_dwell_reduction_hours: int  # est, conservative


PLAYBOOKS: Dict[AIBreachPatternType, Playbook] = {

    AIBreachPatternType.SHADOW_AI: Playbook(
        pattern=AIBreachPatternType.SHADOW_AI,
        mitre_atlas_ids=("AML.T0049", "AML.T0048"),  # Discover & Exfil via LLM
        immediate_steps=(
            PlaybookStep(1, "Block egress to the public LLM host at the proxy or DNS layer for the affected user group", "security_engineer", True),
            PlaybookStep(2, "Surface the prompt-payload hashes (already redacted) to the calibration team for triage", "compliance", False),
        ),
        short_term_steps=(
            PlaybookStep(3, "Provision a sanctioned LLM gateway (single-tenant, logged, with DLP) for the same user group", "security_engineer", False),
            PlaybookStep(4, "Run a one-week awareness micro-training on what data may not leave the perimeter", "compliance", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Add a recurring 30-day Shadow-AI sweep to the governance gate so this is detected on the first event, not the hundredth", "ciso", True),
        ),
        expected_dwell_reduction_hours=72,
    ),

    AIBreachPatternType.PROMPT_INJECTION: Playbook(
        pattern=AIBreachPatternType.PROMPT_INJECTION,
        mitre_atlas_ids=("AML.T0051", "AML.T0054"),
        immediate_steps=(
            PlaybookStep(1, "Quarantine the agent: revoke its tool-use credentials and pause its job queue", "security_engineer", True),
            PlaybookStep(2, "Snapshot the offending input and the resulting tool calls for forensics", "ml_engineer", True),
        ),
        short_term_steps=(
            PlaybookStep(3, "Re-deploy the agent with a strict allow-list of tools and a separate untrusted-content channel", "ml_engineer", False),
            PlaybookStep(4, "Add a content-firewall pre-filter (Lakera, Rebuff or in-house regex) in front of the agent", "security_engineer", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Adopt the dual-LLM pattern (privileged executor + untrusted reader) for any agent that touches user content", "ml_engineer", False),
        ),
        expected_dwell_reduction_hours=24,
    ),

    AIBreachPatternType.NHI_MISUSE: Playbook(
        pattern=AIBreachPatternType.NHI_MISUSE,
        mitre_atlas_ids=("AML.T0012",),  # Valid Accounts (NHI variant)
        immediate_steps=(
            PlaybookStep(1, "Rotate the non-human credential and revoke any session tokens it minted in the last 24h", "security_engineer", True),
            PlaybookStep(2, "Constrain its IAM policy to the minimum action set seen in the prior 30-day baseline", "security_engineer", True),
        ),
        short_term_steps=(
            PlaybookStep(3, "Add a per-NHI behavioural baseline alert in the SIEM with a 15-minute window", "security_engineer", False),
            PlaybookStep(4, "Tag the NHI with an owner and an expiry date — orphaned NHIs are the largest class of misuse", "compliance", True),
        ),
        long_term_steps=(
            PlaybookStep(5, "Migrate the workload to short-lived workload-identity tokens (OIDC, IRSA, workload identity federation)", "security_engineer", False),
        ),
        expected_dwell_reduction_hours=48,
    ),

    AIBreachPatternType.MODEL_POISONING: Playbook(
        pattern=AIBreachPatternType.MODEL_POISONING,
        mitre_atlas_ids=("AML.T0020", "AML.T0018"),
        immediate_steps=(
            PlaybookStep(1, "Roll back the model to the last known-good checkpoint", "ml_engineer", True),
            PlaybookStep(2, "Quarantine the latest training shard and freeze the data ingestion pipeline", "ml_engineer", True),
        ),
        short_term_steps=(
            PlaybookStep(3, "Re-run integrity hashes on every training file added since the last good checkpoint", "ml_engineer", False),
            PlaybookStep(4, "Compare model outputs against the held-out canary set; flag any class with > 5% accuracy drop", "ml_engineer", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Move ingestion to signed-source-only with a content provenance log (C2PA-style)", "ml_engineer", False),
        ),
        expected_dwell_reduction_hours=120,
    ),

    AIBreachPatternType.SLEEPER_AGENT: Playbook(
        pattern=AIBreachPatternType.SLEEPER_AGENT,
        mitre_atlas_ids=("AML.T0018", "AML.T0011"),
        immediate_steps=(
            PlaybookStep(1, "Take the suspect model version offline and route traffic to the prior version", "ml_engineer", True),
            PlaybookStep(2, "Snapshot the burst-window inputs, outputs and tool calls for offline analysis", "security_engineer", True),
        ),
        short_term_steps=(
            PlaybookStep(3, "Run trigger-discovery: sweep the input space for sentinel tokens that elicit the burst behaviour", "ml_engineer", False),
            PlaybookStep(4, "If model is third-party, contact the vendor with the trigger evidence and request a clean re-build", "ciso", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Add behavioural canaries (off-distribution prompts) that run nightly and alert on output-distribution drift", "ml_engineer", False),
        ),
        expected_dwell_reduction_hours=168,
    ),

    AIBreachPatternType.AI_SOCIAL_ENGINEERING: Playbook(
        pattern=AIBreachPatternType.AI_SOCIAL_ENGINEERING,
        mitre_atlas_ids=("AML.T0052", "AML.T0054"),
        immediate_steps=(
            PlaybookStep(1, "Reach the targeted user(s) by an out-of-band channel (in-person, verified phone) and verify any recent action they were asked to take", "security_engineer", False),
            PlaybookStep(2, "Block the originating destinations at the email and voice gateways", "security_engineer", True),
        ),
        short_term_steps=(
            PlaybookStep(3, "Trigger forced password reset and step-up MFA for the targeted users", "security_engineer", True),
            PlaybookStep(4, "Add a multi-channel-pressure alert template to the awareness program", "compliance", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Adopt voice-biometric or call-back verification for finance and admin actions over a defined threshold", "ciso", False),
        ),
        expected_dwell_reduction_hours=8,
    ),

    AIBreachPatternType.DEFENDER_OVER_TRUST: Playbook(
        pattern=AIBreachPatternType.DEFENDER_OVER_TRUST,
        mitre_atlas_ids=("AML.T0040",),  # ML-Enabled Defense Evasion (variant)
        immediate_steps=(
            PlaybookStep(1, "Insert a mandatory cool-off (eg 5-second pause + diff view) before any AI-recommended decision can be approved", "security_engineer", True),
            PlaybookStep(2, "Re-run the last 100 auto-approved decisions through a second analyst for spot-audit", "compliance", False),
        ),
        short_term_steps=(
            PlaybookStep(3, "Add a per-analyst over-trust dashboard (approval rate, median latency, dissent rate) to the monthly governance review", "ciso", True),
            PlaybookStep(4, "Inject deliberate red-team prompts (known-bad cases) into the triage stream weekly to keep human attention calibrated", "security_engineer", False),
        ),
        long_term_steps=(
            PlaybookStep(5, "Reward dissent: change the analyst KPI to include 'caught a model error' alongside 'cleared queue'", "ciso", False),
        ),
        expected_dwell_reduction_hours=36,
    ),
}


def get_playbook(pattern: AIBreachPatternType) -> Playbook:
    return PLAYBOOKS[pattern]


def all_playbooks() -> List[Playbook]:
    return list(PLAYBOOKS.values())


def playbook_to_dict(pb: Playbook) -> Dict:
    return {
        "pattern": pb.pattern.value,
        "mitre_atlas_ids": list(pb.mitre_atlas_ids),
        "expected_dwell_reduction_hours": pb.expected_dwell_reduction_hours,
        "immediate_steps": [_step_dict(s) for s in pb.immediate_steps],
        "short_term_steps": [_step_dict(s) for s in pb.short_term_steps],
        "long_term_steps": [_step_dict(s) for s in pb.long_term_steps],
    }


def _step_dict(s: PlaybookStep) -> Dict:
    return {
        "order": s.order,
        "action": s.action,
        "owner_role": s.owner_role,
        "automatable": s.automatable,
    }
