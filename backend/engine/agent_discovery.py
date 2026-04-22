"""Agent / AI endpoint discovery scanner.

Closes one of the limits called out in Appendix O: the platform
detected risky AI use *after* an event happened, but never tried to
discover where AI was actually being used in the first place.

This module gives operators a way to feed in raw text artefacts —
URLs, environment exports, config files, JSON manifests, source
fragments — and get back a structured list of AI / agent endpoints
the artefacts reference, each labelled with a vendor (when known) and
a confidence in [0, 1].

Intentional non-goals:
  * No live network probing. We never make outbound HTTP from this
    module; the host decides whether to hand us text. That keeps the
    scanner safe to run inside any tenant's environment.
  * No model-internal telemetry. We only see what the host gives us.
    Honest gap, mirrored in Appendix P.

Pure stdlib (regex + urllib.parse), thread-safe by virtue of being
stateless apart from the constant catalogue.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


# ── Catalogue of known AI / agent surfaces ───────────
#
# Each entry maps a host or scheme pattern to a vendor label and the
# kind of surface it represents. Deliberately conservative — entries
# only cover endpoints that actually serve model inference or agent
# orchestration today.
_VENDOR_HOSTS: Dict[str, Tuple[str, str]] = {
    "api.openai.com":        ("openai",        "llm_api"),
    "openai.azure.com":      ("azure_openai",  "llm_api"),
    "api.anthropic.com":     ("anthropic",     "llm_api"),
    "api.cohere.ai":         ("cohere",        "llm_api"),
    "api.cohere.com":        ("cohere",        "llm_api"),
    "api.mistral.ai":        ("mistral",       "llm_api"),
    "api.together.xyz":      ("together",      "llm_api"),
    "api.replicate.com":     ("replicate",     "llm_api"),
    "api.groq.com":          ("groq",          "llm_api"),
    "api.fireworks.ai":      ("fireworks",     "llm_api"),
    "api-inference.huggingface.co": ("huggingface", "llm_api"),
    "generativelanguage.googleapis.com": ("google_gemini", "llm_api"),
    "bedrock-runtime":       ("aws_bedrock",   "llm_api"),  # substring
    "claude.ai":             ("anthropic",     "consumer_chat"),
    "chat.openai.com":       ("openai",        "consumer_chat"),
    "chatgpt.com":           ("openai",        "consumer_chat"),
    "gemini.google.com":     ("google_gemini", "consumer_chat"),
    "perplexity.ai":         ("perplexity",    "consumer_chat"),
    "poe.com":               ("poe",           "consumer_chat"),
    "you.com":               ("you",           "consumer_chat"),
    "copilot.microsoft.com": ("ms_copilot",    "consumer_chat"),
    "github.com/copilot":    ("github_copilot","consumer_chat"),  # substring
}

# Hosts/ports commonly used by self-hosted agents. We treat these as
# "self_hosted" so an operator knows the AI is inside the perimeter.
_SELF_HOSTED_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\blocalhost:11434\b"),         "ollama",      "self_hosted"),
    (re.compile(r"\b127\.0\.0\.1:11434\b"),      "ollama",      "self_hosted"),
    (re.compile(r"\blocalhost:8080/v1/chat\b"),  "lmstudio",    "self_hosted"),
    (re.compile(r"\blocalhost:5000/v1\b"),       "vllm",        "self_hosted"),
    (re.compile(r"\blocalhost:8000/v1/chat\b"),  "openai_compat","self_hosted"),
    (re.compile(r"\bllama\.cpp\b"),              "llama_cpp",   "self_hosted"),
]

# Agent / MCP scheme patterns — surfaces that orchestrate tool use.
_SCHEME_PATTERNS: List[Tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bmcp://[^\s\"']+"),           "mcp",          "agent_mcp"),
    (re.compile(r"\blangsmith\.com\b"),          "langchain",    "agent_telemetry"),
    (re.compile(r"\bsmith\.langchain\.com\b"),   "langchain",    "agent_telemetry"),
    (re.compile(r"\bagentops\.ai\b"),            "agentops",     "agent_telemetry"),
]

# Indicator keys that are dead giveaways even without a URL — e.g. an
# `OPENAI_API_KEY` exported in a config file.
_KEY_INDICATORS: Dict[str, Tuple[str, str]] = {
    "OPENAI_API_KEY":     ("openai",        "credential"),
    "ANTHROPIC_API_KEY":  ("anthropic",     "credential"),
    "COHERE_API_KEY":     ("cohere",        "credential"),
    "MISTRAL_API_KEY":    ("mistral",       "credential"),
    "REPLICATE_API_TOKEN":("replicate",     "credential"),
    "HUGGINGFACE_TOKEN":  ("huggingface",   "credential"),
    "HF_TOKEN":           ("huggingface",   "credential"),
    "GOOGLE_API_KEY":     ("google_gemini", "credential"),
    "GEMINI_API_KEY":     ("google_gemini", "credential"),
    "GROQ_API_KEY":       ("groq",          "credential"),
    "TOGETHER_API_KEY":   ("together",      "credential"),
    "FIREWORKS_API_KEY":  ("fireworks",     "credential"),
}

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")


@dataclass
class DiscoveredEndpoint:
    """A single AI/agent surface found in scanned text."""
    vendor: str
    kind: str           # llm_api | consumer_chat | self_hosted | agent_mcp | agent_telemetry | credential
    indicator: str      # the matched URL or key
    confidence: float   # [0, 1]
    source_label: str = ""  # human label of where it came from
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "vendor": self.vendor,
            "kind": self.kind,
            "indicator": self.indicator,
            "confidence": round(self.confidence, 3),
            "source_label": self.source_label,
            "metadata": dict(self.metadata),
        }


def _classify_url(url: str) -> Optional[Tuple[str, str, float]]:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    if not host:
        return None
    # Exact host match → high confidence.
    if host in _VENDOR_HOSTS:
        vendor, kind = _VENDOR_HOSTS[host]
        return vendor, kind, 0.95
    # Substring match (covers regional/aws subdomains).
    for needle, (vendor, kind) in _VENDOR_HOSTS.items():
        if needle in host or needle in (parsed.netloc + parsed.path).lower():
            return vendor, kind, 0.85
    return None


def scan_text(
    text: str,
    *,
    source_label: str = "",
) -> List[DiscoveredEndpoint]:
    """Scan a single text blob for AI / agent indicators."""
    if not text:
        return []
    found: List[DiscoveredEndpoint] = []
    seen: set = set()

    def _add(ep: DiscoveredEndpoint) -> None:
        key = (ep.vendor, ep.kind, ep.indicator)
        if key in seen:
            return
        seen.add(key)
        found.append(ep)

    # 1. URLs
    for match in _URL_RE.findall(text):
        cls = _classify_url(match)
        if cls is None:
            continue
        vendor, kind, conf = cls
        _add(DiscoveredEndpoint(
            vendor=vendor, kind=kind, indicator=match,
            confidence=conf, source_label=source_label,
        ))

    # 2. Self-hosted patterns
    for pat, vendor, kind in _SELF_HOSTED_PATTERNS:
        for m in pat.findall(text):
            _add(DiscoveredEndpoint(
                vendor=vendor, kind=kind, indicator=m,
                confidence=0.80, source_label=source_label,
            ))

    # 3. Scheme patterns (mcp://, langsmith, agentops…)
    for pat, vendor, kind in _SCHEME_PATTERNS:
        for m in pat.findall(text):
            _add(DiscoveredEndpoint(
                vendor=vendor, kind=kind, indicator=m,
                confidence=0.85, source_label=source_label,
            ))

    # 4. Credential / env-key indicators
    upper = text.upper()
    for key, (vendor, kind) in _KEY_INDICATORS.items():
        if key in upper:
            _add(DiscoveredEndpoint(
                vendor=vendor, kind=kind, indicator=key,
                confidence=0.70, source_label=source_label,
            ))

    return found


def scan_artefacts(
    artefacts: Iterable[Dict[str, str]],
) -> List[DiscoveredEndpoint]:
    """Scan a sequence of {label, content} blobs and merge results.

    Useful when an integration uploads a batch of files / configs.
    """
    merged: Dict[Tuple[str, str, str], DiscoveredEndpoint] = {}
    for art in artefacts:
        label = str(art.get("label", ""))
        content = str(art.get("content", ""))
        for ep in scan_text(content, source_label=label):
            key = (ep.vendor, ep.kind, ep.indicator)
            existing = merged.get(key)
            if existing is None or ep.confidence > existing.confidence:
                merged[key] = ep
    return list(merged.values())


def summarise(endpoints: List[DiscoveredEndpoint]) -> Dict[str, object]:
    """Produce a compact dashboard-friendly summary of a scan."""
    by_vendor: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for ep in endpoints:
        by_vendor[ep.vendor] = by_vendor.get(ep.vendor, 0) + 1
        by_kind[ep.kind] = by_kind.get(ep.kind, 0) + 1
    consumer = [ep for ep in endpoints if ep.kind == "consumer_chat"]
    self_hosted = [ep for ep in endpoints if ep.kind == "self_hosted"]
    agent = [ep for ep in endpoints if ep.kind in ("agent_mcp", "agent_telemetry")]
    creds = [ep for ep in endpoints if ep.kind == "credential"]
    # Heuristic risk heuristic: shadow-AI surface area = consumer_chat
    # + credentials present without an enterprise control plane.
    shadow_ai_indicators = len(consumer) + len(creds)
    return {
        "total": len(endpoints),
        "by_vendor": by_vendor,
        "by_kind": by_kind,
        "shadow_ai_indicators": shadow_ai_indicators,
        "self_hosted_count": len(self_hosted),
        "agent_surface_count": len(agent),
    }
