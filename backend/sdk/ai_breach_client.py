"""
DriftGuard AI Breach Client
============================
Thin Python helper for sending AI-era signals (LLM calls, agent actions,
non-human-identity activity) to DriftGuard's `/ai-breach` endpoints and
retrieving detections, playbooks and the 24-hour risk forecast.

Stdlib only. Works against any DriftGuard instance reachable over HTTP.

Example:
    client = AIBreachClient("https://driftguard-api-mbdj.onrender.com")
    signal = build_signal(
        actor_type="agent",
        actor_id="copilot-agent-7",
        action="tool_call",
        prompt_size_tokens=900,
        contains_instruction_tokens=True,
    )
    result = client.scan([signal])
    print(result["aggregate"]["alert_level"])
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def build_signal(
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    timestamp: Optional[str] = None,
    model_id: Optional[str] = None,
    model_version: Optional[str] = None,
    tool_name: Optional[str] = None,
    destination: Optional[str] = None,
    prompt_size_tokens: int = 0,
    output_size_tokens: int = 0,
    contains_instruction_tokens: bool = False,
    decision_latency_ms: int = 0,
    approved_by_human: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a single AI signal dict that the `/ai-breach/scan` endpoint accepts.

    `actor_type` should be one of: "human", "agent", "service_account",
    "model", "nhi". `action` is free-form ("tool_call", "prompt", "fine_tune",
    "deploy", etc.). All numeric fields default to zero so callers can supply
    only what they have.
    """
    return {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "model_id": model_id,
        "model_version": model_version,
        "action": action,
        "tool_name": tool_name,
        "destination": destination,
        "prompt_size_tokens": int(prompt_size_tokens),
        "output_size_tokens": int(output_size_tokens),
        "contains_instruction_tokens": bool(contains_instruction_tokens),
        "decision_latency_ms": int(decision_latency_ms),
        "approved_by_human": bool(approved_by_human),
        "metadata": metadata or {},
    }


class AIBreachClient:
    """Synchronous client for the DriftGuard AI breach endpoints.

    Uses urllib so it has zero third-party dependencies.
    """

    def __init__(
        self,
        base_url: str,
        api_prefix: str = "/api/v1",
        timeout: float = 10.0,
        api_key: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_prefix = "/" + api_prefix.strip("/")
        self.timeout = timeout
        self.api_key = api_key

    # --- HTTP plumbing ---------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.base_url}{self.api_prefix}/ai-breach{path}"

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self._url(path), data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            payload = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"DriftGuard {method} {path} -> HTTP {e.code}: {payload}") from None

    # --- Public API ------------------------------------------------------
    def patterns(self) -> Dict[str, Any]:
        """Return the catalogue of seven AI breach patterns."""
        return self._request("GET", "/patterns")

    def scan(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run heuristic detection over a batch of `AISignal` records.

        Returns the full response including `detections` and `aggregate`
        (overall_risk_score, alert_level, active_patterns).
        """
        return self._request("POST", "/scan", {"signals": signals})

    def risk(self, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate-only risk view for the supplied signals."""
        return self._request("POST", "/risk", {"signals": signals})

    def playbooks(self) -> Dict[str, Any]:
        """All seven mitigation playbooks with MITRE ATLAS mapping."""
        return self._request("GET", "/playbooks")

    def playbook(self, pattern: str) -> Dict[str, Any]:
        """Single playbook for a given pattern enum value (eg. 'Prompt_Injection')."""
        return self._request("GET", f"/playbooks/{pattern}")

    def forecast(self) -> Dict[str, Any]:
        """24-hour EWMA risk forecast (auto-seeds with demo points if empty)."""
        return self._request("GET", "/forecast")

    def correlate(
        self,
        signals: List[Dict[str, Any]],
        human_events: List[Dict[str, Any]],
        window_minutes: int = 60,
    ) -> Dict[str, Any]:
        """Surface AI patterns that fired in the same window as human-drift events."""
        return self._request(
            "POST",
            "/correlate",
            {"signals": signals, "human_events": human_events, "window_minutes": window_minutes},
        )

    def demo(self) -> Dict[str, Any]:
        """Run the bundled demo scan (5 active patterns, Critical level)."""
        return self._request("GET", "/demo")
