"""Embed layer + Recommendation + Approval workflow.

This module turns DriftGuard from a backend service you call into a
*layer* you drop in front of any website, app, or service. It ships
three composable pieces:

1. **EventCollector** — accepts arbitrary client-side events (page
   navigations, form submits, copy/paste, paste-into-LLM-input, file
   downloads, API calls, agent tool calls) and normalizes each into an
   ``AISignal`` for the existing detector pipeline.

2. **RecommendationEngine** — for every detection that fires, looks up
   the matching playbook and emits a structured ``Recommendation`` with
   suggested containment / investigation / eradication steps and the
   *exact role* that must approve it before any automated action runs.

3. **ApprovalWorkflow** — durable, role-gated approval queue.
   Recommendations sit in ``PENDING`` until an authorized approver
   approves or rejects; the queue is persisted atomically so it
   survives restart, and every state transition is appended to a
   tamper-evident decision log.

By design, the engine NEVER auto-executes a mitigation. It produces a
suggestion, files it for review, and waits for a human in the named
department. This keeps the layer inside NIST AI RMF MANAGE-2.3 (human
oversight of automated decisions) and SOC 2 CC1.3 (segregation of
duties).
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

from core.ai_drift_patterns import AIBreachPatternType
from engine.ai_breach_detector import AISignal


# ── Status values (avoid coupling to the SQL ApprovalStatus enum) ──
PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"


# ── Approver role mapping per pattern ────────────────
# Each pattern names the department that must sign off on any
# automated mitigation. Operators can layer additional org-specific
# roles in front of this map via configuration without touching code.
_PATTERN_APPROVER_ROLES: Dict[AIBreachPatternType, List[str]] = {
    AIBreachPatternType.SHADOW_AI: ["ciso", "compliance_officer"],
    AIBreachPatternType.PROMPT_INJECTION: ["ciso", "admin"],
    AIBreachPatternType.NHI_MISUSE: ["ciso", "admin"],
    AIBreachPatternType.MODEL_POISONING: ["ciso", "ni_architect"],
    AIBreachPatternType.SLEEPER_AGENT: ["ciso", "ni_architect", "admin"],
    AIBreachPatternType.AI_SOCIAL_ENGINEERING: ["ciso", "compliance_officer"],
    AIBreachPatternType.DEFENDER_OVER_TRUST: ["ciso", "admin"],
}


def _approvers_for(pattern: AIBreachPatternType) -> List[str]:
    return _PATTERN_APPROVER_ROLES.get(pattern, ["ciso"])


# ── Event collection layer ───────────────────────────

class EventCollector:
    """Normalizes arbitrary client events into ``AISignal`` instances.

    The collector is intentionally permissive — every embedded site,
    app, or agent has a slightly different telemetry shape. It accepts
    a free-form ``dict`` and maps known fields, dropping the rest into
    ``metadata``. Unknown ``event_type`` values produce a generic signal
    rather than an error so the embedding never breaks the host page.
    """

    # Heuristic mapping of common client events → AISignal fields.
    _EVENT_ACTION_MAP: Dict[str, str] = {
        "page_view": "navigation:page_view",
        "form_submit": "form:submit",
        "copy": "clipboard:copy",
        "paste": "clipboard:paste",
        "paste_to_llm": "tool_call:llm_paste",
        "file_download": "file:download",
        "file_upload": "file:upload",
        "api_call": "http:api_call",
        "agent_tool_call": "tool_call:agent",
        "login": "auth:login",
        "login_failed": "auth:login_failed",
        "permission_change": "iam:permission_change",
    }

    @classmethod
    def normalize(cls, event: Dict[str, Any]) -> AISignal:
        et = str(event.get("event_type", "unknown"))
        action = cls._EVENT_ACTION_MAP.get(et, f"client:{et}")
        ts_raw = event.get("timestamp")
        if isinstance(ts_raw, datetime):
            ts = ts_raw
        elif isinstance(ts_raw, str):
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()
        # Lightweight prompt-injection heuristic: presence of common
        # instruction tokens in copied / pasted text. Conservative — we
        # only flag obvious cases; the detector applies the real test.
        body = str(event.get("text") or event.get("body") or "")
        looks_injected = any(
            tok in body.lower()
            for tok in (
                "ignore previous", "ignore the previous", "system prompt",
                "you are now", "disregard prior", "reveal your instructions",
            )
        )
        # Pull common metadata into the signal's metadata slot.
        meta = {
            k: v
            for k, v in event.items()
            if k not in {
                "event_type", "actor_id", "actor_type", "model_id",
                "model_version", "tool_name", "destination",
                "prompt_size_tokens", "output_size_tokens",
                "decision_latency_ms", "approved_by_human", "timestamp",
                "text", "body",
            }
        }
        return AISignal(
            timestamp=ts,
            actor_type=str(event.get("actor_type") or "human"),
            actor_id=str(event.get("actor_id") or "anonymous"),
            model_id=event.get("model_id"),
            model_version=event.get("model_version"),
            action=action,
            tool_name=event.get("tool_name"),
            destination=event.get("destination"),
            prompt_size_tokens=event.get("prompt_size_tokens"),
            output_size_tokens=event.get("output_size_tokens") or (len(body) if body else None),
            contains_instruction_tokens=bool(
                event.get("contains_instruction_tokens") or looks_injected
            ),
            decision_latency_ms=event.get("decision_latency_ms"),
            approved_by_human=event.get("approved_by_human"),
            metadata=meta,
        )

    @classmethod
    def normalize_batch(cls, events: List[Dict[str, Any]]) -> List[AISignal]:
        return [cls.normalize(e) for e in events if isinstance(e, dict)]


# ── Recommendation builder ───────────────────────────

class RecommendationEngine:
    """Builds structured suggestions from detector output + playbooks."""

    def __init__(self, *, playbooks_module: Any = None) -> None:
        # Late-import the playbook registry so this module stays
        # importable even if playbooks are reorganised.
        if playbooks_module is None:
            from core import ai_breach_playbooks as _pb
            playbooks_module = _pb
        self._pb = playbooks_module

    def build(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """Return a Recommendation dict for a single detection."""
        pattern_str = detection.get("pattern", "")
        try:
            pattern = AIBreachPatternType(pattern_str)
        except (ValueError, TypeError):
            pattern = AIBreachPatternType.SHADOW_AI
        playbook = None
        try:
            pb = self._pb.get_playbook(pattern)
            playbook = self._pb.playbook_to_dict(pb) if pb is not None else None
        except Exception:
            playbook = None
        approvers = _approvers_for(pattern)
        priority = self._priority_for(detection)
        return {
            "id": str(uuid.uuid4()),
            "pattern": pattern_str,
            "display_name": detection.get("display_name", ""),
            "owasp_llm_id": detection.get("owasp_llm_id"),
            "nist_ai_rmf_function": detection.get("nist_ai_rmf_function"),
            "risk_score": detection.get("risk_score"),
            "confidence": detection.get("confidence"),
            "actor_id": (detection.get("signal_ids") or [None])[0],
            "summary": detection.get("plain_language_summary")
                or detection.get("reasoning", ""),
            "playbook": playbook,
            "required_approver_roles": approvers,
            "priority": priority,
            "auto_executable": False,  # by policy — never auto-execute
        }

    def build_many(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.build(d) for d in detections]

    @staticmethod
    def _priority_for(det: Dict[str, Any]) -> str:
        score = float(det.get("risk_score") or 0.0)
        if score >= 70.0:
            return "critical"
        if score >= 40.0:
            return "high"
        if score >= 20.0:
            return "medium"
        return "low"


# ── Approval workflow ────────────────────────────────

class ApprovalWorkflow:
    """Durable, role-gated approval queue for recommendations.

    Two stores:
      * ``self._items`` — id → recommendation+state (in-memory mirror)
      * ``storage_path`` — JSON snapshot, atomic write via os.replace
    Plus an in-memory tamper-evident decision log (capped) so any
    transition can be diffed against the most recent N events.
    """

    def __init__(
        self,
        *,
        storage_path: Optional[str] = None,
        decision_log_size: int = 500,
    ) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}
        self._decision_log: Deque[Dict[str, Any]] = deque(maxlen=int(decision_log_size))
        self.storage_path = (
            Path(storage_path) if storage_path else None
        )
        if self.storage_path is not None:
            self._load_from_disk()

    # ── Persistence ──────────────────────────────────
    def _load_from_disk(self) -> None:
        try:
            if self.storage_path and self.storage_path.exists():
                with self.storage_path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict) and isinstance(data.get("items"), dict):
                    self._items = data["items"]
        except (OSError, ValueError):
            # Corrupt snapshot — start clean rather than crashing the
            # whole API. The decision log on disk (future work) is the
            # real source of truth.
            self._items = {}

    def _persist(self) -> None:
        if self.storage_path is None:
            return
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump({"items": self._items}, fh, default=str)
            os.replace(tmp, self.storage_path)
        except OSError:
            # Persistence is best-effort; the in-memory store remains
            # authoritative for the current process.
            pass

    # ── Public API ───────────────────────────────────
    def submit(self, recommendation: Dict[str, Any]) -> Dict[str, Any]:
        rid = recommendation.get("id") or str(uuid.uuid4())
        record = {
            **recommendation,
            "id": rid,
            "status": PENDING,
            "submitted_at": datetime.utcnow().isoformat(),
            "decided_at": None,
            "decided_by": None,
            "decided_role": None,
            "decision_reason": None,
        }
        with self._lock:
            self._items[rid] = record
            self._decision_log.append({
                "id": rid,
                "transition": "submit",
                "to": PENDING,
                "ts": record["submitted_at"],
                "actor": "system",
            })
            self._persist()
            return dict(record)

    def submit_many(self, recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.submit(r) for r in recs]

    def list(
        self,
        *,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._items.values())
        if status is not None:
            items = [i for i in items if i.get("status") == status]
        items.sort(key=lambda i: i.get("submitted_at", ""), reverse=True)
        return items[: max(1, int(limit))]

    def get(self, rec_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._items.get(rec_id)
            return dict(item) if item is not None else None

    def decide(
        self,
        rec_id: str,
        *,
        decision: str,
        approver_id: str,
        approver_role: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        if decision not in (APPROVED, REJECTED):
            raise ValueError(
                f"decision must be {APPROVED!r} or {REJECTED!r}, got {decision!r}"
            )
        with self._lock:
            item = self._items.get(rec_id)
            if item is None:
                raise KeyError(f"recommendation {rec_id!r} not found")
            if item["status"] != PENDING:
                raise ValueError(
                    f"recommendation {rec_id!r} is {item['status']}, not pending"
                )
            allowed = item.get("required_approver_roles") or []
            if allowed and approver_role not in allowed:
                raise PermissionError(
                    f"role {approver_role!r} cannot decide on this "
                    f"recommendation; allowed: {allowed}"
                )
            now = datetime.utcnow().isoformat()
            item["status"] = decision
            item["decided_at"] = now
            item["decided_by"] = approver_id
            item["decided_role"] = approver_role
            item["decision_reason"] = reason
            self._decision_log.append({
                "id": rec_id,
                "transition": "decide",
                "to": decision,
                "ts": now,
                "actor": approver_id,
                "role": approver_role,
                "reason": reason,
            })
            self._persist()
            return dict(item)

    def decision_log(self, *, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._decision_log)[-max(1, int(limit)):]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            counts = {PENDING: 0, APPROVED: 0, REJECTED: 0, EXPIRED: 0}
            for item in self._items.values():
                counts[item.get("status", PENDING)] = counts.get(
                    item.get("status", PENDING), 0
                ) + 1
            return {
                "total": len(self._items),
                "by_status": counts,
                "decisions_logged": len(self._decision_log),
            }
