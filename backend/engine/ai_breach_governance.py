"""
AI BREACH GOVERNANCE — tamper-evident audit chain + agent quarantine.
=====================================================================

Two additive mechanisms layered on top of the existing AI-breach detector:

1. ``AuditChain``
   - Append-only ledger of detections.
   - Each entry stores (prev_hash, payload_json) and a SHA-256 commit hash.
   - ``verify()`` walks the chain and returns the first index where the
     hash linkage is broken (or -1 if intact). This makes any post-hoc
     tampering with a logged AI detection trivially detectable, satisfying
     NIST AI RMF GOVERN-1.4 ("decisions are documented and traceable")
     and the EU AI Act Art. 12 logging obligation for high-risk systems.

2. ``AgentQuarantine``
   - Per-actor rolling risk budget over a configurable window.
   - When the cumulative risk score for an actor crosses ``threshold``,
     the actor is marked quarantined and a structured "kill-switch" record
     is produced. Listing endpoints can return this record to drive
     downstream IDP / IAM disable hooks (out of scope here).
   - Quarantine is informational, never destructive — the human-review
     gate still owns final action, preserving the
     ``confidence < 0.70 -> requires_human_review = True`` invariant.

Both pieces are stdlib-only and process-local. A multi-worker deployment
would back the chain with the existing PersistenceService and the
quarantine map with Redis; for the current single-worker Render service
the in-memory implementation is sufficient and is fully exercised by
unit tests.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional


# ── Audit chain ──────────────────────────────────────

GENESIS_HASH = "0" * 64


def _canonical_json(obj: Any) -> str:
    """Stable JSON for hashing — sorted keys, no whitespace, default=str."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, payload_json: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"|")
    h.update(payload_json.encode("utf-8"))
    return h.hexdigest()


@dataclass
class AuditEntry:
    index: int
    timestamp: datetime
    prev_hash: str
    payload: Dict[str, Any]
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "prev_hash": self.prev_hash,
            "payload": self.payload,
            "entry_hash": self.entry_hash,
        }


class AuditChain:
    """Append-only, hash-linked ledger of AI breach detections."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._entries: List[AuditEntry] = []

    def append(self, payload: Dict[str, Any]) -> AuditEntry:
        with self._lock:
            prev = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            payload_json = _canonical_json(payload)
            entry = AuditEntry(
                index=len(self._entries),
                timestamp=datetime.now(timezone.utc),
                prev_hash=prev,
                payload=payload,
                entry_hash=_hash(prev, payload_json),
            )
            self._entries.append(entry)
            return entry

    def append_detections(self, detections: Iterable[Any]) -> List[AuditEntry]:
        out: List[AuditEntry] = []
        for d in detections:
            payload = d.to_dict() if hasattr(d, "to_dict") else dict(d)
            out.append(self.append(payload))
        return out

    def entries(self, *, limit: Optional[int] = None) -> List[AuditEntry]:
        with self._lock:
            data = list(self._entries)
        if limit is not None:
            data = data[-limit:]
        return data

    def head(self) -> str:
        with self._lock:
            return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def verify(self) -> Dict[str, Any]:
        """Return chain integrity status. ``broken_at`` is -1 if intact."""
        with self._lock:
            entries = list(self._entries)
        prev = GENESIS_HASH
        for e in entries:
            expected = _hash(prev, _canonical_json(e.payload))
            if e.prev_hash != prev or e.entry_hash != expected:
                return {
                    "intact": False,
                    "broken_at": e.index,
                    "length": len(entries),
                    "head": entries[-1].entry_hash if entries else GENESIS_HASH,
                }
            prev = e.entry_hash
        return {
            "intact": True,
            "broken_at": -1,
            "length": len(entries),
            "head": prev,
        }


# ── Agent quarantine / circuit breaker ───────────────

@dataclass
class QuarantineRecord:
    actor_id: str
    cumulative_risk: float
    detections: int
    window_minutes: int
    quarantined_at: datetime
    reason: str
    requires_human_review: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "cumulative_risk": round(self.cumulative_risk, 1),
            "detections": self.detections,
            "window_minutes": self.window_minutes,
            "quarantined_at": self.quarantined_at.isoformat(),
            "reason": self.reason,
            "requires_human_review": self.requires_human_review,
        }


class AgentQuarantine:
    """Track per-actor risk over a rolling window. Quarantine when over budget."""

    def __init__(
        self,
        *,
        threshold: float = 150.0,
        window_minutes: int = 60,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be > 0")
        if window_minutes <= 0:
            raise ValueError("window_minutes must be > 0")
        self._lock = RLock()
        self.threshold = float(threshold)
        self.window_minutes = int(window_minutes)
        # actor_id -> list[(timestamp, risk_score, pattern)]
        self._events: Dict[str, List[tuple]] = {}
        self._quarantined: Dict[str, QuarantineRecord] = {}

    def _prune(self, actor_id: str, now: datetime) -> None:
        cutoff = now - timedelta(minutes=self.window_minutes)
        kept = [e for e in self._events.get(actor_id, []) if e[0] >= cutoff]
        self._events[actor_id] = kept

    def record(self, detection: Any, *, actor_id: Optional[str] = None) -> Optional[QuarantineRecord]:
        """Record a detection. Returns a QuarantineRecord if the actor just crossed
        the threshold on this call, else None."""
        d = detection
        actor = actor_id or getattr(d, "actor_id", None) or (
            d.get("actor_id") if isinstance(d, dict) else None
        )
        if not actor:
            # Detections don't always carry an actor id directly; fall back to
            # the first signal id so we still have a stable bucket.
            sig_ids = getattr(d, "signal_ids", None) or (
                d.get("signal_ids") if isinstance(d, dict) else None
            )
            actor = f"signal:{sig_ids[0]}" if sig_ids else "unknown"
        risk = float(getattr(d, "risk_score", 0.0) or (
            d.get("risk_score", 0.0) if isinstance(d, dict) else 0.0
        ))
        pattern = getattr(d, "pattern", None)
        pattern_value = pattern.value if hasattr(pattern, "value") else (
            d.get("pattern") if isinstance(d, dict) else "unknown"
        )
        now = datetime.now(timezone.utc)
        with self._lock:
            self._events.setdefault(actor, []).append((now, risk, pattern_value))
            self._prune(actor, now)
            cumulative = sum(e[1] for e in self._events[actor])
            count = len(self._events[actor])
            if actor in self._quarantined:
                return None
            if cumulative >= self.threshold:
                rec = QuarantineRecord(
                    actor_id=actor,
                    cumulative_risk=cumulative,
                    detections=count,
                    window_minutes=self.window_minutes,
                    quarantined_at=now,
                    reason=(
                        f"cumulative AI-breach risk {cumulative:.1f} >= "
                        f"threshold {self.threshold:.1f} over {self.window_minutes}m"
                    ),
                )
                self._quarantined[actor] = rec
                return rec
        return None

    def status(self, actor_id: str) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._prune(actor_id, now)
            events = self._events.get(actor_id, [])
            cumulative = sum(e[1] for e in events)
            quarantined = self._quarantined.get(actor_id)
        return {
            "actor_id": actor_id,
            "quarantined": quarantined is not None,
            "cumulative_risk": round(cumulative, 1),
            "detections_in_window": len(events),
            "threshold": self.threshold,
            "window_minutes": self.window_minutes,
            "record": quarantined.to_dict() if quarantined else None,
        }

    def list_quarantined(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._quarantined.values()]

    def release(self, actor_id: str) -> bool:
        """Manually clear a quarantine (requires human review upstream)."""
        with self._lock:
            existed = actor_id in self._quarantined
            self._quarantined.pop(actor_id, None)
            self._events.pop(actor_id, None)
            return existed
