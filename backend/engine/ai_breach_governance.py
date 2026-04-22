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
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    """Append-only, hash-linked ledger of AI breach detections.

    If ``storage_path`` is provided, every appended entry is also persisted
    to that JSON-Lines file (one entry per line). On construction the file
    is replayed so the chain survives process restarts. The file format is
    intentionally trivial — `cat`, `tail`, `wc` and `jq` all work — and
    contains no secrets, so it can safely be checked into a backup bucket.
    """

    def __init__(self, *, storage_path: Optional[str] = None) -> None:
        self._lock = RLock()
        self._entries: List[AuditEntry] = []
        self._storage_path: Optional[Path] = (
            Path(storage_path) if storage_path else None
        )
        if self._storage_path is not None:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        path = self._storage_path
        if path is None or not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    raw = json.loads(line)
                    entry = AuditEntry(
                        index=int(raw["index"]),
                        timestamp=datetime.fromisoformat(raw["timestamp"]),
                        prev_hash=str(raw["prev_hash"]),
                        payload=raw["payload"],
                        entry_hash=str(raw["entry_hash"]),
                    )
                    self._entries.append(entry)
        except (OSError, ValueError, KeyError):
            # Corrupted file — keep what we managed to load and let
            # verify() flag the discontinuity to operators.
            return

    def _persist(self, entry: AuditEntry) -> None:
        if self._storage_path is None:
            return
        try:
            with self._storage_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict(), default=str))
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            # Persistence is best-effort; in-memory chain is still authoritative
            # for the running process.
            pass

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
            self._persist(entry)
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

    def entry_at(self, index: int) -> Optional[AuditEntry]:
        """Return the entry at the given chain index, or ``None`` if out of
        range. Used by the per-entry receipt endpoint so a customer can
        prove a single detection was logged without disclosing the rest of
        the chain."""
        with self._lock:
            if 0 <= index < len(self._entries):
                return self._entries[index]
        return None

    @staticmethod
    def verify_entry_receipt(entry: Dict[str, Any]) -> Dict[str, Any]:
        """Self-contained verification of a single entry receipt — does not
        require access to the live chain.

        Recomputes ``entry_hash = sha256(prev_hash || canonical(payload))``
        and compares to the stored ``entry_hash``. This proves the receipt
        is internally well-formed (the payload hasn't been edited and the
        hash binding is intact). Cross-checking that the receipt matches
        what the live chain holds at ``entry.index`` is left to the caller
        (typically by fetching ``GET /audit/entry/{index}`` and comparing
        ``entry_hash`` byte-for-byte)."""
        try:
            prev_hash = str(entry["prev_hash"])
            payload = entry["payload"]
            stored = str(entry["entry_hash"])
        except (KeyError, TypeError):
            return {"valid": False, "reason": "malformed entry receipt"}
        recomputed = _hash(prev_hash, _canonical_json(payload))
        if recomputed != stored:
            return {
                "valid": False,
                "reason": "entry_hash does not match prev_hash + canonical(payload)",
                "expected": recomputed,
                "stored": stored,
            }
        return {"valid": True, "reason": "entry hash binding intact"}

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

    def anchor_snapshot(self, *, anchor_dir: Optional[str] = None) -> Dict[str, Any]:
        """Produce a portable, signed-by-content snapshot of the current chain
        head. Anchors are themselves hash-linked: each new anchor embeds the
        previous anchor's id, so the published anchor stream forms a second
        tamper-evident chain. A regulator holding *any* past anchor can
        verify the whole anchor history forward.

        The snapshot doc is
        ``{length, head, timestamp, prev_anchor_id, anchor_id}`` where
        ``anchor_id = sha256(length || head || timestamp || prev_anchor_id)``.
        For the very first anchor minted into a directory, ``prev_anchor_id``
        is ``GENESIS_HASH``. Legacy anchors that omit ``prev_anchor_id`` are
        still verifiable via the original formula (see ``verify_anchor``).

        If ``anchor_dir`` is provided, the snapshot is also written there as
        ``anchor-<anchor_id_prefix>.json``. External systems (S3 with
        object-lock, a customer-controlled git repo, a public timestamp
        service) can publish this file to obtain external tamper-evidence
        in addition to the in-process hash chain.
        """
        with self._lock:
            length = len(self._entries)
            head = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        ts = datetime.now(timezone.utc).isoformat()
        prev_anchor_id = GENESIS_HASH
        if anchor_dir:
            prev_anchor_id = self._latest_anchor_id_in_dir(anchor_dir) or GENESIS_HASH
        anchor_id = hashlib.sha256(
            f"{length}|{head}|{ts}|{prev_anchor_id}".encode("utf-8")
        ).hexdigest()
        snapshot = {
            "length": length,
            "head": head,
            "timestamp": ts,
            "prev_anchor_id": prev_anchor_id,
            "anchor_id": anchor_id,
        }
        if anchor_dir:
            try:
                d = Path(anchor_dir)
                d.mkdir(parents=True, exist_ok=True)
                (d / f"anchor-{anchor_id[:16]}.json").write_text(
                    json.dumps(snapshot, indent=2), encoding="utf-8"
                )
                snapshot["written_to"] = str(d)
            except OSError as exc:
                snapshot["write_error"] = str(exc)
        return snapshot

    @staticmethod
    def _latest_anchor_id_in_dir(anchor_dir: str) -> Optional[str]:
        """Find the most recent anchor file in a directory and return its
        ``anchor_id``. Used to chain a new anchor onto the previous one."""
        try:
            d = Path(anchor_dir)
            if not d.exists():
                return None
            latest_ts = ""
            latest_id: Optional[str] = None
            for p in d.glob("anchor-*.json"):
                try:
                    raw = json.loads(p.read_text(encoding="utf-8"))
                    ts = str(raw.get("timestamp", ""))
                    aid = raw.get("anchor_id")
                    if aid and ts > latest_ts:
                        latest_ts = ts
                        latest_id = str(aid)
                except (OSError, ValueError, KeyError):
                    continue
            return latest_id
        except OSError:
            return None

    def verify_anchor(self, anchor: Dict[str, Any]) -> Dict[str, Any]:
        """Verify an external anchor doc against the live chain.

        Returns ``{valid, reason, anchor_length, current_length}``. The check
        proves three things to a regulator without trusting our clock or
        storage:

        1. The anchor's own ``anchor_id`` is recomputable from its fields
           (the snapshot wasn't edited after publication). If the anchor
           includes ``prev_anchor_id`` it is included in the recomputation;
           otherwise the legacy 3-field formula is used so older anchors
           still verify.
        2. The live chain still contains the entry at ``anchor.length`` and
           its hash matches ``anchor.head`` (the chain wasn't truncated or
           reorged below the anchor point).
        3. The chain has only grown since (``current_length >= anchor.length``).
        """
        try:
            length = int(anchor["length"])
            head = str(anchor["head"])
            ts = str(anchor["timestamp"])
            claimed_id = str(anchor["anchor_id"])
        except (KeyError, TypeError, ValueError):
            return {"valid": False, "reason": "malformed anchor document"}

        if "prev_anchor_id" in anchor:
            prev_id = str(anchor["prev_anchor_id"])
            recomputed = hashlib.sha256(
                f"{length}|{head}|{ts}|{prev_id}".encode("utf-8")
            ).hexdigest()
        else:
            recomputed = hashlib.sha256(
                f"{length}|{head}|{ts}".encode("utf-8")
            ).hexdigest()
        if recomputed != claimed_id:
            return {
                "valid": False,
                "reason": "anchor_id does not match its own fields",
                "anchor_length": length,
            }

        with self._lock:
            current_length = len(self._entries)
            if length == 0:
                chain_head_at = GENESIS_HASH
            elif length <= current_length:
                chain_head_at = self._entries[length - 1].entry_hash
            else:
                return {
                    "valid": False,
                    "reason": "chain truncated below anchor",
                    "anchor_length": length,
                    "current_length": current_length,
                }

        if chain_head_at != head:
            return {
                "valid": False,
                "reason": "chain head at anchor.length does not match anchor.head",
                "anchor_length": length,
                "current_length": current_length,
            }
        return {
            "valid": True,
            "reason": "anchor matches live chain",
            "anchor_length": length,
            "current_length": current_length,
            "growth_since_anchor": current_length - length,
        }

    def verify_anchor_history(self, anchor_dir: str) -> Dict[str, Any]:
        """Walk every anchor file in ``anchor_dir`` (sorted by timestamp) and
        prove three things in one shot:

        1. Each anchor's ``anchor_id`` is recomputable from its own fields
           (no individual anchor was edited after publication).
        2. Each anchor's ``prev_anchor_id`` matches the previous anchor's
           ``anchor_id`` (the anchors-of-anchors chain is unbroken). Anchors
           that pre-date the J.1 chaining upgrade are tolerated: they may
           omit ``prev_anchor_id`` and the linkage check is skipped for them.
        3. Each anchor still verifies against the live entry chain.

        Returns ``{count, valid, broken_at, anchors:[…]}`` where ``broken_at``
        is the index of the first failing anchor (or -1 if intact). The
        ``anchors`` list is the per-anchor verification result so a regulator
        can see *exactly* which snapshot failed and why.
        """
        d = Path(anchor_dir)
        if not d.exists():
            return {"count": 0, "valid": True, "broken_at": -1, "anchors": []}

        loaded: List[Dict[str, Any]] = []
        for p in sorted(d.glob("anchor-*.json")):
            try:
                loaded.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                return {
                    "count": len(loaded),
                    "valid": False,
                    "broken_at": len(loaded),
                    "reason": f"anchor file unreadable: {p.name}",
                    "anchors": [],
                }
        loaded.sort(key=lambda a: str(a.get("timestamp", "")))

        results: List[Dict[str, Any]] = []
        prev_id: Optional[str] = None
        for i, anchor in enumerate(loaded):
            res = self.verify_anchor(anchor)
            if not res["valid"]:
                results.append({"index": i, "anchor_id": anchor.get("anchor_id"), **res})
                return {
                    "count": len(loaded),
                    "valid": False,
                    "broken_at": i,
                    "reason": res["reason"],
                    "anchors": results,
                }
            if "prev_anchor_id" in anchor and prev_id is not None:
                expected = prev_id
                if str(anchor["prev_anchor_id"]) != expected:
                    results.append({
                        "index": i,
                        "anchor_id": anchor.get("anchor_id"),
                        "valid": False,
                        "reason": "prev_anchor_id does not match previous anchor",
                    })
                    return {
                        "count": len(loaded),
                        "valid": False,
                        "broken_at": i,
                        "reason": "prev_anchor_id does not match previous anchor",
                        "anchors": results,
                    }
            results.append({
                "index": i,
                "anchor_id": anchor.get("anchor_id"),
                "length": anchor.get("length"),
                "valid": True,
            })
            prev_id = str(anchor.get("anchor_id"))

        return {
            "count": len(loaded),
            "valid": True,
            "broken_at": -1,
            "anchors": results,
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
    """Track per-actor risk over a rolling window. Quarantine when over budget.

    If ``storage_path`` is provided, the set of currently quarantined records
    is persisted to a JSON file and reloaded on construction. The rolling
    event buffer itself is intentionally not persisted — it's window-bounded
    and would re-fill within ``window_minutes`` from new traffic — but the
    *quarantine status* of an actor must survive a restart so a tripped
    breaker does not silently re-arm. This closes the single-worker portion
    of §G.4 gap #2; cross-worker consistency still requires Redis.
    """

    def __init__(
        self,
        *,
        threshold: float = 150.0,
        window_minutes: int = 60,
        storage_path: Optional[str] = None,
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
        self._storage_path: Optional[Path] = (
            Path(storage_path) if storage_path else None
        )
        if self._storage_path is not None:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        path = self._storage_path
        if path is None or not path.exists():
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for item in raw.get("quarantined", []):
                self._quarantined[item["actor_id"]] = QuarantineRecord(
                    actor_id=item["actor_id"],
                    cumulative_risk=float(item["cumulative_risk"]),
                    detections=int(item["detections"]),
                    window_minutes=int(item["window_minutes"]),
                    quarantined_at=datetime.fromisoformat(item["quarantined_at"]),
                    reason=item["reason"],
                    requires_human_review=bool(item.get("requires_human_review", True)),
                )
        except (OSError, ValueError, KeyError):
            return

    def _persist(self) -> None:
        path = self._storage_path
        if path is None:
            return
        try:
            payload = {
                "quarantined": [r.to_dict() for r in self._quarantined.values()],
            }
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            return

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
                self._persist()
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
            if existed:
                self._persist()
            return existed
