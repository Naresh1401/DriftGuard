"""Real-time per-actor risk trajectory + z-score anomaly detection.

This module turns DriftGuard's per-request scan results into a streaming,
stateful signal. Each scan feeds a per-actor rolling window of
(timestamp, risk_score) samples. From that window we compute a baseline
mean / stdev and flag points whose z-score exceeds a configurable
threshold as live anomalies.

Design goals
------------
* Stdlib only (``statistics``, ``collections.deque``, ``threading``).
* Bounded memory: per-actor deques and a global anomaly buffer are both
  capped.
* Thread-safe under uvicorn's default async + worker model — every public
  method acquires ``self._lock``.
* No file I/O. State is process-local; multi-worker correctness is an
  explicit non-goal (mirrors the existing ``RiskForecaster`` and
  ``AgentQuarantine`` posture, see Appendix J).

The analyzer is intentionally orthogonal to ``AIBreachDetector``: it does
not classify drift, it watches how aggregate risk *moves* per actor over
time. A burst of medium-severity detections from a single actor will
trip an anomaly even if no single detection crosses the Critical
threshold — which is exactly what regulators expect from
"continuous monitoring" (NIST AI RMF MEASURE-2.7 / GOVERN-1.5).
"""
from __future__ import annotations

import statistics
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional, Tuple


# ── Defaults ─────────────────────────────────────────
_DEFAULT_WINDOW = 50           # max samples kept per actor
_DEFAULT_BASELINE_MIN = 8      # need at least this many points to z-score
_DEFAULT_Z_THRESHOLD = 2.5     # ~99% of normal traffic; anything beyond is flagged
_DEFAULT_ANOMALY_BUFFER = 200  # global ring buffer of anomaly events
_DEFAULT_TTL_MINUTES = 60      # drop samples older than this (rolling window)


class RealtimeAnalyzer:
    """Per-actor rolling risk trajectory with z-score anomaly detection."""

    def __init__(
        self,
        *,
        window: int = _DEFAULT_WINDOW,
        baseline_min: int = _DEFAULT_BASELINE_MIN,
        z_threshold: float = _DEFAULT_Z_THRESHOLD,
        anomaly_buffer: int = _DEFAULT_ANOMALY_BUFFER,
        ttl_minutes: int = _DEFAULT_TTL_MINUTES,
    ) -> None:
        self.window = int(window)
        self.baseline_min = int(baseline_min)
        self.z_threshold = float(z_threshold)
        self.ttl = timedelta(minutes=int(ttl_minutes))
        self._lock = threading.Lock()
        self._tracks: Dict[str, Deque[Tuple[datetime, float]]] = {}
        self._anomalies: Deque[Dict[str, Any]] = deque(maxlen=int(anomaly_buffer))

    # ── Internal helpers ─────────────────────────────
    def _evict_stale(self, track: Deque[Tuple[datetime, float]], now: datetime) -> None:
        cutoff = now - self.ttl
        while track and track[0][0] < cutoff:
            track.popleft()

    def _baseline(self, track: Deque[Tuple[datetime, float]]) -> Optional[Tuple[float, float]]:
        if len(track) < self.baseline_min:
            return None
        # Use everything *before* the latest sample for the baseline so the
        # current point is scored against its own past, not against itself.
        scores = [s for _, s in list(track)[:-1]]
        if len(scores) < self.baseline_min - 1:
            return None
        try:
            mu = statistics.mean(scores)
            sigma = statistics.pstdev(scores)
        except statistics.StatisticsError:
            return None
        return mu, sigma

    # ── Public API ───────────────────────────────────
    def observe(
        self,
        actor_id: str,
        risk_score: float,
        *,
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Record one (actor, score) sample and return its anomaly verdict.

        Return shape::

            {
              "actor_id": str,
              "risk_score": float,
              "timestamp": iso8601,
              "samples": int,
              "baseline_ready": bool,
              "z": float | None,
              "anomaly": bool,
              "reason": str,
            }

        The returned dict is also appended to the global anomaly ring
        buffer when ``anomaly=True``, so SSE subscribers can replay the
        most recent N anomalies on reconnect.
        """
        ts = timestamp or datetime.utcnow()
        actor = str(actor_id)
        score = float(risk_score)
        with self._lock:
            track = self._tracks.setdefault(actor, deque(maxlen=self.window))
            track.append((ts, score))
            self._evict_stale(track, ts)
            base = self._baseline(track)
            if base is None:
                verdict = {
                    "actor_id": actor,
                    "risk_score": round(score, 2),
                    "timestamp": ts.isoformat(),
                    "samples": len(track),
                    "baseline_ready": False,
                    "z": None,
                    "anomaly": False,
                    "reason": "warming up — not enough history for baseline",
                }
                return verdict
            mu, sigma = base
            if sigma <= 1e-9:
                # Degenerate baseline (all-equal history). Only flag if the
                # new sample is meaningfully different.
                anomaly = abs(score - mu) > 1e-6
                z: Optional[float] = float("inf") if anomaly else 0.0
                reason = (
                    f"baseline is constant at {mu:.1f}; new value {score:.1f} differs"
                    if anomaly
                    else "baseline constant and new value matches"
                )
            else:
                z = (score - mu) / sigma
                anomaly = abs(z) >= self.z_threshold
                reason = (
                    f"|z|={abs(z):.2f} >= {self.z_threshold} (mu={mu:.1f}, sigma={sigma:.1f})"
                    if anomaly
                    else f"|z|={abs(z):.2f} < {self.z_threshold}"
                )
            verdict = {
                "actor_id": actor,
                "risk_score": round(score, 2),
                "timestamp": ts.isoformat(),
                "samples": len(track),
                "baseline_ready": True,
                "baseline_mean": round(mu, 2),
                "baseline_stdev": round(sigma, 2),
                "z": None if z is None else (round(z, 3) if z != float("inf") else None),
                "anomaly": bool(anomaly),
                "reason": reason,
            }
            if anomaly:
                self._anomalies.append(verdict)
            return verdict

    def trajectory(self, actor_id: str) -> Dict[str, Any]:
        """Return the full rolling window for one actor plus its baseline."""
        actor = str(actor_id)
        with self._lock:
            track = self._tracks.get(actor)
            if not track:
                return {
                    "actor_id": actor,
                    "samples": 0,
                    "points": [],
                    "baseline_ready": False,
                }
            base = self._baseline(track)
            return {
                "actor_id": actor,
                "samples": len(track),
                "points": [
                    {"ts": t.isoformat(), "risk": round(s, 2)} for t, s in track
                ],
                "baseline_ready": base is not None,
                "baseline_mean": round(base[0], 2) if base else None,
                "baseline_stdev": round(base[1], 2) if base else None,
                "z_threshold": self.z_threshold,
            }

    def actors(self) -> List[Dict[str, Any]]:
        """Snapshot: one row per tracked actor, ordered by latest score desc."""
        with self._lock:
            rows = []
            for actor, track in self._tracks.items():
                if not track:
                    continue
                latest_ts, latest_score = track[-1]
                base = self._baseline(track)
                rows.append({
                    "actor_id": actor,
                    "samples": len(track),
                    "latest_ts": latest_ts.isoformat(),
                    "latest_risk": round(latest_score, 2),
                    "baseline_mean": round(base[0], 2) if base else None,
                    "baseline_stdev": round(base[1], 2) if base else None,
                })
        rows.sort(key=lambda r: r["latest_risk"], reverse=True)
        return rows

    def recent_anomalies(self, *, limit: int = 50) -> List[Dict[str, Any]]:
        """Most recent anomalies, newest last. Used by /anomalies and SSE."""
        with self._lock:
            return list(self._anomalies)[-int(limit):]

    def stats(self) -> Dict[str, Any]:
        """Lightweight overview for dashboards / health checks."""
        with self._lock:
            return {
                "actors_tracked": len(self._tracks),
                "anomalies_buffered": len(self._anomalies),
                "window": self.window,
                "baseline_min": self.baseline_min,
                "z_threshold": self.z_threshold,
                "ttl_minutes": int(self.ttl.total_seconds() / 60),
            }
