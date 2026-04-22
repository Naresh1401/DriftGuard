"""Online learned classifier on top of the heuristic detector.

Closes another limit from Appendix O: detections were rule + threshold
based, with no learning loop. Operators were marking recommendations
``approved`` (confirmed real) or ``rejected`` (false positive) but the
signal was being thrown away.

This module turns the approval decision log into training data for a
small online logistic-regression head per ``(pattern, vendor)`` cell.
The head doesn't replace the heuristic detector — it *re-weights* the
priority and confidence the engine emits, so the operator's own
judgement bends future scoring without anyone editing thresholds.

Pure stdlib. State is JSON-serialisable. Designed to lose gracefully:
when no training data exists the calibration is the identity function
and the heuristic confidence flows through unchanged.
"""
from __future__ import annotations

import json
import math
import os
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Tunables ────────────────────────────────────────
_LEARNING_RATE = 0.10
_L2 = 0.01           # weak shrinkage
_MIN_SAMPLES = 5     # below this, fall through to heuristic
_PRIOR_WEIGHT = 0.5  # bias init toward "alert is true"

# Feature names (kept stable so checkpoints are readable)
_FEATURES = (
    "bias",
    "risk_score_norm",   # detector risk_score / 100
    "confidence",        # detector confidence
    "vendor_consumer",   # 1 if vendor in consumer-chat catalogue
    "vendor_selfhosted", # 1 if self-hosted
    "has_injection",     # 1 if signal flagged instruction tokens
)


def _sigmoid(z: float) -> float:
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


def _features_for(detection: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
    risk = float(detection.get("risk_score") or 0.0)
    conf = float(detection.get("confidence") or 0.0)
    vendor = str(context.get("vendor") or "").lower()
    consumer_vendors = {
        "openai", "anthropic", "google_gemini", "perplexity", "poe",
        "you", "ms_copilot", "github_copilot",
    }
    selfhosted = vendor in {"ollama", "lmstudio", "vllm", "openai_compat", "llama_cpp"}
    return {
        "bias": 1.0,
        "risk_score_norm": min(1.0, risk / 100.0),
        "confidence": min(1.0, max(0.0, conf)),
        "vendor_consumer": 1.0 if vendor in consumer_vendors else 0.0,
        "vendor_selfhosted": 1.0 if selfhosted else 0.0,
        "has_injection": 1.0 if context.get("contains_instruction_tokens") else 0.0,
    }


class LearnedClassifier:
    """One logistic head per ``pattern`` (``Shadow_AI``, ``Prompt_Injection``…).

    All operations are O(|features|). Persistence is an atomic JSON
    file mirroring the approval-queue pattern in embed_layer.
    """

    def __init__(self, *, storage_path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        # weights[pattern][feature_name] -> float
        self._weights: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {f: 0.0 for f in _FEATURES}
        )
        # samples seen per pattern (for the MIN_SAMPLES gate)
        self._counts: Dict[str, int] = defaultdict(int)
        self.storage_path = Path(storage_path) if storage_path else None
        if self.storage_path is not None:
            self._load()

    # ── persistence ──────────────────────────────────
    def _load(self) -> None:
        try:
            if self.storage_path and self.storage_path.exists():
                with self.storage_path.open("r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                if isinstance(raw, dict):
                    weights = raw.get("weights", {})
                    counts = raw.get("counts", {})
                    if isinstance(weights, dict):
                        for pat, w in weights.items():
                            if isinstance(w, dict):
                                self._weights[pat] = {
                                    f: float(w.get(f, 0.0)) for f in _FEATURES
                                }
                    if isinstance(counts, dict):
                        for pat, c in counts.items():
                            self._counts[pat] = int(c)
        except (OSError, ValueError):
            self._weights.clear()
            self._counts.clear()

    def _persist(self) -> None:
        if self.storage_path is None:
            return
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump({
                    "weights": {p: dict(w) for p, w in self._weights.items()},
                    "counts": dict(self._counts),
                }, fh)
            os.replace(tmp, self.storage_path)
        except OSError:
            pass

    # ── inference ────────────────────────────────────
    def calibrate(
        self,
        detection: Dict[str, Any],
        *,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a copy of ``detection`` with a calibrated confidence.

        When the head for the pattern has < MIN_SAMPLES it falls back
        to the heuristic confidence so newly added patterns aren't
        penalised by an empty model.
        """
        ctx = context or {}
        pattern = str(detection.get("pattern") or "")
        out = dict(detection)
        with self._lock:
            count = self._counts.get(pattern, 0)
            weights = self._weights.get(pattern)
            if count < _MIN_SAMPLES or weights is None:
                out["learned_confidence"] = None
                out["learned_samples"] = count
                return out
            feats = _features_for(detection, ctx)
            z = sum(weights[f] * feats[f] for f in _FEATURES)
            p = _sigmoid(z)
        # Blend: average heuristic confidence with the learned head.
        heuristic = float(detection.get("confidence") or 0.0)
        blended = 0.5 * heuristic + 0.5 * p
        out["confidence"] = round(blended, 4)
        out["learned_confidence"] = round(p, 4)
        out["learned_samples"] = count
        return out

    # ── training ─────────────────────────────────────
    def train_one(
        self,
        detection: Dict[str, Any],
        *,
        context: Optional[Dict[str, Any]] = None,
        label: int,
    ) -> None:
        """Apply one SGD step. ``label=1`` if approved, ``0`` if rejected."""
        if label not in (0, 1):
            raise ValueError("label must be 0 (rejected) or 1 (approved)")
        ctx = context or {}
        pattern = str(detection.get("pattern") or "")
        feats = _features_for(detection, ctx)
        with self._lock:
            weights = self._weights[pattern]
            # First-time prior: bias toward "alert is true" so the head
            # matches the heuristic until evidence pushes it elsewhere.
            if self._counts[pattern] == 0:
                weights["bias"] = _PRIOR_WEIGHT
            z = sum(weights[f] * feats[f] for f in _FEATURES)
            p = _sigmoid(z)
            err = p - float(label)
            for f in _FEATURES:
                grad = err * feats[f] + _L2 * weights[f]
                weights[f] -= _LEARNING_RATE * grad
            self._counts[pattern] += 1
        self._persist()

    def train_from_decision_log(
        self,
        log: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """Replay an approval decision log and return per-pattern counts.

        Only ``transition='decide'`` entries with a known ``to`` status
        are used; all others are skipped silently.
        """
        applied: Dict[str, int] = defaultdict(int)
        for entry in log:
            if entry.get("transition") != "decide":
                continue
            to = entry.get("to")
            if to == "approved":
                label = 1
            elif to == "rejected":
                label = 0
            else:
                continue
            det = entry.get("detection") or {}
            ctx = entry.get("context") or {}
            pattern = str(det.get("pattern") or entry.get("pattern") or "")
            if not pattern:
                continue
            det.setdefault("pattern", pattern)
            self.train_one(det, context=ctx, label=label)
            applied[pattern] += 1
        return dict(applied)

    # ── inspection ───────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "patterns_trained": len([p for p, c in self._counts.items() if c >= _MIN_SAMPLES]),
                "patterns_seen": len(self._counts),
                "min_samples_for_inference": _MIN_SAMPLES,
                "samples_per_pattern": dict(self._counts),
                "weights": {
                    p: {f: round(w[f], 4) for f in _FEATURES}
                    for p, w in self._weights.items()
                },
            }
