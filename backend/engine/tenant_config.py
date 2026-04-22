"""Per-tenant approver role configuration.

Closes the third limit from Appendix O: the approver-role mapping for
each pattern was hard-coded in ``embed_layer._PATTERN_APPROVER_ROLES``.
Fine for a single-tenant pilot; broken the moment two organisations
have different governance.

This module gives every recommendation a tenant-aware lookup. Tenants
register a JSON config that overrides the per-pattern approver list;
unknown tenants and unset patterns fall back to the default map.

Pure stdlib, atomic JSON persistence, thread-safe.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_TENANT = "_default"


class TenantApproverConfig:
    """Storage for ``{org_id: {pattern: [roles]}}`` overrides."""

    def __init__(
        self,
        *,
        storage_path: Optional[str] = None,
        defaults: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self._defaults: Dict[str, List[str]] = dict(defaults or {})
        self._tenants: Dict[str, Dict[str, List[str]]] = {}
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
                    tenants = raw.get("tenants", {})
                    if isinstance(tenants, dict):
                        for org, pmap in tenants.items():
                            if isinstance(pmap, dict):
                                self._tenants[str(org)] = {
                                    str(p): [str(r) for r in roles]
                                    for p, roles in pmap.items()
                                    if isinstance(roles, list)
                                }
        except (OSError, ValueError):
            self._tenants.clear()

    def _persist(self) -> None:
        if self.storage_path is None:
            return
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump({"tenants": self._tenants}, fh)
            os.replace(tmp, self.storage_path)
        except OSError:
            pass

    # ── public API ───────────────────────────────────
    def set_defaults(self, defaults: Dict[str, List[str]]) -> None:
        with self._lock:
            self._defaults = {str(k): [str(r) for r in v] for k, v in defaults.items()}

    def set_overrides(
        self,
        org_id: str,
        overrides: Dict[str, List[str]],
    ) -> Dict[str, List[str]]:
        if not org_id or not isinstance(overrides, dict):
            raise ValueError("org_id and overrides dict are required")
        cleaned = {
            str(p): [str(r) for r in roles]
            for p, roles in overrides.items()
            if isinstance(roles, list) and roles
        }
        with self._lock:
            self._tenants[str(org_id)] = cleaned
        self._persist()
        return cleaned

    def clear_overrides(self, org_id: str) -> bool:
        with self._lock:
            existed = self._tenants.pop(str(org_id), None) is not None
        if existed:
            self._persist()
        return existed

    def get_overrides(self, org_id: str) -> Dict[str, List[str]]:
        with self._lock:
            return dict(self._tenants.get(str(org_id), {}))

    def list_tenants(self) -> List[str]:
        with self._lock:
            return sorted(self._tenants.keys())

    def approvers_for(
        self,
        pattern: str,
        *,
        org_id: Optional[str] = None,
    ) -> List[str]:
        """Return the role list authorised to clear ``pattern`` for ``org_id``."""
        with self._lock:
            if org_id and org_id in self._tenants:
                roles = self._tenants[org_id].get(pattern)
                if roles:
                    return list(roles)
            return list(self._defaults.get(pattern, ["ciso"]))
