"""
COMPONENT 5 — DOMAIN ADAPTER LAYER
====================================
The app works in any industry without code changes.
YAML-driven domain adapter system.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from models import DriftPatternType, NISTControl, SignalType

logger = logging.getLogger(__name__)


class DomainConfig:
    """Parsed domain configuration."""

    def __init__(self, raw: Dict[str, Any]):
        self.domain: str = raw.get("domain", "enterprise")
        self.display_name: str = raw.get("display_name", self.domain.title())
        self.description: str = raw.get("description", "")
        self.signals: List[SignalConfig] = [
            SignalConfig(s) for s in raw.get("signals", [])
        ]
        self.priority_controls: List[str] = raw.get("priority_controls", [])
        self.alert_sensitivity: str = raw.get("alert_sensitivity", "balanced")
        self.response_delivery: List[str] = raw.get("response_delivery", ["dashboard"])
        self.compliance: Dict[str, bool] = raw.get("compliance", {})
        self.highest_drift_risks: List[str] = raw.get("highest_drift_risks", [])
        self.risk_notes: str = raw.get("risk_notes", "")

    def get_signal_types(self) -> List[str]:
        return [s.signal_type for s in self.signals]

    def get_patterns_for_signal(self, signal_type: str) -> List[str]:
        for s in self.signals:
            if s.signal_type == signal_type:
                return s.maps_to
        return []

    def get_nist_controls_for_signal(self, signal_type: str) -> List[str]:
        for s in self.signals:
            if s.signal_type == signal_type:
                return s.nist_controls
        return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "display_name": self.display_name,
            "description": self.description,
            "signals": [s.to_dict() for s in self.signals],
            "priority_controls": self.priority_controls,
            "alert_sensitivity": self.alert_sensitivity,
            "response_delivery": self.response_delivery,
            "compliance": self.compliance,
            "highest_drift_risks": self.highest_drift_risks,
            "risk_notes": self.risk_notes,
        }


class SignalConfig:
    def __init__(self, raw: Dict[str, Any]):
        self.signal_type: str = raw.get("type", "custom")
        self.maps_to: List[str] = raw.get("maps_to", [])
        self.nist_controls: List[str] = raw.get("nist_controls", [])
        self.description: str = raw.get("description", "")
        self.source_connector: str = raw.get("source_connector", "")

    def to_dict(self) -> Dict:
        return {
            "type": self.signal_type,
            "maps_to": self.maps_to,
            "nist_controls": self.nist_controls,
            "description": self.description,
            "source_connector": self.source_connector,
        }


class DomainAdapterRegistry:
    """Registry of all available domain adapters."""

    def __init__(self, configs_dir: Optional[str] = None):
        self._domains: Dict[str, DomainConfig] = {}
        self._configs_dir = Path(configs_dir) if configs_dir else None

    def load_builtin_configs(self, configs_dir: Optional[str] = None) -> int:
        """Load all YAML configs from the configs directory."""
        directory = Path(configs_dir) if configs_dir else self._configs_dir
        if not directory or not directory.exists():
            logger.warning(f"Domain configs directory not found: {directory}")
            return 0

        count = 0
        for yaml_file in sorted(directory.glob("*.yaml")):
            config = self.load_config_file(str(yaml_file))
            if config:
                count += 1
        return count

    def load_config_file(self, path: str) -> Optional[DomainConfig]:
        """Load a single YAML domain configuration file."""
        try:
            with open(path, "r") as f:
                raw = yaml.safe_load(f)
            config = DomainConfig(raw)
            self._domains[config.domain] = config
            logger.info(f"Loaded domain config: {config.domain}")
            return config
        except Exception as e:
            logger.error(f"Failed to load domain config {path}: {e}")
            return None

    def load_config_string(self, yaml_string: str) -> Optional[DomainConfig]:
        """Load a domain config from a YAML string (upload wizard)."""
        try:
            raw = yaml.safe_load(yaml_string)
            config = DomainConfig(raw)
            self._domains[config.domain] = config
            return config
        except Exception as e:
            logger.error(f"Failed to parse YAML config: {e}")
            return None

    def get_domain(self, domain_name: str) -> Optional[DomainConfig]:
        return self._domains.get(domain_name)

    def list_domains(self) -> List[Dict[str, str]]:
        return [
            {
                "domain": d.domain,
                "display_name": d.display_name,
                "description": d.description,
                "signal_count": len(d.signals),
                "sensitivity": d.alert_sensitivity,
            }
            for d in self._domains.values()
        ]

    def get_sensitivity_multiplier(self, domain_name: str) -> float:
        """Get alert sensitivity multiplier for a domain."""
        config = self._domains.get(domain_name)
        if not config:
            return 1.0
        return {
            "conservative": 0.7,
            "balanced": 1.0,
            "aggressive": 1.3,
        }.get(config.alert_sensitivity, 1.0)
