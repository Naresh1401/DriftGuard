"""
Universal App Adapter
======================
Allows ANY application type — not just industry verticals — to define
its own signal taxonomy, drift thresholds, and alert rules via YAML.

Example custom_app.yaml:
    app:
      name: "My E-Commerce Platform"
      type: "web_application"
      domain: "retail"

    signals:
      - type: "access_log"
        sources: ["auth-service", "api-gateway"]
        maps_to: ["Fatigue", "Hoarding"]
        nist_controls: ["AC-2", "CA-7"]

      - type: "approval_workflow"
        sources: ["checkout-service", "payment-gateway"]
        maps_to: ["Hurry", "Overconfidence"]
        nist_controls: ["AU-6"]

      - type: "custom"
        name: "cart_abandonment"
        maps_to: ["Fatigue"]
        feature_fields:
          - abandon_rate
          - session_duration

    thresholds:
      confidence: 0.70
      severity_weights:
        signal_intensity: 0.30
        temporal_weight: 0.35
        acceleration_ratio: 0.20
        confidence: 0.15
      alert_rules:
        critical_patterns: 3
        warning_patterns: 2
        review_duration_threshold: 30
        silence_duration_threshold: 48

    delivery:
      methods: ["dashboard", "email", "slack"]
      slack_channel: "#security-alerts"
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger("driftguard.app_adapter")


@dataclass
class AppSignalConfig:
    """Signal configuration for a specific app."""
    signal_type: str
    sources: List[str] = field(default_factory=list)
    maps_to: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    name: Optional[str] = None
    feature_fields: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class AppThresholds:
    """Configurable thresholds for an app — replaces hardcoded values."""
    confidence: float = 0.70
    severity_weights: Dict[str, float] = field(default_factory=lambda: {
        "signal_intensity": 0.30,
        "temporal_weight": 0.35,
        "acceleration_ratio": 0.20,
        "confidence": 0.15,
    })
    alert_rules: Dict[str, Any] = field(default_factory=lambda: {
        "critical_patterns": 3,
        "warning_patterns": 2,
        "review_duration_threshold": 30,
        "silence_duration_threshold": 48,
        "acceleration_threshold": 1.5,
    })
    temporal: Dict[str, Any] = field(default_factory=lambda: {
        "lookback_days": 14,
        "half_life_days": 3.0,
        "acceleration_window_days": 7,
    })


@dataclass
class AppDeliveryConfig:
    """Delivery configuration for an app."""
    methods: List[str] = field(default_factory=lambda: ["dashboard"])
    slack_channel: Optional[str] = None
    email_recipients: List[str] = field(default_factory=list)
    webhook_url: Optional[str] = None


@dataclass
class UniversalAppConfig:
    """Complete configuration for any application integrated with DriftGuard."""
    app_name: str
    app_type: str = "generic"
    domain: str = "enterprise"
    description: str = ""
    signals: List[AppSignalConfig] = field(default_factory=list)
    thresholds: AppThresholds = field(default_factory=AppThresholds)
    delivery: AppDeliveryConfig = field(default_factory=AppDeliveryConfig)
    custom_event_mappings: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class UniversalAppRegistry:
    """Registry of all application configurations.

    Supports:
    - Pre-built domain configs (healthcare, finance, etc.)
    - Custom YAML configs for any app
    - Runtime registration via API
    - Dynamic threshold tuning per app
    """

    def __init__(self):
        self._apps: Dict[str, UniversalAppConfig] = {}
        self._default_config = UniversalAppConfig(
            app_name="default",
            app_type="generic",
            domain="enterprise",
            description="Default configuration for unregistered apps",
        )

    def register_from_yaml(self, yaml_content: str) -> UniversalAppConfig:
        """Register an app from a YAML configuration string."""
        data = yaml.safe_load(yaml_content)
        return self._parse_and_register(data)

    def register_from_file(self, path: str) -> UniversalAppConfig:
        """Register an app from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return self._parse_and_register(data)

    def register_from_dict(self, data: Dict[str, Any]) -> UniversalAppConfig:
        """Register an app from a dictionary (API registration)."""
        return self._parse_and_register(data)

    def get_config(self, app_name: str) -> UniversalAppConfig:
        """Get app configuration. Returns default if not found."""
        return self._apps.get(app_name, self._default_config)

    def get_thresholds(self, app_name: str) -> AppThresholds:
        """Get thresholds for an app — used by pipeline components."""
        return self.get_config(app_name).thresholds

    def get_event_mapping(self, app_name: str) -> Dict[str, str]:
        """Get custom event type → signal type mapping for an app."""
        return self.get_config(app_name).custom_event_mappings

    def list_apps(self) -> List[Dict[str, Any]]:
        """List all registered apps."""
        return [
            {
                "app_name": cfg.app_name,
                "app_type": cfg.app_type,
                "domain": cfg.domain,
                "signals": len(cfg.signals),
                "description": cfg.description,
            }
            for cfg in self._apps.values()
        ]

    def load_builtin_app_configs(self, directory: str) -> int:
        """Load all YAML configs from a directory."""
        config_dir = Path(directory)
        if not config_dir.exists():
            return 0

        count = 0
        for yaml_file in config_dir.glob("*.yaml"):
            try:
                self.register_from_file(str(yaml_file))
                count += 1
            except Exception as e:
                logger.warning(f"Failed to load app config {yaml_file}: {e}")
        return count

    def _parse_and_register(self, data: Dict[str, Any]) -> UniversalAppConfig:
        """Parse raw YAML/dict data into UniversalAppConfig."""
        app_data = data.get("app", data)
        app_name = app_data.get("name", app_data.get("app_name", "unknown"))

        # Parse signals
        signals = []
        for s in data.get("signals", []):
            signals.append(AppSignalConfig(
                signal_type=s.get("type", "custom"),
                sources=s.get("sources", []),
                maps_to=s.get("maps_to", []),
                nist_controls=s.get("nist_controls", []),
                name=s.get("name"),
                feature_fields=s.get("feature_fields", []),
                description=s.get("description", ""),
            ))

        # Parse thresholds
        thresh_data = data.get("thresholds", {})
        thresholds = AppThresholds(
            confidence=thresh_data.get("confidence", 0.70),
            severity_weights=thresh_data.get("severity_weights", AppThresholds().severity_weights),
            alert_rules=thresh_data.get("alert_rules", AppThresholds().alert_rules),
            temporal=thresh_data.get("temporal", AppThresholds().temporal),
        )

        # Parse delivery
        delivery_data = data.get("delivery", {})
        delivery = AppDeliveryConfig(
            methods=delivery_data.get("methods", ["dashboard"]),
            slack_channel=delivery_data.get("slack_channel"),
            email_recipients=delivery_data.get("email_recipients", []),
            webhook_url=delivery_data.get("webhook_url"),
        )

        config = UniversalAppConfig(
            app_name=app_name,
            app_type=app_data.get("type", "generic"),
            domain=app_data.get("domain", "enterprise"),
            description=app_data.get("description", ""),
            signals=signals,
            thresholds=thresholds,
            delivery=delivery,
            custom_event_mappings=data.get("event_mappings", {}),
            metadata=data.get("metadata", {}),
        )

        self._apps[app_name] = config
        logger.info(f"Registered app: {app_name} ({config.app_type})")
        return config
