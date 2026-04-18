"""
DriftGuard Universal Client
============================
Lightweight client that any application can use to send signals
to a DriftGuard instance for cybersecurity breach prevention.

Works with ANY language/framework that can make HTTP calls.
This Python client is a convenience wrapper.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("driftguard.sdk")


class DriftGuardClient:
    """Universal client for sending signals to DriftGuard.

    Any application — web, mobile backend, CLI tool, IoT gateway,
    microservice — can use this to integrate breach detection.

    Example:
        client = DriftGuardClient(
            api_url="http://localhost:8000",
            api_key="your-api-key",
            app_id="my-ecommerce-app",
        )

        # Send a single signal
        client.send_signal(
            signal_type="access_log",
            source="auth-service",
            data={"access_count": 50, "after_hours": True},
        )

        # Send batch signals
        client.send_batch([
            {"signal_type": "access_log", "source": "api-gw", "data": {...}},
            {"signal_type": "audit_review", "source": "compliance", "data": {...}},
        ])

        # Register a custom webhook
        client.register_webhook(
            url="https://my-app.com/driftguard/alerts",
            events=["alert.critical", "alert.warning"],
        )
    """

    # Standard signal types any app can use
    SIGNAL_TYPES = {
        "access_log",
        "audit_review",
        "incident_response",
        "communication",
        "approval_workflow",
        "training_completion",
        "custom",
    }

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        app_id: Optional[str] = None,
        app_name: Optional[str] = None,
        domain: str = "enterprise",
        timeout: int = 30,
        verify_ssl: bool = True,
        async_mode: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.app_id = app_id or str(uuid4())
        self.app_name = app_name or "unknown"
        self.domain = domain
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.async_mode = async_mode
        self._session = None

    # ── Sync API ─────────────────────────────────────

    def send_signal(
        self,
        signal_type: str,
        source: str,
        data: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a single signal to DriftGuard."""
        import urllib.request
        import urllib.error

        payload = {
            "signal_type": signal_type if signal_type in self.SIGNAL_TYPES else "custom",
            "source": f"{self.app_name}:{source}",
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "data": data,
            "domain": self.domain,
            "metadata": {
                **(metadata or {}),
                "app_id": self.app_id,
                "app_name": self.app_name,
                "sdk_version": "1.0.0",
            },
        }

        return self._post("/api/v1/signals/ingest", payload)

    def send_batch(
        self,
        signals: List[Dict[str, Any]],
        team_id: Optional[str] = None,
        system_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a batch of signals and trigger full pipeline analysis."""
        formatted = []
        for s in signals:
            st = s.get("signal_type", "custom")
            formatted.append({
                "signal_type": st if st in self.SIGNAL_TYPES else "custom",
                "source": f"{self.app_name}:{s.get('source', 'unknown')}",
                "timestamp": s.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "data": s.get("data", {}),
                "domain": s.get("domain", self.domain),
                "metadata": {
                    **s.get("metadata", {}),
                    "app_id": self.app_id,
                    "app_name": self.app_name,
                },
            })

        payload = {
            "signals": formatted,
            "team_id": team_id,
            "system_id": system_id,
            "domain": self.domain,
        }

        return self._post("/api/v1/signals/ingest/batch", payload)

    def send_webhook_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source_app: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a generic webhook event — DriftGuard auto-classifies it."""
        webhook_payload = {
            "event_type": event_type,
            "payload": payload,
            "source_app": source_app or self.app_name,
            "app_id": self.app_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self._post("/api/v1/integrations/webhook", webhook_payload)

    def register_app(
        self,
        app_name: str,
        domain: str = "enterprise",
        signal_types: Optional[List[str]] = None,
        webhook_url: Optional[str] = None,
        webhook_events: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register this application with DriftGuard for monitoring."""
        payload = {
            "app_id": self.app_id,
            "app_name": app_name,
            "domain": domain,
            "signal_types": signal_types or list(self.SIGNAL_TYPES),
            "webhook_url": webhook_url,
            "webhook_events": webhook_events or ["alert.critical", "alert.warning"],
        }
        return self._post("/api/v1/integrations/apps/register", payload)

    def get_alerts(
        self,
        level: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve alerts for this app."""
        params = {"app_id": self.app_id}
        if level:
            params["level"] = level
        if status:
            params["status"] = status
        return self._get("/api/v1/alerts", params)

    def get_health_score(self) -> Dict[str, Any]:
        """Get the organizational health score."""
        return self._get("/api/v1/alerts/health-score", {"app_id": self.app_id})

    def health_check(self) -> Dict[str, Any]:
        """Check DriftGuard service health."""
        return self._get("/api/v1/health")

    # ── Async API ────────────────────────────────────

    async def async_send_signal(
        self,
        signal_type: str,
        source: str,
        data: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Async version of send_signal for async frameworks."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for async mode: pip install httpx")

        payload = {
            "signal_type": signal_type if signal_type in self.SIGNAL_TYPES else "custom",
            "source": f"{self.app_name}:{source}",
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "data": data,
            "domain": self.domain,
            "metadata": {
                **(metadata or {}),
                "app_id": self.app_id,
                "app_name": self.app_name,
                "sdk_version": "1.0.0",
            },
        }

        async with httpx.AsyncClient(
            timeout=self.timeout, verify=self.verify_ssl
        ) as client:
            resp = await client.post(
                f"{self.api_url}/api/v1/signals/ingest",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def async_send_webhook_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source_app: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Async version of send_webhook_event."""
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required for async mode: pip install httpx")

        webhook_payload = {
            "event_type": event_type,
            "payload": payload,
            "source_app": source_app or self.app_name,
            "app_id": self.app_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with httpx.AsyncClient(
            timeout=self.timeout, verify=self.verify_ssl
        ) as client:
            resp = await client.post(
                f"{self.api_url}/api/v1/integrations/webhook",
                json=webhook_payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ── Internal helpers ─────────────────────────────

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers["X-DriftGuard-App-ID"] = self.app_id
        return headers

    def _post(self, path: str, data: Dict) -> Dict[str, Any]:
        import urllib.request
        import urllib.error

        body = json.dumps(data, default=str).encode("utf-8")
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            data=body,
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            logger.error(f"DriftGuard API error: {e.code} {e.read().decode()}")
            raise
        except urllib.error.URLError as e:
            logger.error(f"DriftGuard connection error: {e}")
            raise

    def _get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        import urllib.request
        import urllib.error
        import urllib.parse

        url = f"{self.api_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            logger.error(f"DriftGuard API error: {e.code} {e.read().decode()}")
            raise
        except urllib.error.URLError as e:
            logger.error(f"DriftGuard connection error: {e}")
            raise

    def generate_webhook_signature(self, payload: bytes, secret: str) -> str:
        """Generate HMAC-SHA256 signature for webhook verification."""
        return hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_webhook_signature(
        payload: bytes, signature: str, secret: str
    ) -> bool:
        """Verify an incoming DriftGuard webhook signature."""
        expected = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
