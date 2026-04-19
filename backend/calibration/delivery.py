"""Calibration response delivery — multiple channels."""
from __future__ import annotations

import logging
from typing import Dict, Optional

from models import Alert, CalibrationDelivery, CalibrationResponse
from uuid import uuid4

logger = logging.getLogger(__name__)


class CalibrationDeliveryService:
    """Deliver calibration responses via configured channels.

    Delivery formats are user-configurable:
    - dashboard alert
    - email digest
    - real-time push notification
    - Slack integration
    """

    def __init__(self, config: Optional[Dict] = None):
        self._config = config or {}
        self._handlers = {
            "dashboard": self._deliver_dashboard,
            "email": self._deliver_email,
            "push": self._deliver_push,
            "slack": self._deliver_slack,
        }

    async def deliver(
        self,
        response: CalibrationResponse,
        alert: Alert,
        methods: list[str] | None = None,
    ) -> list[CalibrationDelivery]:
        """Deliver a calibration response via one or more methods."""
        methods = methods or ["dashboard"]
        deliveries = []

        for method in methods:
            handler = self._handlers.get(method)
            if not handler:
                logger.warning(f"Unknown delivery method: {method}")
                continue

            delivery = CalibrationDelivery(
                id=uuid4(),
                response_id=response.id,
                alert_id=alert.id,
                delivery_method=method,
            )

            success = await handler(response, alert)
            if success:
                deliveries.append(delivery)
                logger.info(
                    f"Calibration response {response.id} delivered via {method}"
                )

        return deliveries

    async def _deliver_dashboard(
        self, response: CalibrationResponse, alert: Alert
    ) -> bool:
        """Dashboard delivery — store for frontend retrieval."""
        # In production this writes to the database/cache
        # for the React dashboard to pick up
        return True

    async def _deliver_email(
        self, response: CalibrationResponse, alert: Alert
    ) -> bool:
        """Email digest delivery via SMTP."""
        smtp_host = self._config.get("smtp_host")
        if not smtp_host:
            logger.info("Email delivery skipped: SMTP not configured")
            return False

        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            smtp_port = int(self._config.get("smtp_port", 587))
            smtp_user = self._config.get("smtp_user", "")
            smtp_pass = self._config.get("smtp_pass", "")
            to_addr = self._config.get("alert_email", "security@org.local")

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"DriftGuard Alert — {alert.alert_level.value}: {', '.join(c.pattern.value for c in alert.drift_patterns)}"
            msg["From"] = smtp_user or "driftguard@org.local"
            msg["To"] = to_addr

            body = (
                f"Alert Level: {alert.alert_level.value}\n"
                f"Severity: {alert.severity_score.value}/5\n"
                f"Patterns: {', '.join(c.pattern.value for c in alert.drift_patterns)}\n\n"
                f"Calibration Response:\n{response.response_text}\n\n"
                f"— DriftGuard Automated Alert"
            )
            msg.attach(MIMEText(body, "plain"))

            await aiosmtplib.send(
                msg,
                hostname=smtp_host,
                port=smtp_port,
                username=smtp_user or None,
                password=smtp_pass or None,
                start_tls=True,
            )
            logger.info(f"Email sent for alert {alert.id} to {to_addr}")
            return True
        except ImportError:
            logger.warning("aiosmtplib not installed — email delivery unavailable")
            return False
        except Exception as e:
            logger.error(f"Email delivery failed: {e}")
            return False

    async def _deliver_push(
        self, response: CalibrationResponse, alert: Alert
    ) -> bool:
        """Real-time push notification via WebSocket broadcast."""
        try:
            from main import app_state
            ws_clients = getattr(app_state, '_ws_clients', [])
            if not ws_clients:
                logger.info("Push delivery: no connected WebSocket clients")
                return True  # not a failure

            payload = {
                "type": "calibration_response",
                "alert_id": str(alert.id),
                "alert_level": alert.alert_level.value,
                "patterns": [c.pattern.value for c in alert.drift_patterns],
                "severity": alert.severity_score.value,
                "response_preview": response.response_text[:200],
            }
            import json
            msg = json.dumps(payload)
            disconnected = []
            for ws in ws_clients:
                try:
                    await ws.send_text(msg)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                ws_clients.remove(ws)

            logger.info(f"Push notification sent to {len(ws_clients)} clients for alert {alert.id}")
            return True
        except Exception as e:
            logger.error(f"Push delivery failed: {e}")
            return False

    async def _deliver_slack(
        self, response: CalibrationResponse, alert: Alert
    ) -> bool:
        """Slack integration delivery."""
        webhook = self._config.get("slack_webhook_url")
        if not webhook:
            logger.info("Slack delivery skipped: webhook not configured")
            return False

        try:
            import httpx
            payload = {
                "text": (
                    f"*DriftGuard Alert — {alert.alert_level.value}*\n"
                    f"Pattern: {', '.join(c.pattern.value for c in alert.drift_patterns)}\n"
                    f"Severity: {alert.severity_score.value}/5\n\n"
                    f"_Calibration Response:_\n{response.response_text}"
                ),
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook, json=payload, timeout=10)
                return resp.status_code == 200
        except Exception as e:
            logger.error(f"Slack delivery failed: {e}")
            return False
