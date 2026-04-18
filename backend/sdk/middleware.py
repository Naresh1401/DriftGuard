"""
DriftGuard Universal Middleware
================================
Drop-in ASGI/WSGI middleware that automatically monitors any web
application for cybersecurity drift patterns.

ASGI (FastAPI, Starlette, Django 3+):
    from sdk.middleware import DriftGuardASGIMiddleware
    app.add_middleware(DriftGuardASGIMiddleware, api_url="http://localhost:8000")

WSGI (Flask, Django 2.x):
    from sdk.middleware import DriftGuardWSGIMiddleware
    app.wsgi_app = DriftGuardWSGIMiddleware(app.wsgi_app, api_url="http://localhost:8000")
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("driftguard.middleware")


class _SignalBuffer:
    """Thread-safe signal buffer that flushes periodically to DriftGuard."""

    def __init__(
        self,
        api_url: str,
        api_key: Optional[str],
        app_id: str,
        flush_interval: int = 60,
        max_buffer_size: int = 100,
    ):
        self._api_url = api_url
        self._api_key = api_key
        self._app_id = app_id
        self._flush_interval = flush_interval
        self._max_buffer_size = max_buffer_size
        self._buffer: List[Dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def add(self, signal: Dict) -> None:
        with self._lock:
            self._buffer.append(signal)
            if len(self._buffer) >= self._max_buffer_size:
                self._flush()

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._flush()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while self._running:
            time.sleep(self._flush_interval)
            self._flush()

    def _flush(self) -> None:
        with self._lock:
            if not self._buffer:
                return
            signals = self._buffer[:]
            self._buffer.clear()

        try:
            import urllib.request
            import urllib.error

            payload = json.dumps({
                "signals": signals,
                "domain": "enterprise",
            }, default=str).encode("utf-8")

            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            headers["X-DriftGuard-App-ID"] = self._app_id

            req = urllib.request.Request(
                f"{self._api_url}/api/v1/signals/ingest/batch",
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.debug(f"Flushed {len(signals)} signals to DriftGuard")
        except Exception as e:
            logger.warning(f"Failed to flush signals to DriftGuard: {e}")
            # Re-buffer on failure (with cap to prevent memory growth)
            with self._lock:
                self._buffer = signals[:self._max_buffer_size] + self._buffer
                self._buffer = self._buffer[:self._max_buffer_size * 2]


def _classify_request(method: str, path: str, status: int) -> str:
    """Classify an HTTP request into a DriftGuard signal type."""
    path_lower = path.lower()

    # Authentication/access signals
    if any(p in path_lower for p in ["/login", "/auth", "/token", "/session", "/oauth"]):
        return "access_log"

    # Approval/workflow signals
    if any(p in path_lower for p in ["/approve", "/workflow", "/review", "/request"]):
        return "approval_workflow"

    # Audit signals
    if any(p in path_lower for p in ["/audit", "/compliance", "/report"]):
        return "audit_review"

    # Incident signals
    if any(p in path_lower for p in ["/incident", "/alert", "/ticket", "/issue"]):
        return "incident_response"

    # Training signals
    if any(p in path_lower for p in ["/training", "/course", "/certification"]):
        return "training_completion"

    # Error responses may indicate incident patterns
    if status >= 500:
        return "incident_response"

    # Failed auth
    if status in (401, 403):
        return "access_log"

    return "access_log"


def _extract_signal_data(
    method: str,
    path: str,
    status: int,
    duration_ms: float,
    headers: Dict[str, str],
) -> Dict[str, Any]:
    """Extract drift-relevant features from an HTTP request."""
    now = datetime.now(timezone.utc)
    is_after_hours = now.hour < 6 or now.hour > 20

    return {
        "method": method,
        "path": path,
        "status_code": status,
        "duration_ms": round(duration_ms, 2),
        "after_hours": is_after_hours,
        "access_count": 1,  # Aggregated by buffer
        "access_type": "write" if method in ("POST", "PUT", "DELETE", "PATCH") else "read",
        "role_match": True,  # Default; override via header X-DriftGuard-Role-Match
        "unique_resources": 1,
    }


class DriftGuardASGIMiddleware:
    """ASGI middleware for automatic drift signal collection.

    Any ASGI app (FastAPI, Starlette, Django 3+, Quart) can use this:

        app.add_middleware(
            DriftGuardASGIMiddleware,
            api_url="http://localhost:8000",
            api_key="your-key",
            app_name="my-web-app",
        )

    What it monitors (automatically, no code changes needed):
    - Authentication patterns (login frequency, failed auth, after-hours access)
    - Approval workflows (request/approve endpoint patterns)
    - Error rates (5xx spikes = potential incident response drift)
    - Access patterns (resource access frequency, unusual paths)
    """

    def __init__(
        self,
        app,
        api_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        app_id: Optional[str] = None,
        app_name: str = "unknown",
        domain: str = "enterprise",
        flush_interval: int = 60,
        max_buffer_size: int = 100,
        exclude_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.app_name = app_name
        self.domain = domain
        self._exclude_paths = set(exclude_paths or [
            "/health", "/healthz", "/ready", "/metrics", "/favicon.ico",
        ])
        self._buffer = _SignalBuffer(
            api_url=api_url,
            api_key=api_key,
            app_id=app_id or str(uuid4()),
            flush_interval=flush_interval,
            max_buffer_size=max_buffer_size,
        )
        self._buffer.start()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")

        # Skip excluded paths
        if any(path.startswith(ex) for ex in self._exclude_paths):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        start_time = time.monotonic()
        status_code = 200

        # Capture response status
        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.monotonic() - start_time) * 1000
            headers = dict(scope.get("headers", []))

            signal_type = _classify_request(method, path, status_code)
            signal_data = _extract_signal_data(
                method, path, status_code, duration_ms,
                {k.decode() if isinstance(k, bytes) else k: v.decode() if isinstance(v, bytes) else v
                 for k, v in headers.items()}
            )

            self._buffer.add({
                "signal_type": signal_type,
                "source": f"{self.app_name}:{method}:{path}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": signal_data,
                "domain": self.domain,
                "metadata": {
                    "app_name": self.app_name,
                    "middleware": "asgi",
                },
            })


class DriftGuardWSGIMiddleware:
    """WSGI middleware for automatic drift signal collection.

    Any WSGI app (Flask, Django, Bottle, Pyramid) can use this:

        # Flask
        app.wsgi_app = DriftGuardWSGIMiddleware(
            app.wsgi_app,
            api_url="http://localhost:8000",
            api_key="your-key",
            app_name="my-flask-app",
        )

        # Django (in wsgi.py)
        application = DriftGuardWSGIMiddleware(
            application,
            api_url="http://localhost:8000",
            app_name="my-django-app",
        )
    """

    def __init__(
        self,
        app,
        api_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        app_id: Optional[str] = None,
        app_name: str = "unknown",
        domain: str = "enterprise",
        flush_interval: int = 60,
        max_buffer_size: int = 100,
        exclude_paths: Optional[List[str]] = None,
    ):
        self.app = app
        self.app_name = app_name
        self.domain = domain
        self._exclude_paths = set(exclude_paths or [
            "/health", "/healthz", "/ready", "/metrics", "/favicon.ico",
        ])
        self._buffer = _SignalBuffer(
            api_url=api_url,
            api_key=api_key,
            app_id=app_id or str(uuid4()),
            flush_interval=flush_interval,
            max_buffer_size=max_buffer_size,
        )
        self._buffer.start()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")

        # Skip excluded paths
        if any(path.startswith(ex) for ex in self._exclude_paths):
            return self.app(environ, start_response)

        method = environ.get("REQUEST_METHOD", "GET")
        start_time = time.monotonic()
        status_code = 200

        def capturing_start_response(status, headers, exc_info=None):
            nonlocal status_code
            status_code = int(status.split(" ", 1)[0])
            return start_response(status, headers, exc_info)

        try:
            result = self.app(environ, capturing_start_response)
            return result
        finally:
            duration_ms = (time.monotonic() - start_time) * 1000
            signal_type = _classify_request(method, path, status_code)
            signal_data = _extract_signal_data(method, path, status_code, duration_ms, {})

            self._buffer.add({
                "signal_type": signal_type,
                "source": f"{self.app_name}:{method}:{path}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": signal_data,
                "domain": self.domain,
                "metadata": {
                    "app_name": self.app_name,
                    "middleware": "wsgi",
                },
            })
