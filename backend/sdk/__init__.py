"""
DriftGuard Universal SDK
========================
Drop-in cybersecurity breach prevention layer for ANY application.

Usage (any Python app):
    from sdk import DriftGuardClient

    dg = DriftGuardClient(api_url="http://localhost:8000", api_key="your-key")
    dg.send_signal("access_log", source="my-app", data={"access_count": 5})

Usage (ASGI middleware — FastAPI, Starlette, Django 3+):
    from sdk.middleware import DriftGuardASGIMiddleware
    app.add_middleware(DriftGuardASGIMiddleware, api_key="your-key")

Usage (WSGI middleware — Flask, Django):
    from sdk.middleware import DriftGuardWSGIMiddleware
    app.wsgi_app = DriftGuardWSGIMiddleware(app.wsgi_app, api_key="your-key")
"""

from sdk.client import DriftGuardClient
from sdk.middleware import DriftGuardASGIMiddleware, DriftGuardWSGIMiddleware

__all__ = [
    "DriftGuardClient",
    "DriftGuardASGIMiddleware",
    "DriftGuardWSGIMiddleware",
]
