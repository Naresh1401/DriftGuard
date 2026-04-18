"""Domain configuration API endpoints."""
from __future__ import annotations

import logging
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, HttpUrl

from api.middleware.auth import get_current_user
from models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/domains", tags=["Domains"])


@router.get("")
async def list_domains(user: User = Depends(get_current_user)):
    """List all available domain configurations."""
    from main import app_state
    return {"domains": app_state.domain_registry.list_domains()}


@router.get("/{domain_name}")
async def get_domain(domain_name: str, user: User = Depends(get_current_user)):
    """Get a specific domain configuration."""
    from main import app_state
    config = app_state.domain_registry.get_domain(domain_name)
    if not config:
        raise HTTPException(status_code=404, detail=f"Domain '{domain_name}' not found")
    return config.to_dict()


@router.post("/upload")
async def upload_domain_config(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
):
    """Upload a custom YAML domain configuration."""
    from main import app_state

    if not file.filename or not file.filename.endswith((".yaml", ".yml")):
        raise HTTPException(status_code=400, detail="File must be a YAML file")

    content = await file.read()
    yaml_string = content.decode("utf-8")

    config = app_state.domain_registry.load_config_string(yaml_string)
    if not config:
        raise HTTPException(status_code=400, detail="Invalid YAML domain configuration")

    return {
        "status": "uploaded",
        "domain": config.domain,
        "display_name": config.display_name,
        "signal_count": len(config.signals),
    }


class YamlConfigInput(BaseModel):
    yaml_content: str


@router.post("/upload/yaml")
async def upload_yaml_string(
    input: YamlConfigInput,
    user: User = Depends(get_current_user),
):
    """Upload a YAML domain configuration as a string."""
    from main import app_state

    config = app_state.domain_registry.load_config_string(input.yaml_content)
    if not config:
        raise HTTPException(status_code=400, detail="Invalid YAML configuration")

    return {
        "status": "uploaded",
        "domain": config.domain,
        "signals": [s.to_dict() for s in config.signals],
    }


# ── Breach / Security Analysis ──────────────────────────────────────────────

EXPECTED_SECURITY_HEADERS = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "description": "Forces browsers to use HTTPS, preventing downgrade attacks.",
        "nist": "SC-8",
        "severity": "high",
    },
    "content-security-policy": {
        "label": "Content-Security-Policy (CSP)",
        "description": "Prevents XSS and data injection attacks by whitelisting content sources.",
        "nist": "SI-10",
        "severity": "high",
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing — should be set to 'nosniff'.",
        "nist": "SI-10",
        "severity": "medium",
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "nist": "SI-10",
        "severity": "medium",
    },
    "x-xss-protection": {
        "label": "X-XSS-Protection",
        "description": "Legacy XSS filter. Should be '0' or absent if CSP is set.",
        "nist": "SI-10",
        "severity": "low",
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "description": "Controls how much referrer information is shared with other sites.",
        "nist": "AC-4",
        "severity": "low",
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "description": "Controls browser features available to the page (camera, mic, geolocation).",
        "nist": "AC-4",
        "severity": "medium",
    },
    "cross-origin-opener-policy": {
        "label": "Cross-Origin-Opener-Policy (COOP)",
        "description": "Isolates the browsing context to prevent cross-origin attacks.",
        "nist": "SC-8",
        "severity": "low",
    },
    "cross-origin-resource-policy": {
        "label": "Cross-Origin-Resource-Policy (CORP)",
        "description": "Controls which sites can load resources from this origin.",
        "nist": "AC-4",
        "severity": "low",
    },
}

SEVERITY_SCORES = {"critical": 10, "high": 8, "medium": 5, "low": 2}


def _check_ssl_cert(hostname: str, port: int = 443) -> dict:
    """Check SSL certificate details for a hostname."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"valid": False, "error": "No certificate returned"}

                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                subject_parts = dict(x[0] for x in cert.get("subject", []))

                return {
                    "valid": days_remaining > 0,
                    "issuer": issuer_parts.get("organizationName", "Unknown"),
                    "subject": subject_parts.get("commonName", "Unknown"),
                    "not_before": not_before.isoformat(),
                    "expires": not_after.isoformat(),
                    "days_remaining": days_remaining,
                    "protocol": ssock.version(),
                    "expired": days_remaining <= 0,
                    "expiring_soon": 0 < days_remaining <= 30,
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e.verify_message}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _analyze_cookies(response: httpx.Response) -> list[dict]:
    """Analyze cookies for security flags."""
    findings = []
    for cookie in response.cookies.jar:
        issues = []
        if not cookie.secure:
            issues.append("Missing Secure flag — cookie sent over HTTP")
        if not getattr(cookie, "_rest", {}).get("HttpOnly", False):
            # httpx doesn't expose HttpOnly easily; check Set-Cookie header
            pass
        if issues:
            findings.append({"name": cookie.name, "issues": issues})

    # Also parse raw Set-Cookie headers for deeper analysis
    for header_val in response.headers.get_list("set-cookie"):
        lower = header_val.lower()
        name = header_val.split("=", 1)[0].strip()
        cookie_issues = []
        if "secure" not in lower:
            cookie_issues.append("Missing Secure flag")
        if "httponly" not in lower:
            cookie_issues.append("Missing HttpOnly flag — accessible to JavaScript")
        if "samesite" not in lower:
            cookie_issues.append("Missing SameSite attribute — vulnerable to CSRF")
        if cookie_issues:
            # Avoid duplicates
            if not any(f["name"] == name for f in findings):
                findings.append({"name": name, "issues": cookie_issues})
    return findings


class AnalyzeUrlInput(BaseModel):
    url: HttpUrl


@router.post("/analyze-url")
async def analyze_url(
    input: AnalyzeUrlInput,
    user: User = Depends(get_current_user),
):
    """Analyze a website URL for security posture and potential breach indicators.

    Performs:
    - SSL/TLS certificate validation
    - Security header analysis (OWASP recommended)
    - Cookie security flag checks
    - Server information disclosure detection
    - NIST SP 800-53 control mapping for each finding
    """
    url_str = str(input.url)
    parsed = urlparse(url_str)
    hostname = parsed.hostname
    is_https = parsed.scheme == "https"

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL — hostname could not be parsed")

    findings: list[dict] = []
    header_results: list[dict] = []
    risk_score = 0

    # 1. Fetch the page
    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            verify=True,
        ) as client:
            response = await client.get(url_str, headers={"User-Agent": "DriftGuard-Breach-Analyzer/1.0"})
    except httpx.ConnectError:
        raise HTTPException(status_code=400, detail=f"Could not connect to {hostname}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=400, detail=f"Connection to {hostname} timed out")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {e}")

    response_headers = {k.lower(): v for k, v in response.headers.items()}

    # 2. HTTPS check
    if not is_https:
        findings.append({
            "category": "transport",
            "severity": "critical",
            "title": "No HTTPS",
            "description": "Site is served over plain HTTP. All traffic is unencrypted and vulnerable to interception.",
            "nist_control": "SC-8",
            "recommendation": "Enable HTTPS with a valid TLS certificate.",
        })
        risk_score += SEVERITY_SCORES["critical"]

    # 3. SSL certificate check
    ssl_info = None
    if is_https:
        ssl_info = _check_ssl_cert(hostname, parsed.port or 443)
        if not ssl_info.get("valid"):
            findings.append({
                "category": "certificate",
                "severity": "critical",
                "title": "Invalid SSL Certificate",
                "description": ssl_info.get("error", "Certificate is invalid or expired."),
                "nist_control": "SC-8",
                "recommendation": "Renew or replace the SSL/TLS certificate immediately.",
            })
            risk_score += SEVERITY_SCORES["critical"]
        elif ssl_info.get("expiring_soon"):
            findings.append({
                "category": "certificate",
                "severity": "medium",
                "title": f"SSL Certificate Expiring Soon ({ssl_info['days_remaining']} days)",
                "description": f"Certificate expires on {ssl_info['expires']}.",
                "nist_control": "SC-8",
                "recommendation": "Renew the certificate before expiration.",
            })
            risk_score += SEVERITY_SCORES["medium"]

    # 4. Security headers analysis
    for header_key, meta in EXPECTED_SECURITY_HEADERS.items():
        present = header_key in response_headers
        value = response_headers.get(header_key, None)
        header_results.append({
            "header": meta["label"],
            "present": present,
            "value": value,
            "severity": meta["severity"],
            "nist_control": meta["nist"],
        })
        if not present:
            findings.append({
                "category": "headers",
                "severity": meta["severity"],
                "title": f"Missing {meta['label']}",
                "description": meta["description"],
                "nist_control": meta["nist"],
                "recommendation": f"Add the {header_key} response header.",
            })
            risk_score += SEVERITY_SCORES[meta["severity"]]

    # 5. Server information disclosure
    server_header = response_headers.get("server")
    powered_by = response_headers.get("x-powered-by")
    if server_header:
        findings.append({
            "category": "disclosure",
            "severity": "low",
            "title": f"Server Header Exposed: {server_header}",
            "description": "The Server header reveals software details that help attackers target known vulnerabilities.",
            "nist_control": "SC-8",
            "recommendation": "Remove or obfuscate the Server header.",
        })
        risk_score += SEVERITY_SCORES["low"]
    if powered_by:
        findings.append({
            "category": "disclosure",
            "severity": "medium",
            "title": f"X-Powered-By Exposed: {powered_by}",
            "description": "Reveals the application framework, making it easier to find known exploits.",
            "nist_control": "SC-8",
            "recommendation": "Remove the X-Powered-By header.",
        })
        risk_score += SEVERITY_SCORES["medium"]

    # 6. Cookie security
    cookie_findings = _analyze_cookies(response)
    for cf in cookie_findings:
        for issue in cf["issues"]:
            findings.append({
                "category": "cookies",
                "severity": "medium",
                "title": f"Cookie '{cf['name']}': {issue}",
                "description": f"The cookie '{cf['name']}' is missing a security attribute.",
                "nist_control": "AC-4",
                "recommendation": f"Set the appropriate flag on the '{cf['name']}' cookie.",
            })
            risk_score += SEVERITY_SCORES["medium"]

    # 7. Compute overall grade
    max_possible = (
        SEVERITY_SCORES["critical"]  # HTTPS
        + sum(SEVERITY_SCORES[m["severity"]] for m in EXPECTED_SECURITY_HEADERS.values())
        + SEVERITY_SCORES["low"] * 2   # disclosure
    )
    security_score = max(0, round(100 - (risk_score / max_possible) * 100))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    if security_score >= 80:
        grade = "A"
    elif security_score >= 60:
        grade = "B"
    elif security_score >= 40:
        grade = "C"
    elif security_score >= 20:
        grade = "D"
    else:
        grade = "F"

    return {
        "url": url_str,
        "hostname": hostname,
        "status_code": response.status_code,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "security_score": security_score,
        "grade": grade,
        "ssl": ssl_info,
        "headers": header_results,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            **severity_counts,
        },
    }
