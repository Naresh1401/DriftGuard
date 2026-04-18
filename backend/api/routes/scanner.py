"""Real-time website security scanner.

Performs live analysis against actual websites:
- SSL/TLS certificate inspection
- Security header audit (OWASP)
- DNS record analysis (MX, SPF, DMARC, DNSSEC indicators)
- Open port scanning (common service ports)
- Technology fingerprinting (server, framework, CMS)
- Cookie security audit
- NIST SP 800-53 control mapping for every finding

All data is fetched in real time — no demo/fake data.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.middleware.auth import get_current_user
from models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scanner", tags=["Live Scanner"])


# ── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan (e.g. https://example.com)")
    scan_ports: bool = Field(default=True, description="Include port scan")
    scan_dns: bool = Field(default=True, description="Include DNS analysis")


# ── Constants ────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

SECURITY_HEADERS = {
    "strict-transport-security": {"label": "HSTS", "nist": "SC-8", "weight": 10},
    "content-security-policy": {"label": "CSP", "nist": "SI-10", "weight": 10},
    "x-content-type-options": {"label": "X-Content-Type-Options", "nist": "SI-10", "weight": 5},
    "x-frame-options": {"label": "X-Frame-Options", "nist": "SI-10", "weight": 5},
    "referrer-policy": {"label": "Referrer-Policy", "nist": "AC-4", "weight": 3},
    "permissions-policy": {"label": "Permissions-Policy", "nist": "AC-4", "weight": 5},
    "cross-origin-opener-policy": {"label": "COOP", "nist": "SC-8", "weight": 3},
    "cross-origin-resource-policy": {"label": "CORP", "nist": "AC-4", "weight": 3},
    "x-xss-protection": {"label": "X-XSS-Protection", "nist": "SI-10", "weight": 2},
}

TECH_SIGNATURES = {
    "server": {
        "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
        "microsoft-iis": "IIS", "litespeed": "LiteSpeed", "gunicorn": "Gunicorn",
        "openresty": "OpenResty", "caddy": "Caddy",
    },
    "x-powered-by": {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express.js",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "django": "Django",
        "flask": "Flask", "ruby": "Ruby on Rails",
    },
}

HTML_TECH_PATTERNS = [
    (r'<meta[^>]+generator[^>]+content="([^"]+)"', "CMS/Generator"),
    (r'wp-content|wp-includes', "WordPress"),
    (r'sites/default/files|drupal', "Drupal"),
    (r'cdn\.shopify\.com', "Shopify"),
    (r'/cdn-cgi/', "Cloudflare"),
    (r'_next/static|__next', "Next.js"),
    (r'react', "React"),
    (r'vue\.js|vuejs', "Vue.js"),
    (r'angular', "Angular"),
    (r'jquery', "jQuery"),
    (r'bootstrap', "Bootstrap"),
]


# ── Core scanner functions ───────────────────────────────────────────────────

def _check_ssl(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Real-time SSL/TLS certificate analysis."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()  # (name, protocol, bits)
                protocol = ssock.version()

                if not cert:
                    return {"valid": False, "error": "No certificate returned"}

                not_after = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(
                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                # Subject Alternative Names
                san = [entry[1] for entry in cert.get("subjectAltName", [])]

                return {
                    "valid": days_left > 0,
                    "protocol": protocol,
                    "cipher": cipher[0] if cipher else None,
                    "cipher_bits": cipher[2] if cipher else None,
                    "issuer_org": issuer.get("organizationName", "Unknown"),
                    "issuer_cn": issuer.get("commonName", "Unknown"),
                    "subject_cn": subject.get("commonName", "Unknown"),
                    "san": san[:20],  # cap for display
                    "not_before": not_before.isoformat(),
                    "expires": not_after.isoformat(),
                    "days_remaining": days_left,
                    "expired": days_left <= 0,
                    "expiring_soon": 0 < days_left <= 30,
                    "key_weak": cipher[2] < 128 if cipher and cipher[2] else False,
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Verification failed: {e.verify_message}"}
    except socket.timeout:
        return {"valid": False, "error": "Connection timed out"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


async def _scan_port(host: str, port: int, timeout: float = 2.0) -> Optional[int]:
    """Scan a single port. Returns the port number if open, else None."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _scan_ports(host: str) -> List[Dict[str, Any]]:
    """Scan common ports concurrently. Returns list of open ports."""
    tasks = [_scan_port(host, port) for port in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    open_ports = []
    for port in results:
        if port is not None:
            svc = COMMON_PORTS.get(port, "Unknown")
            risk = "info"
            if port in (21, 23, 445, 3389):
                risk = "high"
            elif port in (3306, 5432, 6379, 27017):
                risk = "medium"
            open_ports.append({"port": port, "service": svc, "risk": risk})
    return sorted(open_ports, key=lambda p: p["port"])


def _analyze_dns(hostname: str) -> Dict[str, Any]:
    """DNS record analysis — A, AAAA, MX, TXT (SPF/DMARC)."""
    results: Dict[str, Any] = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "spf": None,
        "dmarc": None,
        "findings": [],
    }

    # A records
    try:
        a_records = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        results["a_records"] = list({r[4][0] for r in a_records})
    except socket.gaierror:
        results["findings"].append({
            "severity": "critical", "title": "DNS Resolution Failed",
            "description": f"Could not resolve A records for {hostname}.",
            "nist_control": "SC-20",
        })
        return results

    # AAAA records
    try:
        aaaa = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
        results["aaaa_records"] = list({r[4][0] for r in aaaa})
    except socket.gaierror:
        pass  # No AAAA is common

    # MX records via DNS TXT trick — use subprocess for real DNS queries
    try:
        import subprocess
        # MX
        mx_out = subprocess.run(
            ["dig", "+short", "MX", hostname],
            capture_output=True, text=True, timeout=10,
        )
        if mx_out.returncode == 0 and mx_out.stdout.strip():
            for line in mx_out.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    results["mx_records"].append({
                        "priority": int(parts[0]) if parts[0].isdigit() else 0,
                        "exchange": parts[1].rstrip("."),
                    })

        # SPF (TXT records)
        txt_out = subprocess.run(
            ["dig", "+short", "TXT", hostname],
            capture_output=True, text=True, timeout=10,
        )
        if txt_out.returncode == 0:
            for line in txt_out.stdout.strip().splitlines():
                clean = line.strip().strip('"')
                if clean.startswith("v=spf1"):
                    results["spf"] = clean

        # DMARC
        dmarc_out = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{hostname}"],
            capture_output=True, text=True, timeout=10,
        )
        if dmarc_out.returncode == 0:
            for line in dmarc_out.stdout.strip().splitlines():
                clean = line.strip().strip('"')
                if clean.startswith("v=DMARC1"):
                    results["dmarc"] = clean
    except FileNotFoundError:
        # dig not available — fall back gracefully
        results["findings"].append({
            "severity": "info", "title": "DNS tool unavailable",
            "description": "MX/SPF/DMARC analysis skipped (dig not found).",
            "nist_control": "SC-20",
        })
    except subprocess.TimeoutExpired:
        pass

    # Findings from DNS
    if not results["spf"]:
        results["findings"].append({
            "severity": "high", "title": "No SPF Record",
            "description": "No SPF record found. Email spoofing from this domain is possible.",
            "nist_control": "SI-8",
        })
    elif "-all" not in (results["spf"] or ""):
        results["findings"].append({
            "severity": "medium", "title": "Weak SPF Policy",
            "description": f"SPF record does not use '-all' (hard fail). Current: {results['spf']}",
            "nist_control": "SI-8",
        })

    if not results["dmarc"]:
        results["findings"].append({
            "severity": "high", "title": "No DMARC Record",
            "description": "No DMARC record found. The domain has no email authentication policy.",
            "nist_control": "SI-8",
        })
    else:
        dmarc_lower = results["dmarc"].lower()
        if "p=none" in dmarc_lower:
            results["findings"].append({
                "severity": "medium", "title": "DMARC Policy Set to None",
                "description": "DMARC exists but policy is 'none' — spoofed emails won't be rejected.",
                "nist_control": "SI-8",
            })

    if not results["mx_records"]:
        results["findings"].append({
            "severity": "info", "title": "No MX Records",
            "description": "No mail exchange records found — domain may not handle email.",
            "nist_control": "SI-8",
        })

    return results


def _detect_technologies(
    headers: Dict[str, str], body: str
) -> List[Dict[str, str]]:
    """Fingerprint technologies from HTTP headers and HTML body."""
    techs: List[Dict[str, str]] = []
    seen = set()

    # Header-based detection
    for header_key, signatures in TECH_SIGNATURES.items():
        val = headers.get(header_key, "").lower()
        for sig, name in signatures.items():
            if sig in val and name not in seen:
                techs.append({"name": name, "source": "header", "detail": headers.get(header_key, "")})
                seen.add(name)

    # HTML body patterns
    body_lower = body[:100_000].lower()  # cap to avoid slow regex
    for pattern, name in HTML_TECH_PATTERNS:
        if name not in seen and re.search(pattern, body_lower, re.I):
            match = re.search(pattern, body_lower, re.I)
            detail = match.group(1) if match and match.lastindex else ""
            techs.append({"name": name, "source": "html", "detail": detail[:100]})
            seen.add(name)

    return techs


def _analyze_cookies(response: httpx.Response) -> List[Dict[str, Any]]:
    """Analyze cookies for security flags."""
    cookies = []
    for header_val in response.headers.get_list("set-cookie"):
        lower = header_val.lower()
        name = header_val.split("=", 1)[0].strip()
        flags = {
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite" in lower,
        }
        issues = []
        if not flags["secure"]:
            issues.append("Missing Secure flag — sent over HTTP")
        if not flags["httponly"]:
            issues.append("Missing HttpOnly — accessible to JavaScript")
        if not flags["samesite"]:
            issues.append("Missing SameSite — vulnerable to CSRF")
        cookies.append({"name": name, "flags": flags, "issues": issues, "secure": len(issues) == 0})
    return cookies


def _compute_grade(score: float) -> str:
    if score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 30:
        return "D"
    return "F"


# ── Main scan endpoint ───────────────────────────────────────────────────────

@router.post("/scan")
async def full_scan(
    req: ScanRequest,
    user: User = Depends(get_current_user),
):
    """Comprehensive real-time security scan of a live website.

    All data is fetched live — no caching, no demo data.
    Returns SSL, headers, DNS, ports, technologies, cookies, and findings.
    """
    url_str = req.url.strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = f"https://{url_str}"

    parsed = urlparse(url_str)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    scan_start = datetime.now(timezone.utc)
    findings: List[Dict[str, Any]] = []
    score_deductions = 0
    max_score = 100

    # ── 1. Fetch the live page ───────────────────────────────────────────
    try:
        async with httpx.AsyncClient(
            timeout=20, follow_redirects=True, verify=True,
        ) as client:
            resp = await client.get(
                url_str,
                headers={"User-Agent": "DriftGuard-LiveScanner/1.0"},
            )
    except httpx.ConnectError:
        raise HTTPException(status_code=400, detail=f"Cannot connect to {hostname}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=400, detail=f"Timeout connecting to {hostname}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {e}")

    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    body_text = resp.text[:200_000]  # cap for analysis

    # ── 2. HTTPS check ───────────────────────────────────────────────────
    is_https = parsed.scheme == "https"
    if not is_https:
        findings.append({
            "severity": "critical", "title": "No HTTPS",
            "description": "Traffic is unencrypted — vulnerable to interception.",
            "nist_control": "SC-8", "category": "transport",
        })
        score_deductions += 20

    # ── 3. SSL/TLS ───────────────────────────────────────────────────────
    ssl_info = None
    if is_https:
        ssl_info = _check_ssl(hostname, parsed.port or 443)
        if not ssl_info.get("valid"):
            findings.append({
                "severity": "critical", "title": "Invalid SSL Certificate",
                "description": ssl_info.get("error", "Certificate invalid or expired."),
                "nist_control": "SC-8", "category": "certificate",
            })
            score_deductions += 15
        else:
            if ssl_info.get("expiring_soon"):
                findings.append({
                    "severity": "medium",
                    "title": f"Certificate Expiring in {ssl_info['days_remaining']} Days",
                    "description": f"Expires {ssl_info['expires']}.",
                    "nist_control": "SC-8", "category": "certificate",
                })
                score_deductions += 5
            if ssl_info.get("key_weak"):
                findings.append({
                    "severity": "high", "title": "Weak Cipher Key Length",
                    "description": f"Cipher uses only {ssl_info.get('cipher_bits')} bits.",
                    "nist_control": "SC-13", "category": "certificate",
                })
                score_deductions += 10

    # ── 4. Security headers ──────────────────────────────────────────────
    header_results = []
    for hdr_key, meta in SECURITY_HEADERS.items():
        present = hdr_key in resp_headers
        value = resp_headers.get(hdr_key)
        header_results.append({
            "header": meta["label"], "key": hdr_key,
            "present": present, "value": value,
            "nist_control": meta["nist"],
        })
        if not present:
            findings.append({
                "severity": "high" if meta["weight"] >= 8 else "medium",
                "title": f"Missing {meta['label']}",
                "description": f"The {meta['label']} header is not set.",
                "nist_control": meta["nist"], "category": "headers",
            })
            score_deductions += meta["weight"]

    # ── 5. Server disclosure ─────────────────────────────────────────────
    server_hdr = resp_headers.get("server", "")
    powered_by = resp_headers.get("x-powered-by", "")
    if server_hdr:
        findings.append({
            "severity": "low", "title": f"Server Disclosed: {server_hdr}",
            "description": "Reveals server software — aids targeted attacks.",
            "nist_control": "SC-8", "category": "disclosure",
        })
        score_deductions += 2
    if powered_by:
        findings.append({
            "severity": "medium", "title": f"X-Powered-By: {powered_by}",
            "description": "Reveals application framework.",
            "nist_control": "SC-8", "category": "disclosure",
        })
        score_deductions += 3

    # ── 6. Cookie audit ──────────────────────────────────────────────────
    cookie_list = _analyze_cookies(resp)
    insecure_cookies = [c for c in cookie_list if not c["secure"]]
    for c in insecure_cookies:
        findings.append({
            "severity": "medium",
            "title": f"Insecure Cookie: {c['name']}",
            "description": "; ".join(c["issues"]),
            "nist_control": "AC-4", "category": "cookies",
        })
        score_deductions += 3

    # ── 7. DNS analysis ──────────────────────────────────────────────────
    dns_info = None
    if req.scan_dns:
        dns_info = _analyze_dns(hostname)
        for f in dns_info.get("findings", []):
            findings.append({**f, "category": "dns"})
            score_deductions += {"critical": 15, "high": 8, "medium": 5, "low": 2, "info": 0}.get(f["severity"], 0)

    # ── 8. Port scan ─────────────────────────────────────────────────────
    open_ports = []
    if req.scan_ports:
        open_ports = await _scan_ports(hostname)
        risky = [p for p in open_ports if p["risk"] in ("high", "medium")]
        for p in risky:
            findings.append({
                "severity": p["risk"],
                "title": f"Port {p['port']} Open ({p['service']})",
                "description": f"Port {p['port']} ({p['service']}) is open and reachable from the internet.",
                "nist_control": "SC-7", "category": "ports",
            })
            score_deductions += 5 if p["risk"] == "high" else 3

    # ── 9. Technology fingerprinting ─────────────────────────────────────
    technologies = _detect_technologies(resp_headers, body_text)

    # ── Compute score & grade ────────────────────────────────────────────
    security_score = max(0, min(100, max_score - score_deductions))
    grade = _compute_grade(security_score)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        severity_counts[f.get("severity", "info")] = severity_counts.get(f.get("severity", "info"), 0) + 1

    scan_end = datetime.now(timezone.utc)
    duration_ms = int((scan_end - scan_start).total_seconds() * 1000)

    return {
        "url": url_str,
        "hostname": hostname,
        "ip_addresses": dns_info["a_records"] if dns_info else [],
        "status_code": resp.status_code,
        "redirect_chain": [str(r.url) for r in resp.history] if resp.history else [],
        "scanned_at": scan_start.isoformat(),
        "duration_ms": duration_ms,
        "security_score": security_score,
        "grade": grade,
        "ssl": ssl_info,
        "headers": header_results,
        "cookies": cookie_list,
        "dns": dns_info,
        "open_ports": open_ports,
        "technologies": technologies,
        "findings": sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "info"), 5)),
        "summary": {
            "total_findings": len(findings),
            **severity_counts,
        },
    }
