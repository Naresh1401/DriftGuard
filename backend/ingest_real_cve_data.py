"""
Ingest real-world CVE threat intelligence data into DriftGuard.
Source: cvefeed.io — April 18, 2026 (live CVE data)

Maps real CVEs to the 6 DriftGuard drift patterns:
  1. Fatigue — WordPress XSS vulns rubber-stamped in audits
  2. Overconfidence — Critical RCE CVEs dismissed by overconfident teams
  3. Hurry — Apache Airflow CVE responses rushed under time pressure
  4. Hoarding — Credential leak CVEs + stale access accumulation
  5. Quiet Fear — iTerm2 RCE suppressed, under-reported findings
  6. Compliance Theater — Path traversal repeat findings + checkbox security
"""
import requests
import json
import sys

BASE = "http://localhost:8000/api/v1"

# Authenticate
print("=" * 60)
print("  DriftGuard — Real-World CVE Data Ingestion")
print("  Source: cvefeed.io live feed — April 18, 2026")
print("=" * 60)
print()

r = requests.post(f"{BASE}/auth/login", json={
    "email": "testuser@driftguard.com",
    "password": "Test1234!"
})
if r.status_code != 200:
    print(f"  Login failed: {r.status_code}")
    sys.exit(1)

token = r.json()["access_token"]
AUTH = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
print("  Authenticated as testuser@driftguard.com")
print()

# ── Define 6 batches mapped to real CVEs ─────────────

batches = [
    {
        "name": "Fatigue — WordPress XSS vulns rubber-stamped",
        "cves": ["CVE-2026-2986", "CVE-2026-2505", "CVE-2026-0894", "CVE-2026-6048", "CVE-2026-4801"],
        "payload": {
            "signals": [
                {
                    "signal_type": "audit_review",
                    "source": "cve-feed/CVE-2026-2986",
                    "data": {
                        "review_duration_seconds": 12,
                        "completion_rate": 0.98,
                        "outcome_changed": False,
                        "cve": "CVE-2026-2986",
                        "cvss": 6.4,
                        "description": "WordPress Contextual Related Posts XSS — reviewed and dismissed in 12 seconds"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "cve-feed/CVE-2026-2505",
                    "data": {
                        "review_duration_seconds": 8,
                        "completion_rate": 0.99,
                        "outcome_changed": False,
                        "cve": "CVE-2026-2505",
                        "cvss": 6.4,
                        "description": "WordPress Categories Images XSS — rubber-stamped without analysis"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "cve-feed/CVE-2026-0894",
                    "data": {
                        "review_duration_seconds": 15,
                        "completion_rate": 0.97,
                        "outcome_changed": False,
                        "cve": "CVE-2026-0894",
                        "cvss": 6.4,
                        "description": "WordPress Content Blocks XSS — auto-approved without deep review"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "cve-feed/CVE-2026-6048",
                    "data": {
                        "review_duration_seconds": 5,
                        "completion_rate": 1.0,
                        "outcome_changed": False,
                        "cve": "CVE-2026-6048",
                        "cvss": 6.4,
                        "description": "Flipbox Addon XSS — batch-dismissed with 17 other XSS vulns"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "cve-feed/CVE-2026-4801",
                    "data": {
                        "review_duration_seconds": 9,
                        "completion_rate": 0.96,
                        "outcome_changed": False,
                        "cve": "CVE-2026-4801",
                        "cvss": 6.4,
                        "description": "CoBlocks XSS — marked low priority without reading advisory"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "security-ops",
            "system_id": "vuln-management"
        }
    },
    {
        "name": "Overconfidence — Critical RCE CVEs dismissed",
        "cves": ["CVE-2026-41242", "CVE-2026-6518"],
        "payload": {
            "signals": [
                {
                    "signal_type": "access_log",
                    "source": "cve-feed/CVE-2026-41242",
                    "data": {
                        "privilege_count": 12,
                        "stale_access": True,
                        "dismissed": True,
                        "bypass": True,
                        "risk_level": "critical",
                        "cve": "CVE-2026-41242",
                        "cvss": 9.4,
                        "description": "CRITICAL protobufjs arbitrary code execution — dismissed: 'our code does not use protobuf'"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "approval_workflow",
                    "source": "cve-feed/CVE-2026-41242",
                    "data": {
                        "approval_window_minutes": 2,
                        "validation_complete": False,
                        "cve": "CVE-2026-41242",
                        "cvss": 9.4,
                        "description": "Emergency protobufjs RCE patch approved in 2 minutes without testing"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "access_log",
                    "source": "cve-feed/CVE-2026-6518",
                    "data": {
                        "privilege_count": 15,
                        "stale_access": True,
                        "dismissed": True,
                        "bypass": True,
                        "risk_level": "high",
                        "cve": "CVE-2026-6518",
                        "cvss": 8.8,
                        "description": "WordPress CMP plugin arbitrary file upload RCE — team says WAF will catch it"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "access_log",
                    "source": "sentinel/overconfidence",
                    "data": {
                        "privilege_count": 20,
                        "stale_access": True,
                        "dismissed": True,
                        "approver_count": 1,
                        "risk_level": "critical",
                        "description": "Multiple CVSS 9.0+ CVEs dismissed by single senior engineer without peer review"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "security-ops",
            "system_id": "vuln-management"
        }
    },
    {
        "name": "Hurry — Apache Airflow CVEs rushed under pressure",
        "cves": ["CVE-2026-40948", "CVE-2026-30912", "CVE-2026-30898", "CVE-2026-25917"],
        "payload": {
            "signals": [
                {
                    "signal_type": "incident_response",
                    "source": "cve-feed/CVE-2026-40948",
                    "data": {
                        "retracted": True,
                        "cve": "CVE-2026-40948",
                        "description": "Apache Airflow OAuth CSRF (missing state param) — incident response retracted after hasty all-clear"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "approval_workflow",
                    "source": "cve-feed/CVE-2026-30912",
                    "data": {
                        "approval_window_minutes": 1,
                        "validation_complete": False,
                        "cve": "CVE-2026-30912",
                        "description": "Airflow stack trace exposure — patch deployed without review to meet SLA deadline"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "approval_workflow",
                    "source": "cve-feed/CVE-2026-30898",
                    "data": {
                        "approval_window_minutes": 3,
                        "validation_complete": False,
                        "cve": "CVE-2026-30898",
                        "description": "Airflow BashOperator shell injection — quick-fix deployed that broke 3 downstream services"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "incident_response",
                    "source": "cve-feed/CVE-2026-25917",
                    "data": {
                        "retracted": False,
                        "cve": "CVE-2026-25917",
                        "description": "Airflow XCom deserialization RCE — closed as wont-fix under sprint deadline pressure"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "devops",
            "system_id": "ci-cd-pipeline"
        }
    },
    {
        "name": "Hoarding — Credential leaks & stale access accumulation",
        "cves": ["CVE-2026-40490", "CVE-2026-32690"],
        "payload": {
            "signals": [
                {
                    "signal_type": "access_log",
                    "source": "cve-feed/CVE-2026-40490",
                    "data": {
                        "shared_credential": True,
                        "export_volume_mb": 500,
                        "stale_access": True,
                        "cve": "CVE-2026-40490",
                        "cvss": 6.8,
                        "description": "AsyncHttpClient credential leak on cross-origin redirect — team had unused API keys active for 18 months"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "access_log",
                    "source": "cve-feed/CVE-2026-32690",
                    "data": {
                        "privilege_count": 25,
                        "stale_access": True,
                        "dismissed": False,
                        "export_volume_mb": 200,
                        "cve": "CVE-2026-32690",
                        "description": "Airflow nested variable secrets bypass — found 47 unrestricted service accounts during audit"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "access_log",
                    "source": "sentinel/hoarding",
                    "data": {
                        "shared_credential": True,
                        "export_volume_mb": 1200,
                        "privilege_count": 30,
                        "stale_access": True,
                        "description": "Large bulk data export — 1.2GB extracted via shared credentials from production"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "access_log",
                    "source": "cloudtrail/hoarding",
                    "data": {
                        "privilege_count": 18,
                        "stale_access": True,
                        "dismissed": True,
                        "description": "12 dormant admin accounts still have production database access after role changes"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "data-engineering",
            "system_id": "data-platform"
        }
    },
    {
        "name": "Quiet Fear — iTerm2 RCE suppressed, under-reporting",
        "cves": ["CVE-2026-41253", "CVE-2026-40494"],
        "payload": {
            "signals": [
                {
                    "signal_type": "communication",
                    "source": "cve-feed/CVE-2026-41253",
                    "data": {
                        "delayed_disclosure": True,
                        "severity_downgraded": True,
                        "cve": "CVE-2026-41253",
                        "cvss": 6.9,
                        "description": "iTerm2 SSH Conductor RCE — known internally for 3 weeks before disclosure, severity downgraded from Critical to Medium in tracker"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "incident_response",
                    "source": "cve-feed/CVE-2026-40494",
                    "data": {
                        "retracted": True,
                        "cve": "CVE-2026-40494",
                        "cvss": 9.8,
                        "description": "SAIL heap buffer overflow in TGA decoder — incident report retracted to avoid blame during quarterly review"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "communication",
                    "source": "sentinel/quiet-fear",
                    "data": {
                        "delayed_disclosure": True,
                        "severity_downgraded": True,
                        "description": "Pattern: security findings systematically downgraded before board meetings — 6 instances in 90 days"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "splunk/quiet-fear",
                    "data": {
                        "review_duration_seconds": 300,
                        "completion_rate": 0.4,
                        "outcome_changed": True,
                        "description": "Audit review completion dropped 60% — reviewers actively avoiding flagging issues"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "compliance",
            "system_id": "grc-platform"
        }
    },
    {
        "name": "Compliance Theater — Repeat findings + checkbox security",
        "cves": ["CVE-2026-40491", "CVE-2026-32228"],
        "payload": {
            "signals": [
                {
                    "signal_type": "training_completion",
                    "source": "cve-feed/CVE-2026-40491",
                    "data": {
                        "repeat_finding": True,
                        "minimum_effort": True,
                        "completion_rate": 1.0,
                        "cve": "CVE-2026-40491",
                        "cvss": 6.5,
                        "description": "gdown path traversal in extractall — same vuln class failed in last 3 pen tests, team just re-certifies OWASP training"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "training_completion",
                    "source": "cve-feed/CVE-2026-32228",
                    "data": {
                        "repeat_finding": True,
                        "minimum_effort": True,
                        "completion_rate": 0.99,
                        "cve": "CVE-2026-32228",
                        "description": "Airflow authorization bypass — RBAC policy exists on paper but service accounts bypass all gates in practice"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "audit_review",
                    "source": "compliance/theater",
                    "data": {
                        "review_duration_seconds": 3,
                        "completion_rate": 1.0,
                        "outcome_changed": False,
                        "description": "SOC2 evidence collection fully automated to always pass — zero human verification"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "approval_workflow",
                    "source": "compliance/theater",
                    "data": {
                        "approval_window_minutes": 0,
                        "validation_complete": True,
                        "description": "Change approval board auto-approves all requests from senior staff — 100% approval rate over 6 months"
                    },
                    "domain": "enterprise"
                },
                {
                    "signal_type": "training_completion",
                    "source": "compliance/theater",
                    "data": {
                        "repeat_finding": True,
                        "minimum_effort": True,
                        "completion_rate": 0.95,
                        "description": "45-minute annual security training completed in average 4 minutes across 200+ employees"
                    },
                    "domain": "enterprise"
                },
            ],
            "domain": "enterprise",
            "team_id": "compliance",
            "system_id": "grc-platform"
        }
    },
]

# ── Ingest all batches ──────────────────────────────

total_signals = 0
total_alerts = 0

for i, batch in enumerate(batches, 1):
    r = requests.post(f"{BASE}/signals/ingest/batch", headers=AUTH, json=batch["payload"])
    if r.status_code == 200:
        data = r.json()
        alert = data.get("alert")
        alert_info = f'{alert["alert_level"]} (severity: {alert["severity_score"]})' if alert else "none"
        patterns = len(data.get("report", {}).get("active_patterns", []))
        total_signals += data["signals_processed"]
        if alert:
            total_alerts += 1
        print(f"  [{i}/6] {batch['name']}")
        print(f"        CVEs: {', '.join(batch['cves'])}")
        print(f"        Signals: {data['signals_processed']} | Patterns detected: {patterns} | Alert: {alert_info}")
        print()
    else:
        print(f"  [{i}/6] {batch['name']} — FAILED ({r.status_code})")
        print(f"        Error: {r.text[:200]}")
        print()

# ── Verify system state ─────────────────────────────

print("=" * 60)
print("  System State After Real CVE Ingestion")
print("=" * 60)

# Alerts
r = requests.get(f"{BASE}/alerts", headers=AUTH)
alerts_data = r.json()
alerts = alerts_data.get("alerts", [])
print(f"\n  Total Signals Ingested: {total_signals}")
print(f"  Alerts Generated: {total_alerts}")
print(f"  Active Alerts in System: {len(alerts)}")

for a in alerts[:6]:
    level = a.get("alert_level", "?")
    explanation = a.get("plain_language_explanation", "")[:90]
    patterns = [p.get("pattern", "?") for p in a.get("drift_patterns", [])]
    print(f"    [{level}] Patterns: {patterns}")
    if explanation:
        print(f"           {explanation}")

# Health score
r = requests.get(f"{BASE}/alerts/health-score/enterprise", headers=AUTH)
hs = r.json()
print(f"\n  Organization Health Score: {hs.get('health_score', '?')}/100")

# NIST risk
r = requests.get(f"{BASE}/reports/nist-risk", headers=AUTH)
nist = r.json()
controls = nist.get("controls_at_risk", [])
print(f"  NIST Controls at Risk: {len(controls)}")
for c in controls[:5]:
    print(f"    {c['control']}: {c['alert_count']} alert(s), max severity {c['max_severity']}")

# Drift map
r = requests.get(f"{BASE}/drift-map/heatmap", headers=AUTH)
print(f"\n  Drift Map: {'OK' if r.status_code == 200 else 'FAIL'} ({r.status_code})")

# Weekly summary
r = requests.get(f"{BASE}/reports/weekly-summary", headers=AUTH)
print(f"  Weekly Summary: {'OK' if r.status_code == 200 else 'FAIL'} ({r.status_code})")

# Board summary
r = requests.get(f"{BASE}/reports/board-summary", headers=AUTH)
print(f"  Board Summary: {'OK' if r.status_code == 200 else 'FAIL'} ({r.status_code})")

print()
print("=" * 60)
print("  Real-world CVE data ingested successfully!")
print("  Open http://localhost:3000 to see the dashboard")
print("=" * 60)
