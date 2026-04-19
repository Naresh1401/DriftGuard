#!/usr/bin/env bash
# DriftGuard — Full E2E Test Suite (15 Steps)
# Usage: TOKEN=<jwt> bash e2e_test.sh

set -euo pipefail

BASE="http://localhost:8000/api/v1"
AUTH="Authorization: Bearer $TOKEN"
CT="Content-Type: application/json"
PASS=0; FAIL=0; WARN=0
declare -a RESULTS=()

log_result() {
  local step="$1" name="$2" status="$3" detail="$4"
  if [[ "$status" == "PASS" ]]; then ((PASS++)); fi
  if [[ "$status" == "FAIL" ]]; then ((FAIL++)); fi
  if [[ "$status" == "WARN" ]]; then ((WARN++)); fi
  RESULTS+=("| $step | $name | $status | $detail |")
}

echo "═══════════════════════════════════════════════════════"
echo "  DriftGuard E2E Test Suite — $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Health Check ─────────────────────────────
echo "▸ Step 1: Health Check"
RESP=$(curl -sf "$BASE/health" 2>&1) || RESP=""
STATUS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
DB=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('database',''))" 2>/dev/null || echo "")
VDB=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('vector_db',''))" 2>/dev/null || echo "")
if [[ "$STATUS" == "healthy" && "$DB" == "connected" ]]; then
  log_result "1" "Health Check" "PASS" "status=$STATUS, db=$DB, vector_db=$VDB"
else
  log_result "1" "Health Check" "FAIL" "status=$STATUS, db=$DB"
fi

# ── Step 2: Authentication ───────────────────────────
echo "▸ Step 2: Authentication (register + login + /me)"
UNIQUE_EMAIL="e2e-$(date +%s)@driftguard.com"
# Register fresh user each run to avoid rate-limiter
REG_RESP=$(curl -s -X POST "$BASE/auth/register" -H "$CT" \
  -d "{\"email\":\"$UNIQUE_EMAIL\",\"password\":\"Test1234!\",\"full_name\":\"E2E\",\"role\":\"admin\",\"organization\":\"DG\"}")
REG_TOKEN=$(echo "$REG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
if [[ -n "$REG_TOKEN" ]]; then
  TOKEN="$REG_TOKEN"
  AUTH="Authorization: Bearer $TOKEN"
fi
# Login
LOGIN_RESP=$(curl -s -X POST "$BASE/auth/login" -H "$CT" \
  -d "{\"email\":\"$UNIQUE_EMAIL\",\"password\":\"Test1234!\"}")
LOGIN_TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
if [[ -n "$LOGIN_TOKEN" ]]; then
  TOKEN="$LOGIN_TOKEN"
  AUTH="Authorization: Bearer $TOKEN"
fi
# Me
ME_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/auth/me" -H "$AUTH")
ME_RESP=$(curl -sf "$BASE/auth/me" -H "$AUTH" 2>&1) || ME_RESP=""
ME_EMAIL=$(echo "$ME_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null || echo "")
if [[ -n "$TOKEN" && "$TOKEN" != "dummy" && "$ME_CODE" == "200" && -n "$ME_EMAIL" ]]; then
  log_result "2" "Authentication" "PASS" "register+login=OK, /me=$ME_EMAIL"
else
  log_result "2" "Authentication" "FAIL" "reg_token=${REG_TOKEN:0:10}…, login_token=${LOGIN_TOKEN:0:10}…, me_code=$ME_CODE"
fi

# ── Step 3: Signal Ingestion ────────────────────────
echo "▸ Step 3: Signal Ingestion (single + batch)"
SIG_RESP=$(curl -sf -X POST "$BASE/signals/ingest" -H "$AUTH" -H "$CT" \
  -d '{"signal_type":"access_log","source":"e2e-test","data":{"user":"alice","action":"login","dismissed":true},"domain":"enterprise"}' 2>&1) || SIG_RESP=""
SIG_ID=$(echo "$SIG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signal_id',''))" 2>/dev/null || echo "")

BATCH_RESP=$(curl -sf -X POST "$BASE/signals/ingest/batch" -H "$AUTH" -H "$CT" \
  -d '{
    "signals": [
      {"signal_type":"audit_review","source":"e2e","data":{"review_duration_seconds":15,"completion_rate":0.95,"outcome_changed":false},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"privilege_count":8,"stale_access":true,"dismissed":true},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"bypass":true,"risk_level":"high","approver_count":1},"domain":"enterprise"},
      {"signal_type":"approval_workflow","source":"e2e","data":{"approval_window_minutes":3,"validation_complete":false},"domain":"enterprise"},
      {"signal_type":"incident_response","source":"e2e","data":{"retracted":true},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"shared_credential":true,"export_volume_mb":250},"domain":"enterprise"},
      {"signal_type":"audit_review","source":"e2e","data":{"repeat_finding":true,"minimum_effort":true,"completion_rate":0.92,"outcome_changed":false},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true},"domain":"enterprise"},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":false},"domain":"enterprise"}
    ],
    "domain": "enterprise"
  }' 2>&1) || BATCH_RESP=""
BATCH_STATUS=$(echo "$BATCH_RESP" | python3 -c "import sys,json; r=json.load(sys.stdin); print('complete' if r.get('signals_processed',0)>0 else '')" 2>/dev/null || echo "")
BATCH_CLS=$(echo "$BATCH_RESP" | python3 -c "import sys,json; r=json.load(sys.stdin); print(len(r.get('report',{}).get('active_patterns',[])))" 2>/dev/null || echo "0")
if [[ -n "$SIG_ID" && "$BATCH_STATUS" == "complete" ]]; then
  log_result "3" "Signal Ingestion" "PASS" "single=$SIG_ID, batch=$BATCH_STATUS, classifications=$BATCH_CLS"
else
  log_result "3" "Signal Ingestion" "FAIL" "sig_id=$SIG_ID, batch_status=$BATCH_STATUS"
fi

# ── Step 4: LangGraph Pipeline ──────────────────────
echo "▸ Step 4: LangGraph Pipeline (analyze endpoint)"
ANALYZE_RESP=$(curl -sf -X POST "$BASE/analyze" -H "$AUTH" -H "$CT" \
  -d '{
    "signals": [
      {"signal_type":"audit_review","source":"e2e","data":{"review_duration_seconds":10,"completion_rate":0.98,"outcome_changed":false}},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true,"batch_size":8}},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true}},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true}},
      {"signal_type":"access_log","source":"e2e","data":{"dismissed":true}},
      {"signal_type":"access_log","source":"e2e","data":{"bypass":true,"exception":true,"risk_level":"critical","approver_count":1}}
    ],
    "domain": "enterprise"
  }' 2>&1) || ANALYZE_RESP=""
ANALYZE_STATUS=$(echo "$ANALYZE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
ANALYZE_COUNT=$(echo "$ANALYZE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signals_processed',0))" 2>/dev/null || echo "0")
if [[ "$ANALYZE_STATUS" == "complete" && "$ANALYZE_COUNT" -gt 0 ]]; then
  log_result "4" "LangGraph Pipeline" "PASS" "status=$ANALYZE_STATUS, signals=$ANALYZE_COUNT (no InvalidUpdateError)"
else
  log_result "4" "LangGraph Pipeline" "FAIL" "status=$ANALYZE_STATUS, count=$ANALYZE_COUNT"
fi

# ── Step 5: Drift Map / Heatmap ─────────────────────
echo "▸ Step 5: Drift Map"
HMAP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/drift-map/heatmap" -H "$AUTH")
HMAP_RESP=$(curl -sf "$BASE/drift-map/heatmap" -H "$AUTH" 2>&1) || HMAP_RESP=""
SUMMARY_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/drift-map/summary" -H "$AUTH")
if [[ "$HMAP_CODE" == "200" && "$SUMMARY_CODE" == "200" ]]; then
  log_result "5" "Drift Map" "PASS" "heatmap=$HMAP_CODE, summary=$SUMMARY_CODE"
else
  log_result "5" "Drift Map" "FAIL" "heatmap=$HMAP_CODE, summary=$SUMMARY_CODE"
fi

# ── Step 6: Alerts ──────────────────────────────────
echo "▸ Step 6: Alert System"
ALERTS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/alerts" -H "$AUTH")
ALERTS_RESP=$(curl -sf "$BASE/alerts" -H "$AUTH" 2>&1) || ALERTS_RESP=""
ALERT_COUNT=$(echo "$ALERTS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "0")
COUNTS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/alerts/active/count" -H "$AUTH")
if [[ "$ALERTS_CODE" == "200" && "$COUNTS_CODE" == "200" ]]; then
  log_result "6" "Alert System" "PASS" "list=$ALERTS_CODE ($ALERT_COUNT alerts), counts=$COUNTS_CODE"
else
  log_result "6" "Alert System" "FAIL" "list=$ALERTS_CODE, counts=$COUNTS_CODE"
fi

# ── Step 7: Reports ─────────────────────────────────
echo "▸ Step 7: Reports"
WEEKLY_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/reports/weekly-summary" -H "$AUTH")
NIST_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/reports/nist-risk" -H "$AUTH")
BOARD_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/reports/board-summary" -H "$AUTH")
EXPORT_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/reports/export?format=json" -H "$AUTH")
TREND_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/reports/trend/fatigue" -H "$AUTH")
if [[ "$WEEKLY_CODE" == "200" && "$NIST_CODE" == "200" && "$BOARD_CODE" == "200" && "$EXPORT_CODE" == "200" ]]; then
  log_result "7" "Reports" "PASS" "weekly=$WEEKLY_CODE, nist=$NIST_CODE, board=$BOARD_CODE, export=$EXPORT_CODE, trend=$TREND_CODE"
else
  log_result "7" "Reports" "FAIL" "weekly=$WEEKLY_CODE, nist=$NIST_CODE, board=$BOARD_CODE, export=$EXPORT_CODE"
fi

# ── Step 8: Scans ───────────────────────────────────
echo "▸ Step 8: Scan Engine"
SCAN_RESP=$(curl -sf -X POST "$BASE/scans/trigger" -H "$AUTH" -H "$CT" \
  -d '{"domain":"enterprise","scope":"quick"}' 2>&1) || SCAN_RESP=""
SCAN_ID=$(echo "$SCAN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan_id',''))" 2>/dev/null || echo "")
sleep 1
SCAN_STATUS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scans/status" -H "$AUTH")
SCAN_HIST_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scans/history" -H "$AUTH")
if [[ -n "$SCAN_ID" && "$SCAN_STATUS_CODE" == "200" && "$SCAN_HIST_CODE" == "200" ]]; then
  log_result "8" "Scan Engine" "PASS" "scan_id=$SCAN_ID, status=$SCAN_STATUS_CODE, history=$SCAN_HIST_CODE"
else
  log_result "8" "Scan Engine" "FAIL" "scan_id=$SCAN_ID, status=$SCAN_STATUS_CODE, history=$SCAN_HIST_CODE"
fi

# ── Step 9: Governance ──────────────────────────────
echo "▸ Step 9: Governance"
GOV_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/governance/audit-log" -H "$AUTH")
PENDING_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/governance/gates/pending" -H "$AUTH")
if [[ "$GOV_CODE" == "200" && "$PENDING_CODE" == "200" ]]; then
  log_result "9" "Governance" "PASS" "audit=$GOV_CODE, pending=$PENDING_CODE"
else
  log_result "9" "Governance" "FAIL" "audit=$GOV_CODE, pending=$PENDING_CODE"
fi

# ── Step 10: Calibration ────────────────────────────
echo "▸ Step 10: NI Calibration"
CAL_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/calibration/retrieve" -H "$AUTH" -H "$CT" \
  -d '{"drift_pattern":"Fatigue","severity":3}')
FEEDBACK_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/calibration/effectiveness" -H "$AUTH")
if [[ "$CAL_CODE" == "200" && "$FEEDBACK_CODE" == "200" ]]; then
  log_result "10" "NI Calibration" "PASS" "retrieve=$CAL_CODE, effectiveness=$FEEDBACK_CODE"
else
  log_result "10" "NI Calibration" "FAIL" "retrieve=$CAL_CODE, effectiveness=$FEEDBACK_CODE"
fi

# ── Step 11: Domains ────────────────────────────────
echo "▸ Step 11: Domain Configurations"
DOMAINS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/domains" -H "$AUTH")
DOMAIN_DETAIL_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/domains/enterprise" -H "$AUTH")
if [[ "$DOMAINS_CODE" == "200" && "$DOMAIN_DETAIL_CODE" == "200" ]]; then
  log_result "11" "Domains" "PASS" "list=$DOMAINS_CODE, detail=$DOMAIN_DETAIL_CODE"
else
  log_result "11" "Domains" "FAIL" "list=$DOMAINS_CODE, detail=$DOMAIN_DETAIL_CODE"
fi

# ── Step 12: Integrations ───────────────────────────
echo "▸ Step 12: Integrations"
APPS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/integrations/apps" -H "$AUTH")
WEBHOOK_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/integrations/webhook" -H "$AUTH" -H "$CT" \
  -d '{"source":"github","event_type":"push","payload":{"ref":"refs/heads/main","repository":{"full_name":"test/repo"}}}')
if [[ "$APPS_CODE" == "200" && "$WEBHOOK_CODE" == "200" ]]; then
  log_result "12" "Integrations" "PASS" "apps=$APPS_CODE, webhook=$WEBHOOK_CODE"
else
  log_result "12" "Integrations" "FAIL" "apps=$APPS_CODE, webhook=$WEBHOOK_CODE"
fi

# ── Step 13: Convenience Endpoints ──────────────────
echo "▸ Step 13: Convenience Endpoints"
APIKEY_RESP=$(curl -sf -X POST "$BASE/api-key" -H "$AUTH" -H "$CT" \
  -d '{"name":"e2e-key","scopes":["read","write"]}' 2>&1) || APIKEY_RESP=""
APIKEY=$(echo "$APIKEY_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_key',''))" 2>/dev/null || echo "")
APIKEY_STATUS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api-key/status" -H "$AUTH")
DASHBOARD_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/dashboard/overview" -H "$AUTH")
DRIFT_DET_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/drift/detections" -H "$AUTH")
NIST_SHORTCUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nist-risk" -H "$AUTH")
TRENDS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/trends" -H "$AUTH")
SIMULATE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/simulate" -H "$AUTH" -H "$CT" \
  -d '{"domain":"enterprise","scope":"quick"}')
if [[ -n "$APIKEY" && "$APIKEY_STATUS_CODE" == "200" && "$DASHBOARD_CODE" == "200" && "$DRIFT_DET_CODE" == "200" && "$NIST_SHORTCUT_CODE" == "200" && "$TRENDS_CODE" == "200" ]]; then
  log_result "13" "Convenience Endpoints" "PASS" "api-key=OK, status=$APIKEY_STATUS_CODE, dashboard=$DASHBOARD_CODE, detections=$DRIFT_DET_CODE, nist=$NIST_SHORTCUT_CODE, trends=$TRENDS_CODE, simulate=$SIMULATE_CODE"
else
  log_result "13" "Convenience Endpoints" "FAIL" "api-key=${APIKEY:0:10}…, status=$APIKEY_STATUS_CODE, dashboard=$DASHBOARD_CODE, detections=$DRIFT_DET_CODE, nist=$NIST_SHORTCUT_CODE, trends=$TRENDS_CODE"
fi

# ── Step 14: Threat Intel ───────────────────────────
echo "▸ Step 14: Threat Intelligence"
THREAT_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/threat-intel/feed" -H "$AUTH")
THREAT_CORR_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/threat-intel/correlate" -H "$AUTH")
if [[ "$THREAT_CODE" == "200" ]]; then
  log_result "14" "Threat Intelligence" "PASS" "feed=$THREAT_CODE, correlate=$THREAT_CORR_CODE"
else
  log_result "14" "Threat Intelligence" "FAIL" "feed=$THREAT_CODE, correlate=$THREAT_CORR_CODE"
fi

# ── Step 15: Ethical Guardrails ─────────────────────
echo "▸ Step 15: Ethical Guardrails"
ETHICAL_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health/ethical-statement" )
ETHICAL_RESP=$(curl -sf "$BASE/health/ethical-statement" 2>&1) || ETHICAL_RESP=""
ETHICAL_HAS_STATEMENT=$(echo "$ETHICAL_RESP" | python3 -c "import sys,json; s=json.load(sys.stdin).get('statement',''); print('yes' if 'not individuals' in s else 'no')" 2>/dev/null || echo "no")
# Verify banner in health response
HEALTH_HAS_BANNER=$(echo "$(curl -sf $BASE/health)" | python3 -c "import sys,json; print('yes' if 'ethical_banner' in json.load(sys.stdin) else 'no')" 2>/dev/null || echo "no")
if [[ "$ETHICAL_CODE" == "200" && "$ETHICAL_HAS_STATEMENT" == "yes" && "$HEALTH_HAS_BANNER" == "yes" ]]; then
  log_result "15" "Ethical Guardrails" "PASS" "statement=present, banner_in_health=yes"
else
  log_result "15" "Ethical Guardrails" "FAIL" "code=$ETHICAL_CODE, statement=$ETHICAL_HAS_STATEMENT, banner=$HEALTH_HAS_BANNER"
fi

# ── Results Table ────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  E2E Test Results Summary"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "| Step | Test | Result | Details |"
echo "|------|------|--------|---------|"
for r in "${RESULTS[@]}"; do echo "$r"; done
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  PASS: $PASS  |  FAIL: $FAIL  |  WARN: $WARN  |  Total: $((PASS+FAIL+WARN))/15"
echo "═══════════════════════════════════════════════════════"
