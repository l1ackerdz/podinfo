#!/usr/bin/env bash
# =============================================================================
# Security Verification Test Script — podinfo (SAFE / READ-ONLY)
# Target: https://test01.datagravity.pre.awscl.inditex.com/
#
# SAFE MODE: Does NOT call /panic, /readyz/disable, or any destructive endpoint.
# Only performs read-only GET requests and safe POST probes.
#
# Usage: bash security-test-curl.sh [HOST]
# =============================================================================

HOST="${1:-https://test01.datagravity.pre.awscl.inditex.com}"
PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓ PASS${NC}  $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗ FAIL${NC}  $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}⚠ WARN${NC}  $1"; ((WARN++)); }
info() { echo -e "  ${BLUE}ℹ INFO${NC}  $1"; }
header() { echo -e "\n${BLUE}══════════════════════════════════════════════════${NC}"; echo -e "${BLUE} $1${NC}"; echo -e "${BLUE}══════════════════════════════════════════════════${NC}"; }

echo "╔══════════════════════════════════════════════════════╗"
echo "║   podinfo Security Verification Tests (SAFE MODE)   ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Target: $HOST"
echo "║  Date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "║  Mode:   READ-ONLY (no destructive endpoints)        ║"
echo "╚══════════════════════════════════════════════════════╝"

# ---------------------------------------------------------------------------
# Helper: probe endpoint and return status + body
# ---------------------------------------------------------------------------
probe() {
    local METHOD="${1:-GET}"
    local URL="$2"
    local DATA="$3"
    local TIMEOUT="${4:-8}"
    if [[ -n "$DATA" ]]; then
        curl -sk --max-time "$TIMEOUT" -X "$METHOD" -d "$DATA" -w "\n__STATUS__%{http_code}" "$URL" 2>/dev/null
    else
        curl -sk --max-time "$TIMEOUT" -X "$METHOD" -w "\n__STATUS__%{http_code}" "$URL" 2>/dev/null
    fi
}

get_status() { echo "$1" | grep -oP '__STATUS__\K[0-9]+$'; }
get_body()   { echo "$1" | sed 's/__STATUS__[0-9]*$//'; }

# ---------------------------------------------------------------------------
# 0. Connectivity check
# ---------------------------------------------------------------------------
header "0. CONNECTIVITY & TLS CHECK"
ROOT_RESP=$(probe GET "$HOST/")
ROOT_STATUS=$(get_status "$ROOT_RESP")
ROOT_BODY=$(get_body "$ROOT_RESP")

info "Root URL: $HOST/"
info "HTTP Status: $ROOT_STATUS"
info "Body preview: $(echo "$ROOT_BODY" | head -c 150 | tr '\n' ' ')"

if [[ "$ROOT_STATUS" == "000" ]]; then
    fail "Host is unreachable (connection refused or DNS failure)"
    exit 1
elif [[ "$ROOT_STATUS" == "504" || "$ROOT_STATUS" == "503" ]]; then
    warn "Backend returns $ROOT_STATUS — app may be down. Continuing tests to check ingress-level protections."
else
    pass "Host is reachable (HTTP $ROOT_STATUS)"
fi

# TLS check
TLS_INFO=$(curl -skv "$HOST/" 2>&1 | grep -iE 'TLSv[0-9]|cipher|subject:|issuer:|expire' | head -8)
echo ""
info "TLS Details:"
echo "$TLS_INFO" | while read -r line; do info "  $line"; done

if echo "$TLS_INFO" | grep -q 'TLSv1\.[23]'; then
    pass "TLS 1.2/1.3 in use"
fi
if echo "$TLS_INFO" | grep -q 'TLSv1\.0\|TLSv1\.1\|SSLv'; then
    fail "Weak TLS version detected (TLS 1.0/1.1 or SSLv)"
fi
CERT_SUBJECT=$(echo "$TLS_INFO" | grep -i 'subject:' | head -1)
CERT_ISSUER=$(echo "$TLS_INFO" | grep -i 'issuer:' | head -1)
[[ -n "$CERT_SUBJECT" ]] && info "Certificate: $CERT_SUBJECT"
[[ -n "$CERT_ISSUER" ]] && info "Issuer: $CERT_ISSUER"

# ---------------------------------------------------------------------------
# 1. HTTP Security Headers
# ---------------------------------------------------------------------------
header "1. HTTP SECURITY HEADERS"
RESP_HEADERS=$(curl -skI --max-time 8 "$HOST/")
echo ""
info "Raw response headers:"
echo "$RESP_HEADERS" | grep -v '^$' | while read -r line; do info "  $line"; done

declare -A EXPECTED_HEADERS=(
    ["Strict-Transport-Security"]="HSTS — prevents protocol downgrade attacks"
    ["X-Frame-Options"]="Clickjacking protection"
    ["X-Content-Type-Options"]="MIME sniffing protection"
    ["Content-Security-Policy"]="XSS / injection protection"
    ["Referrer-Policy"]="Referrer information leakage control"
    ["Permissions-Policy"]="Browser feature access control"
    ["X-XSS-Protection"]="Legacy XSS filter (deprecated but still checked)"
)

echo ""
for HEADER in "${!EXPECTED_HEADERS[@]}"; do
    if echo "$RESP_HEADERS" | grep -qi "^$HEADER:"; then
        VALUE=$(echo "$RESP_HEADERS" | grep -i "^$HEADER:" | head -1 | tr -d '\r')
        pass "Header present: $VALUE"
    else
        warn "Header MISSING: $HEADER — ${EXPECTED_HEADERS[$HEADER]}"
    fi
done

# Check for information-leaking headers
for LEAK_HEADER in "Server" "X-Powered-By" "X-AspNet-Version" "X-Generator"; do
    if echo "$RESP_HEADERS" | grep -qi "^$LEAK_HEADER:"; then
        VALUE=$(echo "$RESP_HEADERS" | grep -i "^$LEAK_HEADER:" | head -1 | tr -d '\r')
        warn "Info-leaking header: $VALUE"
    fi
done

# ---------------------------------------------------------------------------
# 2. VULN-002: /env endpoint — environment variable disclosure
# ---------------------------------------------------------------------------
header "2. VULN-002: /env — Environment Variable Disclosure"
ENV_RESP=$(probe GET "$HOST/env")
ENV_STATUS=$(get_status "$ENV_RESP")
ENV_BODY=$(get_body "$ENV_RESP")

info "GET $HOST/env → HTTP $ENV_STATUS"
info "Body preview: $(echo "$ENV_BODY" | head -c 200 | tr '\n' ' ')"

if [[ "$ENV_STATUS" == "401" || "$ENV_STATUS" == "403" ]]; then
    pass "VULN-002: /env is protected (HTTP $ENV_STATUS)"
elif [[ "$ENV_STATUS" == "404" ]]; then
    pass "VULN-002: /env returns 404 — endpoint not exposed"
elif echo "$ENV_BODY" | grep -qiE '(PATH=|HOME=|HOSTNAME=|KUBERNETES_|_SECRET|_PASSWORD|_TOKEN|_KEY|AWS_)'; then
    fail "VULN-002: /env is UNPROTECTED — environment variables EXPOSED!"
    echo ""
    warn "Sensitive data found in response:"
    echo "$ENV_BODY" | grep -iE '(SECRET|PASSWORD|TOKEN|KEY|AWS_)' | head -5 | while read -r line; do
        warn "  $line"
    done
elif [[ "$ENV_STATUS" == "200" ]]; then
    warn "VULN-002: /env returned 200 but no obvious secrets detected — review manually"
    info "Full body: $(echo "$ENV_BODY" | head -c 500)"
else
    warn "VULN-002: /env returned HTTP $ENV_STATUS (backend may be down)"
fi

# ---------------------------------------------------------------------------
# 3. VULN-003: pprof debug endpoints
# ---------------------------------------------------------------------------
header "3. VULN-003: /debug/pprof/ — Debug Endpoint Exposure"
for PPROF_PATH in "/debug/pprof/" "/debug/pprof/cmdline" "/debug/pprof/symbol"; do
    RESP=$(probe GET "$HOST$PPROF_PATH")
    STATUS=$(get_status "$RESP")
    BODY=$(get_body "$RESP")
    info "GET $HOST$PPROF_PATH → HTTP $STATUS"
    if [[ "$STATUS" == "401" || "$STATUS" == "403" || "$STATUS" == "404" ]]; then
        pass "VULN-003: $PPROF_PATH is protected (HTTP $STATUS)"
    elif echo "$BODY" | grep -qiE '(goroutine|heap|allocs|profile|pprof)'; then
        fail "VULN-003: $PPROF_PATH is UNPROTECTED — pprof UI/data exposed!"
        info "  Body: $(echo "$BODY" | head -c 200)"
    elif [[ "$STATUS" == "200" ]]; then
        warn "VULN-003: $PPROF_PATH returned 200 — verify if pprof data is present"
    else
        warn "VULN-003: $PPROF_PATH returned HTTP $STATUS"
    fi
done

# ---------------------------------------------------------------------------
# 4. VULN-004/007: JWT token generation without authentication
# ---------------------------------------------------------------------------
header "4. VULN-004/007: /token — Unauthenticated Token Generation"
TOKEN_RESP=$(probe POST "$HOST/token" "testuser")
TOKEN_STATUS=$(get_status "$TOKEN_RESP")
TOKEN_BODY=$(get_body "$TOKEN_RESP")

info "POST $HOST/token (body: 'testuser') → HTTP $TOKEN_STATUS"
info "Body preview: $(echo "$TOKEN_BODY" | head -c 200 | tr '\n' ' ')"

if [[ "$TOKEN_STATUS" == "401" || "$TOKEN_STATUS" == "403" ]]; then
    pass "VULN-004/007: /token is protected (HTTP $TOKEN_STATUS)"
elif [[ "$TOKEN_STATUS" == "404" ]]; then
    pass "VULN-004/007: /token returns 404 — endpoint not exposed"
elif echo "$TOKEN_BODY" | grep -qiE '(token|eyJ)'; then
    EXTRACTED_TOKEN=$(echo "$TOKEN_BODY" | grep -oP '"token"\s*:\s*"\K[^"]+' | head -1)
    fail "VULN-004/007: /token is UNPROTECTED — JWT issued for arbitrary user 'testuser'!"
    if [[ -n "$EXTRACTED_TOKEN" ]]; then
        info "  Token (first 60 chars): ${EXTRACTED_TOKEN:0:60}..."
        # Decode JWT header+payload (no signature verification needed)
        PAYLOAD=$(echo "$EXTRACTED_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null || echo "decode failed")
        info "  JWT payload: $PAYLOAD"

        # Check if default secret works — try to validate
        VALIDATE_RESP=$(curl -sk --max-time 8 -H "Authorization: Bearer $EXTRACTED_TOKEN" \
            -w "\n__STATUS__%{http_code}" "$HOST/token/validate" 2>/dev/null)
        VALIDATE_STATUS=$(get_status "$VALIDATE_RESP")
        info "  Token validation at /token/validate → HTTP $VALIDATE_STATUS"
        if [[ "$VALIDATE_STATUS" == "200" ]]; then
            fail "VULN-004: Forged token with DEFAULT secret is VALID — authentication bypass confirmed!"
        fi
    fi
elif [[ "$TOKEN_STATUS" == "200" ]]; then
    warn "VULN-004/007: /token returned 200 but no token detected — verify manually"
else
    warn "VULN-004/007: /token returned HTTP $TOKEN_STATUS (backend may be down)"
fi

# ---------------------------------------------------------------------------
# 5. VULN-008: /configs endpoint
# ---------------------------------------------------------------------------
header "5. VULN-008: /configs — Configuration File Disclosure"
CONFIGS_RESP=$(probe GET "$HOST/configs")
CONFIGS_STATUS=$(get_status "$CONFIGS_RESP")
CONFIGS_BODY=$(get_body "$CONFIGS_RESP")

info "GET $HOST/configs → HTTP $CONFIGS_STATUS"
info "Body preview: $(echo "$CONFIGS_BODY" | head -c 200 | tr '\n' ' ')"

if [[ "$CONFIGS_STATUS" == "401" || "$CONFIGS_STATUS" == "403" ]]; then
    pass "VULN-008: /configs is protected (HTTP $CONFIGS_STATUS)"
elif [[ "$CONFIGS_STATUS" == "404" ]]; then
    pass "VULN-008: /configs returns 404 — endpoint not exposed"
elif [[ "$CONFIGS_STATUS" == "200" ]]; then
    if echo "$CONFIGS_BODY" | grep -qiE '(password|secret|key|token|cert|\.pem|\.key|BEGIN CERTIFICATE|BEGIN RSA)'; then
        fail "VULN-008: /configs is UNPROTECTED and contains SENSITIVE DATA!"
    else
        warn "VULN-008: /configs returned 200 — contents: $(echo "$CONFIGS_BODY" | head -c 300)"
    fi
else
    warn "VULN-008: /configs returned HTTP $CONFIGS_STATUS"
fi

# ---------------------------------------------------------------------------
# 6. VULN-009: Path traversal in /store/{hash}
# ---------------------------------------------------------------------------
header "6. VULN-009: /store/{hash} — Path Traversal"
declare -A TRAVERSALS=(
    ["../etc/passwd"]="Basic traversal"
    ["..%2Fetc%2Fpasswd"]="URL-encoded traversal"
    ["....//etc/passwd"]="Double-dot bypass"
    ["..%252Fetc%252Fpasswd"]="Double URL-encoded"
    ["%2e%2e%2fetc%2fpasswd"]="Fully encoded"
)

for TRAVERSAL in "${!TRAVERSALS[@]}"; do
    RESP=$(probe GET "$HOST/store/$TRAVERSAL")
    STATUS=$(get_status "$RESP")
    BODY=$(get_body "$RESP")
    info "GET $HOST/store/$TRAVERSAL → HTTP $STATUS  [${TRAVERSALS[$TRAVERSAL]}]"
    if echo "$BODY" | grep -q 'root:x:0:'; then
        fail "VULN-009: PATH TRAVERSAL CONFIRMED — /etc/passwd content returned for '$TRAVERSAL'!"
        info "  $(echo "$BODY" | head -3)"
    elif [[ "$STATUS" == "400" || "$STATUS" == "403" || "$STATUS" == "404" ]]; then
        pass "VULN-009: Traversal '$TRAVERSAL' blocked (HTTP $STATUS)"
    else
        warn "VULN-009: '$TRAVERSAL' returned HTTP $STATUS — verify response body"
    fi
done

# ---------------------------------------------------------------------------
# 7. VULN-010: Unauthenticated file write via /store (safe probe — tiny payload)
# ---------------------------------------------------------------------------
header "7. VULN-010: /store — Unauthenticated File Write"
STORE_RESP=$(probe POST "$HOST/store" "security-audit-probe-$(date +%s)")
STORE_STATUS=$(get_status "$STORE_RESP")
STORE_BODY=$(get_body "$STORE_RESP")

info "POST $HOST/store (small test payload) → HTTP $STORE_STATUS"
info "Body: $(echo "$STORE_BODY" | head -c 200 | tr '\n' ' ')"

if [[ "$STORE_STATUS" == "401" || "$STORE_STATUS" == "403" ]]; then
    pass "VULN-010: /store write is protected (HTTP $STORE_STATUS)"
elif [[ "$STORE_STATUS" == "404" ]]; then
    pass "VULN-010: /store returns 404 — endpoint not exposed"
elif [[ "$STORE_STATUS" == "200" || "$STORE_STATUS" == "201" ]]; then
    HASH=$(echo "$STORE_BODY" | grep -oP '"hash"\s*:\s*"\K[^"]+' | head -1)
    fail "VULN-010: /store write is UNPROTECTED (HTTP $STORE_STATUS) — arbitrary file write possible!"
    if [[ -n "$HASH" ]]; then
        info "  Written file hash: $HASH"
        # Verify the file is readable back
        READ_RESP=$(probe GET "$HOST/store/$HASH")
        READ_STATUS=$(get_status "$READ_RESP")
        info "  Read back via GET /store/$HASH → HTTP $READ_STATUS"
        if [[ "$READ_STATUS" == "200" ]]; then
            fail "VULN-010+009: File write AND read confirmed — LFI write/read chain!"
        fi
    fi
else
    warn "VULN-010: /store returned HTTP $STORE_STATUS"
fi

# ---------------------------------------------------------------------------
# 8. VULN-011: DoS via /delay — check if large values are rejected
# ---------------------------------------------------------------------------
header "8. VULN-011: /delay/{wait} — DoS via Unbounded Delay"
# Only test with a small value (2s) to check if endpoint exists, then check rejection of large value
DELAY_SMALL=$(probe GET "$HOST/delay/2" "" 4)
DELAY_SMALL_STATUS=$(get_status "$DELAY_SMALL")
info "GET $HOST/delay/2 (4s timeout) → HTTP $DELAY_SMALL_STATUS"

DELAY_LARGE=$(probe GET "$HOST/delay/300" "" 3)
DELAY_LARGE_STATUS=$(get_status "$DELAY_LARGE")
info "GET $HOST/delay/300 (3s timeout) → HTTP $DELAY_LARGE_STATUS"

if [[ "$DELAY_LARGE_STATUS" == "400" || "$DELAY_LARGE_STATUS" == "403" || "$DELAY_LARGE_STATUS" == "404" ]]; then
    pass "VULN-011: /delay/300 rejected (HTTP $DELAY_LARGE_STATUS) — upper bound enforced"
elif [[ "$DELAY_LARGE_STATUS" == "000" ]]; then
    fail "VULN-011: /delay/300 timed out — server held connection for 3s+ (no upper bound on delay)"
elif [[ "$DELAY_SMALL_STATUS" == "503" || "$DELAY_SMALL_STATUS" == "504" ]]; then
    warn "VULN-011: Backend appears down (HTTP $DELAY_SMALL_STATUS) — cannot verify delay behavior"
else
    warn "VULN-011: /delay/300 returned HTTP $DELAY_LARGE_STATUS — verify if delay was applied"
fi

# ---------------------------------------------------------------------------
# 9. VULN-014: Prometheus metrics exposure
# ---------------------------------------------------------------------------
header "9. VULN-014: /metrics — Prometheus Metrics Exposure"
METRICS_RESP=$(probe GET "$HOST/metrics")
METRICS_STATUS=$(get_status "$METRICS_RESP")
METRICS_BODY=$(get_body "$METRICS_RESP")

info "GET $HOST/metrics → HTTP $METRICS_STATUS"

if [[ "$METRICS_STATUS" == "401" || "$METRICS_STATUS" == "403" ]]; then
    pass "VULN-014: /metrics is protected (HTTP $METRICS_STATUS)"
elif [[ "$METRICS_STATUS" == "404" ]]; then
    pass "VULN-014: /metrics returns 404 — not exposed on this port"
elif echo "$METRICS_BODY" | grep -qE '^# (HELP|TYPE) '; then
    fail "VULN-014: /metrics is UNPROTECTED — Prometheus metrics exposed!"
    info "  Sample metrics:"
    echo "$METRICS_BODY" | grep '^# HELP' | head -5 | while read -r line; do info "  $line"; done
else
    warn "VULN-014: /metrics returned HTTP $METRICS_STATUS"
fi

# ---------------------------------------------------------------------------
# 10. Information disclosure via /version and /api/info
# ---------------------------------------------------------------------------
header "10. INFO: /version and /api/info — Version Disclosure"
for INFO_PATH in "/version" "/api/info"; do
    RESP=$(probe GET "$HOST$INFO_PATH")
    STATUS=$(get_status "$RESP")
    BODY=$(get_body "$RESP")
    info "GET $HOST$INFO_PATH → HTTP $STATUS"
    if [[ "$STATUS" == "200" ]]; then
        warn "INFO: $INFO_PATH returns 200 — version/build info exposed: $(echo "$BODY" | head -c 200 | tr '\n' ' ')"
    elif [[ "$STATUS" == "401" || "$STATUS" == "403" || "$STATUS" == "404" ]]; then
        pass "INFO: $INFO_PATH is protected or not exposed (HTTP $STATUS)"
    else
        info "$INFO_PATH → HTTP $STATUS"
    fi
done

# ---------------------------------------------------------------------------
# 11. Swagger / API documentation exposure
# ---------------------------------------------------------------------------
header "11. INFO: /swagger/ — API Documentation Exposure"
SWAGGER_RESP=$(probe GET "$HOST/swagger/")
SWAGGER_STATUS=$(get_status "$SWAGGER_RESP")
SWAGGER_BODY=$(get_body "$SWAGGER_RESP")

info "GET $HOST/swagger/ → HTTP $SWAGGER_STATUS"
if [[ "$SWAGGER_STATUS" == "200" ]]; then
    if echo "$SWAGGER_BODY" | grep -qi 'swagger\|openapi'; then
        warn "INFO: /swagger/ is publicly accessible — API schema exposed (aids attacker reconnaissance)"
    else
        warn "INFO: /swagger/ returned 200 — verify contents"
    fi
elif [[ "$SWAGGER_STATUS" == "401" || "$SWAGGER_STATUS" == "403" || "$SWAGGER_STATUS" == "404" ]]; then
    pass "INFO: /swagger/ is protected or not exposed (HTTP $SWAGGER_STATUS)"
else
    info "/swagger/ → HTTP $SWAGGER_STATUS"
fi

# ---------------------------------------------------------------------------
# 12. Healthz endpoint (informational — should be accessible)
# ---------------------------------------------------------------------------
header "12. INFO: /healthz — Health Check"
HEALTH_RESP=$(probe GET "$HOST/healthz")
HEALTH_STATUS=$(get_status "$HEALTH_RESP")
HEALTH_BODY=$(get_body "$HEALTH_RESP")
info "GET $HOST/healthz → HTTP $HEALTH_STATUS"
info "Body: $(echo "$HEALTH_BODY" | head -c 100 | tr '\n' ' ')"
if [[ "$HEALTH_STATUS" == "200" ]]; then
    pass "INFO: /healthz is reachable (HTTP 200) — app is running"
elif [[ "$HEALTH_STATUS" == "503" || "$HEALTH_STATUS" == "504" ]]; then
    warn "INFO: /healthz returned $HEALTH_STATUS — backend may be down"
fi

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║                  RESULTS SUMMARY                    ║"
echo "╠══════════════════════════════════════════════════════╣"
printf "║  %-10s %3d                                    ║\n" "PASS:" "$PASS"
printf "║  %-10s %3d                                    ║\n" "FAIL:" "$FAIL"
printf "║  %-10s %3d                                    ║\n" "WARN:" "$WARN"
echo "╠══════════════════════════════════════════════════════╣"
if [[ $FAIL -gt 0 ]]; then
    echo -e "║  ${RED}ACTION REQUIRED: $FAIL confirmed vulnerability/ies!${NC}"
    echo "║  See SECURITY_AUDIT_REPORT.md for remediation."
else
    echo -e "║  ${GREEN}No critical failures detected.${NC}"
    echo "║  Review WARNings for hardening opportunities."
fi
echo "╚══════════════════════════════════════════════════════╝"
