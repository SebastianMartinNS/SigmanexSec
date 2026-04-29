#!/usr/bin/env bash
# scripts/check_hardening.sh — Validate P0 hardening posture.
#
# Returns 0 if all checks pass, non-zero on the first failure.
# Run after `bash start_all.sh`.

set -uo pipefail
cd "$(dirname "$0")/.."

C_GREEN="\e[32m"; C_RED="\e[31m"; C_YEL="\e[33m"; C_RST="\e[0m"
ok()   { echo -e "${C_GREEN}[ OK ]${C_RST} $*"; }
warn() { echo -e "${C_YEL}[WARN]${C_RST} $*"; }
fail() { echo -e "${C_RED}[FAIL]${C_RST} $*"; FAILS=$((FAILS+1)); }

FAILS=0

echo "=== SAP Hardening Check (P0) ==="

# 1) All listening ports must be on loopback only.
echo
echo "--- Network exposure ---"
NON_LOOPBACK=$(ss -ltn 2>/dev/null \
    | awk 'NR>1 {print $4}' \
    | grep -E ':(8080|8765|9001|9002|9003|9004|9005|9006)$' \
    | grep -vE '^(127\.0\.0\.1|::1|\[::1\]):' || true)
if [[ -z "$NON_LOOPBACK" ]]; then
    ok "all SAP ports bound to loopback only"
else
    fail "non-loopback listeners detected:"
    echo "$NON_LOOPBACK" | sed 's/^/      /'
fi

# 2) No default credentials in start_all.sh.
echo
echo "--- Default credentials ---"
if grep -qE 'SAP_DASHBOARD_PASS:-test|SAP_DASHBOARD_PASS=test\b' start_all.sh; then
    fail "start_all.sh still contains default password 'test'"
else
    ok "no default 'test' password in start_all.sh"
fi

if [[ -n "${SAP_DASHBOARD_PASS:-}" ]]; then
    if [[ "$SAP_DASHBOARD_PASS" == "test" || "$SAP_DASHBOARD_PASS" == "admin" || ${#SAP_DASHBOARD_PASS} -lt 12 ]]; then
        fail "SAP_DASHBOARD_PASS env var is weak/default"
    else
        ok "SAP_DASHBOARD_PASS strength acceptable (${#SAP_DASHBOARD_PASS} chars)"
    fi
fi

# 3) Secrets file permissions.
echo
echo "--- Secrets file permissions ---"
SECRETS_FILE="${SAP_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/sap}/secrets.env"
if [[ -f "$SECRETS_FILE" ]]; then
    perms=$(stat -c '%a' "$SECRETS_FILE")
    if [[ "$perms" == "600" ]]; then
        ok "secrets.env mode is 600"
    else
        fail "secrets.env mode is $perms (expected 600)"
    fi
else
    warn "secrets.env not present at $SECRETS_FILE (run start_all.sh first)"
fi

# 4) LLM endpoint requires Bearer auth (if API key set).
echo
echo "--- LLM auth ---"
if ss -ltn '( sport = :8080 )' 2>/dev/null | grep -q LISTEN; then
    if [[ -n "${SAP_LLM_API_KEY:-}" ]]; then
        code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/v1/models)
        if [[ "$code" == "401" || "$code" == "403" ]]; then
            ok "LLM /v1/models returns $code without Bearer (auth enforced)"
        else
            fail "LLM /v1/models returns $code without Bearer (expected 401/403)"
        fi
        code=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer $SAP_LLM_API_KEY" http://127.0.0.1:8080/v1/models)
        if [[ "$code" == "200" ]]; then
            ok "LLM /v1/models returns 200 with valid Bearer"
        else
            warn "LLM /v1/models returns $code with Bearer (expected 200)"
        fi
    else
        warn "SAP_LLM_API_KEY not set — LLM auth check skipped"
    fi
else
    warn "LLM not listening on :8080 — skipped"
fi

# 5) Dashboard requires auth + serves over HTTPS by default.
echo
echo "--- Dashboard auth & TLS ---"
if ss -ltn '( sport = :8765 )' 2>/dev/null | grep -q LISTEN; then
    # Try HTTPS first.
    https_code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8765/api/health || echo 000)
    http_code=$(curl -s  -o /dev/null -w '%{http_code}' http://127.0.0.1:8765/api/health || echo 000)
    if [[ "$https_code" =~ ^(200|401|403)$ ]]; then
        ok "dashboard responds on HTTPS (code $https_code)"
    elif [[ "$http_code" =~ ^(200|401|403)$ ]]; then
        warn "dashboard on HTTP only (code $http_code) — set up TLS"
    else
        fail "dashboard not responding on HTTPS or HTTP"
    fi

    # /api/engagements without auth must be 401/503.
    auth_code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8765/api/engagements || echo 000)
    if [[ "$auth_code" =~ ^(401|503)$ ]]; then
        ok "dashboard /api/engagements requires auth (code $auth_code)"
    else
        fail "dashboard /api/engagements returns $auth_code without auth (expected 401)"
    fi

    # Security headers
    hdrs=$(curl -sIk https://127.0.0.1:8765/ 2>/dev/null || true)
    for h in "X-Content-Type-Options" "X-Frame-Options" "Content-Security-Policy" "Referrer-Policy"; do
        if echo "$hdrs" | grep -qi "^$h:"; then
            ok "header $h present"
        else
            fail "header $h missing"
        fi
    done
    if echo "$hdrs" | grep -qi "^Strict-Transport-Security:"; then
        ok "HSTS header present"
    else
        warn "HSTS header missing (only emitted on HTTPS)"
    fi
    if echo "$hdrs" | grep -qi "Content-Security-Policy.*unsafe-eval"; then
        fail "CSP still allows 'unsafe-eval'"
    fi

    # CSRF: POST without token + with cookie should 403; without cookie (Basic) should 401.
    csrf_code=$(curl -sk -o /dev/null -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' \
        --cookie "sap_session=invalid" \
        https://127.0.0.1:8765/api/engagements -d '{}' || echo 000)
    # Either 401 (cookie rejected) or 403 (CSRF rejected) is acceptable; never 200.
    if [[ "$csrf_code" == "200" ]]; then
        fail "POST /api/engagements with bogus session cookie returned 200 (CSRF/auth bypass)"
    else
        ok "POST without CSRF rejected (code $csrf_code)"
    fi
else
    warn "dashboard not listening on :8765 — skipped"
fi

# 6) Log file permissions.
echo
echo "--- Log file permissions ---"
for f in logs/*.pid logs/audit.jsonl 2>/dev/null; do
    [[ -f "$f" ]] || continue
    perms=$(stat -c '%a' "$f")
    if [[ "$perms" == "600" || "$perms" == "640" ]]; then
        ok "$f mode $perms"
    else
        warn "$f mode $perms (expected 600)"
    fi
done

echo
if [[ "$FAILS" -eq 0 ]]; then
    echo -e "${C_GREEN}=== Hardening check PASSED ===${C_RST}"
    exit 0
else
    echo -e "${C_RED}=== Hardening check FAILED: $FAILS issue(s) ===${C_RST}"
    exit 1
fi
