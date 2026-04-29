#!/usr/bin/env bash
# start_all.sh — Avvia in background tutti i servizi SAP-Pentest:
#   - llama.cpp server         (porta 8080)
#   - 6 MCP server streamable  (porte 9001-9006)
#   - dashboard FastAPI        (porta 8765)
#
# Uso:    bash start_all.sh
# Log:    logs/llm.log, logs/mcp_*.log, logs/dashboard.log
# Stop:   bash stop_all.sh
# Status: bash status_all.sh

set -uo pipefail
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
umask 0077
mkdir -p logs sessions

# ── Single-instance lock (prevent double-launch port collisions) ─────────────
# Two concurrent invocations would race on every bind (8080, 9001-9006, 8765).
# We use flock on a descriptor; if another instance holds the lock we abort
# with a clear message instead of half-starting and corrupting PID files.
LOCK_FILE="${SAP_START_LOCK:-logs/start_all.lock}"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo -e "\e[31m[FAIL]\e[0m Another start_all.sh is already running (lock: $LOCK_FILE)."
    echo "       Run 'bash stop_all.sh' first, or remove the lock if stale."
    exit 3
fi
# Release the lock automatically when the script exits.
trap 'flock -u 9 2>/dev/null || true' EXIT

# ── Secrets store (persistent, mode 0600) ────────────────────────────────────
SAP_STATE_DIR="${SAP_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/sap}"
mkdir -p "$SAP_STATE_DIR" && chmod 0700 "$SAP_STATE_DIR"
SECRETS_FILE="$SAP_STATE_DIR/secrets.env"
export SAP_STATE_DIR

if [[ ! -f "$SECRETS_FILE" ]]; then
    : > "$SECRETS_FILE" && chmod 0600 "$SECRETS_FILE"
fi
# shellcheck disable=SC1090
source "$SECRETS_FILE"

_secret_persist() {
    # _secret_persist KEY VALUE
    local key="$1" val="$2"
    if grep -q "^export ${key}=" "$SECRETS_FILE" 2>/dev/null; then
        sed -i "s|^export ${key}=.*|export ${key}=\"${val}\"|" "$SECRETS_FILE"
    else
        printf 'export %s="%s"\n' "$key" "$val" >> "$SECRETS_FILE"
    fi
}

# Generate API key for the LLM if missing.
if [[ -z "${SAP_LLM_API_KEY:-}" ]]; then
    SAP_LLM_API_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    _secret_persist SAP_LLM_API_KEY "$SAP_LLM_API_KEY"
fi
export SAP_LLM_API_KEY
# The orchestrator (OpenAI client) reads LOCAL_LLM_API_KEY.
export LOCAL_LLM_API_KEY="$SAP_LLM_API_KEY"

# Persisted, application-wide session signing key (cookie auth).
if [[ -z "${SAP_SESSION_SECRET:-}" ]]; then
    SAP_SESSION_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
    _secret_persist SAP_SESSION_SECRET "$SAP_SESSION_SECRET"
fi
export SAP_SESSION_SECRET

# ── Credenziali dashboard ────────────────────────────────────────────────────
# No default fallback: credentials MUST be set via env or persisted secrets.
# On first run we generate a strong random password and persist it (0600).
if [[ -z "${SAP_DASHBOARD_USER:-}" ]]; then
    SAP_DASHBOARD_USER="admin"
    _secret_persist SAP_DASHBOARD_USER "$SAP_DASHBOARD_USER"
fi
if [[ -z "${SAP_DASHBOARD_PASS:-}" ]]; then
    SAP_DASHBOARD_PASS="$(python3 -c 'import secrets;print(secrets.token_urlsafe(20))')"
    _secret_persist SAP_DASHBOARD_PASS "$SAP_DASHBOARD_PASS"
    echo -e "\e[33m[NEW] Generated dashboard password (saved to ${SECRETS_FILE} — chmod 0600).\e[0m"
fi
# Hard fail-closed: refuse insecure defaults.
if [[ "$SAP_DASHBOARD_PASS" == "test" || "$SAP_DASHBOARD_PASS" == "admin" || ${#SAP_DASHBOARD_PASS} -lt 12 ]]; then
    echo -e "\e[31m[FAIL]\e[0m SAP_DASHBOARD_PASS is too weak (min 12 chars, no defaults). Aborting."
    exit 2
fi
export SAP_DASHBOARD_USER SAP_DASHBOARD_PASS

C_GREEN="\e[32m"; C_RED="\e[31m"; C_YEL="\e[33m"; C_RST="\e[0m"
ok()   { echo -e "${C_GREEN}[ OK ]${C_RST} $*"; }
warn() { echo -e "${C_YEL}[WARN]${C_RST} $*"; }
err()  { echo -e "${C_RED}[FAIL]${C_RST} $*"; }
hdr()  { echo -e "\n\e[1;36m═══ $* ═══${C_RST}"; }

port_busy() { ss -ltn "( sport = :$1 )" 2>/dev/null | grep -q LISTEN; }

wait_port() {
    local port="$1" name="$2" tries="${3:-60}"
    for ((i=0; i<tries; i++)); do
        if port_busy "$port"; then ok "$name listening on :$port"; return 0; fi
        sleep 1
    done
    err "$name non risponde su :$port dopo ${tries}s — vedi logs/"
    return 1
}

# Real LLM healthcheck — hits /v1/models with the API key. A bound port is
# necessary but not sufficient: llama-server may listen while the model is
# still loading from disk (tens of seconds for 35B Q4_K_M).
healthcheck_llm() {
    local tries="${1:-180}" auth="Authorization: Bearer ${SAP_LLM_API_KEY:-}"
    for ((i=0; i<tries; i++)); do
        if curl -fsS -m 3 -H "$auth" "http://127.0.0.1:8080/v1/models" \
                >/dev/null 2>&1; then
            ok "llama-server /v1/models healthy (dopo ${i}s)"
            return 0
        fi
        sleep 1
    done
    err "llama-server /v1/models non risponde dopo ${tries}s — vedi logs/llm.log"
    return 1
}

# Real MCP healthcheck — issues a JSON-RPC tools/list against the server.
# The MCP HTTP runner accepts initialize-less tools/list when only listing
# is requested; we accept any non-5xx as evidence the runner is responsive.
healthcheck_mcp() {
    local port="$1" name="$2" tries="${3:-15}"
    local body='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    for ((i=0; i<tries; i++)); do
        local code
        code="$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
            -H 'Content-Type: application/json' \
            -H 'Accept: application/json, text/event-stream' \
            -X POST "http://127.0.0.1:${port}/mcp" -d "$body" 2>/dev/null || echo 000)"
        # 2xx (json reply) or 4xx (e.g. 400 'session id missing' — server up).
        if [[ "$code" =~ ^[24] ]]; then
            ok "mcp-${name} JSON-RPC healthy (HTTP ${code}, dopo ${i}s)"
            return 0
        fi
        sleep 1
    done
    err "mcp-${name} non risponde su /mcp dopo ${tries}s — vedi logs/mcp_${name}.log"
    return 1
}

# ── Sudo broker (UDS, deve precedere tutti gli altri) ───────────────────────
hdr "Sudo broker (Unix socket)"
SUDO_SOCK="${XDG_RUNTIME_DIR:-/tmp}/sap_sudo_$(id -u).sock"
SUDO_PIDFILE="logs/sudo_broker.pid"
export SAP_SUDO_BROKER="$SUDO_SOCK"
export PYTHONPATH="${SCRIPT_DIR}"

# Kill stale broker if its PID is dead or socket missing.
if [[ -f "$SUDO_PIDFILE" ]] && kill -0 "$(cat "$SUDO_PIDFILE")" 2>/dev/null; then
    if [[ -S "$SUDO_SOCK" ]]; then
        ok "broker già attivo PID=$(cat "$SUDO_PIDFILE") — socket: $SUDO_SOCK"
    else
        warn "broker PID vivo ma socket mancante — riavvio"
        kill -TERM "$(cat "$SUDO_PIDFILE")" 2>/dev/null || true
        sleep 1
    fi
fi
if ! [[ -S "$SUDO_SOCK" ]]; then
    : >logs/sudo_broker.log
    SAP_SUDO_BROKER_PROCESS=1 nohup python3 -u -m core.sudo_broker \
        --socket "$SUDO_SOCK" --pidfile "$SUDO_PIDFILE" \
        >>logs/sudo_broker.log 2>&1 &
    # Wait up to 5s for the socket file to appear.
    for ((i=0; i<25; i++)); do
        [[ -S "$SUDO_SOCK" ]] && break
        sleep 0.2
    done
    if [[ -S "$SUDO_SOCK" ]]; then
        ok "sudo broker PID=$(cat "$SUDO_PIDFILE" 2>/dev/null || echo ?) — socket: $SUDO_SOCK"
    else
        err "sudo broker non avviato — vedi logs/sudo_broker.log"
        tail -10 logs/sudo_broker.log | sed 's/^/    /'
    fi
fi

# ── 0. Cleanup eventuali stale ────────────────────────────────────────────────
hdr "Cleanup stale processes"
for pat in 'cli\.py dashboard' 'mcp_http_runner\.py' 'llama-server' \
           'mcp_servers/.*_server\.py'; do
    if pgrep -f "$pat" >/dev/null; then
        pkill -TERM -f "$pat" 2>/dev/null || true
        warn "SIGTERM: $pat"
    fi
done
sleep 2
# SIGKILL chi non è morto
for pat in 'cli\.py dashboard' 'mcp_http_runner\.py' 'llama-server' \
           'mcp_servers/.*_server\.py'; do
    if pgrep -f "$pat" >/dev/null; then
        pkill -KILL -f "$pat" 2>/dev/null || true
        warn "SIGKILL: $pat"
    fi
done
sleep 1

# ── 1. llama.cpp server ──────────────────────────────────────────────────────
hdr "llama.cpp server (porta 8080)"
if port_busy 8080; then
    warn ":8080 già occupata — salto avvio LLM"
else
    : >logs/llm.log
    nohup bash start_llm.sh server >>logs/llm.log 2>&1 &
    LLM_PID=$!
    echo $LLM_PID > logs/llm.pid
    chmod 0600 logs/llm.pid logs/llm.log 2>/dev/null || true
    ok "llama-server PID=$LLM_PID — log: logs/llm.log"
    # Poll: bail out early if the process dies (OOM, missing model, ...).
    started=0
    for ((i=0; i<120; i++)); do
        if ! kill -0 "$LLM_PID" 2>/dev/null; then
            err "llama-server è morto dopo ${i}s. Ultime righe del log:"
            tail -25 logs/llm.log | sed 's/^/    /'
            warn "prova: NGL=0 bash start_llm.sh server   (CPU-only)"
            warn "oppure: VRAM_HEADROOM_MB=3500 bash start_all.sh"
            break
        fi
        if port_busy 8080; then
            ok "llama-server listening on :8080 (dopo ${i}s)"
            started=1
            break
        fi
        sleep 1
    done
    [[ $started -eq 0 ]] && [[ -z "${LLM_PID_DEAD:-}" ]] \
        && warn "llama-server non ancora pronto dopo 120s — vedi logs/llm.log"
    # Real readiness probe: /v1/models must respond before MCP/dashboard
    # try to use the LLM. Skipped if the process is already dead.
    if [[ $started -eq 1 ]] && kill -0 "$LLM_PID" 2>/dev/null; then
        healthcheck_llm 180 || warn "LLM listening but /v1/models not ready"
    fi
fi

# ── 2. MCP servers (6 porte) ─────────────────────────────────────────────────
hdr "MCP servers (porte 9001-9006)"
declare -A SERVERS=( [engagement]=9001 [recon]=9002 [exploit]=9003 [blueteam]=9004 [parrot]=9005 [osint]=9006 )
export MCP_TRANSPORT=streamable-http
export FASTMCP_HOST=127.0.0.1
export PYTHONPATH="${SCRIPT_DIR}"
export SESSION_DB_PATH="${SCRIPT_DIR}/sessions/assessments.db"
export AUDIT_LOG_PATH="${SCRIPT_DIR}/logs/audit.jsonl"

for name in engagement recon exploit blueteam parrot osint; do
    port="${SERVERS[$name]}"
    log="logs/mcp_${name}.log"
    if port_busy "$port"; then
        warn ":${port} già occupata — salto $name"
        continue
    fi
    : >"$log"
    nohup python3 -u mcp_http_runner.py "$name" "$port" >>"$log" 2>&1 &
    echo $! > "logs/mcp_${name}.pid"
    ok "mcp-${name} PID=$(cat logs/mcp_${name}.pid) :${port}"
done
sleep 2
for name in engagement recon exploit blueteam parrot osint; do
    healthcheck_mcp "${SERVERS[$name]}" "$name" 15 || true
done

# ── 3. Dashboard ─────────────────────────────────────────────────────────────
hdr "Dashboard (porta 8765)"
if port_busy 8765; then
    warn ":8765 già occupata — salto avvio dashboard"
else
    : >logs/dashboard.log
    nohup python3 cli.py dashboard --host 127.0.0.1 --port 8765 \
        >>logs/dashboard.log 2>&1 &
    echo $! > logs/dashboard.pid
    ok "dashboard PID=$(cat logs/dashboard.pid) — http://127.0.0.1:8765"
    wait_port 8765 "dashboard" 30 || true
fi

# ── 4. Riepilogo ─────────────────────────────────────────────────────────────
hdr "Riepilogo"
echo
printf "  %-18s %-8s %s\n" "SERVIZIO" "PORTA" "STATO"
printf "  %-18s %-8s %s\n" "------------------" "--------" "------"
for entry in "llama-server:8080" "dashboard:8765" \
             "mcp-engagement:9001" "mcp-recon:9002" "mcp-exploit:9003" \
             "mcp-blueteam:9004" "mcp-parrot:9005" "mcp-osint:9006"; do
    name="${entry%:*}"; port="${entry#*:}"
    if port_busy "$port"; then
        printf "  %-18s %-8s ${C_GREEN}UP${C_RST}\n" "$name" "$port"
    else
        printf "  %-18s %-8s ${C_RED}DOWN${C_RST}\n" "$name" "$port"
    fi
done
echo
echo "  Dashboard:   https://127.0.0.1:8765   (user=$SAP_DASHBOARD_USER — password: see ${SECRETS_FILE})"
echo "  LLM API   :  http://127.0.0.1:8080/v1   (Bearer key in ${SECRETS_FILE})"
echo
echo "  Stop:      bash stop_all.sh"
echo "  Monitor:   bash monitor_all.sh"
echo
