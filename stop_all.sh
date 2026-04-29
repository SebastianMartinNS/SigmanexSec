#!/usr/bin/env bash
# stop_all.sh — Ferma tutti i servizi SAP-Pentest (TERM → grace 3s → KILL)
set -u
cd "$(dirname "$0")"

C_GREEN="\e[32m"; C_YEL="\e[33m"; C_RST="\e[0m"

PATTERNS=(
    'cli\.py dashboard'
    'mcp_http_runner\.py'
    'mcp_servers/.*_server\.py'
    'core\.sudo_broker'
    'start_llm\.sh'
    'llama-server'
    'llama-cli'
)
NAMES=(
    'dashboard'
    'mcp servers (http)'
    'mcp stdio fallback'
    'sudo broker'
    'llama wrapper'
    'llama.cpp server'
    'llama.cpp cli'
)

# Best-effort: TERM by PID file first (più preciso del pattern match).
for pidfile in logs/llm.pid logs/dashboard.pid logs/sudo_broker.pid logs/mcp_*.pid; do
    [[ -f "$pidfile" ]] || continue
    pid="$(cat "$pidfile" 2>/dev/null)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        # Termina anche il process group (figli di nohup bash → llama-server)
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        echo -e "${C_YEL}[term]${C_RST} pid $pid ($(basename "$pidfile" .pid))"
    fi
done

for i in "${!PATTERNS[@]}"; do
    pat="${PATTERNS[$i]}"; name="${NAMES[$i]}"
    if pgrep -f "$pat" >/dev/null; then
        pkill -TERM -f "$pat" 2>/dev/null || true
        echo -e "${C_YEL}[term]${C_RST} $name"
    fi
done

sleep 3

for i in "${!PATTERNS[@]}"; do
    pat="${PATTERNS[$i]}"; name="${NAMES[$i]}"
    if pgrep -f "$pat" >/dev/null; then
        pkill -KILL -f "$pat" 2>/dev/null || true
        echo -e "${C_YEL}[kill]${C_RST} $name (forced)"
    fi
done

rm -f logs/*.pid 2>/dev/null
# Remove the sudo broker socket if it lingers.
rm -f "${XDG_RUNTIME_DIR:-/tmp}/sap_sudo_$(id -u).sock" 2>/dev/null

# ── Pulizia RAM cache (pagecache + dentries + inodes) ────────────────────────
# Libera la memoria che il kernel tiene come cache disco dopo lo scarico
# del modello GGUF (~20 GB mmap). Skip con SKIP_DROP_CACHES=1.
if [[ "${SKIP_DROP_CACHES:-0}" != "1" ]]; then
    BEFORE_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    sync
    DROPPED=0
    if [[ $EUID -eq 0 ]]; then
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null && DROPPED=1
    elif sudo -n true 2>/dev/null; then
        sudo -n sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null && DROPPED=1
    fi
    if [[ $DROPPED -eq 1 ]]; then
        AFTER_KB=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
        FREED_MB=$(( (AFTER_KB - BEFORE_KB) / 1024 ))
        echo -e "${C_GREEN}[cache]${C_RST} drop_caches eseguito (liberati ~${FREED_MB} MB)"
    else
        echo -e "${C_YEL}[cache]${C_RST} drop_caches saltato (serve sudo non interattivo). Esegui:"
        echo "         sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'"
    fi
fi

echo -e "${C_GREEN}[done]${C_RST} tutti i servizi fermati"
