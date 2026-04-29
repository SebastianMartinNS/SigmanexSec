#!/usr/bin/env bash
# Lancia tutti i server MCP in modalità streamable-http per la WebUI di llama.cpp.
#
# La WebUI usa --webui-mcp-proxy per bypassare CORS e parla con:
#   http://127.0.0.1:9001/mcp  — engagement
#   http://127.0.0.1:9002/mcp  — recon
#   http://127.0.0.1:9003/mcp  — exploit
#   http://127.0.0.1:9004/mcp  — blueteam
#   http://127.0.0.1:9005/mcp  — parrot (catalogue runner)
#   http://127.0.0.1:9006/mcp  — osint
#
# Uso:   bash start_mcp_http.sh            (foreground, Ctrl-C per stop)
#        bash start_mcp_http.sh --bg       (background, log in logs/mcp_*.log)

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs

export MCP_TRANSPORT=streamable-http
export FASTMCP_HOST=127.0.0.1

declare -A SERVERS=(
    [engagement]=9001
    [recon]=9002
    [exploit]=9003
    [blueteam]=9004
    [parrot]=9005
    [osint]=9006
)

PIDS=()
cleanup() {
    echo
    echo "[mcp] stopping..."
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

BG=0
[[ "${1:-}" == "--bg" ]] && BG=1

for name in engagement recon exploit blueteam parrot osint; do
    port="${SERVERS[$name]}"
    log="logs/mcp_${name}.log"
    echo "[mcp] $name -> http://127.0.0.1:${port}/mcp  (log: $log)"
    python3 -u mcp_http_runner.py "$name" "$port" >"$log" 2>&1 &
    PIDS+=("$!")
done

if (( BG )); then
    trap - INT TERM EXIT
    echo "[mcp] started pids=${PIDS[*]}  (detached)"
    exit 0
fi

echo "[mcp] all up. Ctrl-C to stop."
wait
