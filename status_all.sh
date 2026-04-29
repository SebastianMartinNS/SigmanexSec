#!/usr/bin/env bash
# status_all.sh — Mostra stato sintetico di tutti i servizi SAP-Pentest
cd "$(dirname "$0")"

C_GREEN="\e[32m"; C_RED="\e[31m"; C_RST="\e[0m"
port_busy() { ss -ltn "( sport = :$1 )" 2>/dev/null | grep -q LISTEN; }

printf "\n  %-18s %-8s %-6s %s\n" "SERVIZIO" "PORTA" "STATO" "PID"
printf "  %-18s %-8s %-6s %s\n" "------------------" "--------" "------" "-------"
# Sudo broker first (UDS, no TCP port).
_SOCK="${XDG_RUNTIME_DIR:-/tmp}/sap_sudo_$(id -u).sock"
_BROKER_PID=$(pgrep -f 'core\.sudo_broker' | head -1)
if [[ -S "$_SOCK" && -n "$_BROKER_PID" ]]; then
    printf "  %-18s %-8s ${C_GREEN}UP${C_RST}     %s\n" "sudo-broker" "uds" "$_BROKER_PID"
else
    printf "  %-18s %-8s ${C_RED}DOWN${C_RST}   %s\n" "sudo-broker" "uds" "-"
fi
for entry in "llama-server:8080:llama-server" "dashboard:8765:cli.py dashboard" \
             "mcp-engagement:9001:mcp_http_runner.py engagement" \
             "mcp-recon:9002:mcp_http_runner.py recon" \
             "mcp-exploit:9003:mcp_http_runner.py exploit" \
             "mcp-blueteam:9004:mcp_http_runner.py blueteam" \
             "mcp-parrot:9005:mcp_http_runner.py parrot" \
             "mcp-osint:9006:mcp_http_runner.py osint"; do
    name="${entry%%:*}"; rest="${entry#*:}"; port="${rest%%:*}"; pat="${rest#*:}"
    pid=$(pgrep -f "$pat" | head -1)
    if port_busy "$port"; then
        printf "  %-18s %-8s ${C_GREEN}UP${C_RST}     %s\n" "$name" "$port" "${pid:--}"
    else
        printf "  %-18s %-8s ${C_RED}DOWN${C_RST}   %s\n" "$name" "$port" "-"
    fi
done
echo
echo "  Dashboard: http://127.0.0.1:8765"
echo "  LLM API  : http://127.0.0.1:8080/v1"
echo
