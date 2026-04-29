#!/usr/bin/env bash
# monitor_all.sh — Apre tab/pannelli con: status loop + tail di tutti i log.
#
# Backend (in ordine di preferenza):
#   1. konsole   (KDE)            → tabs file
#   2. tmux                       → 1 sessione 'sap-monitor', 10 finestre
#   3. fallback inline            → tail -F multiplo nello stesso terminale
#
# Pannelli/finestre:
#   1. STATUS (status_all.sh ogni 3s)
#   2. llama.cpp     -> logs/llm.log
#   3. dashboard     -> logs/dashboard.log
#   4-9. mcp-{engagement,recon,exploit,blueteam,parrot,osint}
#   10. audit jsonl  -> logs/audit.jsonl

set -u
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
mkdir -p logs
touch logs/llm.log logs/dashboard.log \
      logs/mcp_engagement.log logs/mcp_recon.log logs/mcp_exploit.log \
      logs/mcp_blueteam.log logs/mcp_parrot.log logs/mcp_osint.log \
      logs/audit.jsonl

PANELS=(
    "STATUS|bash -c 'while true; do clear; bash status_all.sh; echo \"  (refresh ogni 3s — Ctrl-C per uscire)\"; sleep 3; done'"
    "llama.cpp|tail -F logs/llm.log"
    "dashboard|tail -F logs/dashboard.log"
    "engagement|tail -F logs/mcp_engagement.log"
    "recon|tail -F logs/mcp_recon.log"
    "exploit|tail -F logs/mcp_exploit.log"
    "blueteam|tail -F logs/mcp_blueteam.log"
    "parrot|tail -F logs/mcp_parrot.log"
    "osint|tail -F logs/mcp_osint.log"
    "audit|bash -c 'tail -F logs/audit.jsonl | (command -v jq >/dev/null && jq -c . || cat)'"
)

# ── Backend 1: konsole ───────────────────────────────────────────────────────
if command -v konsole >/dev/null; then
    TABS_FILE="$(mktemp /tmp/sap-monitor-tabs.XXXXXX)"
    trap 'rm -f "$TABS_FILE"' EXIT
    : >"$TABS_FILE"
    for entry in "${PANELS[@]}"; do
        title="${entry%%|*}"; cmd="${entry#*|}"
        echo "title: ${title};; workdir: ${SCRIPT_DIR};; command: ${cmd}" >>"$TABS_FILE"
    done
    exec konsole --hide-menubar --separate --tabs-from-file "$TABS_FILE"
fi

# ── Backend 2: tmux ──────────────────────────────────────────────────────────
if command -v tmux >/dev/null; then
    SESSION="sap-monitor"
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    first=1
    for entry in "${PANELS[@]}"; do
        title="${entry%%|*}"; cmd="${entry#*|}"
        if [[ $first -eq 1 ]]; then
            tmux new-session -d -s "$SESSION" -n "$title" -c "$SCRIPT_DIR" "$cmd"
            first=0
        else
            tmux new-window -t "$SESSION" -n "$title" -c "$SCRIPT_DIR" "$cmd"
        fi
    done
    echo "[ok] tmux session '$SESSION' creata. Allega con: tmux attach -t $SESSION"
    exec tmux attach -t "$SESSION"
fi

# ── Backend 3: fallback inline (multitail/tail) ──────────────────────────────
echo "[warn] né konsole né tmux trovati — fallback su tail multiplo."
echo "       Installa tmux per un'esperienza migliore: sudo apt install tmux"
echo ""
if command -v multitail >/dev/null; then
    exec multitail -i logs/llm.log -i logs/dashboard.log \
                   -i logs/mcp_engagement.log -i logs/mcp_recon.log \
                   -i logs/mcp_exploit.log -i logs/mcp_blueteam.log \
                   -i logs/mcp_parrot.log -i logs/mcp_osint.log \
                   -i logs/audit.jsonl
fi
exec tail -F logs/llm.log logs/dashboard.log \
           logs/mcp_engagement.log logs/mcp_recon.log \
           logs/mcp_exploit.log logs/mcp_blueteam.log \
           logs/mcp_parrot.log logs/mcp_osint.log logs/audit.jsonl
