#!/usr/bin/env bash
# launch_sap.sh — Lanciato dal .desktop sul Desktop:
#   1. Avvia tutti i servizi (start_all.sh)
#   2. Apre la console di monitoraggio (monitor_all.sh)
#   3. Apre il browser sulla dashboard
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG=/tmp/sap_launch.log
echo "=== launch $(date) ===" >>"$LOG"

# ── Secrets store ─────────────────────────────────────────────────────────────
# Source persisted secrets (SAP_LLM_API_KEY, SAP_SESSION_SECRET, dashboard creds)
# so that every child konsole/monitor/browser inherits them. start_all.sh will
# (re-)generate any missing keys on first run.
SAP_STATE_DIR="${SAP_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/sap}"
export SAP_STATE_DIR
SECRETS_FILE="$SAP_STATE_DIR/secrets.env"
if [[ -f "$SECRETS_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$SECRETS_FILE"; set +a
    echo "[LAUNCH] sourced secrets from $SECRETS_FILE" >>"$LOG"
fi

# ── Config LLM forzata: CUDA offload garantito (RTX 4060 8GB) ────────────────
# Valori validati: NGL=12 → ~6.5 GB VRAM, ~27 t/s, 9/9 tool tests OK.
# L'auto-detect di start_llm.sh con NGL=17 è andato in CUDA OOM in passato e
# ha fatto fallback a CPU-only (12 t/s). Pinniamo i valori sicuri.
export NGL="${NGL:-12}"
export CTX="${CTX:-200704}"   # 196k token (196*1024) — max ctx Qwen3.5-35B
export VRAM_HEADROOM_MB="${VRAM_HEADROOM_MB:-3500}"
echo "[LAUNCH] LLM env: NGL=$NGL CTX=$CTX VRAM_HEADROOM_MB=$VRAM_HEADROOM_MB" >>"$LOG"

# 1) Avvia servizi e mostra l'output in una konsole dedicata
#    (export NGL/CTX vengono ereditati da start_all.sh → start_llm.sh)
konsole --hold --hide-menubar -p "tabtitle=SAP Start" \
    --workdir "$SCRIPT_DIR" \
    -e bash -c "NGL=$NGL CTX=$CTX VRAM_HEADROOM_MB=$VRAM_HEADROOM_MB bash start_all.sh; echo; echo '[premi INVIO per chiudere]'; read" \
    >>"$LOG" 2>&1 &
START_PID=$!

# 2) Attendi che la dashboard sia su (max 60s) prima di lanciare monitor + browser
for i in $(seq 1 60); do
    if ss -ltn '( sport = :8765 )' 2>/dev/null | grep -q LISTEN; then break; fi
    sleep 1
done

# 3) Apri monitor multi-tab
bash "$SCRIPT_DIR/monitor_all.sh" >>"$LOG" 2>&1 &

# 4) Apri browser sulla dashboard
sleep 1
if command -v xdg-open >/dev/null; then
    xdg-open "https://127.0.0.1:8765" >>"$LOG" 2>&1 &
fi

wait $START_PID 2>/dev/null || true
