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

# ── Config LLM forzata: split smart MoE su RTX 4060 8 GB ─────────────────────
# Modello: Qwen3.5-35B-A3B-heretic (40 layer, MoE 256 esperti, 8 attivi/token).
# Strategia per CTX max (196k) + throughput su VRAM 8 GB:
#   • NGL=40         → tutti i 40 layer su GPU per attention + shared FFN
#                      (cap = n_layer; >40 viene clampato dal runtime)
#   • NCMOE=34       → esperti dei PRIMI 34 layer in RAM, ultimi 6 in GPU.
#                      Lascia ~1.5 GB VRAM liberi per il KV cache (vedi sotto).
#   • CTX=200704     → 196k token (max pratico Qwen3.5-35B)
#   • NO_KV_OFFLOAD=0 → KV cache su GPU. Qwen3.5-35B ha GQA aggressivo
#                      (n_kv_head=2, head_dim=256): KV q4_0 a 196k = solo
#                      1.1 GB, sta in VRAM. Tenerlo in RAM (default
#                      auto-attivato con CTX>32k) costa ~300 MB di transfer
#                      PCIe per ogni token decodificato → cap a ~12 t/s.
# Tuning:
#   - CUDA OOM al caricamento → alzare NCMOE (35-37, libera ~500 MB/step)
#   - VRAM > 1 GB libera a regime → scendere NCMOE (32-33, più esperti su GPU)
#   - CPU-only:  NGL=0 NCMOE=0 launch_sap.sh
export NGL="${NGL:-40}"
export NCMOE="${NCMOE:-34}"
export CTX="${CTX:-200704}"   # 196k token (196*1024) — max ctx Qwen3.5-35B
export NO_KV_OFFLOAD="${NO_KV_OFFLOAD:-0}"
export VRAM_HEADROOM_MB="${VRAM_HEADROOM_MB:-3500}"
echo "[LAUNCH] LLM env: NGL=$NGL NCMOE=$NCMOE CTX=$CTX NO_KV_OFFLOAD=$NO_KV_OFFLOAD VRAM_HEADROOM_MB=$VRAM_HEADROOM_MB" >>"$LOG"

# 1) Avvia servizi e mostra l'output in una konsole dedicata
#    (export NGL/NCMOE/CTX/NO_KV_OFFLOAD vengono ereditati da start_all.sh → start_llm.sh)
konsole --hold --hide-menubar -p "tabtitle=SAP Start" \
    --workdir "$SCRIPT_DIR" \
    -e bash -c "NGL=$NGL NCMOE=$NCMOE CTX=$CTX NO_KV_OFFLOAD=$NO_KV_OFFLOAD VRAM_HEADROOM_MB=$VRAM_HEADROOM_MB bash start_all.sh; echo; echo '[premi INVIO per chiudere]'; read" \
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
