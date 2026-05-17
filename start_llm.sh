#!/usr/bin/env bash
# start_llm.sh — Avvia Qwen3.5-35B-A3B-Heretic con llama-server (Linux, CUDA)
#
# MEMORIA — budget su 30 GB RAM / 0 swap:
#   Modello GGUF mmap (CPU):  ~20 GB RSS (tutti i layer in RAM)
#   KV cache ctx=4096, q4_0:  ~0.15 GB   (trascurabile)
#   Overhead llama.cpp:        ~0.5 GB
#   ─────────────────────────────────────
#   Totale CPU-only:          ~21 GB  ←  7 GB headroom ✓
#   Con GPU offload 28 layer: ~12 GB  ← 16 GB headroom ✓✓
#
# CONTEXT BUDGET per tool-calling agentico:
#   System prompt:  ~1500 token
#   Tool schemas:   ~2000 token  (37 tool)
#   Conv + risposte: ~500 token per turno × 8 turni = 4000 token
#   Totale:         <8000 token — ctx=8192 basta, 4096 per test sicuri
#
# USO:
#   bash start_llm.sh           # server API (default, ctx=8192)
#   bash start_llm.sh cli       # chat interattiva
#   CTX=4096 bash start_llm.sh  # ctx ridotto per test
#   NGL=0 bash start_llm.sh     # forza CPU-only
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MODE="${1:-server}"

# ── Paths ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="/home/resolutor/Desktop/qwen/Qwen3.5-35B-A3B-heretic.Q4_K_M.gguf"
SERVER_BIN="${SCRIPT_DIR}/llama.cpp/build/bin/llama-server"
CLI_BIN="${SCRIPT_DIR}/llama.cpp/build/bin/llama-cli"

# ── Parametri configurabili via env ───────────────────────────────────────────
# Default validati su RTX 4060 Laptop 8 GB con Qwen3.5-35B-A3B (n_layer=40):
#   NGL=40 NCMOE=34 CTX=200704 NO_KV_OFFLOAD=0
#   → 33-37 t/s con CTX 196k, KV q4_0 su GPU (2 GB), graph_splits=124.
# Sovrascrivibili da env (es. CPU-only: NGL=0 NCMOE=0 bash start_llm.sh).
CTX="${CTX:-200704}"            # 196k default (196*1024) — max ctx Qwen3.5-35B
PORT="${PORT:-8080}"

# ── Pre-flight memory check ────────────────────────────────────────────────────
# Modello GGUF: ~20 GB RSS su CPU. Con 0 swap serve almeno 22 GB disponibili.
AVAIL_KB=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
AVAIL_GB=$(( AVAIL_KB / 1024 / 1024 ))
MIN_GB=22

if [[ $AVAIL_GB -lt $MIN_GB ]]; then
    echo ""
    echo "╔══════════ MEMORIA INSUFFICIENTE — AVVIO BLOCCATO ══════════╗"
    echo "  Disponibile: ${AVAIL_GB} GB — Minimo richiesto: ${MIN_GB} GB"
    echo "  Il modello occupa ~20 GB RAM su CPU (nessun GPU offload)."
    echo ""
    echo "  Soluzioni:"
    echo "    1. Chiudi browser/app pesanti e riprova"
    echo "    2. Abilita GPU offload (bash install_gpu.sh cuda)"
    echo "    3. Aggiungi swap:  sudo fallocate -l 8G /swapfile"
    echo "                        sudo mkswap /swapfile && sudo swapon /swapfile"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    exit 1
fi

echo "[MEM] Disponibile: ${AVAIL_GB} GB — OK (minimo ${MIN_GB} GB)"

# ── Validation ────────────────────────────────────────────────────────────────
if [[ ! -f "$MODEL" ]]; then
    echo "[ERRORE] Modello non trovato: $MODEL" >&2
    exit 1
fi

# ── P1.8 hardening: SHA256 integrity gate (best-effort unless MODEL_VERIFY_STRICT=1) ──
if [[ -x "${SCRIPT_DIR}/scripts/verify_model_integrity.sh" ]]; then
    if ! STRICT="${MODEL_VERIFY_STRICT:-0}" \
         MODELS_SHA256="${SCRIPT_DIR}/models.sha256" \
         "${SCRIPT_DIR}/scripts/verify_model_integrity.sh"; then
        echo "[ERRORE] integrity check del modello fallito" >&2
        exit 1
    fi
fi

BIN="$SERVER_BIN"
[[ "$MODE" == "cli" ]] && BIN="$CLI_BIN"

if [[ ! -f "$BIN" ]]; then
    echo "[ERRORE] Binario non trovato: $BIN" >&2
    echo "Compila con: cd \"${SCRIPT_DIR}/llama.cpp\" && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j\$(nproc) --target llama-server llama-cli"
    exit 1
fi

# ── Auto-detect / default NGL ─────────────────────────────────────────────────
# Qwen3.5-35B-A3B MoE: 40 layer (n_layer=40 da meta GGUF qwen35moe).
# Strategia: con CTX grande l'auto-detect "calcolo MB/layer" è inadeguato
# perché ignora il KV cache (1-2 GB su GPU) e il MoE split (--n-cpu-moe).
# Preferiamo i DEFAULT VALIDATI sulla RTX 4060 Laptop 8 GB:
#   NGL=40 + NCMOE=34 + KV su GPU → ~7.4 GB VRAM, 33-37 t/s a CTX 196k.
# L'auto-detect da nvidia-smi viene usato SOLO se la GPU rilevata ha
# meno VRAM (per es. su altra macchina) — formula prudente con NCMOE applicato.
N_LAYER=40
VRAM_HEADROOM_MB="${VRAM_HEADROOM_MB:-1500}"   # KV (~2 GB già contato sotto) + compute buffer
LAYER_COST_MB="${LAYER_COST_MB:-50}"           # con NCMOE attivo i layer "GPU" sono solo attention+shared

if [[ -z "${NGL:-}" ]]; then
    if command -v nvidia-smi &>/dev/null; then
        FREE_MB=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null \
                   | head -1 | tr -d '[:space:]')
        if [[ "$FREE_MB" =~ ^[0-9]+$ ]]; then
            # Su 8 GB Laptop 4060 (FREE_MB ≈ 7800): scegli default validato.
            if [[ $FREE_MB -ge 7000 ]]; then
                NGL=$N_LAYER
                echo "[GPU] VRAM libera ${FREE_MB} MB ≥ 7 GB → default validato NGL=${NGL}/${N_LAYER}"
            else
                # GPU più piccola: stima conservativa assumendo NCMOE applicato.
                # Budget: FREE - headroom - KV(~2GB) - compute(~800MB) = layer_attn
                BUDGET=$(( FREE_MB - VRAM_HEADROOM_MB - 2000 - 800 ))
                [[ $BUDGET -lt 0 ]] && BUDGET=0
                NGL=$(( BUDGET / LAYER_COST_MB ))
                [[ $NGL -gt $N_LAYER ]] && NGL=$N_LAYER
                echo "[GPU] VRAM libera ${FREE_MB} MB — fallback conservativo NGL=${NGL}/${N_LAYER}"
            fi
        else
            NGL=0
            echo "[GPU] Impossibile leggere VRAM — CPU-only (NGL=0)"
        fi
    else
        NGL=0
        echo "[GPU] nvidia-smi non trovato → CPU-only (NGL=0)"
        echo "      Per GPU offload: bash install_gpu.sh cuda"
    fi
else
    echo "[GPU] NGL forzato: ${NGL}"
fi

# Default NCMOE coerente con NGL=40 sul target RTX 4060 8 GB.
# Quando NGL=40 ma NCMOE non è settato, applica il default validato (34).
# Per disattivare il MoE split: NCMOE=0.
if [[ -z "${NCMOE:-}" && "$NGL" == "$N_LAYER" ]]; then
    NCMOE=34
    echo "[MoE] NCMOE non settato + NGL=${NGL} → default validato NCMOE=${NCMOE}"
fi

# Default NO_KV_OFFLOAD coerente con default validato (KV su GPU).
# Sovrascrive l'auto-attivazione \`NGL>0 && CTX>32k\` quando applichiamo i default.
if [[ -z "${NO_KV_OFFLOAD:-}" && "$NGL" == "$N_LAYER" && "${NCMOE:-0}" -ge 30 ]]; then
    NO_KV_OFFLOAD=0
    echo "[KV]  default validato → KV su GPU (NO_KV_OFFLOAD=0)"
fi

# ── Thread count ───────────────────────────────────────────────────────────────
THREADS=$(( $(nproc) / 2 ))
[[ $THREADS -lt 4 ]] && THREADS=4

# ── KV offload location ───────────────────────────────────────────────────────
# Quando i pesi sono su GPU (NGL>0) ma il context è grande (>32k), il KV cache
# può saturare la VRAM. --no-kv-offload tiene i pesi sulla GPU e sposta SOLO il
# KV in RAM (penalità ~10-20% throughput, evita CUDA OOM con CTX 196k su 8 GB).
# Auto-attivato quando NGL>0 e CTX>32768. Override esplicito con NO_KV_OFFLOAD=0/1.
if [[ -z "${NO_KV_OFFLOAD:-}" ]]; then
    if [[ $NGL -gt 0 && $CTX -gt 32768 ]]; then
        NO_KV_OFFLOAD=1
    else
        NO_KV_OFFLOAD=0
    fi
fi
NKVO_ARGS=()
if [[ "$NO_KV_OFFLOAD" == "1" ]]; then
    NKVO_ARGS=(--no-kv-offload)
    echo "[KV]  --no-kv-offload attivo → pesi su GPU, KV in RAM (CTX=$CTX > 32k)"
fi

# ── KV cache type ──────────────────────────────────────────────────────────────
# Decisione DOPO NO_KV_OFFLOAD: se il KV vive in RAM con CTX grande, q8_0
# diventa proibitivo (~15 GB a 196k) → forziamo q4_0. Altrimenti seguiamo
# la regola classica: q8_0 se i pesi/KV sono su GPU, q4_0 se siamo CPU-only.
# Override esplicito con KV_TYPE=q8_0|q4_0.
if [[ -z "${KV_TYPE:-}" ]]; then
    if [[ "$NO_KV_OFFLOAD" == "1" ]]; then
        KV_TYPE="q4_0"
        echo "[KV]  KV in RAM + CTX=$CTX → KV q4_0 (q8_0 sarebbe ~2x in RAM)"
    elif [[ $NGL -ge 20 ]]; then
        KV_TYPE="q8_0"
        echo "[KV]  GPU offload + KV su GPU → KV q8_0 (qualità massima)"
    else
        KV_TYPE="q4_0"
        echo "[KV]  CPU-only → KV q4_0 (risparmio ~50% vs q8_0)"
    fi
else
    echo "[KV]  KV_TYPE forzato: $KV_TYPE"
fi

# ── Stima memoria ──────────────────────────────────────────────────────────────
# n_layer=40, ~495 MB/layer di esperti (19.78 GB / 40). Attention/shared ~30 MB/layer.
# KV cache Qwen3.5-35B: n_layer=40, n_kv_head=2, head_dim=256, q8_0 = 1 byte/elem.
RAM_MODEL_GB=$(( (40 - NGL) * 495 / 1024 + 1 ))
KV_MB=$(( CTX * 40 * 2 * 256 * 2 / 1024 / 1024 ))
[[ "$KV_TYPE" == "q4_0" ]] && KV_MB=$(( KV_MB / 2 ))
echo "[MEM] Stima utilizzo: ~${RAM_MODEL_GB} GB pesi CPU + ~${KV_MB} MB KV cache"

# ── Stampa config ──────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
[[ "$MODE" == "server" ]] && echo "  Qwen3.5-35B-A3B Heretic — API Server"
[[ "$MODE" == "cli"    ]] && echo "  Qwen3.5-35B-A3B Heretic — CLI Chat"
echo "════════════════════════════════════════════"
echo "  Modello    : $(basename "$MODEL")"
echo "  GPU layers : ${NGL}/40"
echo "  Contesto   : ${CTX} token"
echo "  Thread CPU : $THREADS"
echo "  Flash Attn : on"
echo "  KV cache   : ${KV_TYPE}"
[[ "$MODE" == "server" ]] && echo "  Endpoint   : http://127.0.0.1:${PORT}/v1"
echo "════════════════════════════════════════════"
echo ""

# Parametri comuni
COMMON_ARGS=(
    -m        "$MODEL"
    -ngl      "$NGL"
    -c        "$CTX"
    -t        "$THREADS"
    -fa       on
    -ctk      "$KV_TYPE"
    -ctv      "$KV_TYPE"
)

# ── Avvio ──────────────────────────────────────────────────────────────────────
# Usa template Qwen3 ufficiale (JSON-based) per tool-calling multi-step.
QWEN3_TMPL="${SCRIPT_DIR}/llama.cpp/models/templates/Qwen-Qwen3-0.6B.jinja"

# Bearer API key for the OpenAI-compatible endpoint. Required when SAP_LLM_API_KEY
# is non-empty; otherwise the server is open to anyone reaching the bind address.
API_KEY_ARGS=()
if [[ -n "${SAP_LLM_API_KEY:-}" ]]; then
    API_KEY_ARGS=(--api-key "$SAP_LLM_API_KEY")
fi

# ── MoE expert offload ───────────────────────────────────────────────────────
# Qwen3.5-35B-A3B is an MoE model (256 experts, 8 active per token). Most of
# the 19.7 GB weight footprint is in the expert FFN tensors which are accessed
# sparsely. On GPUs that cannot fit the whole model, the optimal split is:
#   - all 40 transformer layers fully on GPU (-ngl 40)
#   - MoE expert tensors of the first NCMOE layers kept on CPU (--n-cpu-moe N)
# This keeps attention + shared FFN (the hot path) in VRAM and avoids the
# slow CPU-GPU per-token copy of dense FFNs.
#
# Heuristic: NCMOE = 40 means ALL expert weights stay on CPU (~19 GB host RAM,
# ~1 GB VRAM for attention/embeddings). Lower NCMOE moves more experts to GPU.
# Override with NCMOE=<n>; set NCMOE=0 to disable and revert to plain -ngl mode.
NCMOE_ARGS=()
if [[ -n "${NCMOE:-}" && "$NCMOE" != "0" ]]; then
    NCMOE_ARGS=(--n-cpu-moe "$NCMOE")
    echo "[MoE] --n-cpu-moe ${NCMOE} (experts of first ${NCMOE} layers on CPU)"
fi

# Run llama-server with retry-on-OOM: if CUDA OOMs, retry once with NGL=0.
run_server() {
    local ngl="$1"
    "$BIN" \
        -m "$MODEL" -ngl "$ngl" -c "$CTX" -t "$THREADS" \
        -fa on -ctk "$KV_TYPE" -ctv "$KV_TYPE" \
        "${NKVO_ARGS[@]}" "${NCMOE_ARGS[@]}" \
        --host 127.0.0.1 --port "$PORT" -np 1 \
        "${API_KEY_ARGS[@]}" \
        --jinja --chat-template-file "$QWEN3_TMPL" \
        --webui-mcp-proxy
}

if [[ "$MODE" == "server" ]]; then
    if ! run_server "$NGL"; then
        rc=$?
        if [[ $NGL -gt 0 ]]; then
            echo ""
            echo "[RETRY] llama-server uscito con codice $rc (probabile CUDA OOM con NGL=$NGL)"
            echo "[RETRY] Riavvio in CPU-only (NGL=0). Per evitare in futuro:"
            echo "        VRAM_HEADROOM_MB=3500 bash start_llm.sh"
            echo "        oppure NGL=$(( NGL > 4 ? NGL - 4 : 0 )) bash start_llm.sh"
            echo ""
            exec "$BIN" \
                -m "$MODEL" -ngl 0 -c "$CTX" -t "$THREADS" \
                -fa on -ctk q4_0 -ctv q4_0 \
                --host 127.0.0.1 --port "$PORT" -np 1 \
                "${API_KEY_ARGS[@]}" \
                --jinja --chat-template-file "$QWEN3_TMPL" \
                --webui-mcp-proxy
        fi
        exit $rc
    fi
elif [[ "$MODE" == "cli" ]]; then
    exec "$BIN" \
        "${COMMON_ARGS[@]}" \
        -cnv            \
        --temp  0.6     \
        --top-p 0.95    \
        --top-k 20      \
        --min-p 0       \
        -n      -1
else
    echo "Uso: bash start_llm.sh [server|cli]"
    exit 1
fi

#   - Flash Attention: on
#   - KV cache: Q8_0 (K e V) — risparmia VRAM ~30%
#   - Context: 32768 token
#   - Temperature: 0.6 / top-p: 0.95 / top-k: 20
#   - Parallel slots: 1
#   - Host: 127.0.0.1:8080 (OpenAI-compatible API su /v1)
#
# NGL (GPU layers) auto-rilevato:  (VRAM_libera_MB - 1500) / 230, cap 64
# Fallback sicuro: 20 layer se nvidia-smi non disponibile
#
# Uso:
#   bash start_llm.sh          # modalità server API (default)
#   bash start_llm.sh cli      # chat interattiva
#   NGL=0 bash start_llm.sh    # forza CPU-only
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MODE="${1:-server}"

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL="/home/resolutor/Desktop/qwen/Qwen3.5-35B-A3B-heretic.Q4_K_M.gguf"
SERVER_BIN="${SCRIPT_DIR}/llama.cpp/build/bin/llama-server"
CLI_BIN="${SCRIPT_DIR}/llama.cpp/build/bin/llama-cli"

# ── Validation ───────────────────────────────────────────────────────────────
if [[ ! -f "$MODEL" ]]; then
    echo "[ERRORE] Modello non trovato: $MODEL" >&2
    exit 1
fi

BIN="$SERVER_BIN"
[[ "$MODE" == "cli" ]] && BIN="$CLI_BIN"

if [[ ! -f "$BIN" ]]; then
    echo "[ERRORE] Binario non trovato: $BIN" >&2
    echo ""
    echo "Compila llama.cpp con:"
    echo "  cd \"${SCRIPT_DIR}\""
    echo "  git clone --depth 1 --branch b8250 https://github.com/ggerganov/llama.cpp llama.cpp"
    echo "  cd llama.cpp"
    echo "  cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release"
    echo "  cmake --build build --config Release -j\$(nproc) --target llama-server llama-cli"
    exit 1
fi

# ── Auto-detect NGL (GPU layers) ─────────────────────────────────────────────
# Qwen3.5-35B-A3B MoE ha 64 layer. In Q4_K_M ogni layer pesa ~230 MB.
# Riserviamo 1500 MB per KV cache + overhead CUDA.
if [[ -z "${NGL:-}" ]]; then
    if command -v nvidia-smi &>/dev/null; then
        FREE_MB=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null \
                   | head -1 | tr -d '[:space:]')
        if [[ "$FREE_MB" =~ ^[0-9]+$ ]]; then
            USABLE=$(( FREE_MB - 1500 ))
            [[ $USABLE -lt 0 ]] && USABLE=0
            NGL=$(( USABLE / 230 ))
            [[ $NGL -gt 64 ]] && NGL=64
            echo "[GPU] VRAM libera: ${FREE_MB} MB → offload ${NGL}/64 layer su GPU"
        else
            NGL=20
            echo "[GPU] Impossibile leggere VRAM, uso default conservativo: NGL=${NGL}"
        fi
    else
        # RTX 4060 Mobile = 8 GB VRAM → (8192-1500)/230 = 29, arrotondiamo a 28 sicuro
        # Cambia questo se hai una GPU diversa
        NGL=28
        echo "[GPU] nvidia-smi non trovato. Default NGL=${NGL} (RTX 4060 Mobile 8GB)."
        echo "      Per rilevazione automatica: sudo apt install nvidia-utils-5xx"
    fi
else
    echo "[GPU] NGL forzato a ${NGL} (da variabile di ambiente)"
fi

# ── Thread count (P-core / meta dei thread logici) ───────────────────────────
THREADS=$(( $(nproc) / 2 ))
[[ $THREADS -lt 4 ]] && THREADS=4

# ── Parametri comuni ─────────────────────────────────────────────────────────
COMMON_ARGS=(
    -m        "$MODEL"
    -ngl      "$NGL"
    -c        32768
    -t        "$THREADS"
    -fa       on                # Flash Attention
    -ctk      q8_0              # KV cache K in Q8
    -ctv      q8_0              # KV cache V in Q8
)

# ── Stampa config ─────────────────────────────────────────────────────────────
echo ""
[[ "$MODE" == "server" ]] && echo "════════════════════════════════════════" || true
[[ "$MODE" == "server" ]] && echo "  Qwen3.5-35B-A3B Heretic — API Server" || true
[[ "$MODE" == "cli"    ]] && echo "════════════════════════════════════════" || true
[[ "$MODE" == "cli"    ]] && echo "  Qwen3.5-35B-A3B Heretic — CLI Chat"   || true
echo "════════════════════════════════════════"
echo "  Modello    : $(basename "$MODEL")"
echo "  GPU layers : ${NGL}/64"
echo "  Contesto   : 32768 token"
echo "  Thread CPU : $THREADS"
echo "  Flash Attn : on"
echo "  KV cache   : Q8_0"
[[ "$MODE" == "server" ]] && echo "  Endpoint   : http://127.0.0.1:8080/v1"
echo "════════════════════════════════════════"
echo ""

# ── Avvio ─────────────────────────────────────────────────────────────────────
# NOTA: Il GGUF Heretic contiene un chat_template xLAM (<function=...>) che
# NON è compatibile con il parser tool-call di llama-server (fallisce sul 2°
# turn del multi-step). Usiamo il template ufficiale Qwen3 JSON-based
# incluso nei sorgenti llama.cpp → tool-calls nativi, multi-step affidabile.
QWEN3_TMPL="${SCRIPT_DIR}/llama.cpp/models/templates/Qwen-Qwen3-0.6B.jinja"
if [[ "$MODE" == "server" ]]; then
    LEGACY_API_KEY_ARGS=()
    if [[ -n "${SAP_LLM_API_KEY:-}" ]]; then
        LEGACY_API_KEY_ARGS=(--api-key "$SAP_LLM_API_KEY")
    fi
    exec "$BIN" \
        "${COMMON_ARGS[@]}" \
        --host    127.0.0.1   \
        --port    8080         \
        -np       1            \
        "${LEGACY_API_KEY_ARGS[@]}" \
        --jinja                \
        --chat-template-file "$QWEN3_TMPL"
elif [[ "$MODE" == "cli" ]]; then
    exec "$BIN" \
        "${COMMON_ARGS[@]}" \
        -cnv               \
        --temp    0.6      \
        --top-p   0.95     \
        --top-k   20       \
        --min-p   0        \
        -n        -1
else
    echo "Uso: bash start_llm.sh [server|cli]"
    exit 1
fi


# ── Auto-detect model path ──────────────────────────────────────────────────
find_model() {
    local pattern="*qwen*3*30b*q4*.gguf *qwen*3*35b*q4*.gguf *qwen3*a3b*q4*.gguf"
    for dir in \
        "$HOME/models" "$HOME/.cache/lm-studio/models" \
        "/opt/models" "/data/models" "$HOME/llm/models"; do
        for pat in $pattern; do
            # shellcheck disable=SC2086
            found=$(find "$dir" -maxdepth 4 -iname "$pat" 2>/dev/null | head -1)
            if [[ -n "$found" ]]; then
                echo "$found"
                return 0
            fi
        done
    done
    echo ""
}

if [[ -z "$MODEL_PATH" ]]; then
    MODEL_PATH=$(find_model)
fi

# ── Backend launchers ────────────────────────────────────────────────────────

start_llama_cpp() {
    local bin
    bin=$(command -v llama-server 2>/dev/null \
        || find /usr /opt "$HOME" -maxdepth 8 -name "llama-server" 2>/dev/null | head -1)

    if [[ -z "$bin" ]]; then
        echo "[ERROR] llama-server not found. Build llama.cpp or install Ollama."
        echo "        git clone https://github.com/ggerganov/llama.cpp && cd llama.cpp && make -j$(nproc)"
        exit 1
    fi

    if [[ -z "$MODEL_PATH" || ! -f "$MODEL_PATH" ]]; then
        echo "[ERROR] Model GGUF not found. Pass the path as second argument:"
        echo "        $0 llama /path/to/qwen3-30b-a3b-q4_K_M.gguf"
        exit 1
    fi

    echo "[+] Starting llama.cpp server"
    echo "    model     : $MODEL_PATH"
    echo "    port      : $PORT"
    echo "    ctx       : $CTX"
    echo "    gpu layers: $GPU_LAYERS"
    echo ""

    exec "$bin" \
        --model       "$MODEL_PATH" \
        --port        "$PORT" \
        --ctx-size    "$CTX" \
        --n-predict   "$NPREDICT" \
        --n-gpu-layers "$GPU_LAYERS" \
        --parallel    1 \
        --host        "127.0.0.1" \
        --jinja                   \
        --chat-template chatml    \
        --log-disable
}

start_ollama() {
    if ! command -v ollama &>/dev/null; then
        echo "[ERROR] Ollama not installed. Install with:"
        echo "        curl -fsSL https://ollama.com/install.sh | sh"
        exit 1
    fi

    # Use Ollama's OpenAI-compat endpoint on port 11434
    export OLLAMA_HOST="127.0.0.1:11434"
    PORT=11434

    # Update .env to point at Ollama
    sed -i "s|LOCAL_LLM_BASE_URL=.*|LOCAL_LLM_BASE_URL=http://localhost:11434/v1|" .env 2>/dev/null || true

    echo "[+] Starting Ollama"
    ollama serve &

    sleep 2

    # Pull model if not present
    MODEL_TAG="${OLLAMA_MODEL:-qwen3:30b-a3b-q4_K_M}"
    if ! ollama list | grep -q "$MODEL_TAG"; then
        echo "[+] Pulling $MODEL_TAG (this may take a while)..."
        ollama pull "$MODEL_TAG"
    fi

    echo "[+] Ollama serving at http://127.0.0.1:$PORT/v1"
    echo "[+] Model: $MODEL_TAG"
    echo ""
    echo "    Set in .env:"
    echo "      LLM_MODEL=$MODEL_TAG"
    wait
}

start_kobold() {
    if ! command -v koboldcpp &>/dev/null; then
        echo "[ERROR] koboldcpp not found."
        exit 1
    fi

    if [[ -z "$MODEL_PATH" || ! -f "$MODEL_PATH" ]]; then
        echo "[ERROR] Model GGUF not found."
        exit 1
    fi

    # koboldcpp exposes OpenAI-compat API at /v1 on the same port
    PORT=5001
    sed -i "s|LOCAL_LLM_BASE_URL=.*|LOCAL_LLM_BASE_URL=http://localhost:5001/v1|" .env 2>/dev/null || true

    echo "[+] Starting koboldcpp"
    exec koboldcpp \
        --model "$MODEL_PATH" \
        --port  "$PORT" \
        --contextsize "$CTX" \
        --gpulayers "$GPU_LAYERS" \
        --host "127.0.0.1" \
        --openai
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

case "$BACKEND" in
    llama|llama.cpp|llamacpp)
        start_llama_cpp ;;
    ollama)
        start_ollama ;;
    kobold|koboldcpp)
        start_kobold ;;
    auto)
        if   command -v llama-server &>/dev/null; then start_llama_cpp
        elif command -v ollama       &>/dev/null; then start_ollama
        elif command -v koboldcpp    &>/dev/null; then start_kobold
        else
            echo "[ERROR] No inference backend found."
            echo ""
            echo "Install one of:"
            echo "  llama.cpp : git clone https://github.com/ggerganov/llama.cpp && cd llama.cpp && make -j\$(nproc)"
            echo "  Ollama    : curl -fsSL https://ollama.com/install.sh | sh"
            echo ""
            echo "Then re-run: $0 llama /path/to/model.gguf"
            exit 1
        fi ;;
    *)
        echo "Usage: $0 [llama|ollama|kobold|auto] [/path/to/model.gguf]"
        exit 1 ;;
esac
