#!/usr/bin/env bash
# install_gpu.sh — Installa CUDA toolkit / Vulkan dev e ricompila llama.cpp con GPU
#
# Esegui con: bash install_gpu.sh [cuda|vulkan]
# Default: cuda (per RTX 4060)
#
# RICHIEDE sudo (una sola volta).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

BACKEND="${1:-cuda}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LLAMA_DIR="$SCRIPT_DIR/llama.cpp"
export PATH="$HOME/.local/bin:$PATH"

if [[ ! -d "$LLAMA_DIR" ]]; then
    echo "[ERRORE] $LLAMA_DIR non trovata. Esegui prima start_llm.sh." >&2
    exit 1
fi

rebuild() {
    local extra_flags=("$@")
    echo "[+] Ricompilazione llama.cpp con flag: ${extra_flags[*]}"
    cmake -B "$LLAMA_DIR/build" "${extra_flags[@]}" \
          -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=OFF \
          "$LLAMA_DIR"
    cmake --build "$LLAMA_DIR/build" --config Release \
          -j"$(nproc)" --target llama-server llama-cli
    echo "[+] Build completata."
    "$LLAMA_DIR/build/bin/llama-server" --version
}

case "$BACKEND" in
    cuda)
        echo "[+] Installazione CUDA toolkit 12 + driver NVIDIA (Parrot/Debian)..."
        echo "[!] ATTENZIONE: installa il modulo DKMS del kernel \u2192 REBOOT richiesto."
        sudo apt-get update
        # nvidia-driver: driver proprietario + DKMS + nvidia-smi + libs userspace
        # nvidia-cuda-toolkit: nvcc + runtime CUDA per compilare llama.cpp
        # nvidia-cuda-toolkit-gcc: gcc compat shim (CUDA 12.4 vs gcc host version)
        sudo apt-get install -y nvidia-driver nvidia-cuda-toolkit nvidia-cuda-toolkit-gcc

        # Trova nvcc appena installato
        NVCC=$(which nvcc 2>/dev/null || find /usr -name nvcc 2>/dev/null | head -1)
        if [[ -z "$NVCC" ]]; then
            echo "[ERRORE] nvcc non trovato dopo l'installazione." >&2
            exit 1
        fi
        CUDA_PATH=$(dirname "$(dirname "$NVCC")")
        echo "[+] nvcc trovato: $NVCC"
        echo "[+] CUDA path: $CUDA_PATH"

        rebuild -DGGML_CUDA=ON "-DCMAKE_CUDA_COMPILER=$NVCC"

        echo ""
        echo "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"
        echo "  REBOOT richiesto per caricare il modulo kernel NVIDIA."
        echo "  Esegui: sudo reboot"
        echo "  Al riavvio verifica: nvidia-smi"
        echo "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
        ;;

    vulkan)
        echo "[+] Installazione Vulkan dev e glslang..."
        sudo apt-get install -y libvulkan-dev glslang-tools

        rebuild -DGGML_VULKAN=ON
        ;;

    *)
        echo "Uso: $0 [cuda|vulkan]"
        exit 1
        ;;
esac

echo ""
echo "============================================"
echo "  GPU build completata!"
echo "  Per verificare: bash start_llm.sh server"
echo "============================================"
