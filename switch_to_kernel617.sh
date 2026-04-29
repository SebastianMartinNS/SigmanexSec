#!/usr/bin/env bash
# switch_to_kernel617.sh
# Reinstalla driver NVIDIA 550 (closed), compila DKMS SOLO per kernel 6.17.13+2-amd64,
# imposta 6.17 come default di GRUB, e chiede conferma prima del reboot.
#
# Richiede sudo. Non riavvia automaticamente.
set -u

TARGET_KERNEL="6.17.13+2-amd64"

echo "============================================================"
echo "  SWITCH A KERNEL $TARGET_KERNEL + DRIVER NVIDIA 550"
echo "============================================================"

# ---------- 1. Verifica che il kernel target sia installato ----------
if [[ ! -f "/boot/vmlinuz-$TARGET_KERNEL" ]]; then
    echo "[ERRORE] /boot/vmlinuz-$TARGET_KERNEL non trovato."
    echo "         Installa prima: sudo apt-get install linux-image-$TARGET_KERNEL"
    exit 1
fi
if [[ ! -d "/lib/modules/$TARGET_KERNEL" ]]; then
    echo "[ERRORE] /lib/modules/$TARGET_KERNEL mancante."
    exit 1
fi
echo "[OK] Kernel $TARGET_KERNEL presente."

# ---------- 2. Header del kernel target ----------
if ! dpkg -l "linux-headers-$TARGET_KERNEL" 2>/dev/null | grep -q '^ii'; then
    echo "[+] Installo linux-headers-$TARGET_KERNEL..."
    sudo apt-get install -y "linux-headers-$TARGET_KERNEL" || {
        echo "[ERRORE] apt-get install headers fallito."; exit 1; }
fi
echo "[OK] Headers per $TARGET_KERNEL presenti."

# ---------- 3. Rimuovi driver open (incompatibile) ----------
if dpkg -l nvidia-open-kernel-dkms 2>/dev/null | grep -q '^ii\|^iU\|^iF'; then
    echo "[+] Rimuovo nvidia-open-kernel-dkms..."
    sudo apt-get remove --purge -y nvidia-open-kernel-dkms nvidia-open-kernel-support
fi

# ---------- 4. Reinstalla driver closed ----------
echo "[+] Installo nvidia-driver + nvidia-kernel-dkms (closed)..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o Dpkg::Options::="--force-confold" \
    nvidia-driver nvidia-kernel-dkms || true
# apt può fallire sulla build per 6.19: ignoriamo e andiamo avanti.

# ---------- 5. Rimuovi eventuale build precedente per 6.17 e ricompila ----------
echo "[+] Forzo build DKMS per kernel $TARGET_KERNEL..."
sudo dkms remove nvidia-current/550.163.01 -k "$TARGET_KERNEL" 2>/dev/null || true
sudo dkms install nvidia-current/550.163.01 -k "$TARGET_KERNEL" --force || {
    echo "[ERRORE] DKMS build fallito per $TARGET_KERNEL."
    echo "         Log: /var/lib/dkms/nvidia-current/550.163.01/build/make.log"
    exit 1
}

# ---------- 6. Verifica i .ko ----------
DKMS_DIR="/lib/modules/$TARGET_KERNEL/updates/dkms"
if ! ls "$DKMS_DIR"/nvidia*.ko* >/dev/null 2>&1; then
    echo "[ERRORE] I moduli nvidia non risultano installati in $DKMS_DIR"
    exit 1
fi
echo "[OK] Moduli in $DKMS_DIR:"
ls -1 "$DKMS_DIR"/nvidia*.ko* | sed 's/^/     /'

# ---------- 7. Rigenera initramfs per 6.17 ----------
echo "[+] Rigenero initramfs per $TARGET_KERNEL..."
sudo update-initramfs -u -k "$TARGET_KERNEL"

# ---------- 8. Trova l'entry GRUB esatta ----------
echo "[+] Cerco l'entry GRUB per $TARGET_KERNEL..."
SUBMENU_ID=$(awk -F\' '/^submenu/ {print $2; exit}' /boot/grub/grub.cfg)
ENTRY_ID=$(awk -F\' -v k="$TARGET_KERNEL" '
    /^menuentry/ && $2 ~ k && $2 !~ /recovery/ {print $2; exit}
    /^\tmenuentry/ && $2 ~ k && $2 !~ /recovery/ {print $2; exit}
' /boot/grub/grub.cfg)

if [[ -z "$ENTRY_ID" ]]; then
    echo "[ERRORE] Non trovo entry menuentry per $TARGET_KERNEL in /boot/grub/grub.cfg"
    echo "         Verifica manualmente con: grep menuentry /boot/grub/grub.cfg"
    exit 1
fi

if [[ -n "$SUBMENU_ID" ]]; then
    GRUB_DEFAULT_VALUE="${SUBMENU_ID}>${ENTRY_ID}"
else
    GRUB_DEFAULT_VALUE="$ENTRY_ID"
fi
echo "[OK] Entry trovata:"
echo "     submenu : $SUBMENU_ID"
echo "     entry   : $ENTRY_ID"
echo "     GRUB_DEFAULT = \"$GRUB_DEFAULT_VALUE\""

# ---------- 9. Aggiorna /etc/default/grub ----------
GRUB_FILE="/etc/default/grub"
sudo cp "$GRUB_FILE" "$GRUB_FILE.bak.$(date +%s)"
if grep -q '^GRUB_DEFAULT=' "$GRUB_FILE"; then
    sudo sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"$GRUB_DEFAULT_VALUE\"|" "$GRUB_FILE"
else
    echo "GRUB_DEFAULT=\"$GRUB_DEFAULT_VALUE\"" | sudo tee -a "$GRUB_FILE" >/dev/null
fi
echo "[+] Aggiorno grub..."
sudo update-grub

# ---------- 10. Riepilogo ----------
echo
echo "============================================================"
echo "[SUCCESS] Configurazione completata."
echo "  - DKMS NVIDIA 550 compilato per kernel $TARGET_KERNEL"
echo "  - initramfs rigenerato"
echo "  - GRUB_DEFAULT impostato su quel kernel"
echo
echo "Al prossimo boot parte automaticamente il kernel $TARGET_KERNEL."
echo "Esegui ora:   sudo reboot"
echo
echo "Dopo il reboot verifica con:"
echo "  uname -r            # deve mostrare $TARGET_KERNEL"
echo "  nvidia-smi          # deve mostrare la RTX 4060"
echo "  ls /dev/nvidia*     # deve listare nvidia0, nvidiactl, ecc."
echo "============================================================"
