#!/usr/bin/env bash
# scripts/install_missing_tools.sh
#
# Installa i tool del catalogo parrot_tools.yaml che risultano "missing"
# secondo core.parrot_catalog.gap_report.
#
# Ordine di tentativo per ciascun tool:
#   1) apt (se disponibile come pacchetto)
#   2) go install (per i tool ProjectDiscovery / Go-native)
#   3) pipx install (per i tool Python)
#
# Idempotente: salta i tool già presenti in PATH.
# Richiede sudo per: apt install, ln -s in /usr/local/bin.
#
# Usage:
#   bash scripts/install_missing_tools.sh                # full install
#   bash scripts/install_missing_tools.sh --dry-run      # solo piano
#   bash scripts/install_missing_tools.sh --only=go      # solo categoria
#   bash scripts/install_missing_tools.sh --skip-apt     # niente apt

set -uo pipefail
cd "$(dirname "$0")/.."

DRY=0
ONLY=""
SKIP_APT=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --only=*)  ONLY="${a#--only=}" ;;
    --skip-apt) SKIP_APT=1 ;;
    *) echo "[!] arg sconosciuto: $a" >&2; exit 2 ;;
  esac
done

GO_BIN="${HOME}/go/bin"
LOCAL_BIN="/usr/local/bin"

log()    { printf '\e[36m[install]\e[0m %s\n' "$*"; }
ok()     { printf '\e[32m[ ok ]\e[0m %s\n' "$*"; }
warn()   { printf '\e[33m[warn]\e[0m %s\n' "$*"; }
err()    { printf '\e[31m[fail]\e[0m %s\n' "$*"; }
present(){ command -v "$1" >/dev/null 2>&1; }
run()    { if [[ $DRY -eq 1 ]]; then echo "  DRY: $*"; else eval "$@"; fi; }

# ─── 0. Prerequisiti ───────────────────────────────────────────────────────

ensure_path() {
  case ":$PATH:" in
    *":$GO_BIN:"*) ;;
    *) export PATH="$GO_BIN:$PATH"
       log "PATH esteso con $GO_BIN (sessione corrente)";;
  esac
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) export PATH="$HOME/.local/bin:$PATH";;
  esac
}

ensure_path

ensure_apt_pkgs() {
  [[ $SKIP_APT -eq 1 ]] && { warn "skip apt: prerequisiti saltati"; return; }
  log "Aggiorno indici apt e installo dipendenze base"
  run "sudo apt-get update -y"
  run "sudo apt-get install -y --no-install-recommends \
        ca-certificates curl wget git build-essential pkg-config \
        libpcap-dev pipx python3-venv python3-pip"
  run "pipx ensurepath"
}

# Symlink: dato un percorso file → $LOCAL_BIN/<basename> (sudo).
publish_bin() {
  local src="$1" name
  name="$(basename "$src")"
  if [[ -e "$LOCAL_BIN/$name" ]]; then return 0; fi
  if [[ -x "$src" ]]; then
    run "sudo ln -sf '$src' '$LOCAL_BIN/$name'"
  fi
}

# ─── 1. Helpers d'installazione per categoria ─────────────────────────────

apt_install() {
  local pkg="$1" bin="$2"
  if present "$bin"; then ok "$bin già presente"; return 0; fi
  if [[ $SKIP_APT -eq 1 ]]; then warn "$bin: apt skip"; return 1; fi
  log "apt install $pkg"
  if run "sudo apt-get install -y --no-install-recommends $pkg"; then
    if present "$bin"; then ok "$bin installato via apt"; return 0; fi
  fi
  warn "$pkg: apt non lo fornisce o ha fallito, provo fallback"
  return 1
}

go_install() {
  local mod="$1" bin="$2"
  if present "$bin"; then ok "$bin già presente"; return 0; fi
  if ! present go; then err "go assente, impossibile installare $bin"; return 1; fi
  log "go install $mod"
  if run "GOPROXY=https://proxy.golang.org,direct go install $mod"; then
    if [[ -x "$GO_BIN/$bin" ]]; then
      publish_bin "$GO_BIN/$bin"
      ok "$bin installato via go"
      return 0
    fi
  fi
  err "go install fallito per $bin"
  return 1
}

pipx_install() {
  local pkg="$1" bin="$2"
  if present "$bin"; then ok "$bin già presente"; return 0; fi
  if ! present pipx; then err "pipx assente, salto $bin"; return 1; fi
  log "pipx install $pkg"
  if run "pipx install --force '$pkg'"; then
    if [[ -x "$HOME/.local/bin/$bin" ]]; then
      publish_bin "$HOME/.local/bin/$bin"
    fi
    if present "$bin"; then ok "$bin installato via pipx"; return 0; fi
  fi
  err "pipx install fallito per $bin"
  return 1
}

# ─── 2. Definizione installer per ciascun tool ────────────────────────────

install_amass()        { apt_install amass amass        || go_install github.com/owasp-amass/amass/v4/...@master amass; }
install_subfinder()    { apt_install subfinder subfinder || go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder; }
install_naabu()        { apt_install naabu naabu        || go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest naabu; }
install_katana()       { apt_install katana katana      || go_install github.com/projectdiscovery/katana/cmd/katana@latest katana; }
install_nuclei()       {
  apt_install nuclei nuclei || go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
  if present nuclei; then run "nuclei -update-templates -silent || true"; fi
}
install_dalfox()       { apt_install dalfox dalfox      || go_install github.com/hahwul/dalfox/v2@latest dalfox; }
install_theharvester() { apt_install theharvester theHarvester; }
install_testssl()      { apt_install testssl.sh testssl.sh; }
install_wpscan()       {
  apt_install wpscan wpscan && return 0
  log "fallback gem install wpscan (richiede ruby-dev)"
  run "sudo apt-get install -y --no-install-recommends ruby ruby-dev libcurl4-openssl-dev"
  run "sudo gem install wpscan --no-document"
  present wpscan
}
install_kerbrute()     { go_install github.com/ropnop/kerbrute@latest kerbrute; }
install_certipy()      { pipx_install certipy-ad certipy-ad; }
install_bloodhound()   { pipx_install bloodhound bloodhound.py; }
install_nameThatHash() { pipx_install name-that-hash name-that-hash; }
install_mitm6()        { pipx_install mitm6 mitm6; }
install_gitleaks()     { apt_install gitleaks gitleaks  || go_install github.com/gitleaks/gitleaks/v8@latest gitleaks; }

# ── Phase E: 30 nuovi tool aggiunti col catalogo esteso ───────────────────
install_assetfinder() { apt_install assetfinder assetfinder || go_install github.com/tomnomnom/assetfinder@latest assetfinder; }
install_findomain()   { apt_install findomain findomain; }
install_dnsx()        { apt_install dnsx dnsx || go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest dnsx; }
install_fierce()      { apt_install fierce fierce; }
install_massdns()     { apt_install massdns massdns; }
install_waybackurls() { apt_install waybackurls waybackurls || go_install github.com/tomnomnom/waybackurls@latest waybackurls; }
install_gau()         { apt_install gau gau || go_install github.com/lc/gau/v2/cmd/gau@latest gau; }
install_rustscan()    { apt_install rustscan rustscan; }
install_xsstrike()    { pipx_install xsstrike XSStrike || pipx_install xsstrike xsstrike; }
install_sslyze()      { apt_install sslyze sslyze || pipx_install sslyze sslyze; }
install_hakrawler()   { apt_install hakrawler hakrawler || go_install github.com/hakluke/hakrawler@latest hakrawler; }
install_paramspider() { apt_install paramspider paramspider || pipx_install paramspider paramspider; }
install_searchsploit(){ apt_install exploitdb searchsploit; }
install_hashid_legacy(){ apt_install hash-identifier hash-identifier; }
install_ncat()        { apt_install ncat ncat; }
install_yersinia()    { apt_install yersinia yersinia; }
install_kismet()      { apt_install kismet kismet; }
install_checksec()    { apt_install checksec checksec; }
install_ltrace()      { apt_install ltrace ltrace; }
install_strace()      { apt_install strace strace; }
install_radare2()     { apt_install radare2 r2; }
install_ghidra()      { apt_install ghidra analyzeHeadless; }
install_vol3()        { apt_install volatility3 vol || pipx_install volatility3 vol; }
install_steghide()    { apt_install steghide steghide; }
install_clamav()      { apt_install clamav clamscan; }
install_detect_secrets(){ pipx_install detect-secrets detect-secrets; }
install_ligolo()      { go_install github.com/nicocha30/ligolo-ng/cmd/proxy@latest proxy && go_install github.com/nicocha30/ligolo-ng/cmd/agent@latest ligolo-ng; }
install_jq()          { apt_install jq jq; }

# ── Phase 8: Person/Identity OSINT (category: osint) ──────────────────────
install_sherlock()        { pipx_install sherlock-project sherlock; }
install_maigret()         { pipx_install maigret maigret; }
install_holehe()          { pipx_install holehe holehe; }
install_h8mail()          { pipx_install h8mail h8mail; }
install_whatsmyname()     { pipx_install whatsmyname whatsmyname; }
install_recon_ng()        { pipx_install recon-ng recon-ng; }
install_spiderfoot()      { pipx_install spiderfoot sf; }
install_social_analyzer() { pipx_install social-analyzer social-analyzer; }
install_ghunt()           {
  pipx_install ghunt ghunt
  warn "ghunt requires one-time cookie setup: run 'ghunt login' manually."
}

# Mappa: tool-name (catalogo) → funzione installer
declare -A INSTALLERS=(
  [amass_enum]=install_amass
  [subfinder_run]=install_subfinder
  [naabu_scan]=install_naabu
  [katana_crawl]=install_katana
  [nuclei_scan]=install_nuclei
  [dalfox_xss]=install_dalfox
  [theharvester_run]=install_theharvester
  [testssl]=install_testssl
  [wpscan_run]=install_wpscan
  [kerbrute_userenum]=install_kerbrute
  [certipy_find]=install_certipy
  [bloodhound_python]=install_bloodhound
  [name_that_hash]=install_nameThatHash
  [mitm6_run]=install_mitm6
  [gitleaks_scan]=install_gitleaks
  [assetfinder_run]=install_assetfinder
  [findomain_run]=install_findomain
  [dnsx_resolve]=install_dnsx
  [fierce_run]=install_fierce
  [massdns_resolve]=install_massdns
  [waybackurls_run]=install_waybackurls
  [gau_run]=install_gau
  [rustscan_run]=install_rustscan
  [xsstrike_run]=install_xsstrike
  [sslyze_run]=install_sslyze
  [hakrawler_run]=install_hakrawler
  [paramspider_run]=install_paramspider
  [searchsploit_query]=install_searchsploit
  [exploitdb_papers]=install_searchsploit
  [hash_identifier]=install_hashid_legacy
  [ncat_connect]=install_ncat
  [yersinia_attack]=install_yersinia
  [kismet_run]=install_kismet
  [checksec_check]=install_checksec
  [ltrace_run]=install_ltrace
  [strace_run]=install_strace
  [radare2_session]=install_radare2
  [rabin2_info]=install_radare2
  [ghidra_headless]=install_ghidra
  [volatility3_run]=install_vol3
  [steghide_extract]=install_steghide
  [clamscan_run]=install_clamav
  [detect_secrets_scan]=install_detect_secrets
  [ligolo_ng]=install_ligolo
  [jq_query]=install_jq
  # ── Phase 8: OSINT identity tools ──
  [sherlock_run]=install_sherlock
  [maigret_run]=install_maigret
  [holehe_run]=install_holehe
  [h8mail_run]=install_h8mail
  [whatsmyname_run]=install_whatsmyname
  [recon_ng_batch]=install_recon_ng
  [spiderfoot_batch]=install_spiderfoot
  [social_analyzer_run]=install_social_analyzer
  [ghunt_email]=install_ghunt
)

# ─── 3. Pianifica e installa ──────────────────────────────────────────────

log "Calcolo gap report..."
GAP_JSON="$(bash scripts/inventory_parrot.sh 2>/dev/null)"
MISSING="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print('\n'.join(d['missing']))" "$GAP_JSON")"

if [[ -z "$MISSING" ]]; then
  ok "Nessun tool mancante. Niente da fare."
  exit 0
fi

log "Tool mancanti rilevati:"
printf '  - %s\n' $MISSING

ensure_apt_pkgs

OK_LIST=()
FAIL_LIST=()
SKIP_LIST=()
for tool in $MISSING; do
  fn="${INSTALLERS[$tool]:-}"
  if [[ -z "$fn" ]]; then
    warn "$tool: nessun installer definito"
    SKIP_LIST+=("$tool"); continue
  fi
  case "$fn" in
    install_*go*|install_kerbrute|install_subfinder|install_naabu|install_katana|install_nuclei|install_dalfox|install_amass|install_gitleaks)
      [[ -n "$ONLY" && "$ONLY" != "go" && "$ONLY" != "all" ]] && continue ;;
    install_certipy|install_bloodhound|install_nameThatHash|install_mitm6|install_sherlock|install_maigret|install_holehe|install_h8mail|install_whatsmyname|install_recon_ng|install_spiderfoot|install_social_analyzer|install_ghunt)
      [[ -n "$ONLY" && "$ONLY" != "pipx" && "$ONLY" != "all" ]] && continue ;;
    install_theharvester|install_testssl|install_wpscan)
      [[ -n "$ONLY" && "$ONLY" != "apt" && "$ONLY" != "all" ]] && continue ;;
  esac

  log "── installazione $tool ──"
  if "$fn"; then
    OK_LIST+=("$tool")
  else
    FAIL_LIST+=("$tool")
  fi
done

# ─── 4. Riepilogo finale + re-inventory ────────────────────────────────────

echo
log "Re-inventory finale:"
bash scripts/inventory_parrot.sh 2>&1 | tail -n 5

echo
echo "──── RIEPILOGO ────"
echo "OK    (${#OK_LIST[@]}):    ${OK_LIST[*]:-nessuno}"
echo "FAIL  (${#FAIL_LIST[@]}):  ${FAIL_LIST[*]:-nessuno}"
echo "SKIP  (${#SKIP_LIST[@]}):  ${SKIP_LIST[*]:-nessuno}"
echo
log "Suggerimento: aggiungi a ~/.bashrc:  export PATH=\"\$HOME/go/bin:\$HOME/.local/bin:\$PATH\""
log "Riavvia la dashboard per ricaricare l'inventory:"
log "  pkill -f 'cli.py dashboard'; nohup python3 cli.py dashboard --host 127.0.0.1 --port 8765 > logs/dashboard.log 2>&1 & disown"

[[ ${#FAIL_LIST[@]} -eq 0 ]] || exit 1
exit 0
