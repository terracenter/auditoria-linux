#!/usr/bin/env bash
# ============================================================================
# auditoria-host-linux.sh — Auditoría read-only de host Linux
# ============================================================================
# Basado en la plantilla: Obsidian/Planes/_templates/auditoria-host-linux.md
# Marcos: CIS Controls v8, CIS Ubuntu 22.04 Benchmark v2.0.0, NIST SP 800-53.
# Tooling: herramientas estándar + Lynis (audit system --quick).
#
# Uso:
#   sudo ./auditoria-host-linux.sh [OPCIONES]
#
# Opciones:
#   -h, --help                  Muestra esta ayuda.
#   -o, --output-dir <path>     Dir de salida. Si no se pasa, pregunta al usuario.
#                               Si corre con sudo, default es $HOME del usuario
#                               que invoca (no /root).
#   -c, --cliente <name>        Nombre del cliente (metadata, default: propio).
#   -r, --rol <rol>             Rol del host (web, db, mail, etc., default: other).
#   --skip-lynis                No instala/ejecuta Lynis.
#   --no-install                No intenta instalar paquetes faltantes.
#   --sin-internet              Asume sin internet; aborta si falta herramienta.
#   --no-tar                    No comprime al final (solo deja la carpeta).
#   --tar                       Comprime al final (default).
#   -y, --yes                   No pregunta nada interactivo, usa defaults.
#
# Comportamiento:
#   - Read-only NUNCA modifica el sistema excepto instalar lynis si se puede.
#   - Genera árbol de archivos en el dir de salida (default $HOME del usuario).
#   - Por defecto comprime en .tar.gz al final para SCP/SFTP.
#   - Con --no-tar deja la carpeta cruda (útil si vas a inspeccionar local).
# ============================================================================

set -u
set -o pipefail

# ---------- Defaults ----------
SCRIPT_NAME="auditoria-host-linux.sh"
CLIENTE="propio"
ROL="other"
HOST_NOMBRE="$(hostname 2>/dev/null || echo unknown)"
FECHA="$(date -u +%Y-%m-%d)"
HORA="$(date -u +%H%M%SZ)"
SKIP_LYNIS=0
NO_INSTALL=0
SIN_INTERNET=0
MAKE_TAR=1
ASSUME_YES=0
OUT_DIR=""

# Detectar el usuario que invocó el script (cuando se corre con sudo).
# Cuando no hay sudo, este script sigue siendo root pero $HOME ya es el correcto.
INVOKER_USER="${SUDO_USER:-${USER}}"
INVOKER_HOME="$(getent passwd "${INVOKER_USER}" 2>/dev/null | cut -d: -f6)"
[ -z "${INVOKER_HOME}" ] && INVOKER_HOME="${HOME}"

# ---------- Colores ----------
if [ -t 1 ]; then
  C_RED='\033[0;31m'
  C_GRN='\033[0;32m'
  C_YEL='\033[0;33m'
  C_BLU='\033[0;34m'
  C_RST='\033[0m'
else
  C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_RST=''
fi

log()    { printf "${C_BLU}[*]${C_RST} %s\n" "$*"; }
ok()     { printf "${C_GRN}[+]${C_RST} %s\n" "$*"; }
warn()   { printf "${C_YEL}[!]${C_RST} %s\n" "$*" >&2; }
err()    { printf "${C_RED}[-]${C_RST} %s\n" "$*" >&2; }
section(){ printf "\n${C_BLU}==== %s ====${C_RST}\n" "$*"; }

# ---------- Help ----------
usage() {
  sed -n '2,30p' "$0"
  exit 0
}

# ---------- Parse args ----------
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    -o|--output-dir) OUT_DIR="$2"; shift 2 ;;
    -c|--cliente) CLIENTE="$2"; shift 2 ;;
    -r|--rol) ROL="$2"; shift 2 ;;
    --skip-lynis) SKIP_LYNIS=1; shift ;;
    --no-install) NO_INSTALL=1; shift ;;
    --sin-internet) SIN_INTERNET=1; NO_INSTALL=1; shift ;;
    --no-tar) MAKE_TAR=0; shift ;;
    --tar) MAKE_TAR=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    *) err "Opción desconocida: $1"; usage ;;
  esac
done

# ---------- Resolver OUT_DIR si no se pasó por CLI ----------
if [ -z "${OUT_DIR}" ]; then
  DEFAULT_OUT="${INVOKER_HOME}/auditoria-${HOST_NOMBRE}-${FECHA}-${HORA}"
  if [ -t 0 ] && [ "${ASSUME_YES}" -eq 0 ]; then
    printf "Directorio de salida [Enter = %s]: " "${DEFAULT_OUT}"
    read -r REPLY </dev/tty 2>/dev/null || REPLY="${DEFAULT_OUT}"
    [ -z "${REPLY}" ] && REPLY="${DEFAULT_OUT}"
    OUT_DIR="${REPLY}"
  else
    OUT_DIR="${DEFAULT_OUT}"
  fi
fi
OUT_BASE="$(dirname "${OUT_DIR}")"

# ---------- Pre-flight ----------
if [ "$(id -u)" -ne 0 ]; then
  err "Debe ejecutarse como root (sudo)."
  exit 2
fi

mkdir -p "${OUT_DIR}"/{logs,postura-general,acceso-autenticacion,red-firewall,logs-monitoreo,actualizaciones,backups,lynis,snapshots-config}
exec > >(tee -a "${OUT_DIR}/logs/consolidated.log") 2>&1

log "Inicio: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Host: ${HOST_NOMBRE}"
log "Cliente: ${CLIENTE}"
log "Rol: ${ROL}"
log "Out dir: ${OUT_DIR}"

# ---------- Distro detection (robusta) ----------
DISTRO_ID="unknown"
DISTRO_VER="unknown"
DISTRO_FAMILY="unknown"
PKG_MGR="unknown"
LSB_ID=""
LSB_VER=""

if [ -r /etc/os-release ]; then
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_VER="${VERSION_ID:-unknown}"
fi

# Detección de familia por ID canónico (no por "qué binario existe")
case "${DISTRO_ID}" in
  ubuntu|debian|linuxmint|pop|kali|raspbian|elementary|zorin)
    DISTRO_FAMILY="debian"
    PKG_MGR="apt"
    ;;
  rhel|centos|rocky|almalinux|fedora|ol|amzn)
    DISTRO_FAMILY="rhel"
    PKG_MGR="dnf"
    ;;
  sles|opensuse-tumbleweed|opensuse-leap)
    DISTRO_FAMILY="suse"
    PKG_MGR="zypper"
    ;;
  *)
    # Fallback: detectar por binario si no se pudo por /etc/os-release
    if command -v apt-get >/dev/null 2>&1; then
      DISTRO_FAMILY="debian"
      PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
      DISTRO_FAMILY="rhel"
      PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
      DISTRO_FAMILY="rhel"
      PKG_MGR="yum"
    elif command -v zypper >/dev/null 2>&1; then
      DISTRO_FAMILY="suse"
      PKG_MGR="zypper"
    fi
    ;;
esac

log "Distro: ${DISTRO_ID} ${DISTRO_VER} (familia: ${DISTRO_FAMILY}, pkg: ${PKG_MGR})"

# ---------- Helper: ejecutar con sudo si no es root ----------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

# ---------- Helper: try install ----------
try_install() {
  local pkg="$1"
  if [ "${NO_INSTALL}" -eq 1 ]; then
    warn "Saltando instalación de ${pkg} (--no-install o --sin-internet)."
    return 1
  fi
  if [ "${SIN_INTERNET}" -eq 1 ]; then
    warn "Modo --sin-internet: no instalo ${pkg}."
    return 1
  fi
  case "${PKG_MGR}" in
    apt)
      DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get update -y >/dev/null 2>&1
      DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get install -y "${pkg}" >/dev/null 2>&1
      ;;
    dnf|yum)
      ${SUDO} ${PKG_MGR} install -y "${pkg}" >/dev/null 2>&1
      ;;
    zypper)
      ${SUDO} zypper --non-interactive install "${pkg}" >/dev/null 2>&1
      ;;
    *)
      warn "Package manager ${PKG_MGR} no soportado para instalar ${pkg}."
      return 1
      ;;
  esac
}

# ---------- Helper: write section ----------
write_phase_header() {
  local phase="$1"; local desc="$2"
  cat > "${OUT_DIR}/${phase}.md" <<EOF
# ${phase} — ${desc}

Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Host: ${HOST_NOMBRE}
Cliente: ${CLIENTE}

EOF
}

# ============================================================================
# FASE 1 — Inventario y postura general
# ============================================================================
section "FASE 1 — Inventario y postura general"
write_phase_header "fase-01-inventario" "Inventario y postura general"

OUT01="${OUT_DIR}/postura-general"
{
  echo "## Task 1.1 — Identidad y kernel"; echo
  echo '```bash'
  echo "$ hostnamectl"; hostnamectl 2>/dev/null || true
  echo "$ cat /etc/os-release"; cat /etc/os-release
  echo "$ uname -a"; uname -a
  echo "$ uptime"; uptime
  echo "$ who"; who
  echo "$ last -n 20"; last -n 20 2>/dev/null || true
  echo '```'
} > "${OUT01}/identidad-kernel.md"

{
  echo "## Task 1.2 — Hardware, particiones, discos"; echo
  echo '```bash'
  echo "$ lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null || true
  echo "$ df -hT"; df -hT
  echo "$ cat /etc/fstab"; cat /etc/fstab 2>/dev/null || true
  echo "$ swapon --show"; swapon --show 2>/dev/null || true
  echo "$ free -h"; free -h
  echo "$ nproc"; nproc
  echo "$ lscpu | head -20"; lscpu 2>/dev/null | head -20 || true
  echo "$ dmidecode -s system-manufacturer"; dmidecode -s system-manufacturer 2>/dev/null || true
  echo "$ systemd-detect-virt"; systemd-detect-virt 2>/dev/null || true
  echo '```'
} > "${OUT01}/hardware.md"

{
  echo "## Task 1.3 — Paquetes instalados (resumen)"; echo
  echo '```bash'
  echo "$ dpkg -l | wc -l   # total paquetes"
  dpkg -l 2>/dev/null | wc -l
  echo
  echo "$ Paquetes de seguridad relevantes:"
  case "${PKG_MGR}" in
    apt)
      dpkg -l 2>/dev/null | grep -iE 'openssh|sudo|ufw|nftables|audit|unattended|chrony|ntp|rsyslog|fail2ban|wazuh|zabbix|lynis|apticron|debsums' || echo "(ninguno listado)"
      ;;
    dnf)
      rpm -qa 2>/dev/null | grep -iE 'openssh|sudo|firewalld|nftables|audit|chrony|rsyslog|fail2ban|wazuh|zabbix|lynis' || echo "(ninguno listado)"
      ;;
  esac
  echo '```'
} > "${OUT01}/paquetes.md"

{
  echo "## Task 1.4 — Usuarios y grupos (sin hashes)"; echo
  echo '```bash'
  echo "$ Usuarios con UID >= 1000 y < 65534 (cuenta):"
  getent passwd 2>/dev/null | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | wc -l
  echo
  echo "$ Cuentas con password vacío en /etc/shadow (debe ser 0):"
  awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || echo "(no se pudo leer)"
  echo
  echo "$ root status (login shell):"
  awk -F: '($1 == "root") {print $1": login="$7" shell="$NF}' /etc/passwd
  echo
  echo "$ /home:"
  ls -la /home/ 2>/dev/null || true
  echo
  echo "$ /etc/passwd con login shell válidos (no nologin/false):"
  awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ && $3 >= 1000 && $3 < 65534 {print $1":"$7}' /etc/passwd 2>/dev/null
  echo '```'
} > "${OUT_DIR}/acceso-autenticacion/usuarios-grupos.md"

# ---------- Task 1.0 baseline comparison ----------
cat > "${OUT_DIR}/postura-general/baseline-comparison.md" <<EOF
## Task 1.0 — Comparación contra baseline Freddy

| Componente | Esperado | Actual | Estado |
|---|---|---|---|
| fail2ban | instalado, active+enabled | $(command -v fail2ban-client >/dev/null 2>&1 && systemctl is-enabled fail2ban 2>/dev/null || echo no-inst) | $(command -v fail2ban-client >/dev/null 2>&1 && (systemctl is-enabled fail2ban 2>/dev/null | grep -q enabled && echo OK || echo NO) || echo FAIL) |
| unattended-upgrades | instalado, active | $(command -v unattended-upgrade >/dev/null 2>&1 && echo OK || echo NO) | $(command -v unattended-upgrade >/dev/null 2>&1 && (systemctl is-active unattended-upgrades 2>/dev/null | grep -q active && echo OK || echo NO) || echo FAIL) |
| auditd | instalado, active+enabled | $(command -v auditctl >/dev/null 2>&1 && echo OK || echo NO) | $(command -v auditctl >/dev/null 2>&1 && (systemctl is-enabled auditd 2>/dev/null | grep -q enabled && echo OK || echo NO) || echo FAIL) |
| chrony/timesyncd | instalado, active | $(command -v chronyc >/dev/null 2>&1 && echo chrony || (systemctl is-active systemd-timesyncd 2>/dev/null | grep -q active && echo timesyncd || echo NO)) | N/A |
| rsyslog | instalado, active | $(command -v rsyslogd >/dev/null 2>&1 && echo OK || echo NO) | $(command -v rsyslogd >/dev/null 2>&1 && (systemctl is-active rsyslog 2>/dev/null | grep -q active && echo OK || echo NO) || echo FAIL) |
| lynis | instalado (recomendado) | $(command -v lynis >/dev/null 2>&1 && echo OK || echo NO) | N/A |
EOF

ok "Fase 1 completa."

# ============================================================================
# FASE 2 — Acceso y autenticación
# ============================================================================
section "FASE 2 — Acceso y autenticación"
OUT02="${OUT_DIR}/acceso-autenticacion"
SNAP="${OUT_DIR}/snapshots-config"
mkdir -p "${SNAP}"

# Snapshot configs
for src in /etc/ssh/sshd_config /etc/sudoers /etc/security/pwquality.conf; do
  if [ -e "$src" ]; then
    cp -a "$src" "${SNAP}/$(basename "$src").snapshot" 2>/dev/null || true
  fi
done
[ -d /etc/ssh/sshd_config.d ] && cp -ra /etc/ssh/sshd_config.d "${SNAP}/" 2>/dev/null || true
[ -d /etc/sudoers.d ] && cp -ra /etc/sudoers.d "${SNAP}/" 2>/dev/null || true
[ -d /etc/pam.d ] && cp -ra /etc/pam.d "${SNAP}/" 2>/dev/null || true

# SHA256
( cd "${SNAP}" && find . -type f -exec sha256sum {} \; ) > "${OUT_DIR}/logs/snapshots.sha256" 2>/dev/null || true

{
  echo "## Task 2.1 — Snapshot de configs (golden files)"; echo
  echo "Snapshots en: \`${SNAP}\`"
  echo
  echo '```bash'
  echo "$ sha256sum snapshots/ (extracto)"
  cat "${OUT_DIR}/logs/snapshots.sha256" 2>/dev/null | head -30
  echo '```'
} > "${OUT02}/snapshots-configs.md"

{
  echo "## Task 2.2 — sshd effective config"; echo
  echo '```bash'
  echo "$ sudo sshd -T | grep -iE ..."
  sshd -T 2>/dev/null | grep -iE '^(port|addressfamily|listenaddress|permittrootlogin|passwordauthentication|permitemptypasswords|kbdinteractiveauthentication|x11forwarding|clientaliveinterval|clientalivecountmax|logingracetime|allowusers|allowgroups|denyusers|denygroups|maxauthtries|maxsessions|banner|authenticationmethods)' || echo "(sshd no disponible)"
  echo '```'
} > "${OUT02}/sshd-effective.md"

{
  echo "## Task 2.3 — sshd crypto (ciphers/macs/kex/hostkeys)"; echo
  echo '```bash'
  sshd -T 2>/dev/null | grep -iE '^(ciphers|macs|kexalgorithms|hostkeyalgorithms) ' || echo "(no disponible)"
  echo '```'
} > "${OUT02}/sshd-crypto.md"

{
  echo "## Task 2.4 — sudoers"; echo
  echo '```bash'
  echo "$ /etc/sudoers"; cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' || echo "(vacío)"
  echo
  echo "$ ls /etc/sudoers.d/"; ls -la /etc/sudoers.d/ 2>/dev/null
  echo
  echo "$ contenido /etc/sudoers.d/*"
  for f in /etc/sudoers.d/*; do
    [ -e "$f" ] || continue
    echo "--- $f ---"
    cat "$f" 2>/dev/null
    echo
  done
  echo '```'
} > "${OUT02}/sudoers.md"

{
  echo "## Task 2.5 — PAM password policy"; echo
  echo '```bash'
  echo "$ pwquality.conf"; cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$' || echo "(no existe)"
  echo
  echo "$ pam_pwquality / pam_faillock / pam_unix:"
  grep -rE 'pam_pwquality|pam_faillock|pam_unix' /etc/pam.d/ 2>/dev/null
  echo '```'
} > "${OUT02}/pam-policy.md"

ok "Fase 2 completa."

# ============================================================================
# FASE 3 — Red y firewall
# ============================================================================
section "FASE 3 — Red y firewall"
OUT03="${OUT_DIR}/red-firewall"

{
  echo "## Task 3.1 — Listeners (excluyendo Docker)"; echo
  echo '```bash'
  echo "$ ss -tlnp"; ss -tlnp 2>/dev/null | grep -v 'docker\|containerd' || ss -tlnp
  echo
  echo "$ ss -ulnp"; ss -ulnp 2>/dev/null | grep -v 'docker\|containerd' || ss -ulnp
  echo '```'
} > "${OUT03}/listeners.md"

{
  echo "## Task 3.2 — Firewall activo"; echo
  echo '```bash'
  echo "$ ufw status verbose"; ufw status verbose 2>&1
  echo
  echo "$ ufw status numbered"; ufw status numbered 2>&1
  echo
  echo "$ iptables -S"; iptables -S 2>&1 | head -80
  echo
  echo "$ iptables -L -n"; iptables -L -n 2>&1 | head -80
  echo
  echo "$ nft list ruleset (si aplica)"; nft list ruleset 2>&1 | head -80
  echo '```'
} > "${OUT03}/firewall.md"

{
  echo "## Task 3.3 — Sysctl de red (CIS 3.x)"; echo
  echo '```bash'
  sysctl -a 2>/dev/null | grep -E '^(net.ipv4.ip_forward|net.ipv4.conf.all.rp_filter|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.secure_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.log_martians|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.icmp_ignore_bogus_error_responses|net.ipv4.tcp_syncookies|net.ipv6.conf.all.accept_source_route|net.ipv6.conf.all.accept_redirects|net.ipv6.conf.all.accept_ra)'
  echo '```'
} > "${OUT03}/sysctl-red.md"

{
  echo "## Task 3.4 — DNS resolver"; echo
  echo '```bash'
  echo "$ /etc/resolv.conf (con meta)"; ls -la /etc/resolv.conf; cat /etc/resolv.conf 2>/dev/null
  echo
  echo "$ systemd-resolved status"; systemctl is-active systemd-resolved 2>&1 || true
  if systemctl is-active systemd-resolved >/dev/null 2>&1; then
    echo "$ resolvectl status"; resolvectl status 2>&1 | head -40 || true
  fi
  echo '```'
} > "${OUT03}/dns.md"

{
  echo "## Task 3.b — Netplan / interfaces"; echo
  echo '```bash'
  if [ -d /etc/netplan ]; then
    ls -la /etc/netplan/
    for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do
      [ -e "$f" ] || continue
      echo "--- $f ---"
      cat "$f"
      echo
    done
  fi
  echo
  echo "$ ip addr"; ip addr 2>/dev/null
  echo
  echo "$ ip route"; ip route 2>/dev/null
  echo '```'
} > "${OUT03}/netplan.md"

ok "Fase 3 completa."

# ============================================================================
# FASE 4 — Logs, monitoreo y tiempo
# ============================================================================
section "FASE 4 — Logs, monitoreo y tiempo"
OUT04="${OUT_DIR}/logs-monitoreo"

{
  echo "## Task 4.1 — journald / rsyslog"; echo
  echo '```bash'
  echo "$ rsyslog:"; systemctl is-active rsyslog 2>&1
  echo "$ journald:"; systemctl is-active systemd-journald 2>&1
  echo
  echo "$ rsyslog.conf (no-comentado):"; cat /etc/rsyslog.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30
  echo
  echo "$ /var/log:"; ls -la /var/log/ 2>/dev/null
  echo
  echo "$ journald disk-usage"; journalctl --disk-usage 2>&1 || true
  echo
  echo "$ journald.conf"; cat /etc/systemd/journald.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20
  echo '```'
} > "${OUT04}/journald-rsyslog.md"

{
  echo "## Task 4.2 — auditd (CIS 4.1.x)"; echo
  echo '```bash'
  echo "$ systemctl status auditd:"; systemctl is-active auditd 2>&1
  echo
  echo "$ /etc/audit/auditd.conf:"
  cat /etc/audit/auditd.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20
  echo
  echo "$ /etc/audit/rules.d/*.rules:"
  for f in /etc/audit/rules.d/*.rules; do
    [ -e "$f" ] || continue
    echo "--- $f ---"
    cat "$f" 2>/dev/null
    echo
  done
  echo
  echo "$ auditctl -l (live rules):"
  auditctl -l 2>&1 | head -50
  echo '```'
} > "${OUT04}/auditd.md"

{
  echo "## Task 4.3 — NTP / chrony (CIS 2.x)"; echo
  echo '```bash'
  echo "$ chrony:"; systemctl is-active chrony 2>&1 || true
  echo "$ systemd-timesyncd:"; systemctl is-active systemd-timesyncd 2>&1 || true
  echo
  if [ -e /etc/chrony/chrony.conf ]; then
    echo "$ chrony.conf:"; cat /etc/chrony/chrony.conf 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20
  fi
  echo
  echo "$ timedatectl status:"; timedatectl status 2>&1
  echo '```'
} > "${OUT04}/ntp.md"

{
  echo "## Task 4.4 — Monitoreo (Zabbix / Wazuh)"; echo
  echo '```bash'
  echo "$ zabbix-agent2:"; systemctl is-active zabbix-agent2 2>&1 || true
  echo "$ wazuh-agentd:"; systemctl is-active wazuh-agentd 2>&1 || true
  echo
  echo "$ /etc/zabbix/zabbix_agent2.d/"; ls -la /etc/zabbix/zabbix_agent2.d/ 2>&1
  echo
  echo "$ /var/ossec/etc/ossec.conf (head):"; head -30 /var/ossec/etc/ossec.conf 2>/dev/null || echo "(no presente)"
  echo '```'
} > "${OUT04}/monitoreo.md"

ok "Fase 4 completa."

# ============================================================================
# FASE 5 — Actualizaciones y paquetes
# ============================================================================
section "FASE 5 — Actualizaciones y paquetes"
OUT05="${OUT_DIR}/actualizaciones"

{
  echo "## Task 5.1 — unattended-upgrades / dnf-automatic"; echo
  echo '```bash'
  case "${PKG_MGR}" in
    apt)
      echo "$ systemctl is-active unattended-upgrades:"; systemctl is-active unattended-upgrades 2>&1
      echo
      echo "$ /etc/apt/apt.conf.d/20auto-upgrades:"; cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
      echo
      echo "$ /etc/apt/apt.conf.d/50unattended-upgrades (no-comentado):"
      cat /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -v '^//' | grep -v '^$' | head -30
      ;;
    dnf)
      echo "$ systemctl is-active dnf-automatic.timer:"; systemctl is-active dnf-automatic.timer 2>&1
      echo
      echo "$ /etc/dnf/automatic.conf:"; cat /etc/dnf/automatic.conf 2>/dev/null | head -30
      ;;
  esac
  echo '```'
} > "${OUT05}/auto-upgrades.md"

{
  echo "## Task 5.2 — Paquetes pendientes y CVEs"; echo
  echo '```bash'
  case "${PKG_MGR}" in
    apt) apt list --upgradable 2>/dev/null | head -50 ;;
    dnf) dnf check-update -q 2>&1 | head -40 ;;
  esac
  echo '```'
} > "${OUT05}/paquetes-pendientes.md"

ok "Fase 5 completa."

# ============================================================================
# FASE 6 — Backups del host
# ============================================================================
section "FASE 6 — Backups del host"
OUT06="${OUT_DIR}/backups"

{
  echo "## Task 6.1 — Inventario de backups"; echo
  echo '```bash'
  echo "$ /etc/crontab"; cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' || true
  echo
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    echo "$ ls $d"
    ls -la "$d" 2>/dev/null || true
    echo
  done
  echo
  echo "$ crontabs por usuario:"
  for user in $(cut -f1 -d: /etc/passwd); do
    cr=$(crontab -u "$user" -l 2>/dev/null)
    [ -n "$cr" ] && { echo "=== $user ==="; echo "$cr"; echo; }
  done
  echo
  echo "$ systemctl list-timers:"
  systemctl list-timers --all 2>&1 | head -30
  echo '```'
} > "${OUT06}/cron-y-timers.md"

{
  echo "## Task 6.2 — Compliance legal"
  echo
  echo "> [!IMPORTANT] Alcance de esta sección"
  echo "> Este script bash **NO** realiza análisis legal. Solo recolecta"
  echo "> **evidencia** para que el operador (o el módulo \`internal/modules/audit/\`"
  echo "> de Security-Manager-NG) la cruze con el marco regulatorio aplicable"
  echo "> al país/jurisdicción donde opera el host y al tipo de data que maneja."
  echo ">"
  echo "> La auditoría bash es **el input**, no el análisis final."
  echo ">"
  echo "> El módulo SM-NG \`audit/\` SÍ debe ser parametrizable por país e"
  echo "> industria (Venezuela: SUNACRIP/CONATEL/Ley Infogobierno; UE: GDPR;"
  echo "> USA: SOX/HIPAA/CCPA; etc.). El script bash no implementa esto hoy."
  echo
  echo "### Compliance Venezuela (default — ajustar si el host está en otra jurisdicción)"
  echo
  echo "- [ ] Política de backup firmada por gerencia."
  echo "- [ ] Procedimiento de notificación a SUNACRIP."
  echo "- [ ] Retención de logs críticos (definir según tipo de data)."
  echo "- [ ] Cadena de custodia ante incidente."
  echo
  echo "### Otros marcos (referencia)"
  echo
  echo "- **UE / EEE**: GDPR, NIS2, ISO 27001 (si aplica por industria)."
  echo "- **USA**: HIPAA (salud), SOX (financiero), CCPA (privacidad)."
  echo "- **LATAM**: Ley 1581/2012 Colombia, LGPD Brasil, etc."
  echo "- **Telecomunicaciones** (Fibex/Conatel): RETIE, reglamentos sectoriales."
  echo
  echo "### Evidencia recolectada por este script (ver otras secciones)"
  echo
  echo "- Logs y monitoreo: \`logs-monitoreo/journald-rsyslog.md\` (Fase 4)"
  echo "- Auditd: \`logs-monitoreo/auditd.md\` (Fase 4)"
  echo "- Configuración de backups: \`backups/cron-y-timers.md\` (Fase 6)"
  echo "- Usuarios y accesos: \`acceso-autenticacion/usuarios-grupos.md\` (Fase 1)"
} > "${OUT06}/compliance-legal.md"

ok "Fase 6 completa."

# ============================================================================
# FASE 7 — Lynis (herramienta de auditoría)
# ============================================================================
section "FASE 7 — Lynis (herramienta de auditoría de seguridad)"

LYNIS_OK=0

if [ "${SKIP_LYNIS}" -eq 1 ]; then
  warn "Saltando Lynis por --skip-lynis."
elif [ "${SIN_INTERNET}" -eq 1 ]; then
  warn "Modo --sin-internet: no instalo Lynis."
else
  if ! command -v lynis >/dev/null 2>&1; then
    warn "Lynis no encontrado. Intentando instalar via ${PKG_MGR}..."
    if try_install lynis; then
      ok "Lynis instalado via gestor de paquetes."
    else
      # GitHub release de Lynis NO publica SHA256SUMS firmado (verificado 2026-08-21
      # via api.github.com/repos/CISOfy/lynis/releases/latest — assets: []).
      # Por política de integridad (no descargar binarios sin verificación), no
      # usamos el tarball. El informe lo marcará como pendiente.
      warn "Lynis no instalable via gestor de paquetes. NO se descarga tarball"
      warn "porque la release oficial no publica checksums (verificado en API)."
      warn "Para resolverse, el operador puede:"
      warn "  1. apt-get install lynis   (si la distro lo provee)"
      warn "  2. Compilar desde fuente: https://github.com/CISOfy/lynis (sin verificación)"
      warn "  3. Deshabilitar Fase 7 con --skip-lynis"
    fi
  fi

  if command -v lynis >/dev/null 2>&1; then
    OUT07="${OUT_DIR}/lynis"
    mkdir -p "${OUT07}"
    log "Ejecutando: lynis audit system --quick --no-colors"
    lynis audit system --quick --no-colors --logfile "${OUT07}/lynis.log" --report-file "${OUT07}/lynis-report.dat" 2>&1 | tee "${OUT07}/lynis-stdout.txt" || warn "Lynis salió con código no-cero (no es error de auditoría)."
    [ -f "${OUT07}/lynis-report.dat" ] && {
      ok "Lynis reporte: ${OUT07}/lynis-report.dat"
      HARDENING_SCORE=$(grep -E "^hardening_index|^Hardening index" "${OUT07}/lynis-report.dat" | head -1)
      log "Hardening score: ${HARDENING_SCORE}"
      LYNIS_OK=1
    }
  else
    warn "Lynis no disponible. Continuando sin Fase 7."
  fi
fi

# Marcar estado Lynis en resumen
echo "Lynis: ${LYNIS_OK}" >> "${OUT_DIR}/logs/lynis.status"

# ============================================================================
# Resumen ejecutivo (auto-generado preliminar)
# ============================================================================
section "Generando resumen ejecutivo preliminar"

_h2b() { command -v "$1" >/dev/null 2>&1 && echo "instalado" || echo "NO instalado"; }
_chrony() { command -v chronyc >/dev/null 2>&1 && echo "chrony-instalado" || (systemctl is-active systemd-timesyncd 2>/dev/null | grep -q active && echo "timesyncd-activo" || echo "NO"); }

cat > "${OUT_DIR}/RESUMEN-EJECUTIVO.md" <<EOF
# Resumen Ejecutivo Preliminar — Auditoría de Host

| Campo | Valor |
|---|---|
| Host | ${HOST_NOMBRE} |
| Cliente | ${CLIENTE} |
| Rol | ${ROL} |
| Distro | ${DISTRO_ID} ${DISTRO_VER} (familia: ${DISTRO_FAMILY}) |
| Fecha UTC | ${FECHA} ${HORA} |
| Out dir | \`${OUT_DIR}\` |
| Tarball | $([ "${MAKE_TAR}" -eq 1 ] && echo "\`${OUT_DIR}.tar.gz\`" || echo "(no generado, usar --no-tar)") |

## Inventario rápido
- fail2ban:           $(_h2b fail2ban-client)
- auditd:             $(_h2b auditctl)
- rsyslog:            $(_h2b rsyslogd)
- chrony/timesyncd:   $(_chrony)
- unattended-upgrades: $(_h2b unattended-upgrade)
- lynis:              $([ "${LYNIS_OK}" -eq 1 ] && echo "INSTALADO+EJECUTADO" || echo "NO EJECUTADO")

## Estado de las fases
| Fase | Archivo | Estado |
|---|---|---|
| 1 — Inventario | \`postura-general/\` | OK |
| 2 — Acceso/auth | \`acceso-autenticacion/\` | OK |
| 3 — Red/firewall | \`red-firewall/\` | OK |
| 4 — Logs/monitoreo | \`logs-monitoreo/\` | OK |
| 5 — Updates | \`actualizaciones/\` | OK |
| 6 — Backups | \`backups/\` | OK |
| 7 — Lynis | \`lynis/\` | $([ "${LYNIS_OK}" -eq 1 ] && echo "OK" || echo "FALTA (no instalado)") |

## Próximos pasos (humano)
1. Bajar el tarball: \`${OUT_DIR}.tar.gz\` desde \`${HOME}/\`.
2. Parsear cada archivo .md por fase.
3. Comparar contra CIS Ubuntu 22.04 Benchmark v2.0.0.
4. Armar tabla de hallazgos P0/P1/P2.
5. Si Lynis falta: el operador debe revisarlo y decidir qué hallazgos cubre solo.
EOF

# ============================================================================
# Empaquetar y finalizar
# ============================================================================
section "Empaquetando"

TAR_PATH=""
if [ "${MAKE_TAR}" -eq 1 ]; then
  cd "${OUT_BASE}"
  tar -czf "${OUT_DIR}.tar.gz" "$(basename "${OUT_DIR}")"
  TAR_PATH="${OUT_DIR}.tar.gz"
  TAR_SIZE=$(du -h "${TAR_PATH}" | awk '{print $1}')
fi

# ---------- Ajuste de permisos al usuario que invocó el script ----------
# Si el script corrió bajo sudo (INVOKER_USER != root), transferimos ownership
# del directorio y del tarball al usuario real para que pueda scp/editar sin
# escalación adicional. Esto cubre los casos:
#   - sudo bash script.sh           -> INVOKER_USER = usuario original
#   - sudo -u otro bash script.sh   -> INVOKER_USER = "otro"
#   - bash script.sh (como root)    -> INVOKER_USER = root, no se cambia
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  log "Ajustando ownership a ${INVOKER_USER}:${INVOKER_USER} para SCP sin escalación."
  if chown -R "${INVOKER_USER}:${INVOKER_USER}" "${OUT_DIR}" 2>/dev/null; then
    [ -n "${TAR_PATH}" ] && chown "${INVOKER_USER}:${INVOKER_USER}" "${TAR_PATH}" 2>/dev/null || true
    ok "Ownership aplicado a ${OUT_DIR}"
  else
    warn "No se pudo aplicar chown a ${OUT_DIR} (¿filesystem readonly?). El reporte queda como root:root."
  fi
fi

ok "Listo."
if [ -n "${TAR_PATH}" ]; then
  ok "📦 Reporte empaquetado en: ${TAR_PATH} (${TAR_SIZE})"
fi
ok "📁 Carpeta cruda: ${OUT_DIR}"
if [ -n "${TAR_PATH}" ]; then
  warn "Bajá con: scp ${INVOKER_USER}@${HOST_NOMBRE}:${TAR_PATH} /tmp/"
else
  warn "Bajá con: scp -r ${INVOKER_USER}@${HOST_NOMBRE}:${OUT_DIR}/ /tmp/"
fi

exit 0
