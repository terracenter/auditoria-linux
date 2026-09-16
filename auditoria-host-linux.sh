#!/usr/bin/env bash
# ============================================================================
# auditoria-host-linux.sh — Auditoría de Host Linux
# ============================================================================
# Auditoría operativa multidistribución para hosts Linux: postura, red,
# firewall, accesos, logs, paquetes, backups y controles básicos de seguridad.
#
# Fases:
#   0 — Checklist operacional (10 validaciones críticas, aborta si no hay firewall)
#   1 — Inventario y postura general
#   2 — Acceso y autenticación (sshd, sudoers, PAM)
#   3 — Red y firewall (ufw/nft/iptables, sysctl, DNS)
#   4 — Logs, monitoreo y tiempo
#   5 — Actualizaciones y paquetes
#   6 — Backups del host
#   7 — Lynis (herramienta externa)
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
#   --keep-tree                 Después de empaquetar, conserva la carpeta cruda.
#                               (default: la carpeta cruda se borra para no dejar basura).
#   --no-cleanup                No limpia corridas anteriores con permisos root:root.
#                               (default: las limpia al inicio).
#   --send                      Al final envía el reporte por scp/rsync.
#   --send-method <scp|rsync>   Método de envío (default: scp).
#   --send-target <user@host:/path>  Destino remoto no interactivo.
#                               Si se pasa user@host sin ruta, usa /tmp/<archivo>.
#   --no-send                   No pregunta ni envía reporte al final.
#   -y, --yes                   No pregunta nada interactivo, usa defaults.
#
# Comportamiento:
#   - Read-only NUNCA modifica el sistema excepto instalar lynis si se puede.
#   - Genera árbol de archivos en el dir de salida (default $HOME del usuario).
#   - Por defecto comprime en .tar.gz al final para SCP/SFTP.
#   - Por defecto BORRA la carpeta cruda después de empaquetar (no deja basura).
#   - Al inicio, limpia corridas anteriores que quedaron con permisos root:root.
# ============================================================================

set -u
set -o pipefail

# ---------- Defaults ----------
SCRIPT_NAME="auditoria-host-linux.sh"
SCRIPT_VERSION="2026.09.16-5"
CLIENTE="propio"
ROL="other"
HOST_NOMBRE="$(hostname 2>/dev/null || echo unknown)"
FECHA="$(date -u +%Y-%m-%d)"
HORA="$(date -u +%H%M%SZ)"
SKIP_LYNIS=0
NO_INSTALL=0
SIN_INTERNET=0
MAKE_TAR=1
KEEP_TREE=0
ASSUME_YES=0
NO_CLEANUP=0
SEND_REPORT="ask"
SEND_METHOD="scp"
SEND_TARGET=""
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
  cat <<EOF
================
${SCRIPT_NAME} — Auditoría de Host Linux
Versión: ${SCRIPT_VERSION}
================
Auditoría operativa multidistribución para hosts Linux: postura, red,
firewall, accesos, logs, paquetes, backups y controles básicos de seguridad.

Fases:
0 — Checklist operacional (10 validaciones críticas, aborta si no hay firewall)
1 — Inventario y postura general
2 — Acceso y autenticación (sshd, sudoers, PAM)
3 — Red y firewall (ufw/nft/iptables, sysctl, DNS)
4 — Logs, monitoreo y tiempo
5 — Actualizaciones y paquetes
6 — Backups del host
7 — Lynis (herramienta externa, si está disponible o se puede instalar)

Uso:
sudo ./auditoria-host-linux.sh [OPCIONES]

Opciones:
-h, --help                         Muestra esta ayuda.
--version                          Muestra la versión del script.
-o, --output-dir <path>            Dir de salida. Si no se pasa, pregunta al usuario.
                                   Si corre con sudo, default es \$HOME del usuario
                                   que invoca (no /root).
-c, --cliente <name>               Nombre del cliente (metadata, default: propio).
-r, --rol <rol>                    Rol del host (web, db, mail, firewall, etc.).
--skip-lynis                       No instala/ejecuta Lynis.
--no-install                       No intenta instalar paquetes faltantes.
--sin-internet                     Asume sin internet; aborta si falta herramienta.
--no-tar                           No comprime al final (solo deja la carpeta).
--tar                              Comprime al final (default).
--keep-tree                        Después de empaquetar, conserva la carpeta cruda.
--no-cleanup                       No limpia corridas anteriores con permisos root:root.
--send                             Al final envía el reporte por scp/rsync.
--send-method <scp|rsync>          Método de envío (default: scp).
--send-target <user@host:/path>    Destino remoto no interactivo.
                                   Si se pasa user@host sin ruta, usa /tmp/<archivo>.
--no-send                          No pregunta ni envía reporte al final.
-y, --yes                          No pregunta nada interactivo, usa defaults.
EOF
  exit 0
}

# ---------- Parse args ----------
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage ;;
    --version) printf '%s\n' "${SCRIPT_VERSION}"; exit 0 ;;
    -o|--output-dir) OUT_DIR="$2"; shift 2 ;;
    -c|--cliente) CLIENTE="$2"; shift 2 ;;
    -r|--rol) ROL="$2"; shift 2 ;;
    --skip-lynis) SKIP_LYNIS=1; shift ;;
    --no-install) NO_INSTALL=1; shift ;;
    --sin-internet) SIN_INTERNET=1; NO_INSTALL=1; shift ;;
    --no-tar) MAKE_TAR=0; shift ;;
    --tar) MAKE_TAR=1; shift ;;
    --keep-tree) KEEP_TREE=1; shift ;;
    --no-cleanup) NO_CLEANUP=1; shift ;;
    --send) SEND_REPORT="yes"; shift ;;
    --send-method) SEND_METHOD="$2"; shift 2 ;;
    --send-target) SEND_TARGET="$2"; SEND_REPORT="yes"; shift 2 ;;
    --no-send) SEND_REPORT="no"; shift ;;
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

# ---------- Limpieza preventiva de corridas anteriores con root:root ----------
# Bug histórico (versiones < d99634d): las carpetas quedaban como root:root
# cuando el script corría bajo sudo. Esto bloqueaba al operador para hacer scp
# sin escalar. Al inicio, si hay carpetas de auditorías previas del MISMO host
# con owner root y NO son la corrida actual, las limpiamos para no acumular
# basura que el usuario no puede inspeccionar.
if [ "${NO_CLEANUP}" -eq 0 ] && [ -n "${INVOKER_USER}" ] && [ "${INVOKER_USER}" != "root" ]; then
  HOST_PREFIX="${HOST_NOMBRE}"
  HOME_BASE="${INVOKER_HOME}"
  if [ -d "${HOME_BASE}" ]; then
    # Buscar carpetas que coincidan con el patrón auditoria-<HOST>-*,
    # excluyendo la corrida actual, que sean del usuario actual (suyas), o
    # que estén como root:root (basura histórica del bug).
    found_stale=0
    while IFS= read -r -d '' stale_dir; do
      [ -z "${stale_dir}" ] && continue
      [ "${stale_dir}" = "${OUT_DIR}" ] && continue
      owner="$(stat -c '%U' "${stale_dir}" 2>/dev/null)"
      if [ "${owner}" = "root" ]; then
        if [ -t 1 ] && [ "${ASSUME_YES}" -eq 0 ]; then
          printf "¿Borrar carpeta histórica con permisos root:root? [y/N] %s: " "${stale_dir}"
          read -r REPLY </dev/tty 2>/dev/null || REPLY="n"
        else
          REPLY="y"
        fi
        case "${REPLY}" in
          y|Y|yes|YES)
            if rm -rf "${stale_dir}" 2>/dev/null; then
              ok "Limpiada: ${stale_dir}"
              found_stale=$((found_stale + 1))
            else
              warn "No se pudo borrar ${stale_dir}."
            fi
            ;;
          *)
            warn "Conservando: ${stale_dir}"
            ;;
        esac
      fi
    done < <(find "${HOME_BASE}" -maxdepth 1 -type d -name "auditoria-${HOST_PREFIX}-*" -print0 2>/dev/null)
    [ "${found_stale}" -gt 0 ] && ok "Limpieza preventiva completada (${found_stale} carpeta(s))."
  fi
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

update_installed_package() {
  local pkg="$1"
  if [ "${NO_INSTALL}" -eq 1 ] || [ "${SIN_INTERNET}" -eq 1 ]; then
    warn "No se valida actualización de ${pkg} (--no-install o --sin-internet)."
    return 1
  fi

  case "${PKG_MGR}" in
    apt)
      DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get update -y >/dev/null 2>&1 || return 1
      DEBIAN_FRONTEND=noninteractive ${SUDO} apt-get install --only-upgrade -y "${pkg}" >/dev/null 2>&1 || return 1
      ;;
    dnf|yum)
      ${SUDO} ${PKG_MGR} upgrade -y "${pkg}" >/dev/null 2>&1 || return 1
      ;;
    zypper)
      ${SUDO} zypper --non-interactive update "${pkg}" >/dev/null 2>&1 || return 1
      ;;
    *)
      warn "Package manager ${PKG_MGR} no soportado para actualizar ${pkg}."
      return 1
      ;;
  esac
}

lynis_version() {
  if command -v lynis >/dev/null 2>&1; then
    lynis show version 2>/dev/null | head -1 || lynis --version 2>/dev/null | head -1 || true
  fi
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
# FASE 0 — Checklist operacional (10 validaciones críticas)
# ============================================================================
# Esta fase corre ANTES de las 7 fases de auditoría. Valida que el host
# cumple con el estándar mínimo de seguridad definido en:
#   Obsidian/03_Manuales_Borradores/Seguridad/Manual/
#   (Firewall, Whitelist, GeoIP, Fail2ban, SSH Hardening, Anti-Recon,
#    Hardening Root, Verificación Integral)
#
# Política:
#   - Sin firewall (cualquiera)         → ABORTAR (exit 3)
#   - Backend iptables-legacy           → WARN urgente (nftables es lo correcto)
#   - BLOQUE 2 anti-recon ausente        → WARN URGENTE
#   - Fail2ban ausente                   → WARN URGENTE
#   - infra-whitelist vacío              → WARN URGENTE
#   - GeoIP allowlist vacío              → WARN URGENTE
#   - Zabbix agent ausente               → WARN URGENTE
#   - Bare metal vs VPS                  → INFO
#   - Registro GLPI                      → INFO (placeholder, el operador
#                                                 documenta manualmente)
#   - Docker + iptables-legacy           → INFO (problema conocido, ver
#                                                 Obsidian/Planes/_templates/
#                                                 auditoria-host-linux.md §9)

section "FASE 0 — Checklist operacional (10 validaciones críticas)"
write_phase_header "fase-00-checklist" "Checklist operacional de seguridad"

CHECKLIST_TXT="${OUT_DIR}/fase-00-checklist-operacional.md"
CHECKLIST_RESULT="${OUT_DIR}/fase-00-checklist-resultados.md"

# Inicializar archivo de resultados
# Separador interno: \t (TAB) para evitar ambigüedad con pipes dentro de
# la descripción del hallazgo.
CHECKLIST_SUMMARY="check_id\testado\tcategoria\tdescripcion\n"
declare -A CHECKLIST_STATUS

# Helper para registrar resultado
chk() {
  local id="$1"; local estado="$2"; local cat="$3"; local desc="$4"
  CHECKLIST_STATUS["$id"]="$estado"
  CHECKLIST_SUMMARY+="${id}\t${estado}\t${cat}\t${desc}\n"
}

# ---- Check #1: Bare metal vs VPS (INFO) ----
# Capturar via archivo temporal para evitar que la asignación se imprima
# al log (exec > >(tee...) redirige TODO).
TMPDIR_CHECK="${OUT_DIR}/logs"
VIRT_FILE="${TMPDIR_CHECK}/virt.detect"
{ systemd-detect-virt 2>/dev/null || echo unknown; } > "${VIRT_FILE}"
VIRT="$(head -1 "${VIRT_FILE}" | tr -d '[:space:]')"
[ -z "${VIRT}" ] && VIRT="unknown"
{
  echo "## Check #1 — Bare metal vs VPS"; echo
  echo "\`\`\`bash"
  echo "\$ systemd-detect-virt"; systemd-detect-virt 2>&1 || true
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
case "${VIRT}" in
  none)
    chk "C1-BAREMETAL" "OK" "INFO" "Host bare-metal (systemd-detect-virt=none)"
    ;;
  kvm|qemu|vmware|xen|microsoft|oracle|amazon)
    chk "C1-BAREMETAL" "WARN" "INFO" "Host es VM (systemd-detect-virt=${VIRT})"
    ;;
  *)
    chk "C1-BAREMETAL" "WARN" "INFO" "Tipo de virtualización desconocido (systemd-detect-virt='${VIRT}')"
    ;;
esac

# ---- Check #2: Firewall activo (CRÍTICO - aborta si falta) ----
FW_PRESENTE=0
FW_BACKEND="ninguno"
{
  echo "## Check #2 — Firewall activo"; echo
  echo "\`\`\`bash"
  if command -v ufw >/dev/null 2>&1; then
    echo "\$ ufw status verbose"; ufw status verbose 2>&1
    if ufw status 2>&1 | grep -q "Status: active"; then
      FW_PRESENTE=1
      FW_BACKEND="ufw"
    fi
  fi
  if [ "${FW_PRESENTE}" -eq 0 ] && command -v nft >/dev/null 2>&1; then
    echo "\$ nft list ruleset | head -10"; nft list ruleset 2>&1 | head -10
    if nft list ruleset 2>/dev/null | grep -q "table inet"; then
      FW_PRESENTE=1
      FW_BACKEND="nftables"
    fi
  fi
  if [ "${FW_PRESENTE}" -eq 0 ]; then
    echo "\$ iptables -S | head -10"; iptables -S 2>&1 | head -10
    if iptables -S 2>/dev/null | grep -qE '^-A|-P'; then
      FW_PRESENTE=1
      FW_BACKEND="iptables"
    fi
  fi
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${FW_PRESENTE}" -eq 1 ]; then
  chk "C2-FIREWALL" "OK" "CRITICO" "Firewall activo (backend=${FW_BACKEND})"
else
  chk "C2-FIREWALL" "FATAL" "CRITICO" "Sin firewall — URGENTE instalar antes de continuar"
  cat >> "${CHECKLIST_RESULT}" <<EOF
| C2-FIREWALL | **FATAL** | CRITICO | Sin firewall — instalar UFW/nftables antes de continuar |

> **El script ABORTÓ en Check #2. El host NO tiene firewall activo (ni UFW, ni nftables,
> ni iptables con reglas).** Esto es crítico — sin firewall el host está completamente
> expuesto a internet. Instalar \`ufw\` (\`apt install ufw\`) o configurar nftables y volver
> a ejecutar la auditoría. Referencia: Manual 01.Firewall.md en
> \`Obsidian/03_Manuales_Borradores/Seguridad/Manual/\`.
EOF
  err "ABORTANDO — sin firewall activo. Instalar UFW antes de continuar."
  exit 3
fi

# ---- Check #3: Backend del firewall (nft vs legacy iptables) ----
FW_NFTABLES=0
lsmod_output="$(lsmod 2>/dev/null | grep -E '^nf_tables|^ip_tables|^iptable_nat|^iptable_filter' || true)"
{
  echo "## Check #3 — Backend del firewall (nftables vs iptables-legacy)"; echo
  echo "\`\`\`bash"
  echo "\$ lsmod | grep -E 'nf_tables|ip_tables|iptable_'"; echo "${lsmod_output}"
  echo "\$ ls -la /sbin/iptables /sbin/ip6tables /sbin/arptables /sbin/ebtables 2>/dev/null"
  ls -la /sbin/iptables /sbin/ip6tables /sbin/arptables /sbin/ebtables 2>/dev/null || true
  echo "\$ update-alternatives --display iptables 2>&1 | head"
  update-alternatives --display iptables 2>&1 | head -10 || true
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if echo "${lsmod_output}" | grep -q "^nf_tables "; then
  FW_NFTABLES=1
fi
if [ "${FW_NFTABLES}" -eq 1 ]; then
  chk "C3-FWBACKEND" "OK" "WARN" "Firewall usa backend nftables (correcto)"
else
  chk "C3-FWBACKEND" "WARN" "WARN" "Firewall parece usar iptables-legacy (no nftables). Migrar a nftables si es posible"
fi

# ---- Check #4: BLOQUE 2 anti-reconocimiento aplicado (URGENTE) ----
# Importante: como el script corre bajo exec > >(tee ...) que redirige TODO
# al log, ANTIRECON_COUNT debe asignarse desde un archivo temporal para que
# el output del grep -c no se imprima DOS veces (una por la asignación y
# otra por el echo posterior).
TMPDIR_CHECK="${OUT_DIR}/logs"
ANTIRECON_FILE="${TMPDIR_CHECK}/antirecon.count"
{ grep -c "ANTIRECON" /etc/ufw/before.rules 2>/dev/null || echo 0; } > "${ANTIRECON_FILE}"
ANTIRECON_COUNT="$(cat "${ANTIRECON_FILE}" | tr -d '[:space:]')"
[ -z "${ANTIRECON_COUNT}" ] && ANTIRECON_COUNT=0
{
  echo "## Check #4 — BLOQUE 2 anti-reconocimiento"; echo
  echo "\`\`\`bash"
  echo "\$ grep -c ANTIRECON /etc/ufw/before.rules"
  echo "${ANTIRECON_COUNT}"
  echo "\$ grep -A1 'ANTIRECON' /etc/ufw/before.rules 2>/dev/null | head -16"
  grep -A1 "ANTIRECON" /etc/ufw/before.rules 2>/dev/null | head -16 || true
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${ANTIRECON_COUNT}" -ge 8 ]; then
  chk "C4-ANTIRECON" "OK" "URGENTE" "BLOQUE 2 anti-recon aplicado (${ANTIRECON_COUNT} reglas)"
else
  chk "C4-ANTIRECON" "WARN" "URGENTE" "BLOQUE 2 anti-recon AUSENTE (${ANTIRECON_COUNT} reglas encontradas, esperado ≥8). Aplicar Manual 01.Firewall.md §BLOQUE 2"
fi

# ---- Check #5: fail2ban instalado (URGENTE) ----
F2B_INSTALLED=0
F2B_ACTIVE=0
if command -v fail2ban-client >/dev/null 2>&1; then
  F2B_INSTALLED=1
  if systemctl is-active fail2ban 2>/dev/null | grep -q active; then
    F2B_ACTIVE=1
  fi
fi
{
  echo "## Check #5 — Fail2ban instalado y activo"; echo
  echo "\`\`\`bash"
  echo "\$ command -v fail2ban-client"
  command -v fail2ban-client 2>&1 || echo "(no instalado)"
  echo "\$ systemctl is-active fail2ban"
  systemctl is-active fail2ban 2>&1 || true
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${F2B_INSTALLED}" -eq 1 ] && [ "${F2B_ACTIVE}" -eq 1 ]; then
  chk "C5-FAIL2BAN" "OK" "URGENTE" "fail2ban instalado y activo"
elif [ "${F2B_INSTALLED}" -eq 1 ]; then
  chk "C5-FAIL2BAN" "WARN" "URGENTE" "fail2ban instalado pero INACTIVO. Activar con 'systemctl enable --now fail2ban'"
else
  chk "C5-FAIL2BAN" "WARN" "URGENTE" "fail2ban NO instalado. Aplicar Manual 04.Fail2ban.md (apt install fail2ban)"
fi

# ---- Check #6: Whitelist corporativa infra-whitelist con contenido (URGENTE) ----
INFRA_WL_COUNT=0
INFRA_WL_CONTENT=""
if command -v ipset >/dev/null 2>&1; then
  INFRA_WL_CONTENT="$(ipset list infra-whitelist 2>/dev/null | grep -cE '^[0-9]' || true)"
  INFRA_WL_COUNT="${INFRA_WL_CONTENT}"
fi
{
  echo "## Check #6 — Whitelist corporativa infra-whitelist"; echo
  echo "\`\`\`bash"
  echo "\$ ipset list infra-whitelist 2>&1"
  ipset list infra-whitelist 2>&1 | head -30 || true
  echo "\$ wc -l /etc/ipset/infra-whitelist.txt 2>/dev/null"
  wc -l /etc/ipset/infra-whitelist.txt 2>/dev/null || echo "(no existe SSoT)"
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${INFRA_WL_COUNT}" -ge 1 ]; then
  chk "C6-WHITELIST" "OK" "URGENTE" "infra-whitelist con ${INFRA_WL_COUNT} entradas"
else
  chk "C6-WHITELIST" "WARN" "URGENTE" "infra-whitelist VACÍA o inexistente. Agregar IPs de gestión (Manual 02.infra-whitelist.md)"
fi

# ---- Check #7: GeoIP allowlist con contenido (URGENTE) ----
GEOIP_ALLOW_COUNT=0
GEOIP_BLOCK_COUNT=0
if command -v ipset >/dev/null 2>&1; then
  GEOIP_ALLOW_COUNT="$(ipset list geoip-allow 2>/dev/null | grep -cE '^[0-9]' || true)"
  GEOIP_BLOCK_COUNT="$(ipset list geoip-block 2>/dev/null | grep -cE '^[0-9]' || true)"
fi
{
  echo "## Check #7 — GeoIP allowlist / blocklist"; echo
  echo "\`\`\`bash"
  echo "\$ ipset list geoip-allow 2>&1 | head -20"
  ipset list geoip-allow 2>&1 | head -20 || true
  echo
  echo "\$ ipset list geoip-block 2>&1 | head -20"
  ipset list geoip-block 2>&1 | head -20 || true
  echo "\$ /etc/ipset/geoip-allow.countries 2>/dev/null"
  cat /etc/ipset/geoip-allow.countries 2>/dev/null || echo "(no existe SSoT)"
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${GEOIP_ALLOW_COUNT}" -ge 1 ]; then
  chk "C7-GEOIP" "OK" "URGENTE" "GeoIP allowlist con ${GEOIP_ALLOW_COUNT} entradas (blocklist: ${GEOIP_BLOCK_COUNT})"
else
  chk "C7-GEOIP" "WARN" "URGENTE" "GeoIP allowlist VACÍA. Configurar países permitidos (Manual 03.geoip-ipset.md)"
fi

# ---- Check #8: Zabbix agent (URGENTE si ausente) ----
ZABBIX_OK=0
ZABBIX_ACTIVE=0
if command -v zabbix_agent2 >/dev/null 2>&1 || command -v zabbix_agentd >/dev/null 2>&1; then
  ZABBIX_OK=1
  if systemctl is-active zabbix-agent2 2>/dev/null | grep -q active \
     || systemctl is-active zabbix-agent 2>/dev/null | grep -q active; then
    ZABBIX_ACTIVE=1
  fi
fi
{
  echo "## Check #8 — Zabbix agent"; echo
  echo "\`\`\`bash"
  echo "\$ command -v zabbix_agent2 || command -v zabbix_agentd"
  command -v zabbix_agent2 2>&1 || command -v zabbix_agentd 2>&1 || echo "(no instalado)"
  echo "\$ systemctl is-active zabbix-agent2 || systemctl is-active zabbix-agent"
  systemctl is-active zabbix-agent2 2>&1 || systemctl is-active zabbix-agent 2>&1 || true
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${ZABBIX_OK}" -eq 1 ] && [ "${ZABBIX_ACTIVE}" -eq 1 ]; then
  chk "C8-ZABBIX" "OK" "URGENTE" "Zabbix agent instalado y activo"
elif [ "${ZABBIX_OK}" -eq 1 ]; then
  chk "C8-ZABBIX" "WARN" "URGENTE" "Zabbix agent instalado pero INACTIVO"
else
  chk "C8-ZABBIX" "WARN" "URGENTE" "Zabbix agent NO instalado. Instalar y registrar en Zabbix server Fibex"
fi

# ---- Check #9: Registro en GLPI (INFO — placeholder, lo valida el operador) ----
{
  echo "## Check #9 — Registro en GLPI"; echo
  echo
  echo "> **El script NO valida GLPI automáticamente.** El operador debe verificar"
  echo "> manualmente en la consola GLPI de Fibex que este host:"
  echo
  echo "> 1. Esté registrado como 'Computador' en la entidad 'Fibex'."
  echo "> 2. Tenga asociado el cliente 'Fibex Telecom'."
  echo "> 3. Tenga creado un ticket de auditoría (este informe, una vez aprobado)."
  echo
  echo "Path en el vault para registrar: \`Obsidian/02_Servidores/Fibex/\`"
} >> "${CHECKLIST_TXT}"
chk "C9-GLPI" "INFO" "INFO" "Validación manual — el operador verifica registro GLPI"

# ---- Check #10: Docker + iptables-legacy (INFO) ----
DOCKER_PRESENTE=0
if command -v docker >/dev/null 2>&1; then
  DOCKER_PRESENTE=1
fi
{
  echo "## Check #10 — Compatibilidad Docker + nftables"; echo
  echo "\`\`\`bash"
  echo "\$ command -v docker"
  command -v docker 2>&1 || echo "(no docker)"
  if [ "${DOCKER_PRESENTE}" -eq 1 ]; then
    echo "\$ docker version --format '{{.Server.Version}}' 2>/dev/null"
    docker version --format '{{.Server.Version}}' 2>/dev/null || echo "(docker no responde)"
    echo "\$ iptables -V"
    iptables -V 2>&1 || true
  fi
  echo "\`\`\`"
} >> "${CHECKLIST_TXT}"
if [ "${DOCKER_PRESENTE}" -eq 1 ] && [ "${FW_NFTABLES}" -eq 1 ]; then
  chk "C10-DOCKER-NFT" "WARN" "INFO" "Docker + nftables detectado. Problema conocido: Docker trabaja con iptables-legacy por defecto. Verificar iptables-nft compatibility. NOTA: pendiente documentar workaround (urgente para IPTV)."
elif [ "${DOCKER_PRESENTE}" -eq 1 ]; then
  chk "C10-DOCKER-NFT" "INFO" "INFO" "Docker detectado, firewall usa iptables-legacy (compatibilidad OK con Docker por ahora)"
else
  chk "C10-DOCKER-NFT" "OK" "INFO" "Sin Docker — no aplica este check"
fi

# ---- Generar tabla de resultados ----
{
  echo "# Resultados del Checklist Operacional (Fase 0)"
  echo
  echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "| Check | Estado | Categoría | Descripción |"
  echo "|---|---|---|---|"
  printf "%b" "${CHECKLIST_SUMMARY}" | \
    awk -F'\t' 'NF >= 4 {printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}'
} > "${CHECKLIST_RESULT}"

# Mostrar resumen al operador
cat "${CHECKLIST_RESULT}"

# Si hubo algún FATAL ya abortamos arriba. Si hubo WARN URGENTE, marcamos en log.
URGENTES=$(printf "${CHECKLIST_SUMMARY}" | grep -c "^C[0-9]|WARN|URGENTE" || true)
if [ "${URGENTES}" -gt 0 ]; then
  warn "Hay ${URGENTES} checks URGENTES pendientes. Ver resultados en fase-00-checklist-resultados.md"
fi

ok "Fase 0 (checklist operacional) completa."

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

    LYNIS_VERSION_BEFORE="$(lynis_version)"
    log "Lynis instalado: ${LYNIS_VERSION_BEFORE:-version no detectada}. Validando actualización via ${PKG_MGR}."
    if update_installed_package lynis; then
      LYNIS_VERSION_AFTER="$(lynis_version)"
      ok "Lynis validado/actualizado via gestor de paquetes: ${LYNIS_VERSION_AFTER:-version no detectada}"
    else
      LYNIS_VERSION_AFTER="$(lynis_version)"
      warn "No se pudo validar actualización de Lynis via gestor de paquetes. Versión actual: ${LYNIS_VERSION_AFTER:-version no detectada}"
    fi

    {
      echo "lynis_version_before=${LYNIS_VERSION_BEFORE:-unknown}"
      echo "lynis_version_after=${LYNIS_VERSION_AFTER:-unknown}"
      echo "package_manager=${PKG_MGR}"
      echo "updated_checked_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "${OUT07}/lynis-version.txt"

    log "Ejecutando: lynis audit system --quick --no-colors"
    LYNIS_RAW_STDOUT="${OUT07}/lynis-stdout.raw.txt"
    LYNIS_FILTERED_STDOUT="${OUT07}/lynis-stdout.txt"
    LYNIS_FILTERED_WARNINGS="${OUT07}/lynis-filtered-warnings.txt"

    set +o pipefail
    lynis audit system --quick --no-colors --logfile "${OUT07}/lynis.log" --report-file "${OUT07}/lynis-report.dat" 2>&1 \
      | tee "${LYNIS_RAW_STDOUT}" \
      | grep -v -F -e "pgrep: pattern that searches for process name longer than 15 characters will result in zero matches" -e "Try \`pgrep -f' option to match against the complete command line." \
      | tee "${LYNIS_FILTERED_STDOUT}"
    LYNIS_RC=${PIPESTATUS[0]}
    set -o pipefail

    grep -F -e "pgrep: pattern that searches for process name longer than 15 characters will result in zero matches" -e "Try \`pgrep -f' option to match against the complete command line." "${LYNIS_RAW_STDOUT}" > "${LYNIS_FILTERED_WARNINGS}" 2>/dev/null || true
    if [ -s "${LYNIS_FILTERED_WARNINGS}" ]; then
      warn "Lynis emitió warnings de pgrep; se guardaron en ${LYNIS_FILTERED_WARNINGS} y no se muestran como ruido operativo."
    fi

    [ "${LYNIS_RC}" -ne 0 ] && warn "Lynis salió con código no-cero (${LYNIS_RC}); revisar ${LYNIS_RAW_STDOUT}."
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
| Carpeta cruda | $([ "${KEEP_TREE}" -eq 1 ] && echo "\`${OUT_DIR}/\` (conservada)" || echo "(borrada — solo queda tarball)") |

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
| 0 — Checklist operacional | \`fase-00-checklist-*.md\` | $([ -s "${OUT_DIR}/fase-00-checklist-resultados.md" ] && echo "OK" || echo "FALTA") |
| 1 — Inventario | \`postura-general/\` | OK |
| 2 — Acceso/auth | \`acceso-autenticacion/\` | OK |
| 3 — Red/firewall | \`red-firewall/\` | OK |
| 4 — Logs/monitoreo | \`logs-monitoreo/\` | OK |
| 5 — Updates | \`actualizaciones/\` | OK |
| 6 — Backups | \`backups/\` | OK |
| 7 — Lynis | \`lynis/\` | $([ "${LYNIS_OK}" -eq 1 ] && echo "OK" || echo "FALTA (no instalado)") |

## Resumen del Checklist Operacional (Fase 0)
$(cat "${OUT_DIR}/fase-00-checklist-resultados.md" 2>/dev/null || echo "(no generado)")

## Próximos pasos (humano)

1. **Bajar el tarball a la laptop** (rsync/scp):
   \`\`\`
   rsync --progress -razuz "${INVOKER_USER}@${HOST_NOMBRE}:~/*.tar.gz" /tmp/
   \`\`\`
2. **Subir a \`le\`** (workspace Freddy vía Tailscale) si la laptop no tiene acceso directo al vault:
   \`\`\`
   scp /tmp/auditoria-*.tar.gz le:/tmp/
   \`\`\`
3. **El agente (en hermes-contabo vía SSH a \`le\`) extrae, lee, y borra el tarball sin dejar basura**.
4. **Comparar contra CIS Ubuntu 22.04 Benchmark v2.0.0**.
5. **Armar tabla de hallazgos P0/P1/P2 + cara ejecutiva + cara técnica**.
6. **Cerrar con GLPI y correo al cliente** (responsable: Freddy).
EOF

# ============================================================================
# Empaquetar y finalizar
# ============================================================================
section "Empaquetando"

# ---------- Ajuste de permisos al usuario que invocó el script ----------
# Se aplica ANTES del tar para que el tarball contenga los permisos del
# usuario real, no de root. Si el script corrió bajo sudo (INVOKER_USER != root),
# transferimos ownership del directorio y dejaremos el tarball bajo el usuario.
# Casos:
#   - sudo bash script.sh           -> INVOKER_USER = usuario original
#   - sudo -u otro bash script.sh   -> INVOKER_USER = "otro"
#   - bash script.sh (como root)    -> INVOKER_USER = root, no se cambia
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  log "Ajustando ownership a ${INVOKER_USER}:${INVOKER_USER} para SCP sin escalación."
  if chown -R "${INVOKER_USER}:${INVOKER_USER}" "${OUT_DIR}" 2>/dev/null; then
    ok "Ownership aplicado a ${OUT_DIR}"
  else
    warn "No se pudo aplicar chown a ${OUT_DIR} (¿filesystem readonly?). El reporte queda como root:root."
  fi
fi

TAR_PATH=""
if [ "${MAKE_TAR}" -eq 1 ]; then
  cd "${OUT_BASE}"
  tar -czf "${OUT_DIR}.tar.gz" "$(basename "${OUT_DIR}")" 2>/dev/null
  TAR_PATH="${OUT_DIR}.tar.gz"
  TAR_SIZE=$(du -h "${TAR_PATH}" | awk '{print $1}')
  # Ajuste de permisos también al tarball (quedó como root porque tar corrió
  # bajo sudo). Mismo user que OUT_DIR.
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    chown "${INVOKER_USER}:${INVOKER_USER}" "${TAR_PATH}" 2>/dev/null || true
  fi
fi

# ---------- Limpieza: borrar carpeta cruda por defecto ----------
# Política: no dejar basura. Solo queda el .tar.gz (o la carpeta si --keep-tree).
if [ "${KEEP_TREE}" -eq 0 ] && [ -n "${TAR_PATH}" ] && [ -d "${OUT_DIR}" ]; then
  log "Borrando carpeta cruda (--keep-tree para conservar)."
  if rm -rf "${OUT_DIR}" 2>/dev/null; then
    ok "Carpeta cruda borrada. Solo queda el tarball."
  else
    warn "No se pudo borrar ${OUT_DIR}. El operador puede hacerlo manualmente."
  fi
fi

ok "Listo."
if [ -n "${TAR_PATH}" ]; then
  ok "📦 Reporte empaquetado en: ${TAR_PATH} (${TAR_SIZE})"
fi
if [ "${KEEP_TREE}" -eq 1 ] && [ -d "${OUT_DIR}" ]; then
  ok "📁 Carpeta cruda (conservada por --keep-tree): ${OUT_DIR}"
fi

# ---------- Envío opcional del reporte ----------
REPORT_PATH=""
if [ -n "${TAR_PATH}" ]; then
  REPORT_PATH="${TAR_PATH}"
elif [ -d "${OUT_DIR}" ]; then
  REPORT_PATH="${OUT_DIR}/"
fi

if [ -n "${REPORT_PATH}" ]; then
  REPORT_BASENAME="$(basename "${REPORT_PATH%/}")"
  DEFAULT_REMOTE_PATH="/tmp/${REPORT_BASENAME}"

  if [ "${SEND_REPORT}" = "ask" ]; then
    if [ -t 0 ] && [ "${ASSUME_YES}" -eq 0 ]; then
      printf "¿Enviar reporte ahora por scp/rsync? [s/N]: "
      read -r REPLY </dev/tty 2>/dev/null || REPLY="n"
      case "${REPLY}" in
        s|S|si|SI|sí|SÍ|y|Y|yes|YES) SEND_REPORT="yes" ;;
        *) SEND_REPORT="no" ;;
      esac
    else
      SEND_REPORT="no"
    fi
  fi

  if [ "${SEND_REPORT}" = "yes" ]; then
    if [ -z "${SEND_TARGET}" ]; then
      if [ -t 0 ] && [ "${ASSUME_YES}" -eq 0 ]; then
        printf "Destino remoto [usuario@host:%s]: " "${DEFAULT_REMOTE_PATH}"
        read -r SEND_TARGET </dev/tty 2>/dev/null || SEND_TARGET=""
        case "${SEND_TARGET}" in
          *@*:*) : ;;
          *@*) SEND_TARGET="${SEND_TARGET}:${DEFAULT_REMOTE_PATH}" ;;
        esac
      fi
    fi

    if [ -z "${SEND_TARGET}" ]; then
      warn "Envío solicitado, pero no se indicó destino remoto. Reporte local: ${REPORT_PATH}"
    else
      case "${SEND_TARGET}" in
        *@*:*) : ;;
        *@*) SEND_TARGET="${SEND_TARGET}:${DEFAULT_REMOTE_PATH}" ;;
      esac

      SSH_SEND_OPTS=(-o StrictHostKeyChecking=accept-new)

      case "${SEND_METHOD}" in
        scp)
          log "Enviando reporte por scp a ${SEND_TARGET}"
          if scp "${SSH_SEND_OPTS[@]}" -p "${REPORT_PATH}" "${SEND_TARGET}"; then
            ok "Reporte enviado por scp a ${SEND_TARGET}"
          else
            warn "Falló el envío por scp. Reporte local: ${REPORT_PATH}"
          fi
          ;;
        rsync)
          log "Enviando reporte por rsync a ${SEND_TARGET}"
          if rsync -e "ssh -o StrictHostKeyChecking=accept-new" --progress -razuz "${REPORT_PATH}" "${SEND_TARGET}"; then
            ok "Reporte enviado por rsync a ${SEND_TARGET}"
          else
            warn "Falló el envío por rsync. Reporte local: ${REPORT_PATH}"
          fi
          ;;
        *)
          warn "Método de envío no soportado: ${SEND_METHOD}. Usa scp o rsync. Reporte local: ${REPORT_PATH}"
          ;;
      esac
    fi
  fi
fi

exit 0
