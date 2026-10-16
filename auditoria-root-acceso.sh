#!/usr/bin/env bash
# auditoria-root-acceso.sh — menú de auditoría de seguridad básica (SOLO LECTURA)
# Prioridad: determinar quién habilitó el acceso root por SSH.
# Uso: sudo ./auditoria-root-acceso.sh [--all] [-o DIR]
# No instala paquetes, no modifica configuración, no toca la red.
set -u
set -o pipefail

VERSION="0.1.0-esqueleto"
OUT_BASE="${TMPDIR:-/tmp}"
RUN_ALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --all) RUN_ALL=1 ;;
    -o) shift; OUT_BASE="${1:?falta DIR}" ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecuta con sudo/root: sin privilegios la evidencia queda incompleta." >&2
  exit 1
fi

HOST="$(hostname -s 2>/dev/null || echo desconocido)"
TS="$(date +%Y%m%d-%H%M%S)"
EVID="$OUT_BASE/auditoria-root-${HOST}-${TS}"
mkdir -p "$EVID" && chmod 700 "$EVID" || { echo "No puedo crear $EVID" >&2; exit 1; }

# --- utilidades -------------------------------------------------------------
declare -A ESTADO   # paso -> pendiente|ok|parcial
# run: ejecuta un comando y guarda "$ cmd", salida y rc en el archivo de evidencia.
run() {
  local f="$1"; shift
  { printf '$ %s\n' "$*"; "$@" 2>&1; printf '[rc=%s]\n\n' "$?"; } >>"$f" 2>&1
}
have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '%s\n' "$*"; }

# --- paso 1: preflight ------------------------------------------------------
paso_01_preflight() {
  local f="$EVID/01-preflight.txt"; : >"$f"
  run "$f" date -u +%FT%TZ
  run "$f" hostname -f
  run "$f" uname -a
  run "$f" cat /etc/os-release
  run "$f" id
  run "$f" uptime
  run "$f" ip -br addr
  have systemctl && run "$f" systemctl is-system-running

  # FreeIPA: se decide por evidencia, no por suposición.
  local ipa="no"
  { [ -f /etc/ipa/default.conf ] || have ipa-client-install || have ipa; } && ipa="si"
  have sssctl && run "$f" sssctl domain-list
  [ -f /etc/ipa/default.conf ] && run "$f" cat /etc/ipa/default.conf
  run "$f" systemctl is-active sssd
  printf 'FREEIPA=%s\n' "$ipa" | tee -a "$f" >"$EVID/.freeipa"

  # Detección de servicios en escucha (base para firewall/fail2ban).
  run "$f" ss -tulnp
  # Herramientas disponibles (informativo; no se instala nada).
  local t
  for t in sshd nft iptables ufw firewall-cmd fail2ban-client auditctl ausearch journalctl lynis; do
    have "$t" && printf 'tool:%s=si\n' "$t" >>"$f" || printf 'tool:%s=no\n' "$t" >>"$f"
  done
  ESTADO[1]="ok"
  say "Paso 1 listo → $f  (FreeIPA: $ipa)"
}

pendiente() { say "Paso $1 ($2): aún no implementado en este esqueleto."; ESTADO[$1]="pendiente"; }

paso_02_root()     { pendiente 2 "Acceso a root (quién lo habilitó)"; }
paso_03_ssh()      { pendiente 3 "SSH hardening (sshd -T, Match, drop-ins)"; }
paso_04_sudo()     { pendiente 4 "sudo/PAM/su"; }
paso_05_firewall() { pendiente 5 "Firewall: política vs puertos"; }
paso_06_fail2ban() { pendiente 6 "Fail2ban: jaulas vs servicios"; }
paso_07_lynis()    { pendiente 7 "Lynis (tarball vendorizado)"; }
paso_08_empaquetar() {
  local tgz="$OUT_BASE/auditoria-root-${HOST}-${TS}.tar.gz"
  tar -C "$OUT_BASE" -czf "$tgz" "$(basename "$EVID")" || { say "Falló tar"; return 1; }
  ( cd "$OUT_BASE" && sha256sum "$(basename "$tgz")" ) | tee "$tgz.sha256"
  ESTADO[8]="ok"
  say "Paquete: $tgz"
}

NOMBRES=(
  "" "Preflight (identidad, distro, FreeIPA, listeners)"
  "Acceso a root (prioridad)" "SSH hardening" "sudo / PAM / su"
  "Firewall" "Fail2ban" "Lynis" "Empaquetar resultado (.tar.gz + SHA256)"
)
FUNCS=( "" paso_01_preflight paso_02_root paso_03_ssh paso_04_sudo paso_05_firewall paso_06_fail2ban paso_07_lynis paso_08_empaquetar )

menu() {
  local op i
  while true; do
    say ""; say "== Auditoría ${HOST} · v${VERSION} · evidencia: $EVID =="
    for i in 1 2 3 4 5 6 7 8; do
      printf ' %s) %-52s [%s]\n' "$i" "${NOMBRES[$i]}" "${ESTADO[$i]:-pendiente}"
    done
    say " a) Ejecutar todos en orden   q) Salir"
    read -r -p "Opción: " op || break
    case "$op" in
      [1-8]) "${FUNCS[$op]}" ;;
      a) for i in 1 2 3 4 5 6 7 8; do "${FUNCS[$i]}"; done ;;
      q) break ;;
      *) say "Opción inválida" ;;
    esac
  done
}

if [ "$RUN_ALL" -eq 1 ]; then
  for i in 1 2 3 4 5 6 7 8; do "${FUNCS[$i]}"; done
else
  menu
fi
