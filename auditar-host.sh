#!/usr/bin/env bash
# auditar-host.sh — lanzador: audita un host remoto con auditoria-root-acceso.sh en un solo comando.
# Uso: ./auditar-host.sh [-d DIR] [usuario@]host-o-ip
#   -d DIR  carpeta local donde dejar el paquete (por defecto, la carpeta actual)
# Corre en TU equipo, no en el host. Copia el script y vendor/, lo ejecuta por SSH con el
# sudo de TU usuario (te pedirá su contraseña), trae el .tar.gz, verifica el SHA256 y
# comprueba que los 8 pasos se ejecutaron. No guarda contraseñas ni llaves.
# En el host solo escribe en ~/auditoria/ (y lo que la auditoría ya crea); nada se borra
# sin tu confirmación.
set -u
set -o pipefail

LANZADOR_VERSION="0.1.0"
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$AQUI/auditoria-root-acceso.sh"
VENDOR="$AQUI/vendor"
DEST="$PWD"

uso() { sed -n '2,6p' "$0"; }
die() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }
paso() { printf '\n[%s] %s\n' "$1" "$2"; }

while getopts "d:h" op; do
  case "$op" in
    d) DEST="$OPTARG" ;;
    h) uso; exit 0 ;;
    *) uso >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || { uso >&2; exit 2; }
TARGET="$1"
case "$TARGET" in
  -*|"") die "destino inválido: $TARGET" ;;
esac
printf '%s' "$TARGET" | grep -Eq '^[A-Za-z0-9._@-]+$' || die "destino inválido: $TARGET (usa usuario@host o IP)"

for c in ssh scp sha256sum tar mktemp; do
  command -v "$c" >/dev/null 2>&1 || die "falta el comando '$c' en este equipo"
done
[ -f "$SCRIPT" ] || die "no encuentro $SCRIPT: ejecuta el lanzador desde la carpeta del repo"
[ -d "$VENDOR/lynis" ] || die "no encuentro $VENDOR/lynis: sin Lynis el paso 7 falla"
[ -d "$DEST" ] && [ ! -L "$DEST" ] || die "la carpeta de destino no existe o es un symlink: $DEST"

TS="$(date +%Y%m%d-%H%M%S)"
RDIR="salida-$TS"                  # carpeta única en el host: evita confundir con corridas anteriores
CTL="$(mktemp -d)" || die "no puedo crear un directorio temporal"
CP="$CTL/cm"                       # una sola conexión SSH reutilizada: una sola contraseña/passphrase
cleanup() { ssh -O exit -o "ControlPath=$CP" "$TARGET" >/dev/null 2>&1; rm -rf "$CTL"; }
trap cleanup EXIT

printf 'auditar-host.sh %s → %s\n' "$LANZADOR_VERSION" "$TARGET"

paso "1/6" "Conectando a $TARGET"
ssh -MNf -o "ControlPath=$CP" "$TARGET" || die "no pude conectar por SSH a $TARGET"

paso "2/6" "Copiando script y vendor/ a ~/auditoria/ del host"
ssh -o "ControlPath=$CP" "$TARGET" 'mkdir -p ~/auditoria' || die "no pude crear ~/auditoria en el host"
scp -q -r -o "ControlPath=$CP" "$SCRIPT" "$VENDOR" "$TARGET:auditoria/" || die "falló la copia al host"

paso "3/6" "Ejecutando la auditoría con sudo (te pedirá la contraseña de TU usuario; tarda unos minutos)"
ssh -t -o "ControlPath=$CP" "$TARGET" \
  "cd ~/auditoria && sudo bash -c 'bash ./auditoria-root-acceso.sh --all -o \"\$PWD/$RDIR\"; rc=\$?; chown -R \"\$SUDO_USER\" \"$RDIR\"; exit \$rc'"
RC_AUDIT=$?
[ "$RC_AUDIT" -eq 0 ] || printf 'AVISO: la ejecución remota terminó con código %s.\n' "$RC_AUDIT"

paso "4/6" "Buscando el paquete en el host"
NAME="$(ssh -o "ControlPath=$CP" "$TARGET" "cd ~/auditoria/$RDIR 2>/dev/null && ls auditoria-root-*.tar.gz 2>/dev/null | head -1")"
[ -n "$NAME" ] || die "no se generó ningún .tar.gz en el host (revisa la salida de arriba)"
printf '%s' "$NAME" | grep -Eq '^auditoria-root-[A-Za-z0-9._-]+\.tar\.gz$' || die "nombre de paquete inesperado: $NAME"

paso "5/6" "Trayendo $NAME a $DEST"
scp -q -o "ControlPath=$CP" "$TARGET:auditoria/$RDIR/$NAME" "$TARGET:auditoria/$RDIR/$NAME.sha256" "$DEST/" || die "falló la descarga"
chmod 600 "$DEST/$NAME" || die "no pude fijar permisos 600 en $DEST/$NAME"

paso "6/6" "Verificando el paquete"
RESULTADO="OK"
if ( cd "$DEST" && sha256sum -c "$NAME.sha256" ); then :; else RESULTADO="FALLO"; printf 'FALLO: el SHA256 no coincide.\n'; fi
MANIFEST="$(tar -xzOf "$DEST/$NAME" --wildcards '*/MANIFEST.txt' 2>/dev/null)"
SIN="$(printf '%s\n' "$MANIFEST" | sed -n 's/^pasos_sin_ejecutar=//p')"
if [ "$SIN" = "ninguno" ]; then printf 'Pasos ejecutados: los 8.\n'
else RESULTADO="FALLO"; printf 'FALLO: pasos sin ejecutar: %s\n' "${SIN:-no se pudo leer el MANIFEST}"; fi
printf 'Resumen del paso 1 (informativo):\n'
tar -xzOf "$DEST/$NAME" --wildcards '*/01-preflight.txt' 2>/dev/null \
  | grep -E '^(FREEIPA|ZABBIX_AGENT|GLPI_AGENT)=|^POLITICA_FIBEX' | sed 's/^/  /'

printf '\n=== RESULTADO: %s ===\n' "$RESULTADO"
if [ "$RESULTADO" = "OK" ]; then
  printf 'Paquete: %s/%s\n' "$DEST" "$NAME"
  printf 'Entrégalo a Freddy. Es confidencial: contiene datos sensibles del host.\n'
  read -r -p "¿Borrar ~/auditoria/ del host ahora? Ya tienes el paquete verificado. [s/N] " r || r=""
  case "$r" in
    s|S) ssh -o "ControlPath=$CP" "$TARGET" 'rm -rf ~/auditoria' && printf 'Borrado.\n' || printf 'AVISO: no pude borrar ~/auditoria en el host.\n' ;;
    *) printf 'Se deja ~/auditoria/ en el host. Bórralo cuando Freddy confirme que recibió el paquete.\n' ;;
  esac
  exit 0
fi
printf 'No entregues este paquete. Guarda la salida completa de arriba y avisa a Freddy.\n'
exit 1
