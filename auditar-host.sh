#!/usr/bin/env bash
# auditar-host.sh — lanzador: audita un host remoto con auditoria-root-acceso.sh en un solo comando.
# Uso: ./auditar-host.sh [-d DIR] [-e DESTINO] [usuario@]host-o-ip
#   -d DIR      carpeta local donde dejar el paquete (por defecto, auditorias/ junto al lanzador)
#   -e DESTINO  envía el paquete por scp a DESTINO (usuario@servidor:ruta); si no lo das, te pregunta
# Corre en TU equipo, no en el host. Copia el script y vendor/, lo ejecuta por SSH con el
# sudo de TU usuario (te pedirá su contraseña), trae el .tar.gz, verifica el SHA256 y
# comprueba que los 8 pasos se ejecutaron. No guarda contraseñas ni llaves.
# En el host solo escribe en ~/auditoria/. Si el paquete llegó verificado a tu equipo (y a
# DESTINO, si lo diste), borra del host lo que el lanzador copió y generó; si algo falla, no borra nada.
set -u
set -o pipefail

LANZADOR_VERSION="0.3.0"
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$AQUI/auditoria-root-acceso.sh"
VENDOR="$AQUI/vendor"
DEST=""

uso() { sed -n "2,9p" "$0"; }
die() { printf 'FALLO: %s\n' "$*" >&2; exit 1; }
paso() { printf '\n[%s] %s\n' "$1" "$2"; }

EDEST=""
while getopts "d:e:h" op; do
  case "$op" in
    d) DEST="$OPTARG" ;;
    e) EDEST="$OPTARG" ;;
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

# usuario@servidor:ruta — sin espacios ni metacaracteres: la ruta se usa en un comando remoto
destino_valido() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9._@][A-Za-z0-9._@-]*:[A-Za-z0-9._/~-]*$'; }
if [ -n "$EDEST" ]; then
  destino_valido "$EDEST" || die "destino -e inválido: $EDEST (usa usuario@servidor:ruta)"
fi

for c in ssh scp sha256sum tar mktemp; do
  command -v "$c" >/dev/null 2>&1 || die "falta el comando '$c' en este equipo"
done
[ -f "$SCRIPT" ] || die "no encuentro $SCRIPT: ejecuta el lanzador desde la carpeta del repo"
[ -d "$VENDOR/lynis" ] || die "no encuentro $VENDOR/lynis: sin Lynis el paso 7 falla"
if [ -z "$DEST" ]; then
  DEST="$AQUI/auditorias"
  [ -L "$DEST" ] && die "auditorias/ es un symlink: $DEST"
  mkdir -p "$DEST" && chmod 700 "$DEST" || die "no puedo crear $DEST"
fi
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
printf 'Usuarios vs lista autorizada (paso 2):\n'
BAN="$(tar -xzOf "$DEST/$NAME" --wildcards '*/02-resumen.txt' 2>/dev/null | grep -E '^(BANDERA ROJA|BANDERAS_ROJAS=)')"
if [ -n "$BAN" ]; then printf '%s\n' "$BAN" | sed 's/^/  /'
else printf '  (el paquete no trae esta comprobación: script anterior a 0.11.0)\n'; fi
NBAN="$(printf '%s\n' "$BAN" | sed -n 's/^BANDERAS_ROJAS=//p')"

ENTREGADO=1
if [ "$RESULTADO" = "OK" ] && [ -z "$EDEST" ]; then
  # sin -e: pregunta a dónde enviarlo (Enter = no enviar; sin terminal o stdin vacío = no enviar)
  for _ in 1 2 3; do
    printf "¿A dónde enviar el paquete? usuario@servidor:ruta (Enter = no enviar): "
    read -r r || { r=""; printf "\n"; }
    [ -z "$r" ] && break
    if destino_valido "$r"; then EDEST="$r"; break; fi
    printf 'Destino inválido: usa usuario@servidor:ruta, o Enter para no enviar.\n'
  done
fi
if [ "$RESULTADO" = "OK" ] && [ -n "$EDEST" ]; then
  EHOST="${EDEST%%:*}"; EPATH="${EDEST#*:}"
  paso "extra" "Enviando el paquete a $EDEST"
  if scp -q "$DEST/$NAME" "$DEST/$NAME.sha256" "$EDEST/" \
     && ssh "$EHOST" "cd ${EPATH:-.} && sha256sum -c $NAME.sha256"; then
    printf 'Entregado y verificado en %s\n' "$EDEST"
  else
    ENTREGADO=0; RESULTADO="FALLO"
    printf 'FALLO: no se pudo enviar o verificar el paquete en %s\n' "$EDEST"
  fi
fi

if [ "$RESULTADO" = "OK" ] && [ "$ENTREGADO" = 1 ]; then
  # solo lo que el lanzador copió o generó; rmdir no borra la carpeta si tiene otras cosas
  if ssh -o "ControlPath=$CP" "$TARGET" "cd ~/auditoria && rm -rf auditoria-root-acceso.sh vendor $RDIR && cd .. && rmdir auditoria 2>/dev/null; [ ! -e ~/auditoria/$RDIR ]"; then
    LIMPIEZA="Host limpio: se borró lo que el lanzador copió y generó en ~/auditoria/."
  else
    LIMPIEZA="AVISO: no pude limpiar ~/auditoria/ en el host; bórralo a mano."
  fi
fi

printf '\n=== RESULTADO: %s ===\n' "$RESULTADO"
if [ "$RESULTADO" = "OK" ]; then
  printf 'Paquete: %s/%s\n' "$DEST" "$NAME"
  printf '%s\n' "$LIMPIEZA"
  case "$NBAN" in
    ""|0|*[!0-9]*) ;;
    *) printf 'ATENCIÓN: %s BANDERA(S) ROJA(S) (usuarios fuera de la lista autorizada o root activo). Avisa a Freddy antes de cerrar el caso.\n' "$NBAN" ;;
  esac
  printf 'Es confidencial: contiene datos sensibles del host.\n'
  exit 0
fi
printf 'No entregues este paquete. En el host se dejó ~/auditoria/ sin borrar. Guarda la salida completa de arriba y avisa a Freddy.\n'
exit 1
