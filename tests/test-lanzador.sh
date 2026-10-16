#!/usr/bin/env bash
# test-lanzador.sh — pruebas de auditar-host.sh SIN red ni host real.
# Usa ssh/scp/sudo/id FALSOS (solo copian entre carpetas locales) puestos al inicio del PATH,
# y un auditoria-root-acceso.sh de mentira (stub). Nunca se invoca el ssh/scp reales:
# cada llamada de los falsos queda en $FAKE_LOG y los casos de rechazo comprueban que está vacío.
# Uso: ./tests/test-lanzador.sh        (no requiere root ni sudo)
set -u
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0; N=0
ok()   { N=$((N+1)); printf 'PASS  %s\n' "$1"; }
bad()  { N=$((N+1)); FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# --- entorno falso -----------------------------------------------------------
mkdir -p "$T/fb" "$T/repo/vendor/lynis" "$T/home" "$T/dest"
cp "$AQUI/auditar-host.sh" "$T/repo/"; chmod +x "$T/repo/auditar-host.sh"
echo dummy >"$T/repo/vendor/lynis/lynis-3.1.7.tar.gz"
cat >"$T/repo/auditoria-root-acceso.sh" <<'EOF'
#!/usr/bin/env bash
# stub: genera un paquete mínimo con el mismo formato que el script real
out=""; while [ $# -gt 0 ]; do case "$1" in -o) shift; out="$1" ;; esac; shift; done
d="$out/auditoria-root-h1-20260101-000000"; mkdir -p "$d"
printf 'pasos_sin_ejecutar=%s\n' "${STUB_FALTAN:-ninguno}" >"$d/MANIFEST.txt"
printf 'FREEIPA=no\nZABBIX_AGENT=activo\nGLPI_AGENT=no\nPOLITICA_FIBEX zabbix_agent=OK glpi_agent=FALLA\n' >"$d/01-preflight.txt"
tar -C "$out" -czf "$out/auditoria-root-h1-20260101-000000.tar.gz" "$(basename "$d")"
( cd "$out" && sha256sum auditoria-root-h1-20260101-000000.tar.gz >auditoria-root-h1-20260101-000000.tar.gz.sha256 )
EOF
cat >"$T/fb/ssh" <<'EOF'
#!/bin/bash
echo "ssh $*" >>"$FAKE_LOG"
[ "${FAKE_SSH_FAIL:-0}" = 1 ] && exit 255
while [ $# -gt 0 ]; do case "$1" in -o) shift 2;; -O|-MNf) exit 0;; -t|-q) shift;; *) break;; esac; done
shift
cd "$FAKEHOME" && HOME="$FAKEHOME" bash -c "$*"
EOF
cat >"$T/fb/scp" <<'EOF'
#!/bin/bash
echo "scp $*" >>"$FAKE_LOG"
args=(); while [ $# -gt 0 ]; do case "$1" in -o) shift 2;; -q|-r) shift;; *) args+=("$1"); shift;; esac; done
n=${#args[@]}; dest="${args[$((n-1))]}"
case "$dest" in /*|*:*) ;; *) echo "scp falso: destino relativo $dest" >&2; exit 99;; esac
[ "${FAKE_E_FAIL:-0}" = 1 ] && case "$dest" in entrega@*) exit 1;; esac
map() { case "$1" in *:*) echo "$FAKEHOME/${1#*:}";; *) echo "$1";; esac; }
d="$(map "$dest")"; mkdir -p "$d"
for ((i=0;i<n-1;i++)); do cp -r "$(map "${args[$i]}")" "$d/"; done
if [ "${FAKE_CORRUPT:-0}" = 1 ] || { [ "${FAKE_E_CORRUPT:-0}" = 1 ] && case "$dest" in entrega@*) true;; *) false;; esac; }; then for f in "$d"/*.tar.gz; do [ -f "$f" ] && echo x >>"$f"; done; fi
exit 0
EOF
cat >"$T/fb/sudo" <<'EOF'
#!/bin/bash
SUDO_USER="$(/usr/bin/id -un)" exec "$@"
EOF
chmod +x "$T/fb/"*

# corre el lanzador con los falsos; $1 = respuesta al prompt de borrado; resto = argumentos
lanza() {
  local resp="$1"; shift
  : >"$T/log"; rm -rf "$T/home/auditoria"
  if [ -n "$resp" ]; then printf '%s\n' "$resp"; else :; fi \
    | env PATH="$T/fb:$PATH" FAKEHOME="$T/home" FAKE_LOG="$T/log" "$@" >"$T/out" 2>&1
  return "${PIPESTATUS[1]}"
}
LANZ="$T/repo/auditar-host.sh"

# 1. camino feliz: OK, paquete en destino con 600, host limpiado sin preguntar nada
rm -f "$T/dest/"*; lanza "" "$LANZ" -d "$T/dest" u@10.0.0.9 </dev/null; rc=$?
check "feliz: exit 0" "[ $rc -eq 0 ]"
check "feliz: RESULTADO OK" "grep -q 'RESULTADO: OK' '$T/out'"
check "feliz: paquete y sha256 en destino" "ls '$T/dest'/auditoria-root-*.tar.gz '$T/dest'/auditoria-root-*.sha256 >/dev/null 2>&1"
check "feliz: permisos 600" "[ \"\$(stat -c %a '$T/dest'/auditoria-root-*.tar.gz)\" = 600 ]"
check "feliz: muestra POLITICA_FIBEX" "grep -q POLITICA_FIBEX '$T/out'"
check "feliz: limpia el host sin preguntar" "[ ! -d '$T/home/auditoria' ] && grep -q 'Host limpio' '$T/out' && ! grep -q '\[s/N\]' '$T/out'"
check "feliz: no envía a ningún DESTINO" "! grep -q 'entrega@' '$T/log'"

# 2. la limpieza no borra lo que no es del lanzador
rm -f "$T/dest/"*; mkdir -p "$T/home/auditoria"; echo ajeno >"$T/home/auditoria/ajeno.txt"
: >"$T/log"; env PATH="$T/fb:$PATH" FAKEHOME="$T/home" FAKE_LOG="$T/log" "$LANZ" -d "$T/dest" u@10.0.0.9 >"$T/out" 2>&1 </dev/null; rc=$?
check "limpieza: conserva archivos ajenos en ~/auditoria" "[ $rc -eq 0 ] && [ -f '$T/home/auditoria/ajeno.txt' ] && [ ! -e '$T/home/auditoria/vendor' ]"

# 3. con -e: entrega verificada y luego limpia
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza "" "$LANZ" -d "$T/dest" -e entrega@srv:entrega u@10.0.0.9 </dev/null; rc=$?
check "-e: exit 0, llega al destino y limpia el host" "[ $rc -eq 0 ] && ls '$T/home/entrega'/auditoria-root-*.tar.gz >/dev/null 2>&1 && [ ! -d '$T/home/auditoria' ] && grep -q 'Entregado y verificado' '$T/out'"

# 3b. sin -e: pregunta a dónde enviar
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza 'entrega@srv:entrega' "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "pregunta: destino válido entrega y limpia" "[ $rc -eq 0 ] && grep -q 'A dónde enviar' '$T/out' && ls '$T/home/entrega'/auditoria-root-*.tar.gz >/dev/null 2>&1 && [ ! -d '$T/home/auditoria' ]"
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza '' "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "pregunta: Enter no envía, y limpia el host" "[ $rc -eq 0 ] && [ \"\$(grep -c 'A dónde enviar' '$T/out')\" = 1 ] && [ ! -d '$T/home/entrega' ] && [ ! -d '$T/home/auditoria' ] && ! grep -q 'entrega@' '$T/log'"
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza $'a b;rm\nentrega@srv:entrega' "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "pregunta: inválido y reintento válido entrega" "[ $rc -eq 0 ] && grep -q 'Destino inválido' '$T/out' && ls '$T/home/entrega'/auditoria-root-*.tar.gz >/dev/null 2>&1"
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza 'entrega@srv:entrega' env FAKE_E_FAIL=1 "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "pregunta: envío falla, FALLO y host intacto" "[ $rc -eq 1 ] && grep -q 'RESULTADO: FALLO' '$T/out' && [ -d '$T/home/auditoria/vendor' ]"
rm -f "$T/dest/"*; lanza 'entrega@srv:entrega' env STUB_FALTAN=7 "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "pregunta: con FALLO previo no pregunta" "[ $rc -eq 1 ] && ! grep -q 'A dónde enviar' '$T/out'"

# 3c. sin -d: deja el paquete en auditorias/ junto al lanzador (no en la carpeta actual)
rm -rf "$T/repo/auditorias"; mkdir -p "$T/cwd"; : >"$T/log"
( cd "$T/cwd" && printf '\n' | env PATH="$T/fb:$PATH" FAKEHOME="$T/home" FAKE_LOG="$T/log" "$LANZ" u@10.0.0.9 >"$T/out" 2>&1 ); rc=$?
check "sin -d: paquete en auditorias/ y nada en la carpeta actual" "[ $rc -eq 0 ] && ls '$T/repo/auditorias'/auditoria-root-*.tar.gz >/dev/null 2>&1 && [ \"\$(stat -c %a '$T/repo/auditorias')\" = 700 ] && [ -z \"\$(ls -A '$T/cwd')\" ]"

# 4. -e falla al enviar: FALLO, exit 1, el host NO se limpia
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza "" env FAKE_E_FAIL=1 "$LANZ" -d "$T/dest" -e entrega@srv:entrega u@10.0.0.9 </dev/null; rc=$?
check "-e falla: exit 1, RESULTADO FALLO y host intacto" "[ $rc -eq 1 ] && grep -q 'RESULTADO: FALLO' '$T/out' && [ -d '$T/home/auditoria/vendor' ]"

# 5. -e llega corrupto: FALLO y host intacto
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza "" env FAKE_E_CORRUPT=1 "$LANZ" -d "$T/dest" -e entrega@srv:entrega u@10.0.0.9 </dev/null; rc=$?
check "-e corrupto: exit 1 y host intacto" "[ $rc -eq 1 ] && grep -q 'no se pudo enviar o verificar' '$T/out' && [ -d '$T/home/auditoria/vendor' ]"

# 6. -e inválido: rechaza SIN llamar a ssh/scp
for e in '-oProxyCommand=x:/t' 'sin-dos-puntos' 'a b@h:/t' 'u@h:/t;rm' 'u@h:$(id)'; do
  lanza "" "$LANZ" -d "$T/dest" -e "$e" u@10.0.0.9 </dev/null; rc=$?
  check "-e inválido '$e': exit != 0 y sin llamadas a ssh/scp" "[ $rc -ne 0 ] && [ ! -s '$T/log' ]"
done

# 7. paquete corrupto en la descarga: FALLO, exit 1, host intacto, no se envía
rm -f "$T/dest/"*; rm -rf "$T/home/entrega"; lanza "" env FAKE_CORRUPT=1 "$LANZ" -d "$T/dest" -e entrega@srv:entrega u@10.0.0.9 </dev/null; rc=$?
check "corrupto: exit 1 y RESULTADO FALLO" "[ $rc -eq 1 ] && grep -q 'RESULTADO: FALLO' '$T/out'"
check "corrupto: no dice 'Entrégalo'" "! grep -q 'Entrégalo' '$T/out'"
check "corrupto: avisa SHA256" "grep -q 'SHA256 no coincide' '$T/out'"
check "corrupto: host intacto y no envía a -e" "[ -d '$T/home/auditoria/vendor' ] && [ ! -d '$T/home/entrega' ]"

# 8. pasos sin ejecutar: host intacto
rm -f "$T/dest/"*; lanza "" env STUB_FALTAN=7 "$LANZ" -d "$T/dest" u@10.0.0.9 </dev/null; rc=$?
check "pasos sin ejecutar: exit 1, lo dice y host intacto" "[ $rc -eq 1 ] && grep -q 'pasos sin ejecutar: 7' '$T/out' && [ -d '$T/home/auditoria/vendor' ]"

# 9. destinos inválidos: rechaza SIN llamar a ssh/scp
for t in '-oProxyCommand=x' 'a b;rm' 'u@h$(id)' ''; do
  lanza "" "$LANZ" -d "$T/dest" "$t"; rc=$?
  check "destino inválido '$t': exit != 0 y sin llamadas a ssh/scp" "[ $rc -ne 0 ] && [ ! -s '$T/log' ]"
done
lanza "" "$LANZ" -d "$T/dest"; rc=$?
check "sin argumentos: exit 2" "[ $rc -eq 2 ]"

# 10. SSH no conecta
lanza "" env FAKE_SSH_FAIL=1 "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "ssh falla: exit 1 y mensaje claro" "[ $rc -eq 1 ] && grep -q 'no pude conectar' '$T/out'"
check "ssh falla: no llama a scp" "! grep -q '^scp' '$T/log'"

# 11. sin vendor/lynis, destino inexistente
rm -rf "$T/repo/vendor/lynis"; lanza "" "$LANZ" -d "$T/dest" u@10.0.0.9; rc=$?
check "sin vendor/lynis: exit 1 y sin llamadas" "[ $rc -eq 1 ] && [ ! -s '$T/log' ]"
mkdir -p "$T/repo/vendor/lynis"
lanza "" "$LANZ" -d "$T/no-existe" u@10.0.0.9; rc=$?
check "destino local inexistente: exit 1 y sin llamadas" "[ $rc -eq 1 ] && [ ! -s '$T/log' ]"

printf '\n%s pruebas, %s fallos\n' "$N" "$FAIL"
[ "$FAIL" -eq 0 ]
