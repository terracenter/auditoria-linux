#!/usr/bin/env bash
# test-agentes.sh — pruebas de la detección de Zabbix agent y cliente GLPI (paso 1 de
# auditoria-root-acceso.sh). Usa id/systemctl/binarios FALSOS al inicio del PATH para correr sin root.
# No toca el host: la evidencia va a un directorio temporal. El caso "sin agentes" se omite
# (SKIP) si esta máquina ya tiene Zabbix o GLPI instalados.
# Uso: ./tests/test-agentes.sh
set -u
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$AQUI/auditoria-root-acceso.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0; N=0
ok()   { N=$((N+1)); printf 'PASS  %s\n' "$1"; }
bad()  { N=$((N+1)); FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -p "$T/sin" "$T/con"
printf '#!/bin/bash\n[ "${1:-}" = "-u" ] && echo 0 || /usr/bin/id "$@"\n' >"$T/sin/id"
cp "$T/sin/id" "$T/con/id"
printf '#!/bin/bash\necho "zabbix_agent2 (daemon) v6.0.0"\n' >"$T/con/zabbix_agent2"
printf '#!/bin/bash\necho "GLPI Agent (1.7.1)"\n' >"$T/con/glpi-agent"
cat >"$T/con/systemctl" <<'EOF'
#!/bin/bash
case "$1" in
 list-unit-files) case "$3" in zabbix-agent2.service|glpi-agent.service) echo "$3 enabled";; esac ;;
 is-active) case "$2" in zabbix-agent2) echo active;; *) echo inactive; exit 3;; esac ;;
 is-enabled) echo enabled ;;
 *) exit 0 ;;
esac
EOF
chmod +x "$T/sin/"* "$T/con/"*

# paso 1 solo: opción 1 del menú y salir
paso1() { # $1 = dir de falsos, $2 = dir de salida
  mkdir -p "$2"; printf '1\nq\n' | env PATH="$1:$PATH" bash "$SCRIPT" -o "$2" >"$2/stdout.txt" 2>&1
}
ev() { printf '%s' "$(cat "$1"/auditoria-root-*/"$2" 2>/dev/null)"; }

# A. sin agentes (omitido si la máquina de pruebas ya los tiene)
if [ -d /etc/zabbix ] || [ -d /etc/glpi-agent ] || command -v zabbix_agent2 >/dev/null 2>&1 \
   || command -v zabbix_agentd >/dev/null 2>&1 || command -v glpi-agent >/dev/null 2>&1; then
  printf 'SKIP  caso sin agentes: esta máquina ya tiene Zabbix o GLPI\n'
else
  paso1 "$T/sin" "$T/A"
  check "sin agentes: ZABBIX_AGENT=no" "[ \"\$(ev '$T/A' .zabbix)\" = 'ZABBIX_AGENT=no' ]"
  check "sin agentes: GLPI_AGENT=no" "[ \"\$(ev '$T/A' .glpi)\" = 'GLPI_AGENT=no' ]"
  check "sin agentes: POLITICA_FIBEX FALLA/FALLA" "grep -q 'POLITICA_FIBEX zabbix_agent=FALLA glpi_agent=FALLA' '$T'/A/auditoria-root-*/01-preflight.txt"
  check "sin agentes: avisa por los dos" "[ \"\$(grep -c 'AVISO política Fibex' '$T/A/stdout.txt')\" = 2 ]"
fi

# B. Zabbix activo, GLPI instalado pero inactivo
paso1 "$T/con" "$T/B"
check "Zabbix activo" "[ \"\$(ev '$T/B' .zabbix)\" = 'ZABBIX_AGENT=activo' ]"
check "GLPI instalado-inactivo" "[ \"\$(ev '$T/B' .glpi)\" = 'GLPI_AGENT=instalado-inactivo' ]"
check "POLITICA_FIBEX OK/FALLA" "grep -q 'POLITICA_FIBEX zabbix_agent=OK glpi_agent=FALLA' '$T'/B/auditoria-root-*/01-preflight.txt"
check "avisa solo por GLPI" "[ \"\$(grep -c 'AVISO política Fibex' '$T/B/stdout.txt')\" = 1 ] && grep -q 'cliente GLPI no está activo' '$T/B/stdout.txt'"

# C. la configuración nunca filtra secretos ni credenciales en URLs
mkdir -p "$T/cfg/conf.d"
printf 'Server=10.0.0.5\nHostname=h\nTLSPSKIdentity=SECRETO_ID\nTLSPSKFile=/x/SECRETO_FILE\n' >"$T/cfg/z.conf"
printf 'server = https://adm:SECRETO_URL@glpi.x/\ntag = fibex\nuser = u\npassword = SECRETO_PASS\nproxy = http://a:SECRETO_PROXY@p:3128\n' >"$T/cfg/agent.cfg"
printf 'server = https://otro/\npassword = SECRETO_CONFD\n' >"$T/cfg/conf.d/x.cfg"
bash -c '
have(){ command -v "$1" >/dev/null 2>&1; }
run(){ local f="$1"; shift; { printf "$ %s\n" "$*"; "$@" 2>&1; printf "[rc=%s]\n\n" "$?"; } >>"$f" 2>&1; }
'"$(sed -n '/^detectar_agente()/,/^}/p' "$SCRIPT")"'
f="'"$T"'/cfg/out.txt"; : >"$f"
detectar_agente "$f" zabbix "" "" "'"$T"'/cfg/z.conf" "Server|ServerActive|Hostname|TLSConnect|TLSAccept" "" >/dev/null
detectar_agente "$f" glpi "" "" "'"$T"'/cfg/agent.cfg '"$T"'/cfg/conf.d/*.cfg" "server|tag|local|no-ssl-check" "" >/dev/null'
check "config: no aparece ningún SECRETO" "! grep -q SECRETO '$T/cfg/out.txt'"
check "config: sí copia Server, Hostname, server y tag" "grep -q 'Server=10.0.0.5' '$T/cfg/out.txt' && grep -q 'Hostname=h' '$T/cfg/out.txt' && grep -q 'tag = fibex' '$T/cfg/out.txt'"
check "config: enmascara credenciales de URL" "grep -q 'server = https://\*\*\*@glpi.x/' '$T/cfg/out.txt'"
check "config: lee conf.d/*.cfg" "grep -q 'server = https://otro/' '$T/cfg/out.txt'"

# D. los archivos de la detección viajan dentro del paquete (.tar.gz)
mkdir -p "$T/D"; printf 'a\nq\n' | env PATH="$T/con:$PATH" bash "$SCRIPT" -o "$T/D" >"$T/D/stdout.txt" 2>&1
check "paquete incluye .zabbix, .glpi y .freeipa" "[ \"\$(tar -tzf '$T'/D/auditoria-root-*.tar.gz | grep -cE '/\.(zabbix|glpi|freeipa)\$')\" = 3 ]"

printf '\n%s pruebas, %s fallos\n' "$N" "$FAIL"
[ "$FAIL" -eq 0 ]
