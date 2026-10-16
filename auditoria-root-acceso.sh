#!/usr/bin/env bash
# auditoria-root-acceso.sh — menú de auditoría de seguridad básica (SOLO LECTURA)
# Prioridad: determinar quién habilitó el acceso root por SSH.
# Uso: sudo ./auditoria-root-acceso.sh [--all] [-o DIR]
# No instala paquetes, no modifica configuración, no toca la red.
set -u
set -o pipefail
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"

VERSION="0.2.0-paso2"
OUT_BASE="$PWD"   # la evidencia queda en el directorio actual (sin /tmp)
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

# --- paso 2: acceso a root (quién lo habilitó) --------------------------------
# Solo lectura. Reúne: estado efectivo, línea de tiempo de archivos, y rastros
# de quién los tocó (logs, auditd, historiales). Sin auditd/logs viejos el
# "quién" puede quedar INDETERMINADO: el resumen lo dice explícitamente.
paso_02_root() {
  local f="$EVID/02-root-acceso.txt" r="$EVID/02-resumen.txt"; : >"$f"; : >"$r"
  local u

  # 2.1 Estado efectivo de SSH para root (considera Match y drop-ins).
  if have sshd; then
    run "$f" bash -c 'sshd -T 2>&1 | grep -Ei "^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|authenticationmethods|permitemptypasswords|usepam)"'
    run "$f" sshd -T -C user=root,host=localhost,addr=127.0.0.1
    run "$f" bash -c 'sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>&1 | grep -i "^permitrootlogin"'
  else
    say "  sshd no está instalado: se omite el estado efectivo."
  fi
  run "$f" bash -c 'grep -RnEi "^[[:space:]]*(PermitRootLogin|Match|Include|AllowUsers|AllowGroups|DenyUsers|DenyGroups|AuthorizedKeysFile)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>&1'
  # Instalación/paquete: ¿la config difiere de la que trae el paquete?
  have dpkg && run "$f" bash -c 'dpkg -V openssh-server 2>&1'
  have rpm  && run "$f" bash -c 'rpm -V openssh-server 2>&1'

  # 2.2 Línea de tiempo: cuándo cambió cada archivo relevante (ctime = cambio real).
  run "$f" bash -c 'ls -la --time-style=full-iso /etc/ssh /etc/ssh/sshd_config.d 2>&1'
  run "$f" bash -c 'stat -c "%z | mtime=%y | %U:%G %a | %n" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d/* /etc/pam.d/su /etc/pam.d/sshd /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /etc/ssh/authorized_keys/* 2>/dev/null | sort'
  run "$f" bash -c 'find /etc/ssh /root/.ssh /etc/sudoers.d -type f \( -name "*.bak*" -o -name "*.orig" -o -name "*~" -o -name "*.save" -o -name "*.rpmsave" -o -name "*.dpkg-*" \) -exec stat -c "%z | %n" {} + 2>&1'

  # 2.3 Cuentas con poder de root.
  run "$f" bash -c 'awk -F: "\$3==0 {print}" /etc/passwd'
  run "$f" bash -c 'getent passwd root; passwd -S root 2>&1; chage -l root 2>&1'
  run "$f" bash -c 'getent group sudo wheel admin root'
  run "$f" bash -c 'grep -RvE "^[[:space:]]*(#|$)" /etc/sudoers /etc/sudoers.d 2>&1'
  run "$f" bash -c 'grep -vE "^[[:space:]]*(#|$)" /etc/pam.d/su /etc/pam.d/su-l 2>&1'
  run "$f" bash -c 'grep -E "^(passwd|group|shadow|sudoers)" /etc/nsswitch.conf'

  # 2.4 authorized_keys de root: huella y comentario (la llave pública no es secreta).
  local ak
  for ak in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [ -f "$ak" ] || continue
    run "$f" bash -c "stat -c '%n | ctime=%z | mtime=%y | %U %a' '$ak'; wc -l '$ak'; ssh-keygen -lf '$ak' 2>&1; grep -nE '^(command=|from=|no-)' '$ak' | cut -c1-120"
  done
  run "$f" bash -c 'ls -la /root/.ssh 2>&1'

  # 2.5 Quién entró como root y cuándo.
  run "$f" bash -c 'last -F -n 50 root 2>&1'
  run "$f" bash -c 'lastlog -u root 2>&1'
  run "$f" bash -c 'zgrep -hE "Accepted .* for root" /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 100'
  have journalctl && run "$f" bash -c 'journalctl --no-pager -q -u ssh -u sshd 2>&1 | grep -E "Accepted .* for root|Failed .* for root" | tail -n 100'
  have journalctl && run "$f" bash -c 'journalctl --no-pager -q --disk-usage 2>&1; journalctl --no-pager -q 2>&1 | head -n 2'

  # 2.6 Quién modificó (rastros). Cada fuente se guarda aparte para citarla.
  local pat='sshd_config|PermitRootLogin|authorized_keys|passwd root|chpasswd|usermod|visudo|sudoers|sudo -i|sudo su|su -'
  run "$f" bash -c "zgrep -hE 'COMMAND=.*($pat)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 200"
  have journalctl && run "$f" bash -c "journalctl --no-pager -q _COMM=sudo 2>&1 | grep -E '$pat' | tail -n 200"
  # Historiales de shell (evidencia débil: editable por el dueño).
  run "$f" bash -c "for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do [ -f \"\$h\" ] && { echo \"== \$h\"; grep -nE '$pat' \"\$h\" | tail -n 50; }; done 2>&1"
  # auditd: la única fuente que atribuye por UID real (auid).
  if have ausearch; then
    run "$f" bash -c 'auditctl -l 2>&1'
    for u in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh/authorized_keys /etc/passwd /etc/shadow /etc/sudoers; do
      run "$f" bash -c "ausearch -i -f '$u' 2>&1 | tail -n 60"
    done
  else
    printf 'AUDITD=no: sin auditd no hay atribución fiable por auid.\n' >>"$f"
  fi

  # 2.7 FreeIPA: root/sudo pueden venir del dominio, no del host.
  if grep -q '^FREEIPA=si' "$EVID/.freeipa" 2>/dev/null; then
    run "$f" bash -c 'grep -vE "^[[:space:]]*(#|$)" /etc/sssd/sssd.conf 2>&1 | grep -viE "password|secret"'
    run "$f" bash -c 'sudo -l -U root 2>&1 | head -n 40'
    printf 'MANUAL(FreeIPA): en el servidor IPA con ticket admin: ipa hbacrule-find; ipa sudorule-find; ipa user-show root --all\n' >>"$f"
  fi

  # Resumen mecánico (hechos, sin interpretar).
  {
    printf '== Resumen paso 2 (%s) ==\n' "$HOST"
    printf 'permitrootlogin efectivo (root@localhost): '
    sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -i '^permitrootlogin' || echo 'no determinado'
    printf 'UID 0: '; awk -F: '$3==0{printf "%s ",$1}' /etc/passwd; echo
    printf 'auditd: '; { have ausearch && echo si; } || echo no
    printf 'Archivos clave por ctime (más reciente al final):\n'
    stat -c '  %z  %n' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /root/.ssh/authorized_keys /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort
    printf 'Detalle completo en: %s\n' "$f"
  } >"$r"
  ESTADO[2]="ok"
  say "Paso 2 listo → $f"; cat "$r"
}
paso_03_ssh() {
  local f="$EVID/03-ssh-hardening.txt" r="$EVID/03-resumen.txt"; : >"$f"; : >"$r"
  if ! have sshd; then
    echo "sshd no instalado: no aplica" | tee -a "$f" >"$r"; ESTADO[3]="ok"; say "Paso 3: sshd no instalado"; return
  fi
  local cfg="$EVID/03-sshd-T.txt"
  sshd -T -C user=root,host=localhost,addr=127.0.0.1 >"$cfg" 2>>"$f" || run "$f" echo "sshd -T falló (ver arriba)"
  run "$f" sshd -V
  run "$f" bash -c 'stat -c "%a %U:%G %n" /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub 2>&1'
  run "$f" bash -c 'ls -la /etc/ssh/sshd_config.d 2>&1; grep -nE "^[[:space:]]*(Include|Match)" /etc/ssh/sshd_config'
  run "$f" bash -c 'cat /etc/issue.net 2>&1 | head -n 5'

  # Tabla CIS L2: directiva | regla | valor requerido. Reglas: eq (igual), le (<=), gt (>0), ne (distinto),
  # nocontain (lista sin ninguno de los patrones débiles).
  local rules=(
    "permitrootlogin|eq|no"
    "passwordauthentication|eq|no"
    "permitemptypasswords|eq|no"
    "pubkeyauthentication|eq|yes"
    "hostbasedauthentication|eq|no"
    "ignorerhosts|eq|yes"
    "strictmodes|eq|yes"
    "usepam|eq|yes"
    "permituserenvironment|eq|no"
    "x11forwarding|eq|no"
    "allowtcpforwarding|eq|no"
    "allowagentforwarding|eq|no"
    "permittunnel|eq|no"
    "gssapiauthentication|eq|no"
    "kerberosauthentication|eq|no"
    "loglevel|in|verbose,info"
    "maxauthtries|le|4"
    "logingracetime|le|60"
    "maxsessions|le|10"
    "clientaliveinterval|gt|0"
    "clientalivecountmax|le|3"
    "banner|ne|none"
    "ciphers|nocontain|3des|cbc|arcfour|rc4|blowfish|cast128"
    "macs|nocontain|md5|sha1-|umac-64|96"
    "kexalgorithms|nocontain|group1-|group14-sha1|group-exchange-sha1"
  )
  local fail=0 total=0 line d rule val act ok pats
  {
    printf '== CIS L2 SSH (%s) — valores de sshd -T con Match root ==\n' "$HOST"
    printf '%-26s %-10s %-28s %s\n' DIRECTIVA ESTADO ACTUAL REQUERIDO
  } >"$r"
  for line in "${rules[@]}"; do
    IFS='|' read -r d rule val pats <<<"$line"
    act="$(awk -v k="$d" '$1==k{$1="";sub(/^ /,"");print;exit}' "$cfg" 2>/dev/null)"
    ok="FAIL"; total=$((total+1))
    if [ -z "$act" ]; then ok="NODET"
    else
      case "$rule" in
        eq) [ "$act" = "$val" ] && ok="OK" ;;
        in) case ",$val," in *",$act,"*) ok="OK" ;; esac ;;
        le) [[ "$act" =~ ^[0-9]+$ ]] && [ "$act" -le "$val" ] && ok="OK" ;;
        gt) [[ "$act" =~ ^[0-9]+$ ]] && [ "$act" -gt "$val" ] && ok="OK" ;;
        ne) [ "$act" != "$val" ] && ok="OK" ;;
        nocontain) ok="OK"; local p; for p in "$val" ${pats//|/ }; do
                     printf '%s' "$act" | grep -qiE -- "$p" && { ok="FAIL"; break; }; done ;;
      esac
    fi
    [ "$ok" = "OK" ] || fail=$((fail+1))
    printf '%-26s %-10s %-28s %s %s\n' "$d" "$ok" "$(printf '%s' "$act" | cut -c1-28)" "$rule" "$val${pats:+|$pats}" >>"$r"
  done
  {
    printf 'Incumplen o sin determinar: %s de %s\n' "$fail" "$total"
    printf 'Nota: ciphers/macs/kex se evalúan por patrones débiles (grep); revisar a mano el detalle en %s\n' "$cfg"
    printf 'Detalle: %s\n' "$f"
  } >>"$r"
  ESTADO[3]="ok"
  say "Paso 3 listo → $f"; cat "$r"
}
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
