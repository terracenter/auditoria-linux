#!/usr/bin/env bash
# auditoria-root-acceso.sh — menú de auditoría de seguridad básica (SOLO LECTURA)
# Prioridad: determinar quién habilitó el acceso root por SSH.
# Uso: sudo ./auditoria-root-acceso.sh [--all] [-o DIR]
# No instala paquetes, no modifica configuración, no toca la red.
set -u
set -o pipefail
PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"

VERSION="0.8.0-paso8"
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
umask 077   # evidencia y paquete solo legibles por root desde su creación
[ -L "$OUT_BASE" ] && { echo "$OUT_BASE es un symlink: abortando" >&2; exit 1; }
mkdir -p "$OUT_BASE" && mkdir "$EVID" || { echo "No puedo crear $EVID" >&2; exit 1; }

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
  [ -f /etc/ipa/default.conf ] && ipa="si"   # enrolado (el paquete solo no basta)
  [ -f /etc/sssd/sssd.conf ] && run "$f" bash -c 'grep -E "^(\[|id_provider|auth_provider|access_provider|sudo_provider|ipa_domain|ldap_uri)" /etc/sssd/sssd.conf 2>&1'
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
    run "$f" bash -c 'sshd -T 2>&1 | grep -Ei "^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|authorizedprincipalsfile|authorizedprincipalscommand|trustedusercakeys|authenticationmethods|permitemptypasswords|usepam)"'
    run "$f" sshd -T -C user=root,host=localhost,addr=127.0.0.1
    for a in 127.0.0.1 10.0.0.1 192.168.1.1 203.0.113.1; do
      run "$f" bash -c "echo addr=$a; sshd -T -C user=root,host=remoto,addr=$a 2>&1 | grep -iE '^(permitrootlogin|passwordauthentication|authenticationmethods)'"
    done
    run "$f" bash -c 'echo "Bloques Match (pueden cambiar el valor por origen/usuario):"; grep -RniE "^[[:space:]]*Match" /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>&1'
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
  local akf; akf="$(sshd -T 2>/dev/null | awk '$1=="authorizedkeysfile"{for(i=2;i<=NF;i++)print $i}' | sed "s|%h|/root|g;s|%u|root|g")"
  for ak in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 $(printf "%s\n" "$akf" | grep "^/"); do
    [ -f "$ak" ] || continue
    run "$f" bash -c "stat -c '%n | ctime=%z | mtime=%y | %U %a' '$ak'; wc -l '$ak'; ssh-keygen -lf '$ak' 2>&1; grep -nE '^(command=|from=|no-)' '$ak' | cut -c1-120"
  done
  run "$f" bash -c 'ls -la /root/.ssh 2>&1'

  # 2.5 Quién entró como root y cuándo.
  run "$f" bash -c 'last -F -n 50 root 2>&1'
  run "$f" bash -c 'lastlog -u root 2>&1'
  run "$f" bash -c 'zgrep -hE "Accepted .* for root from" /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 100'
  have journalctl && run "$f" bash -c 'journalctl --no-pager -q -u ssh -u sshd 2>&1 | grep -E "Accepted .* for root from|Failed .* for root from" | tail -n 100'
  have journalctl && run "$f" bash -c 'journalctl --no-pager -q --disk-usage 2>&1; journalctl --no-pager -q 2>&1 | head -n 2'

  # 2.6 Quién modificó (rastros). Cada fuente se guarda aparte para citarla.
  local pat='sshd_config|PermitRootLogin|authorized_keys|passwd root|chpasswd|usermod|visudo|sudoers|sudo -i|sudo su|su -'
  run "$f" bash -c "zgrep -hE 'COMMAND=.*($pat)' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -n 200"
  have journalctl && run "$f" bash -c "journalctl --no-pager -q _COMM=sudo 2>&1 | grep -E '$pat' | tail -n 200"
  # Historiales de shell (evidencia débil: editable por el dueño).
  run "$f" bash -c "for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do [ -f \"\$h\" ] && { echo \"== \$h\"; grep -noE '$pat' \"\$h\" | tail -n 50; }; done 2>&1"
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
  if [ -f /etc/ipa/default.conf ] || grep -qs 'id_provider *= *ipa' /etc/sssd/sssd.conf; then
    run "$f" bash -c 'grep -vE "^[[:space:]]*(#|$)" /etc/sssd/sssd.conf 2>&1 | grep -viE "password|secret|authtok"'
    run "$f" bash -c 'sudo -l -U root 2>&1 | head -n 40'
    printf 'MANUAL(FreeIPA): en el servidor IPA con ticket admin: ipa hbacrule-find; ipa sudorule-find; ipa user-show root --all\n' >>"$f"
  fi

  # Resumen mecánico (hechos, sin interpretar).
  {
    printf '== Resumen paso 2 (%s) ==\n' "$HOST"
    printf 'permitrootlogin efectivo (root@localhost): '
    sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -i '^permitrootlogin' || echo 'no determinado'
    printf 'UID 0: '; awk -F: '$3==0{printf "%s ",$1}' /etc/passwd; echo
    local aud=no
    if have auditctl && auditctl -l 2>/dev/null | grep -qE 'sshd_config|authorized_keys|/etc/passwd|/etc/sudoers'; then aud="si, con reglas sobre archivos relevantes"
    elif have auditctl; then aud="instalado SIN reglas sobre sshd_config/authorized_keys/sudoers (no habrá atribución por auid)"; fi
    printf 'auditd: %s\n' "$aud"
    printf 'Match: %s bloque(s) en sshd_config*; el valor efectivo depende de usuario/origen (ver 02-root-acceso.txt, addr=...)\n' "$(grep -RiEc '^[[:space:]]*Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')"
    printf 'Vías alternativas de llave: authorizedkeyscommand=%s trustedusercakeys=%s\n' "$(sshd -T 2>/dev/null | awk '$1=="authorizedkeyscommand"{print $2}')" "$(sshd -T 2>/dev/null | awk '$1=="trustedusercakeys"{print $2}')"
    printf 'Archivos clave por ctime (más reciente al final):\n'
    stat -c '  %z  %n' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /root/.ssh/authorized_keys /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort
    printf 'Detalle completo en: %s\n' "$f"
    printf '\n== QUIÉN habilitó root ==\n'
    case "$aud" in
      si*) printf 'Hay auditd con reglas: buscar en 02-root-acceso.txt las líneas ausearch (auid = usuario real). Atribución posible, no automática.\n' ;;
      *) printf 'INDETERMINADO por fuentes del host: sin auditd con reglas no hay atribución fiable. Pistas débiles: ctime de archivos (CUÁNDO, no QUIÉN), sudo en auth.log/journal (solo si no se usó una shell previa: sudo -i / su registran la shell, no lo hecho dentro), historiales (editables). Con FreeIPA/LDAP revisar además el servidor.\n' ;;
    esac
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
paso_04_sudo() {
  local f="$EVID/04-sudo-pam-su.txt" r="$EVID/04-resumen.txt"; : >"$f"; : >"$r"
  local sd; sd="$(grep -rhvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null)"
  printf '%s\n' "$sd" >"$EVID/04-sudoers-efectivo.txt"

  run "$f" bash -c 'stat -c "%a %U:%G %n" /etc/sudoers /etc/sudoers.d /etc/sudoers.d/* /etc/pam.d/su /etc/shadow /etc/gshadow /etc/passwd /etc/group 2>&1'
  have visudo && run "$f" visudo -c
  have sudo && run "$f" sudo -V
  run "$f" bash -c 'grep -RnE "NOPASSWD|!authenticate|ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]*ALL|Defaults" /etc/sudoers /etc/sudoers.d 2>&1 | grep -v ":[[:space:]]*#"'
  run "$f" bash -c 'getent group sudo wheel admin root'
  run "$f" bash -c 'grep -nE "pam_wheel|pam_rootok|pam_securetty|pam_faillock|pam_tally2|pwquality|pam_unix" /etc/pam.d/su /etc/pam.d/su-l /etc/pam.d/sudo /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth 2>&1'
  run "$f" bash -c 'cat /etc/security/pwquality.conf 2>&1 | grep -vE "^[[:space:]]*(#|$)"; cat /etc/security/faillock.conf 2>&1 | grep -vE "^[[:space:]]*(#|$)"'
  run "$f" bash -c 'grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD|SU_WHEEL_ONLY|LOGIN_RETRIES)" /etc/login.defs'
  run "$f" bash -c 'getent passwd root; passwd -S root 2>&1; chage -l root 2>&1'
  run "$f" bash -c 'cat /etc/securetty 2>&1 | head -n 20'
  run "$f" bash -c 'grep -nE "TMOUT|umask|^(export )?PATH" /root/.bashrc /root/.profile /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc 2>&1'
  run "$f" bash -c 'echo "PATH de root:"; sudo -n env 2>/dev/null | grep ^PATH; echo "$PATH" | tr ":" "\n" | grep -nE "^\.?$|^\." '
  # Cuentas
  run "$f" bash -c 'awk -F: "(\$2==\"\" ){print \"SIN PASSWORD: \" \$1}" /etc/shadow 2>&1'
  run "$f" bash -c 'awk -F: "\$3==0{print \"UID0: \" \$1}" /etc/passwd; cut -d: -f3 /etc/passwd | sort | uniq -d | sed "s/^/UID duplicado: /"'
  run "$f" bash -c 'awk -F: "\$3>=1000 && \$7!~/nologin|false/ {print \$1\":\"\$3\":\"\$7}" /etc/passwd'
  run "$f" bash -c 'awk -F: "{if(\$2!~/^(\*|!|!!|!\*)\$/) print \$1\" lastchg=\"\$3\" max=\"\$5}" /etc/shadow 2>&1'
  run "$f" bash -c 'grep -RE "^[^#]*(NOPASSWD)" /etc/sudoers /etc/sudoers.d 2>&1 | cut -d: -f1 | sort -u'

  # Evaluación mecánica
  local n=0 bad=0
  chk() { n=$((n+1)); [ "$2" = "OK" ] || bad=$((bad+1)); printf '%-44s %-8s %s\n' "$1" "$2" "$3" >>"$r"; }
  printf '== CIS L2 sudo/PAM/su/root (%s) ==\n%-44s %-8s %s\n' "$HOST" CONTROL ESTADO DETALLE >"$r"
  if [ ! -r /etc/sudoers ]; then
    chk "sudoers legible (ejecutar como root)" NODET "sin lectura: controles sudo no evaluados"
  elif have sudo; then
    printf '%s' "$sd" | grep -qE '^[[:space:]]*Defaults[[:space:]].*use_pty' && chk "sudo use_pty" OK "" || chk "sudo use_pty" FAIL "falta Defaults use_pty"
    printf '%s' "$sd" | grep -qE '^[[:space:]]*Defaults[[:space:]].*logfile' && chk "sudo logfile" OK "" || chk "sudo logfile" FAIL "falta Defaults logfile (CIS 5.2.3)"
    printf '%s' "$sd" | grep -qE 'NOPASSWD|!authenticate' && chk "sudo sin NOPASSWD/!authenticate" FAIL "$(printf '%s' "$sd" | grep -cE 'NOPASSWD|!authenticate') regla(s)" || chk "sudo sin NOPASSWD/!authenticate" OK ""
    printf '%s' "$sd" | grep -qE 'timestamp_timeout[[:space:]]*=[[:space:]]*(-1|[6-9]|[1-9][0-9])' && chk "sudo timestamp_timeout <=5" FAIL "" || chk "sudo timestamp_timeout <=5" OK "(defecto 5 o menor)"
  else
    chk "sudo instalado" NODET "sudo no instalado"
  fi
  grep -qE '^[^#]*pam_wheel\.so.*(use_uid)' /etc/pam.d/su 2>/dev/null && chk "su restringido (pam_wheel use_uid)" OK "" || chk "su restringido (pam_wheel use_uid)" FAIL "/etc/pam.d/su sin pam_wheel activo"
  local rp; rp="$(passwd -S root 2>/dev/null | awk '{print $2}')"
  [ -n "$rp" ] && chk "estado password de root" OK "passwd -S: $rp (L=bloqueada, P=activa; decisión de política)" || chk "estado password de root" NODET ""
  [ "$(awk -F: '$3==0{c++}END{print c+0}' /etc/passwd)" = 1 ] && chk "único UID 0" OK "" || chk "único UID 0" FAIL "$(awk -F: '$3==0{printf "%s ",$1}' /etc/passwd)"
  [ -z "$(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null)" ] && chk "sin cuentas con password vacío" OK "" || chk "sin cuentas con password vacío" FAIL "$(awk -F: '$2==""{printf "%s ",$1}' /etc/shadow 2>/dev/null)"
  [ "$(stat -c %a /etc/shadow 2>/dev/null)" -le 640 ] 2>/dev/null && chk "permisos /etc/shadow <=640" OK "" || chk "permisos /etc/shadow <=640" FAIL "$(stat -c %a /etc/shadow 2>/dev/null)"
  local pm; pm="$(awk '$1=="PASS_MAX_DAYS"{print $2}' /etc/login.defs 2>/dev/null)"
  [ -n "$pm" ] && [ "$pm" -le 365 ] 2>/dev/null && chk "PASS_MAX_DAYS <=365" OK "$pm" || chk "PASS_MAX_DAYS <=365" FAIL "${pm:-no definido}"
  { grep -qE '^[^#]*pam_(faillock|tally2)' /etc/pam.d/* 2>/dev/null || [ -s /etc/security/faillock.conf ]; } && chk "bloqueo por intentos (faillock)" OK "" || chk "bloqueo por intentos (faillock)" FAIL "no configurado"
  grep -rqE '^[[:space:]]*minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d 2>/dev/null && chk "pwquality minlen" OK "" || chk "pwquality minlen" FAIL "no definido"
  printf 'Incumplen o sin determinar: %s de %s\nDetalle: %s\n' "$bad" "$n" "$f" >>"$r"
  ESTADO[4]="ok"
  say "Paso 4 listo → $f"; cat "$r"
}
# --- paso 5: firewall --------------------------------------------------------
# Solo lectura. Detecta motores activos, evalúa política por defecto (CIS 3.5)
# y lista los puertos en escucha no-loopback para cruzarlos con las reglas.
paso_05_firewall() {
  local f="$EVID/05-firewall.txt" r="$EVID/05-resumen.txt"; : >"$f"
  local n=0 bad=0 act=0 pol_ok=0
  chk() { n=$((n+1)); [ "$2" = "OK" ] || bad=$((bad+1)); printf '%-44s %-8s %s\n' "$1" "$2" "$3" >>"$r"; }
  printf '== CIS L2 firewall (%s) ==\n%-44s %-8s %s\n' "$HOST" CONTROL ESTADO DETALLE >"$r"

  # Motores: instalado vs activo (no se asume nada por la sola presencia).
  local e
  for e in nftables ufw firewalld iptables netfilter-persistent pve-firewall; do
    have systemctl && printf '%s active=%s enabled=%s\n' "$e" \
      "$(systemctl is-active "$e" 2>&1)" "$(systemctl is-enabled "$e" 2>&1)" >>"$f"
  done
  [ "$(id -u)" -ne 0 ] && chk "ejecutado como root" NODET "sin root no se leen reglas (nft/iptables)"

  # nftables
  if have nft; then
    run "$f" nft list ruleset
    local nr; nr="$(nft list ruleset 2>/dev/null)"
    if [ -n "$nr" ]; then
      act=$((act+1))
      printf '%s' "$nr" | grep -E 'hook input' | grep -q 'policy drop' \
        && pol_ok=1 && chk "nft chain input policy drop" OK "" \
        || { printf '%s' "$nr" | grep -qE 'hook input' \
             && chk "nft chain input policy drop" FAIL "hook input sin policy drop (¿drop final en regla?: revisar 05-firewall.txt)" \
             || chk "nft chain input policy drop" FAIL "sin cadena con hook input"; }
    fi
  fi
  # iptables / ip6tables
  local ipt
  for ipt in iptables ip6tables; do
    have "$ipt" || continue
    run "$f" "$ipt" -S
    local pr; pr="$("$ipt" -S 2>/dev/null | awk '$1=="-P"&&$2=="INPUT"{print $3}')"
    if [ -n "$pr" ]; then
      [ "$("$ipt" -S 2>/dev/null | grep -c '^-A')" -gt 0 ] || [ "$pr" = DROP ] && act=$((act+1))
      [ "$pr" = DROP ] || [ "$pr" = REJECT ] \
        && { pol_ok=1; chk "$ipt INPUT policy DROP" OK ""; } \
        || chk "$ipt INPUT policy DROP" FAIL "policy=$pr (si hay DROP final por regla, validar a mano)"
    fi
  done
  # ufw
  if have ufw; then
    run "$f" ufw status verbose
    if ufw status 2>/dev/null | grep -q 'Status: active'; then
      act=$((act+1))
      ufw status verbose 2>/dev/null | grep -qE 'Default: (deny|reject) \(incoming\)' \
        && { pol_ok=1; chk "ufw default deny incoming" OK ""; } || chk "ufw default deny incoming" FAIL ""
    fi
  fi
  # firewalld
  if have firewall-cmd; then
    run "$f" firewall-cmd --state
    run "$f" firewall-cmd --list-all-zones
    if [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
      act=$((act+1))
      local z t; z="$(firewall-cmd --get-default-zone 2>/dev/null)"
      t="$(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null)"
      case "$t" in default|DROP|REJECT) pol_ok=1; chk "firewalld zona $z" OK "target=$t" ;; *) chk "firewalld zona $z" FAIL "target=$t" ;; esac
    fi
  fi
  # Proxmox
  if have pve-firewall; then
    run "$f" pve-firewall status
    run "$f" bash -c 'cat /etc/pve/firewall/cluster.fw /etc/pve/local/host.fw 2>&1'
    pve-firewall status 2>/dev/null | grep -q 'Status: enabled' && act=$((act+1)) \
      && { grep -qE 'policy_in: *(DROP|REJECT)' /etc/pve/firewall/cluster.fw 2>/dev/null && { pol_ok=1; chk "PVE policy_in DROP" OK ""; } || chk "PVE policy_in DROP" FAIL "cluster.fw sin policy_in DROP/REJECT"; }
  fi

  [ "$act" -ge 1 ] && chk "firewall activo (motores: $act)" OK "" || chk "firewall activo" FAIL "ningún motor con reglas/activo"
  [ "$act" -gt 2 ] && chk "un solo motor gestionando" FAIL "$act motores activos: riesgo de conflicto"
  [ "$pol_ok" -eq 1 ] || chk "política por defecto deny entrante" FAIL "ninguna política DROP/deny detectada"

  # Escucha no-loopback (cruce manual con reglas: exposición real)
  { printf '\n== Puertos en escucha NO loopback ==\n'
    ss -H -tulnp 2>/dev/null | awk '$5!~/^(127\.|\[::1\]|::1)/{print $1, $5, $7}'
  } >>"$f"
  ss -H -tulnp 2>/dev/null | awk '$5!~/^(127\.|\[::1\]|::1)/{print $1, $5, $7}' | sed 's/^/  expuesto: /' >>"$r"
  printf 'Incumplen o sin determinar: %s de %s\nDetalle: %s\n' "$bad" "$n" "$f" >>"$r"
  ESTADO[5]="ok"
  say "Paso 5 listo → $f"; cat "$r"
}
# --- paso 6: fail2ban --------------------------------------------------------
# Solo lectura. Cruza servicios en escucha (por nombre de proceso) con las
# jaulas activas: una jaula por servicio protegible. El mapeo es heurístico:
# lo no mapeado se lista como "sin regla conocida" para decisión manual.
paso_06_fail2ban() {
  local f="$EVID/06-fail2ban.txt" r="$EVID/06-resumen.txt"; : >"$f"
  local n=0 bad=0
  chk() { n=$((n+1)); [ "$2" = "OK" ] || bad=$((bad+1)); printf '%-44s %-8s %s\n' "$1" "$2" "$3" >>"$r"; }
  printf '== CIS L2 / Fail2ban (%s) ==\n%-44s %-8s %s\n' "$HOST" CONTROL ESTADO DETALLE >"$r"

  if ! have fail2ban-client; then
    chk "fail2ban instalado" FAIL "fail2ban-client no existe (instalar es acción correctiva, requiere aprobación)"
    ESTADO[6]="ok"; say "Paso 6 listo → $r"; cat "$r"; return
  fi
  have systemctl && run "$f" systemctl status fail2ban --no-pager
  run "$f" fail2ban-client version
  run "$f" fail2ban-client status
  [ "$(id -u)" -ne 0 ] && chk "ejecutado como root" NODET "fail2ban-client requiere root"
  local act; act="$(systemctl is-active fail2ban 2>&1)"
  [ "$act" = active ] && chk "servicio fail2ban activo" OK "" || chk "servicio fail2ban activo" FAIL "is-active=$act"
  have systemctl && [ "$(systemctl is-enabled fail2ban 2>&1)" = enabled ] \
    && chk "fail2ban habilitado al arranque" OK "" || chk "fail2ban habilitado al arranque" FAIL ""

  # Jaulas activas y su configuración efectiva
  local jails j
  jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ',')"
  for j in $jails; do
    run "$f" fail2ban-client status "$j"
    for k in maxretry findtime bantime; do run "$f" fail2ban-client get "$j" "$k"; done
  done
  run "$f" bash -c 'fail2ban-client -d 2>&1 | grep -E "banaction|ignoreip" | sort -u'
  run "$f" bash -c 'ls -l /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>&1'
  [ -n "$jails" ] && chk "jaulas activas" OK "$(printf '%s' "$jails" | wc -w): $jails" || chk "jaulas activas" FAIL "ninguna"

  # ignoreip: rangos amplios anulan la protección
  local ig; ig="$(fail2ban-client get "$(printf '%s' "$jails" | awk '{print $1}')" ignoreip 2>/dev/null | tr '\n' ' ')"
  [ -n "$jails" ] && printf '%s' "$ig" | grep -qE '(^|[ ,])(0\.0\.0\.0/0|10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16)' \
    && chk "ignoreip sin rangos amplios" FAIL "$ig" || chk "ignoreip sin rangos amplios" OK "$ig"

  # Cruce servicio en escucha -> jaula esperada (proceso:jaulas aceptables)
  local procs map p want hit
  procs="$(ss -H -tlnp 2>/dev/null | awk '$4!~/^(127\.|\[::1\])/' | grep -o '(("[^"]*"' | tr -d '("' | sort -u)"
  printf '\n== Servicios en escucha (no loopback) y jaula esperada ==\n' >>"$f"
  map='sshd:sshd nginx:nginx-http-auth|nginx-botsearch|nginx-limit-req apache2:apache-auth|apache-badbots httpd:apache-auth|apache-badbots postfix:postfix|postfix-sasl master:postfix|postfix-sasl dovecot:dovecot vsftpd:vsftpd proftpd:proftpd pure-ftpd:pure-ftpd mysqld:mysqld-auth mariadbd:mysqld-auth named:named-refused asterisk:asterisk pveproxy:proxmox exim4:exim'
  for p in $procs; do
    want="$(printf '%s\n' $map | awk -F: -v p="$p" '$1==p{print $2}')"
    if [ -z "$want" ]; then
      printf 'SIN_REGLA_CONOCIDA %s (decidir a mano si es protegible)\n' "$p" | tee -a "$f" >>"$r"; continue
    fi
    hit=""; for j in $jails; do printf '%s' "$j" | grep -qE "^($want)$" && hit="$j"; done
    printf '%s -> esperada(s): %s | activa: %s\n' "$p" "$want" "${hit:-NINGUNA}" >>"$f"
    [ -n "$hit" ] && chk "jaula para $p" OK "$hit" || chk "jaula para $p" FAIL "esperada: $want"
  done
  printf '%s' "$jails" | grep -qw recidive && chk "jaula recidive (L2)" OK "" || chk "jaula recidive (L2)" FAIL "reincidentes sin ban prolongado"

  printf 'Incumplen o sin determinar: %s de %s\nDetalle: %s\n' "$bad" "$n" "$f" >>"$r"
  ESTADO[6]="ok"
  say "Paso 6 listo → $f"; cat "$r"
}
# --- paso 7: Lynis (tarball vendorizado, no se instala) -----------------------
# Busca vendor/lynis junto al script. Verifica SHA256 (y GPG si hay gpg, con
# keyring aislado en la evidencia), extrae en la carpeta de evidencia y corre
# la auditoría. Obsolescencia: se evalúa el SO (EOL) y la edad del Lynis.
paso_07_lynis() {
  local f="$EVID/07-lynis.txt" r="$EVID/07-resumen.txt"; : >"$f"
  local n=0 bad=0
  chk() { n=$((n+1)); [ "$2" = "OK" ] || bad=$((bad+1)); printf '%-44s %-8s %s\n' "$1" "$2" "$3" >>"$r"; }
  printf '== Lynis (%s) ==\n%-44s %-8s %s\n' "$HOST" CONTROL ESTADO DETALLE >"$r"
  local here v tb
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; v="$here/vendor/lynis"
  # Valores FIJADOS en el script: el archivo verificado es exactamente el que se ejecuta.
  local LY_TGZ="lynis-3.1.7.tar.gz" LY_SHA="b5314a07fd85fa3ffc7da57b508f0108ec3280d84e4af823f805d95cbbc2428c"
  local LY_FPR="84FAA9983B24AEF24D6C87F1FEBB7D1812576482"
  tb="$v/$LY_TGZ"; [ -f "$tb" ] || tb=""
  if [ -z "$tb" ]; then
    chk "tarball vendorizado presente" FAIL "falta $v/lynis-3.1.7.tar.gz: copiar vendor/lynis/ junto al script (o instalar Lynis oficial y validar versión)"
    ESTADO[7]="ok"; say "Paso 7: sin Lynis → $r"; cat "$r"; return
  fi
  chk "tarball vendorizado presente" OK "$(basename "$tb")"

  # Integridad: SHA256 fijado en el script (no se confía en SHA256SUMS de la misma carpeta).
  if [ "$(sha256sum "$tb" | cut -d' ' -f1)" = "$LY_SHA" ]; then chk "SHA256 del tarball (fijado)" OK ""
  else chk "SHA256 del tarball (fijado)" FAIL "no coincide con el valor fijado: NO se ejecuta"; ESTADO[7]="ok"; say "Paso 7: integridad fallida"; cat "$r"; return; fi
  # Firma GPG OBLIGATORIA: keyring aislado, huella primaria fijada (VALIDSIG).
  if ! have gpg || [ ! -f "$tb.asc" ] || [ ! -f "$v/cisofy-software.pub" ]; then
    chk "firma GPG del tarball" FAIL "falta gpg, .asc o .pub: NO se ejecuta (instalar gpg en el host o verificar fuera de línea)"; ESTADO[7]="ok"; cat "$r"; return
  fi
  local gh="$EVID/.gnupg" st; mkdir -p "$gh" && chmod 700 "$gh"
  GNUPGHOME="$gh" gpg --batch --quiet --import "$v/cisofy-software.pub" >>"$f" 2>&1
  st="$(GNUPGHOME="$gh" gpg --batch --status-fd 1 --verify "$tb.asc" "$tb" 2>>"$f")"
  GNUPGHOME="$gh" gpgconf --kill all >/dev/null 2>&1; rm -rf "$gh"
  printf '%s\n' "$st" >>"$f"
  if printf '%s\n' "$st" | grep -qE "^\[GNUPG:\] VALIDSIG .* ${LY_FPR}\$"; then chk "firma GPG (huella fijada)" OK "$LY_FPR [D] huella por confirmar con CISOfy"
  else chk "firma GPG (huella fijada)" FAIL "firma inválida o huella distinta: NO se ejecuta"; ESTADO[7]="ok"; cat "$r"; return; fi

  # Extracción en la carpeta de evidencia (root, sin heredar dueños)
  local d="$EVID/lynis-run"; mkdir -p "$d" && tar -xzf "$tb" -C "$d" --no-same-owner >>"$f" 2>&1 \
    && chmod -R go-w "$d" || { chk "extracción" FAIL ""; ESTADO[7]="ok"; cat "$r"; return; }
  local ly="$d/lynis"
  [ -x "$ly/lynis" ] || { chk "extracción" FAIL "no existe $ly/lynis"; ESTADO[7]="ok"; cat "$r"; return; }

  # Obsolescencia del SO
  local id vid pretty; id="$(. /etc/os-release 2>/dev/null; echo "${ID:-?}")"
  vid="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-?}")"
  pretty="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}")"
  printf 'SO: %s (id=%s version=%s)\n' "$pretty" "$id" "$vid" >>"$f"
  case "$id:$vid" in
    centos:7*|rhel:7*|ol:7*) chk "SO soportado" FAIL "$pretty: fin de soporte (CentOS 7 EOL 2024-06-30); Lynis y paquetes pueden estar obsoletos" ;;
    centos:6*|debian:9*|debian:10*|ubuntu:16*|ubuntu:18*) chk "SO soportado" FAIL "$pretty: sin soporte upstream" ;;
    *) chk "SO soportado" NODET "$pretty: verificar fecha EOL en la distro [D]" ;;
  esac
  local bv; bv="$(bash --version | head -1)"; printf 'bash: %s\n' "$bv" >>"$f"

  # Perfil propio: sin consulta DNS de versión (skip-upgrade-test), sin pruebas que salen a red
  # (NETW-2705 dig a nameservers) ni refrescan metadatos (PKGS-7383 yum repolist).
  # Lynis AÚN escribe /var/run/lynis.pid y temporales en /tmp (se borran al terminar); no modifica config.
  cp "$ly/default.prf" "$ly/auditoria.prf" && printf '\nskip-upgrade-test=yes\nskip-test=NETW-2705\nskip-test=PKGS-7383\n' >>"$ly/auditoria.prf"
  # Ejecución (solo lectura; logs y reporte en la evidencia)
  local rep="$EVID/lynis-report.dat" lg="$EVID/lynis.log"
  ( cd "$ly" && ./lynis audit system --no-colors --quiet --profile "$ly/auditoria.prf" \
      --logfile "$lg" --report-file "$rep" ) </dev/null >"$EVID/07-lynis-stdout.txt" 2>&1
  local rc=$?; printf 'lynis rc=%s\n' "$rc" >>"$f"
  if [ ! -s "$rep" ]; then chk "ejecución de Lynis" FAIL "sin reporte (rc=$rc): ver 07-lynis-stdout.txt"
  else
    chk "ejecución de Lynis" OK "rc=$rc"
    local ver hi nw ns
    ver="$(sed -n 's/^lynis_version=//p' "$rep" | head -1)"
    hi="$(sed -n 's/^hardening_index=//p' "$rep" | head -1)"
    nw="$(grep -c '^warning\[\]=' "$rep")"; ns="$(grep -c '^suggestion\[\]=' "$rep")"
    printf '%s' "$ver" | grep -q '^3\.1\.7' && chk "versión de Lynis ejecutada" OK "$ver" || chk "versión de Lynis ejecutada" FAIL "esperada 3.1.7, reporte: ${ver:-?}"
    [ -n "$hi" ] && chk "hardening_index" OK "$hi/100 (referencia, no es CIS)" || chk "hardening_index" NODET ""
    [ "$nw" -eq 0 ] && chk "warnings de Lynis" OK "0" || chk "warnings de Lynis" FAIL "$nw (ver abajo)"
    chk "suggestions de Lynis" NODET "$ns (revisar lynis-report.dat)"
    { printf '\n== Warnings ==\n'; sed -n 's/^warning\[\]=/  /p' "$rep"; } >>"$r"
  fi
  printf 'Incumplen o sin determinar: %s de %s\nDetalle: %s\n' "$bad" "$n" "$f" >>"$r"
  ESTADO[7]="ok"
  say "Paso 7 listo → $f"; cat "$r"
}
paso_08_empaquetar() {
  local tgz="$OUT_BASE/auditoria-root-${HOST}-${TS}.tar.gz" i faltan=""
  for i in 1 2 3 4 5 6 7; do [ "${ESTADO[$i]:-pendiente}" = ok ] || faltan="$faltan $i"; done
  { printf 'script=%s\nversion=%s\nhost=%s\nfecha=%s\npasos_sin_ejecutar=%s\n' \
      "$(basename "$0")" "$VERSION" "$HOST" "$TS" "${faltan:-ninguno}"
    printf 'sha256_script=%s\n' "$(sha256sum "$0" 2>/dev/null | cut -d' ' -f1)"; } >"$EVID/MANIFEST.txt"
  [ -n "$faltan" ] && say "AVISO: pasos sin ejecutar en este paquete:$faltan"
  # Se excluye el Lynis extraído (reproducible desde vendor/) y el keyring GPG temporal.
  tar -C "$OUT_BASE" --exclude="$(basename "$EVID")/lynis-run" --exclude="$(basename "$EVID")/.gnupg" \
      -czf "$tgz" "$(basename "$EVID")" || { say "Falló tar"; return 1; }
  chmod 600 "$tgz"   # contiene hashes, usuarios y reglas: solo root
  ( cd "$OUT_BASE" && sha256sum "$(basename "$tgz")" ) | tee "$tgz.sha256"
  ESTADO[8]="ok"
  say "Paquete: $tgz"
  say "Para copiarlo: sudo chown \$USER '$tgz' && scp ... (contiene datos sensibles del host)"
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
