#!/usr/bin/env bash
# test-usuarios.sh — pruebas de la política de usuarios (BANDERA ROJA) del paso 2 de
# auditoria-root-acceso.sh. Extrae las funciones del script y las corre con getent/last/journalctl/
# sshd/passwd/ssh-keygen FALSOS al inicio del PATH y archivos de prueba: sin root, sin red, sin tocar el host.
# Uso: ./tests/test-usuarios.sh
set -u
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$AQUI/auditoria-root-acceso.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAIL=0; N=0
ok()   { N=$((N+1)); printf 'PASS  %s\n' "$1"; }
bad()  { N=$((N+1)); FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -p "$T/bin" "$T/etc/sudoers.d" "$T/root/.ssh"
cat >"$T/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
freddy:x:1001:1001::/home/freddy:/bin/bash
jramirez:x:1002:1002::/home/jramirez:/bin/bash
ftaborda:x:1003:1003::/home/ftaborda:/bin/bash
svcapp:x:1004:1004::/srv/app:/usr/sbin/nologin
toor:x:0:0:alt root:/root:/bin/sh
nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin
EOF
printf 'root ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n' >"$T/etc/sudoers"
printf '# comentario\nDefaults env_reset\n%%infra ALL=(ALL) ALL\nADMINS ALL=(ALL) ALL\npedro ALL=(ALL) NOPASSWD: ALL\n' >"$T/etc/sudoers.d/10-x"
printf 'Oct 16 12:00:00 h sudo:   deudes : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n' >"$T/auth.log"
printf '#!/bin/bash\ncase "$1 $2" in\n "group sudo") echo "sudo:x:27:freddy,jramirez";;\n "group wheel") echo "wheel:x:10:root";;\n "group infra") echo "infra:x:900:anava,intruso";;\n *) exit 2;;\nesac\n' >"$T/bin/getent"
printf '#!/bin/bash\nprintf "freddy pts/0 1.2.3.4 Mon Oct 1 10:00 still logged in\\nmario pts/1 1.2.3.5 Mon Oct 1 09:00 - 09:30\\nfreddy2 pts/2 x Mon\\nroot pts/0 9.9.9.9 Mon Oct 1\\nreboot system boot 6.1 Mon Oct 1\\n\\nwtmp begins Mon Oct 1\\n"\n' >"$T/bin/last"
printf '#!/bin/bash\necho "Oct 16 12:00:00 h sudo[1]: ftaborda : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/vim x"\necho "Oct 16 12:00:01 h sudo[2]: pam_unix(sudo:session): session opened for user root(uid=0) by ftaborda(uid=1000)"\necho "Oct 16 12:00:02 h sudo[3]: colado : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id"\n' >"$T/bin/journalctl"
printf '#!/bin/bash\n[ "${FAKE_SSHD_FAIL:-0}" = 1 ] && exit 1\necho "permitrootlogin ${FAKE_PRL:-no}"\n' >"$T/bin/sshd"
printf '#!/bin/bash\necho "root ${FAKE_PW:-L} 2024-10-11 0 99999 7 -1"\n' >"$T/bin/passwd"
printf '#!/bin/bash\necho "256 SHA256:HUELLA root@pve-val-01 (ED25519)"\n' >"$T/bin/ssh-keygen"
chmod +x "$T"/bin/*

# funciones reales del script (no copias): bloque de política + have()
extraer() { { sed -n '/^have()/p' "$SCRIPT"; sed -n '/^# --- política de usuarios/,/^# --- paso 2/p' "$SCRIPT" | sed '$d'; }; }
correr() { # $1 = código a ejecutar con las funciones cargadas; el resto de variables va por env
  env PATH="$T/bin:$PATH" PASSWD_F="$T/etc/passwd" SUDOERS_F="$T/etc/sudoers" SUDOERS_D="$T/etc/sudoers.d" \
      ROOT_HOME="$T/root" AUTH_LOGS="$T/auth.log" "${@:2}" \
      bash -c "$(extraer)"$'\n'"$1" 2>&1
}

# A. candidatos y clasificación (root cerrado)
: >"$T/ev.txt"
OUT="$(correr "usuarios_vs_politica '$T/ev.txt' '$T/ban.txt'")"
check "freddy: AUTORIZADO(PAM)" "printf '%s\n' \"\$OUT\" | grep -q '^AUTORIZADO(PAM) freddy '"
check "ftaborda: AUTORIZADO(IPA) (cuenta local con nombre de admin IPA)" "printf '%s\n' \"\$OUT\" | grep -q '^AUTORIZADO(IPA) ftaborda '"
check "deudes (solo en auth.log): AUTORIZADO(PAM)" "printf '%s\n' \"\$OUT\" | grep -q '^AUTORIZADO(PAM) deudes .*sudo-log'"
check "jramirez (en grupo sudo): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: jramirez .*grupo-sudo'"
check "intruso (miembro de %infra en sudoers): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: intruso .*sudoers-%infra'"
check "anava (en %infra, es admin IPA): AUTORIZADO(IPA)" "printf '%s\n' \"\$OUT\" | grep -q '^AUTORIZADO(IPA) anava '"
check "pedro (usuario directo en sudoers): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: pedro '"
check "mario (solo en wtmp): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: mario .*login-wtmp'"
check "colado (solo en el journal de sudo): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: colado .*sudo-log'"
check "freddy2 NO se confunde con freddy (nombre exacto)" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: freddy2 '"
check "toor (UID 0 que no es root): BANDERA ROJA" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: toor .*UID0-no-root'"
check "alias de sudoers: REVISAR A MANO, no bandera" "printf '%s\n' \"\$OUT\" | grep -q '^REVISAR A MANO: ADMINS '"
check "cuenta de servicio nologin y nobody no aparecen" "! printf '%s\n' \"\$OUT\" | grep -qE 'svcapp|nobody|daemon'"
check "root, reboot y wtmp nunca salen como usuarios de wtmp" "! printf '%s\n' \"\$OUT\" | grep -qE '^(AUTORIZADO\([A-Z]+\) |BANDERA ROJA: )(reboot|wtmp|root|shutdown) '"
check "contador: 7 banderas con root cerrado (jramirez intruso pedro mario colado freddy2 toor)" "printf '%s\n' \"\$OUT\" | grep -qx 'BANDERAS_ROJAS=7'"
check "root cerrado: ninguna bandera de root" "! printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: root '"
check "archivo de banderas: una línea por bandera" "[ \"\$(wc -l <'$T/ban.txt')\" = 7 ] && grep -q '^jramirez|' '$T/ban.txt'"
check "evidencia cruda guarda la lista de candidatos" "grep -q '^jramirez|' '$T/ev.txt'"
check "avisa que IPA se revisa en el servidor" "printf '%s\n' \"\$OUT\" | grep -q '^MANUAL(FreeIPA)'"

# B. root activo
printf 'ssh-ed25519 AAAA root@pve-val-01\n# comentario\n' >"$T/root/.ssh/authorized_keys"
OUT="$(correr "usuarios_vs_politica '$T/ev.txt' '$T/ban.txt'")"
check "root con llave: BANDERA ROJA con huella y comentario" "printf '%s\n' \"\$OUT\" | grep -q '^BANDERA ROJA: root 1 llave(s) SSH autorizadas para root .*SHA256:HUELLA root@pve-val-01'"
check "root con llave y todo lo demás cerrado: solo 1 bandera de root" "[ \"\$(printf '%s\n' \"\$OUT\" | grep -c '^BANDERA ROJA: root ')\" = 1 ]"
check "root con llave: contador 8" "printf '%s\n' \"\$OUT\" | grep -qx 'BANDERAS_ROJAS=8'"
: >"$T/root/.ssh/authorized_keys"; printf '# solo comentario\n' >>"$T/root/.ssh/authorized_keys"
check "authorized_keys solo con comentarios: root no activo" "[ -z \"\$(correr root_activo)\" ]"
rm -f "$T/root/.ssh/authorized_keys"
check "root totalmente cerrado: root_activo no imprime nada" "[ -z \"\$(correr root_activo)\" ]"
check "PermitRootLogin yes: BANDERA" "correr root_activo FAKE_PRL=yes | grep -q 'valores: yes'"
check "PermitRootLogin prohibit-password también es acceso de root" "correr root_activo FAKE_PRL=prohibit-password | grep -q 'valores: prohibit-password'"
check "sshd -T ilegible (sin root): no se da por bueno, sale desconocido" "correr root_activo FAKE_SSHD_FAIL=1 | grep -q 'valores: desconocido'"
check "contraseña de root sin bloquear (P): BANDERA" "correr root_activo FAKE_PW=P | grep -q 'no está bloqueada (passwd -S: P)'"
check "root sin contraseña (NP): BANDERA" "correr root_activo FAKE_PW=NP | grep -q 'passwd -S: NP'"
check "contraseña bloqueada estilo RHEL (LK): sin bandera" "[ -z \"\$(correr root_activo FAKE_PW=LK)\" ]"

# C. listas: el script las trae exactamente como las dictó Freddy
check "lista PAM: freddy manuel angel levy deudes" "grep -q '^USUARIOS_PAM_AUTORIZADOS=\"freddy manuel angel levy deudes\"' '$SCRIPT'"
check "lista IPA: ftaborda mpernia anava lrivero dlinares" "grep -q '^USUARIOS_IPA_AUTORIZADOS=\"ftaborda mpernia anava lrivero dlinares\"' '$SCRIPT'"

printf '\n%s pruebas, %s fallos\n' "$N" "$FAIL"
[ "$FAIL" -eq 0 ]
