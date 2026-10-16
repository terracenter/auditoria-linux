# auditoria-linux

Scripts de auditoría **read-only** para hosts Linux (Ubuntu/Debian/RHEL family).
Hay dos herramientas; usa la que corresponda:

| Script | Para qué | Estado |
|---|---|---|
| `auditoria-root-acceso.sh` | Seguridad básica con menú: **quién habilitó root por SSH**, SSH, sudo/PAM, firewall, Fail2ban, Lynis. Criterio CIS Level 2. | v0.9.0 `[BORRADOR]` |
| `auditoria-host-linux.sh` | Auditoría completa de 7 fases (inventario, red, logs, backups…) según la plantilla del vault. | previo |

Documentación viva en el vault: `Obsidian/04.Documentacion/05.Seguridad/Auditoria/` (manual operativo,
ROADMAP, task log y development log).

## auditoria-root-acceso.sh

Solo lectura: no instala paquetes, no cambia configuración, no toca la red.
Excepciones declaradas: Lynis escribe `/var/run/lynis.pid` y temporales en `/tmp`
(se borran al terminar), y `sudo -l -U root` (solo con FreeIPA/sssd) deja una
entrada en el log de sudo.

### Pasos del menú

| # | Paso | Qué revisa |
|---|---|---|
| 1 | Preflight | SO, red, FreeIPA/sssd, **Zabbix agent y cliente GLPI** (política Fibex: ambos activos en cada host), servicios en escucha, herramientas |
| 2 | Acceso a root | `sshd -T` efectivo (Match, drop-ins), authorized_keys, UID 0, línea de tiempo de archivos, logs/auditd: **quién lo habilitó** |
| 3 | SSH | 25 reglas CIS L2 sobre la configuración efectiva |
| 4 | sudo / PAM / su | sudoers, `pam_wheel`, faillock, pwquality, permisos de `/etc/shadow` |
| 5 | Firewall | nftables / ufw / firewalld / iptables |
| 6 | Fail2ban | una jaula por servicio protegible, `ignoreip`, `recidive` |
| 7 | Lynis | Lynis 3.1.7 vendorizado, verificado por SHA256 + firma GPG |
| 8 | Empaquetar | `.tar.gz` + `.sha256` + `MANIFEST.txt` |

Opciones: `--all` (ejecuta los 8 pasos sin menú), `-o DIR` (directorio de salida;
por defecto el directorio actual), `-h`.

### Procedimiento para iniciar una auditoría (soporte nivel 1)

Necesitas: acceso SSH al host con un usuario con `sudo`, y el repo actualizado en tu equipo.

1. **En tu equipo**, actualiza el repo: `cd ~/Workspace/Desarrollo/auditoria-linux && git pull` (es `Desarrollo/auditoria-linux`, no `Desarrollo/scripts`).
2. **Copia al host** el script **y** la carpeta `vendor/` (sin `vendor/lynis/` el paso 7 falla):

   ```bash
   ssh usuario@host 'mkdir -p ~/auditoria'
   scp -r auditoria-root-acceso.sh vendor usuario@host:~/auditoria/
   ```

   Estructura esperada en el host: `~/auditoria/auditoria-root-acceso.sh` y `~/auditoria/vendor/lynis/`.
3. **Entra al host y ejecuta** desde esa carpeta (la evidencia se guarda en el directorio actual):

   ```bash
   ssh usuario@host
   cd ~/auditoria
   sudo ./auditoria-root-acceso.sh
   ```

   Elige `a` (todos los pasos en orden). Al final aparecen `auditoria-root-<host>-<fecha>.tar.gz` y su `.sha256`.
4. **Revisa el resultado**: si aparece `AVISO: pasos sin ejecutar`, repite el paso que falló. No sigas sin los 8 pasos.
5. **Hazte dueño del paquete** (lo crea root con permisos 600):

   ```bash
   sudo chown "$USER" auditoria-root-*.tar.gz auditoria-root-*.sha256
   ```
6. **Bájalo a tu equipo** y verifica la integridad:

   ```bash
   scp usuario@host:~/auditoria/auditoria-root-*.tar.gz* .
   sha256sum -c auditoria-root-*.sha256
   ```
7. **Entrégalo a Freddy**: él (con el agente) analiza contra CIS L2 y crea la nota del host en el vault.
8. **Limpia el host**: borra `~/auditoria/` solo cuando Freddy confirme que recibió el paquete.

Reglas para soporte N1:
- **No corrijas nada** en el host aunque el script marque FAIL. Las correcciones las aprueba Freddy.
- Si el host no tiene `gpg`, Lynis no se ejecuta (es intencional); anótalo y continúa con el resto.
- Si el script falla o da un error que no entiendes, guarda el mensaje completo y avisa; no lo modifiques.
- El paquete contiene configuración del host: trátalo como confidencial.

### No validado todavía [D]
- Ejecución con root real en un host real (el primer host es la prueba de campo).
- CentOS 7 y Debian 12.
- Huella de la llave de CISOfy contra la publicada por CISOfy.
- Fechas EOL de algunas distribuciones.
- La atribución de "quién" depende de que exista auditd y logs retenidos; si no, el resumen declara INDETERMINADO.

Detalles de la verificación de Lynis: [`vendor/lynis/README.md`](vendor/lynis/README.md).

## auditoria-host-linux.sh

Basado en la plantilla del vault `Obsidian/09.Planes/02.templates/auditoria-host-linux.md`.

### Marcos de referencia

- CIS Controls v8
- CIS Ubuntu 22.04 Benchmark v2.0.0
- NIST SP 800-53 Rev. 5

### Fases

1. Inventario y postura general
2. Acceso y autenticación (sshd, sudoers, PAM)
3. Red y firewall (ufw/nft/iptables, sysctl, DNS)
4. Logs, monitoreo y tiempo
5. Actualizaciones y paquetes
6. Backups del host
7. Lynis (herramienta externa)

### Uso

```bash
# Copiar al host destino y ejecutar como root
scp auditoria-host-linux.sh usuario@host:/tmp/
ssh usuario@host
sudo bash /tmp/auditoria-host-linux.sh

# Resultado queda en $HOME del host:
#   ~/auditoria-<hostname>-<YYYY-MM-DD>-<HHMMSSZ>.tar.gz
```

### Opciones

| Opción | Descripción |
|---|---|
| `-h`, `--help` | Ayuda. |
| `-o <path>` | Directorio de salida (default: `~/`). |
| `-c <name>` | Nombre del cliente (default: `propio`). |
| `-r <rol>` | Rol del host (default: `other`). |
| `--skip-lynis` | No ejecuta Lynis. |
| `--no-install` | No intenta instalar paquetes faltantes. |
| `--sin-internet` | Asume sin internet; aborta si falta herramienta. |

## Roadmap

- [ ] Validar `auditoria-root-acceso.sh` con root real (primer host) y en CentOS 7 / Debian 12.
- [ ] Confirmar la huella de CISOfy.
- [ ] Fase 0: pre-flight checks (out-of-band access, etc.).
- [ ] Comparación automática contra baseline Freddy.
- [ ] Generación de tabla maestra P0/P1/P2.
- [ ] Integración como módulo interno de Security-Manager-NG (en Go).

## Licencia

GNU Affero General Public License v3.0 — ver [LICENSE](LICENSE).

## Integración futura con Security-Manager-NG

Este script bash es el **antecedente manual** del futuro módulo
`internal/modules/audit/` de
[Security-Manager-NG](https://github.com/terracenter/security-manager).
Ver directiva en `Obsidian/09.Planes/Security-Manager-NG/` (en el vault de Freddy).

## Créditos

- Basado en CIS Ubuntu 22.04 Benchmark v2.0.0.
- Lynis (CISOfy) — herramienta externa de auditoría.
- Mantenido por Freddy Taborda <terracenter@gmail.com>.
