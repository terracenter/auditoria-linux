# auditoria-linux

Script de auditoría **read-only** para hosts Linux (Ubuntu/Debian/RHEL family),
basado en la plantilla en `Obsidian/Planes/_templates/auditoria-host-linux.md`.

## Marcos de referencia

- CIS Controls v8
- CIS Ubuntu 22.04 Benchmark v2.0.0
- NIST SP 800-53 Rev. 5

## Fases

1. Inventario y postura general
2. Acceso y autenticación (sshd, sudoers, PAM)
3. Red y firewall (ufw/nft/iptables, sysctl, DNS)
4. Logs, monitoreo y tiempo
5. Actualizaciones y paquetes
6. Backups del host
7. Lynis (herramienta externa)

## Uso

```bash
# Copiar al host destino y ejecutar como root
scp auditoria-host-linux.sh usuario@host:/tmp/
ssh usuario@host
sudo bash /tmp/auditoria-host-linux.sh

# Resultado queda en $HOME del host:
#   ~/auditoria-<hostname>-<YYYY-MM-DD>-<HHMMSSZ>.tar.gz
```

## Procedimiento completo (laptop → le → vault)

1. **Ejecutar en el host destino** (vía SSH desde la laptop que tiene acceso directo):

   ```bash
   ssh ftaborda@iptv-penta-rd
   cd ~/auditoria-linux
   git pull
   sudo bash ~/auditoria-linux/auditoria-host-linux.sh -y
   ls -lh ~/*.tar.gz
   ```

2. **Bajar el `.tar.gz` a la laptop**:

   ```bash
   rsync --progress -razuz "srv-iptv-penta-rd:~/audi*.tar.gz" /tmp/
   ```

3. **Subir el `.tar.gz` desde la laptop a `le`** (workspace Freddy, vía Tailscale):

   ```bash
   scp /tmp/auditoria-*.tar.gz le:/tmp/
   ```

4. **El agente (en hermes-contabo vía SSH a `le`) extrae, lee y borra sin dejar basura**:

   ```bash
   ssh le 'cd /tmp && tar -xzf auditoria-*.tar.gz && <analizar archivos>'
   ssh le 'rm -rf /tmp/auditoria-*.tar.gz /tmp/auditoria-*/'
   ```

5. **El agente arma el informe en el vault**:

   - Path: `02_Servidores/<Cliente>/<hostname>/auditoria-<YYYY-MM-DD>.md`
   - Snapshots: `02_Servidores/<Cliente>/<hostname>/snapshots/<YYYY-MM-DD>/`
   - Con SHA256 calculado por el script bash al inicio (ver `logs/snapshots.sha256`).

6. **Cerrar con GLPI y correo al cliente** (responsable: Freddy).

## Opciones

| Opción | Descripción |
|---|---|
| `-h`, `--help` | Ayuda. |
| `-o <path>` | Directorio de salida (default: `~/`). |
| `-c <name>` | Nombre del cliente (default: `propio`). |
| `-r <rol>` | Rol del host (default: `other`). |
| `--skip-lynis` | No ejecuta Lynis. |
| `--no-install` | No intenta instalar paquetes faltantes. |
| `--sin-internet` | Asume sin internet; aborta si falta herramienta. |

## Recolectar el reporte

```bash
# Desde la workstation
scp usuario@host:~/auditoria-<hostname>-<fecha>-<hora>.tar.gz /tmp/
```

## Roadmap

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
Ver directiva en `Obsidian/Planes/Security-Manager-NG/` (en el vault de Freddy).

## Créditos

- Basado en CIS Ubuntu 22.04 Benchmark v2.0.0.
- Lynis (CISOfy) — herramienta externa de auditoría.
- Mantenido por Freddy Taborda <terracenter@gmail.com>.
