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
#   ~/auditoria-<hostname>-<YYYY-MM-DD>-<HHMMSSZ>/
#   ~/auditoria-<hostname>-<YYYY-MM-DD>-<HHMMSSZ>.tar.gz
```

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

Uso interno.
