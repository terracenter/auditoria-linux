# CLAUDE.md — Repo auditoria-linux

@import ../../Obsidian/CLAUDE.md
@import ../AGENTS.md

## Alcance

Scripts de auditoría de solo lectura para hosts Linux de Fibex y la evidencia vendorizada que necesitan (`vendor/lynis/`).
Herramientas: `auditar-host.sh` (lanzador para soporte N1), `auditoria-root-acceso.sh` (seguridad básica, CIS L2) y `auditoria-host-linux.sh` (auditoría completa de 7 fases). Pruebas en `tests/` (sin red ni root).

## Reglas específicas

- Los scripts son **solo lectura**: no instalan, no modifican configuración, no tocan la red. Cualquier excepción se declara en la cabecera del script.
- No commitear paquetes de evidencia (`auditoria-*.tar.gz`, `auditoria-*/`): contienen configuración de hosts. Ya están en `.gitignore`.
- Al actualizar Lynis, cambiar a la vez el tarball, `SHA256SUMS`, y el nombre/SHA256/huella fijados en el paso 7 del script, y verificar la huella contra CISOfy.
- Todo cambio relevante actualiza `CHANGELOG.md` y la documentación viva en el vault, en
  `/home/freddy/Workspace/Obsidian/04.Documentacion/05.Seguridad/Auditoria/` (manual operativo `10.*`, ROADMAP `90.*`,
  task log `91.*`, development log `92.*`).
- Lo no validado con evidencia real se marca `[D]`; nada se inventa.
