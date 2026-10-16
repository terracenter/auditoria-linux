# Changelog

Todos los cambios relevantes de este repo se documentan en este archivo.

El formato sigue Keep a Changelog y versionado semántico cuando aplique.

## [Unreleased]

### Added
- `auditoria-root-acceso.sh` 0.9.0 (`[BORRADOR]`, sin validar con root real): menú de 8 pasos de solo lectura
  (preflight, acceso a root y quién lo habilitó, SSH, sudo/PAM/su, firewall, Fail2ban, Lynis, empaquetado)
  con criterio CIS Level 2. Opciones `--all` y `-o DIR`.
- `vendor/lynis/`: Lynis 3.1.7 vendorizado; el script verifica SHA256, firma GPG y huella fijados antes de ejecutarlo.
- `CHANGELOG.md`, `VERSION` y `CLAUDE.md` (estándar mínimo de repo privado).
- README: sección con el procedimiento paso a paso para soporte nivel 1.

### Changed
- README reorganizado: dos herramientas (`auditoria-root-acceso.sh` y `auditoria-host-linux.sh`) y enlaces a la documentación viva del vault.
