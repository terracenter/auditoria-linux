# Changelog

Todos los cambios relevantes de este repo se documentan en este archivo.

El formato sigue Keep a Changelog y versionado semántico cuando aplique.

## [Unreleased]

### Changed (0.12.0)
- `auditar-host.sh` 0.2.0: se elimina la pregunta de borrar `~/auditoria/`. Si el paquete queda verificado en el equipo del operador (y en el destino de `-e`, si se dio), el lanzador borra del host solo lo que él copió y generó; si algo falla, no borra nada.
- Nueva opción `-e usuario@servidor:ruta`: envía el paquete por `scp` y verifica allí el SHA256. Un destino mal formado se rechaza antes de abrir ninguna conexión.
- `-h` imprime la cabecera completa (antes cortaba la frase).
- `tests/test-lanzador.sh` pasa a 30 pruebas, verificadas por mutación.

### Added (0.11.0)
- `auditar-host.sh` 0.1.0 (`[BORRADOR]`): lanzador de un solo comando para soporte nivel 1. Corre en el equipo del operador: copia el script y `vendor/` al host, ejecuta la auditoría con `sudo` de su usuario, trae el `.tar.gz`, verifica SHA256 y que los 8 pasos se ejecutaron, y termina con `RESULTADO: OK` o `FALLO`. Reutiliza una sola conexión SSH, valida el destino y no guarda credenciales. Probado solo con ssh/scp falsos; falta SSH real.
- `tests/test-lanzador.sh` (21 pruebas) y `tests/test-agentes.sh` (13 pruebas): sin red ni host real, con comandos falsos; verificadas por mutación.

### Added (0.10.0)
- Paso 1: detecta Zabbix agent (`zabbix-agent2`/`zabbix-agent`) y cliente GLPI (`glpi-agent`) por paquete, binario, unidad systemd y configuración. Estados `activo`, `instalado-inactivo` o `no`; deja `.zabbix` y `.glpi` en la evidencia y la línea `POLITICA_FIBEX` en `01-preflight.txt`; avisa si alguno no está activo. De la configuración solo copia directivas no secretas (sin PSK, usuarios, contraseñas ni proxy) y enmascara credenciales dentro de URLs.

### Added
- `auditoria-root-acceso.sh` 0.9.0 (`[BORRADOR]`, sin validar con root real): menú de 8 pasos de solo lectura
  (preflight, acceso a root y quién lo habilitó, SSH, sudo/PAM/su, firewall, Fail2ban, Lynis, empaquetado)
  con criterio CIS Level 2. Opciones `--all` y `-o DIR`.
- `vendor/lynis/`: Lynis 3.1.7 vendorizado; el script verifica SHA256, firma GPG y huella fijados antes de ejecutarlo.
- `CHANGELOG.md`, `VERSION` y `CLAUDE.md` (estándar mínimo de repo privado).
- README: sección con el procedimiento paso a paso para soporte nivel 1.

### Changed
- README reorganizado: dos herramientas (`auditoria-root-acceso.sh` y `auditoria-host-linux.sh`) y enlaces a la documentación viva del vault.
