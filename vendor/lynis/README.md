# vendor/lynis

Lynis 3.1.7 (tarball oficial de CISOfy), usado por el menú de auditoría para correr sin instalar nada en el host.

- Origen: https://downloads.cisofy.com/lynis/lynis-3.1.7.tar.gz (release https://github.com/CISOfy/lynis/releases/tag/3.1.7, 2026-06-25)
- Firma: `lynis-3.1.7.tar.gz.asc`, verificada con `cisofy-software.pub`
- Huella primaria de la llave: `84FA A998 3B24 AEF2 4D6C  87F1 FEBB 7D18 1257 6482` — [D] pendiente de confirmar contra la huella publicada por CISOfy
- Integridad: `SHA256SUMS` (CISOfy no publica .sha256)
- Licencia de Lynis: GPLv3

Verificar: `sha256sum -c SHA256SUMS`

## Verificación en el script
`auditoria-root-acceso.sh` (paso 7) NO confía en los archivos de esta carpeta: tiene fijados el nombre `lynis-3.1.7.tar.gz`, su SHA256 y la huella primaria `84FAA9983B24AEF24D6C87F1FEBB7D1812576482` (comprobada con `VALIDSIG`). Sin `gpg` en el host, o con firma/huella distinta, Lynis NO se ejecuta. Al actualizar Lynis hay que cambiar esos valores en el script.
Lynis corre con un perfil propio (`skip-upgrade-test`, sin NETW-2705 ni PKGS-7383) para no salir a la red; aun así escribe `/var/run/lynis.pid` y temporales en `/tmp`.
