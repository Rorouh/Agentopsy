# Imágenes OCI por-herramienta (transitorias)

Dockerfiles para las herramientas declaradas con `delivery="container"` en
`backend/forensia/toolkit/catalog.py`. Cada subdirectorio produce una imagen cuyo tag
coincide con el `container_image` del catálogo.

> **Transitorio (pivote 2026-07-02).** En el modelo compose, RULE 1 entrega todas las
> herramientas dentro de las imágenes de los maletines (`toolkit-windows` /
> `toolkit-unix`), construidas por `docker compose up --build`. El maletín
> `toolkit-windows` ya incluye RegRipper; el trabajo de absorber EvtxECmd / MFTECmd y
> retirar estas imágenes sueltas (y las referencias `container_image` del catálogo)
> está en `docs/operacion/proximos-pasos.md`. Hasta entonces, el dispatcher sigue
> resolviendo estos tags.

## Tabla de imágenes

| Image tag | Tool catalog id | Cuándo se usa |
|---|---|---|
| `forensia/regripper:latest` | `regripper` | En todos los hosts (la entrega bundled de Perl portable se descartó) |
| `forensia/evtxecmd:latest` | `evtxecmd` | En Linux / macOS (Windows usa el `.exe` nativo) |
| `forensia/mftecmd:latest` | `mftecmd` | En Linux / macOS (Windows usa el `.exe` nativo) |

## Build local (dev)

```bash
docker build -t forensia/regripper:latest images/regripper/
docker build -t forensia/evtxecmd:latest  images/evtxecmd/
docker build -t forensia/mftecmd:latest   images/mftecmd/
```

El resolver detecta `docker`/`podman`/`nerdctl` en `PATH` y la app las usa directo.

## Invariante forense

Los wrappers que invocan estas imágenes **nunca** montan la imagen raw (`.raw` / `.vmdk`
/ `.E01`) dentro del contenedor — la validación está en `backend/forensia/toolkit/container.py:_validate_mount_paths`.
Para cada herramienta se pre-extrae el artefacto necesario en el host (con TSK `icat` o
similar) y solo ese artefacto derivado se mount-ea read-only en el contenedor.
