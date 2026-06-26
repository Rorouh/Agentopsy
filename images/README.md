# Imágenes OCI del maletín forense

Dockerfiles para las herramientas declaradas con `delivery="container"` en
`backend/forensia/toolkit/catalog.py`. Cada subdirectorio produce una imagen cuyo tag
coincide con el `container_image` del catálogo.

## Tabla de imágenes

| Image tag | Tool catalog id | Cuándo se usa |
|---|---|---|
| `forensia/regripper:latest` | `regripper` | En todos los hosts (la entrega bundled de Perl portable se descartó) |
| `forensia/evtxecmd:latest` | `evtxecmd` | En Linux / macOS (Windows usa el `.exe` bundled) |
| `forensia/mftecmd:latest` | `mftecmd` | En Linux / macOS (Windows usa el `.exe` bundled) |

## Distribución (RULE 1)

Las imágenes **no** se construyen en la máquina del usuario final. El flujo es:

```
CI release pipeline (per OS/arch del instalador)
  └─ docker build images/<tool>/        →  <tag>
  └─ docker save <tag> -o resources/images/<tool>.tar
  └─ electron-builder (incluye resources/images/ en extraResources)

Instalador → primer arranque en máquina del usuario
  └─ docker load -i resources/images/<tool>.tar    (una sola vez)
  └─ subsiguientes runs: docker run --rm <tag> ...
```

Esto preserva el espíritu de RULE 1: el usuario instala FORENSIA + Docker/Podman; no
necesita conectividad de red para que el maletín funcione (las imágenes ya viajan dentro).

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
