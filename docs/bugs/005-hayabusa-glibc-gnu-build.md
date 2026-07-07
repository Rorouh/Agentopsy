# Bug 005 — hayabusa (build gnu) no arranca: `GLIBC_2.38 not found`

- **Severidad:** alta (la tool no ejecuta)
- **Estado:** ✅ **resuelto** (2026-07-04) — usar el build **musl** (static-pie)
- **Componente:** `docker/docker/forensic-toolkit/Dockerfile` (stage windows, descarga de hayabusa)
- **Detectado:** 2026-07-04, al ir a probar `hayabusa` sobre los EVTX

## Síntoma

```
hayabusa --version
→ hayabusa: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by hayabusa)
```

`capabilities` daba `hayabusa` como disponible (el fichero existe y es ejecutable), pero
**cualquier ejecución falla** — el binario no puede cargar.

## Causa raíz

El Dockerfile descargaba el release **`hayabusa-<ver>-lin-x64-gnu.zip`**, que se enlaza
**dinámicamente** contra glibc y exige **glibc ≥ 2.38**. La imagen base es **Ubuntu 22.04
(Jammy)** con **glibc 2.35**. Mismatch → `GLIBC_2.38 not found`.

(`chainsaw` 2.16.0 **no** sufre esto: su binario es autocontenido y arranca en 22.04.)

## Fix aplicado

Cambiar la descarga al build **musl** (`hayabusa-<ver>-lin-x64-musl.zip`), que es
**static-pie** (estáticamente enlazado, sin dependencia de glibc) → corre en cualquier base.
En el Dockerfile: URL `gnu`→`musl`, patrón del `find` `...-gnu`→`...-musl`, y `HAYABUSA_SHA256`
actualizado al del zip musl (`c2fa65e4…`). Se reconstruyó `toolkit-windows`.

## Lección

Para **binarios de terceros descargados** en el maletín, preferir builds **estáticos**
(musl / static-pie) sobre los `gnu` dinámicos: evitan acoplar la versión de glibc del binario
a la de la imagen base. Si solo hay build `gnu`, hay que alinear la base (Ubuntu ≥ 23.10 para
glibc 2.38) o compilar. Revisar el mismo riesgo en futuras tools .NET/Rust/Go pinneadas.
