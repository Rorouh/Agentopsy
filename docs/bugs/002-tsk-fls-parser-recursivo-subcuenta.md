# Bug 002 — El parser de `tsk_fls` recursivo subcuenta masivamente (14.234 → 22)

- **Severidad:** media (no corrompe evidencia; **engaña al agente/UI** con un recuento falso)
- **Estado:** abierto (documentado, sin corregir)
- **Componente:** `backend/forensia/toolkit/wrappers/tsk_fls.py` (`parse` / `_FLS_LINE_RE`)
- **Detectado:** 2026-07-04, probando `tsk_fls` sobre `dvwa-container-rootfs/dvwa-disk.raw`

## Síntoma

`tsk_fls -r` (recursivo) sobre una imagen con 14.234 entradas devuelve en el resultado
`parsed.entries_count = 22` — solo las entradas de la **raíz**. Todo el árbol anidado
(14.212 entradas) queda fuera del recuento y de `parsed.entries`.

## Reproducción

```
run tsk_fls {recursive: true}   → parsed.entries_count = 22
run tsk_fls {recursive: true, body_format: true} → parsed.lines = 14234   (verdad)
wc -l stdout.txt del run recursivo → 14234                                 (verdad)
```

## Causa raíz

El regex de `parse` ancla el tipo al **inicio de línea**:

```python
_FLS_LINE_RE = re.compile(r"^(?P<type>[rdlcps?-]/[rdlcps?-])\s+...")
```

Pero la salida recursiva de TSK **prefija cada línea con la profundidad** usando `+`:

```
r/r 12:	.dockerenv            ← raíz (matchea)
+ r/r 14:	bash                ← profundidad 1 (NO matchea: empieza por '+ ')
++++ r/r 13552:	config.inc.php  ← profundidad 4 (NO matchea)
```

Como el regex exige el tipo al principio, solo casan las ~22 líneas de la raíz. El resto se
descarta silenciosamente → `entries_count` mentiroso.

## Impacto

- El agente "cree" que el sistema tiene 22 ficheros cuando tiene 14.234 → decisiones y
  resúmenes erróneos ("sistema casi vacío").
- La UI/informe muestran un recuento falso.
- Afecta a **toda imagen real** (cualquier FS con subdirectorios), no solo a esta.

## Fix propuesto (no aplicado)

Tolerar el prefijo de profundidad en el regex, p. ej.:

```python
_FLS_LINE_RE = re.compile(r"^\+*\s*(?P<type>[rdlcps?-]/[rdlcps?-])\s+(?P<inode>...)...")
```

(o hacer `line.lstrip('+ ')` antes de matchear). Añadir un test con salida recursiva
multinivel para fijar el recuento.

## Notas

- El path de ejecución (dispatcher → exec-agent → maletín) funciona: `fls` corre y el
  `stdout.txt` del artefacto tiene las 14.234 líneas **correctas**. El bug es **solo del
  parser** que resume esa salida.
- Workaround mientras tanto: contar `wc -l` del artefacto o usar `body_format: true`
  (`parsed.lines`) para el total real.
