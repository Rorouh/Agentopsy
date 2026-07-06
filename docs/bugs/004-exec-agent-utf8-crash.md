# Bug 004 — El exec-agent crashea con salida de tool no-UTF-8 (RemoteDisconnected)

- **Severidad:** alta (rompe tools reales sobre discos reales)
- **Estado:** ✅ **resuelto** (2026-07-04)
- **Componente:** `docker/docker/forensic-toolkit/exec_agent.py` (`_exec`)
- **Detectado:** 2026-07-04, ejecutando `tsk_mactime` sobre la raíz de Metasploitable 2

## Síntoma

`tsk_mactime` (y cualquier tool cuya salida contenga bytes no-UTF-8) falla por el dispatcher
con:

```
MaletinExecError: no se pudo ejecutar en el exec-agent http://toolkit-unix:8666
  (RemoteDisconnected): Remote end closed connection without response
```

El maletín **sigue healthy** (el `/health` responde) — solo muere el hilo que atendía esa
petición, y el api ve la conexión cerrada sin respuesta.

## Causa raíz

El exec-agent hacía `subprocess.run(argv, capture_output=True, text=True, …)` con
decodificación **UTF-8 estricta**. La salida forense **no** es UTF-8 válido en general: los
**nombres de fichero de un disco real** (y datos crudos) llevan bytes arbitrarios. mactime
imprime esos nombres en el CSV → al decodificar salta `UnicodeDecodeError` dentro del hilo
del `ThreadingHTTPServer`, que muere sin enviar respuesta → `RemoteDisconnected`.

Reproducción mínima (en el maletín):
```
subprocess.run(['mactime','-b',<bodyfile>,'-d','-y'], capture_output=True, text=True)
→ UnicodeDecodeError: 'utf-8' codec can't decode byte 0x9e in position 5422791
```

Por qué `strings`/`bulk_extractor` no lo destaparon antes: su salida (offsets hex + ASCII)
sí era UTF-8 válida; mactime fue el primero con nombres de fichero binarios.

## Fix aplicado

`subprocess.run(..., text=True, errors="replace")` en `exec_agent.py::_exec`: los bytes
inválidos se sustituyen por el carácter de reemplazo en vez de crashear. Se reconstruyeron
los maletines y `tsk_mactime` pasó a exit 0 (228.514 filas de timeline).

## Pendiente relacionado (menor)

`forensia.toolkit.tool.run_argv` (camino *bundled* del dispatcher, poco usado hoy) tiene el
mismo patrón `text=True` sin `errors=`; conviene aplicarle `errors="replace"` por coherencia
antes de que alguien lo ejercite con salida binaria.

## Lección

Toda captura de salida de herramienta forense debe ser **tolerante a bytes no-UTF-8**
(`errors="replace"`/`surrogateescape`), nunca decodificación estricta. La evidencia es datos
hostiles/arbitrarios también en sus nombres.
