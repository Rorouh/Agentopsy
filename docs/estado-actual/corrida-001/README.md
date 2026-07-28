# Archivo de la corrida #001 — caso «Prueba 188k tokens»

> Rastro forense conservado del caso `f575846e-bd82-4720-a512-976b0feb788e`,
> **archivado el 2026-07-28** antes de borrar el caso para liberar disco.
> El análisis de estos datos está en
> [`../07-corrida-agente-001.md`](../07-corrida-agente-001.md).

## Qué hay aquí

| Fichero | Qué es |
|---|---|
| `audit.jsonl` | Los **41 eventos** de la cadena hash-encadenada, íntegra y en orden |
| `chats/main.jsonl` | La conversación completa: la pregunta del perito y las 9 iteraciones del agente |
| `case.json` | Metadatos del caso (nombre, examinador, `os_profile` derivado) |

## Qué NO hay, y por qué

Se borró todo lo que ocupaba espacio y es **reproducible o irrelevante**:

- `evidence/` (25 GB) — las dos copias inmutables. Las evidencias de origen
  siguen en la bandeja `./evidence` del host; re-registrarlas reproduce el
  mismo baseline (los hashes están abajo).
- `artifacts/` (421 MB) — las salidas de las 4 herramientas ejecutadas. Sus
  `run_id` y hashes constan en el audit.

## Anclas para verificar

| Evidencia | SHA-256 |
|---|---|
| `ram.raw` (5 GB, `memory`/`windows`) | `a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240` |
| `original.vmdk` (20,4 GB, `container_disk`/`windows`) | `60919a3adc8450fa7e720ee68f6815d2179673c21c1844f198d7e45b38497068` |

> ⚠️ El hash del `.vmdk` **no coincide** con el del enunciado de la UCM
> (`…b38597068`, difiere en el carácter 58). Ver
> [`../08-analisis-comparativo.md`](../08-analisis-comparativo.md) §4.6: el
> baseline de Agentopsy es autorreferencial y no lo detectó.

## Por qué se conserva

Es la **línea base de medición**: 49.446 tokens reportados, $4,13, 9
iteraciones, 0 hallazgos persistidos y ninguna respuesta. Cualquier mejora del
agente se compara contra estos números, y el audit es lo que los sostiene.

Consultar el gasto:

```bash
python3 -c "
import json
ti=to=0; cost=0.0
for l in open('docs/estado-actual/corrida-001/audit.jsonl'):
    d=json.loads(l)
    if d.get('action')=='executor_run_finish':
        ti+=d.get('input_tokens') or 0; to+=d.get('output_tokens') or 0
        cost+=d.get('cost_usd') or 0.0
print('in',ti,'out',to,'total',ti+to,'USD',round(cost,2))
"
```
