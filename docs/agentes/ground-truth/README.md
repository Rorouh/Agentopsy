# Ground-truth del corpus Windows — la "traza dorada"

Este directorio contiene, **una por imagen del corpus**
([`corpus-windows.md`](../corpus-windows.md)), la lista documentada de hallazgos
esperados con el artefacto que los sostiene. Es la **"traza dorada"** (golden
trace) contra la que se mide el sub-agente `windows`.

## Por qué es la traza dorada

El diseño (§9.4 de [`diseno-fase2.md`](../diseno-fase2.md)) define las métricas
científicas del TFM. Dos de ellas se calculan comparando la salida del agente con
lo que un analista humano sabe que hay en la imagen:

| Métrica | Qué mide | Se compara contra |
|---|---|---|
| `findings_recall` | ¿encontró los hallazgos esperados? | los `hallazgo esperado` de estos ficheros |
| `findings_precision` | ¿cuántos falsos positivos? | hallazgos que **no** están en estos ficheros |

Sin una lista verificada de "lo que realmente hay", recall y precision no son
calculables: no habría denominador ni referencia de verdad. Por eso el
ground-truth es el **cimiento empírico** — se escribe **antes** de refinar prompts
o construir evals, y esos productos se derivan de él (pasos A1–A2 del
[plan de ruta](../plan-ruta-forensia-win.md)).

## Regla dura: ningún hallazgo sin artefacto que lo sostenga

Coherente con CLAUDE.md **RULE 2** (sin fallbacks, no inventar) y con el contrato
de finding del diseño (§3.3: *ningún finding sin `provenance` resoluble*):

- Cada fila de la tabla de hallazgos **debe** citar el artefacto concreto que lo
  sostiene y el `tool_id` del catálogo que lo produce.
- Lo que aún no se ha confirmado analizando la imagen se marca con `<verificar>`
  — **no** se rellena con una suposición.
- El `technique_id` de MITRE sale de la **enum cerrada** de la semilla
  ([`mitre_attack_seed.md`](../../agentes/_orchestrator/knowledge/mitre_attack_seed.md)):
  si una técnica no está en la semilla, no se cita aquí.

## Relación corpus ↔ ground-truth ↔ evals

```
corpus-windows.md            ground-truth/<img>.md              evals/case-win-*.yaml
(qué imagen, dónde,     →    (qué hallazgos, con qué      →     (expected_findings +
 hash, licencia)              artefacto y tool_id)               expected_mitre medibles)
```

El ground-truth es el eslabón intermedio: traduce "esta imagen existe" en "estos
hallazgos concretos, sostenidos por estos artefactos", que luego se convierten en
etiquetas doradas de eval. **El ground-truth documenta evidencia real; las evals
usan fixtures sintéticas** — la traza dorada dice *qué buscar*, no aporta los bytes.

## Cómo añadir un ground-truth nuevo

1. Copia [`_plantilla.md`](_plantilla.md) a `ground-truth/<id-imagen>.md`.
2. Rellena el bloque de metadatos (id, SHA-256, tipo, SO/build) desde la fila del
   manifiesto.
3. Analiza la imagen y ve rellenando la tabla de hallazgos, marcando `<verificar>`
   lo que aún no hayas confirmado con un artefacto.
4. Enlaza el fichero desde la columna `ground-truth` de `corpus-windows.md`.

## Ficheros

- [`_plantilla.md`](_plantilla.md) — plantilla base (no es un caso; es el molde).
- [`lonewolf-2018.md`](lonewolf-2018.md) — escenario 2018 Lone Wolf (disco + RAM).
