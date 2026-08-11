# Grafo del repo — estado de frescura

> Fichero **generado** por `tools/graph/graph-refresh.py` en cada arranque de
> sesión. No se edita a mano. El mapa curado por el equipo es
> [`CONTEXT.md`](../CONTEXT.md); esto solo dice a qué versión del código
> corresponde el grafo que hay en `out/`.

- **Actualizado:** 2026-08-10 15:05:43Z
- **Commit del repo:** `22e05f4`
- **Esta corrida:** no hizo falta reconstruir
- **Nota:** graphify no está instalado en esta máquina, así que el grafo de `out/` es el último que commiteó alguien y puede no corresponder a este código. Instálalo con `python -m pip install graphifyy` (herramienta de dev; no viaja en el compose — RULE 1).

## Tamaño del grafo

| grafo | nodos | aristas |
|---|---:|---:|
| backend | 3355 | 6176 |
| web | 290 | 649 |
| merged | 3645 | 6825 |

## ⚠ `CONTEXT.md` va por detrás

`CONTEXT.md` dice estar anclado al commit `a323b71`, pero el repo está en
`22e05f4`. Las CIFRAS y los god-nodes de ese fichero pueden no corresponder a
este código. El grafo de `out/` sí está al día (esta corrida lo garantiza);
cuando la arquitectura se haya movido de verdad, actualiza `CONTEXT.md` a mano
y re-ancla el commit (RULE 4 — la doc no se queda atrás).

## Cómo consultarlo

```
graphify explain "EvidenceManager" --graph tools/graph/out/forensia-graph.json
graphify query   "que conecta capabilities con los maletines" --graph tools/graph/out/forensia-graph.json
graphify affected "AuditLog" --graph tools/graph/out/forensia-graph.json
```
