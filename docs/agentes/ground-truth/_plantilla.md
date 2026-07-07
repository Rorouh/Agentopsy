<!--
  PLANTILLA de ground-truth (molde, NO un caso). Cópiala a <id-imagen>.md y
  rellénala. Reglas: ver ground-truth/README.md.
  - Ningún hallazgo sin artefacto que lo sostenga (RULE 2 / diseño §3.3).
  - Marca <verificar> lo que aún no hayas confirmado analizando la imagen.
  - tool_id: SOLO ids de la allowlist agentes/forensia-windows/policy/tools.yaml.
  - technique_id: SOLO de la enum cerrada mitre_attack_seed.md.
  - severidad: low | medium | high | critical (mismo enum que Finding, diseño §7).
-->

# Ground-truth — `<id-imagen>`

## Metadatos

| Campo | Valor |
|---|---|
| id de imagen | `<id del manifiesto, p.ej. lonewolf-2018-disk>` |
| SHA-256 baseline | `<pendiente: computar con scripts/hash-evidence.py>` |
| tipo | `<disk | memory>` |
| formato | `<.raw | .E01 | .vmdk | .mem | .dmp>` |
| SO/build | `<p.ej. Windows 10>` |
| fuente/URL | `<enlace del escenario>` |
| entrada en el manifiesto | [corpus-windows.md](../corpus-windows.md) |

## Contexto

`<Descripción breve del escenario: qué host, qué historia, qué se investiga.>`

## Fuentes de la traza dorada

`<De dónde sale la "verdad": outputs oficiales del escenario, write-ups públicos,
etc. Indica explícitamente qué NO se usa (p.ej. guías restringidas a profesorado).>`

## Limitaciones documentadas

`<Qué NO cubre esta imagen — para no exigirle al agente hallazgos imposibles y para
saber qué técnicas hay que cubrir con otra imagen.>`

## Hallazgos esperados

> Marca `<verificar>` lo que aún no hayas confirmado con un artefacto. No inventes
> filas: cada hallazgo necesita un artefacto que lo sostenga.

| hallazgo esperado | artefacto que lo sostiene | `tool_id` (catálogo) | técnica MITRE (semilla) | severidad | cómo verificarlo manualmente |
|---|---|---|---|---|---|
| `<hallazgo>` | `<artefacto concreto: ruta/clave/evento>` | `<tool_id>` | `<Txxxx[.yyy]>` | `<low|medium|high|critical>` | `<pasos de verificación manual>` |
| `<verificar>` | `<verificar>` | `<verificar>` | `<verificar>` | `<verificar>` | `<verificar>` |
