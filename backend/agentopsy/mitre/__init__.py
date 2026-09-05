"""MITRE ATT&CK: catálogo de referencia y cobertura por caso.

- `catalog` — derivado de la **semilla** del orquestador
  (`agentes/_orchestrator/knowledge/mitre_attack_seed.md`), que es la enum
  cerrada que el agente tiene permitido emitir. Una sola fuente de verdad.
- `coverage` — dos ejes separados: lo que el agente **propone** (desde los
  `mitre_hints` de hallazgos reales) y lo que el operador **dictamina**
  (confirmada / sospechosa / descartada, auditado).

`coverage` se importa a propósito por su ruta completa
(`from agentopsy.mitre.coverage import coverage_store`) y NO se reexporta aquí:
depende de `agentopsy.findings.store`, que a su vez consume `catalog` para validar
los `mitre_hints`. Reexportarlo cerraría un ciclo de imports.
"""

from agentopsy.mitre import catalog

__all__ = ["catalog"]
