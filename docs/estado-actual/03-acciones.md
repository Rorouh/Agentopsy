# 03 — Acciones ejecutadas (audit log)

> Volcado íntegro del audit log hash-encadenado del caso. Índice:
> [`README.md`](README.md).

El audit log del caso tiene **3 entradas**. Es la totalidad de lo que la
aplicación ejecutó sobre esta evidencia.

Fichero: `projects/cases/f575846e-bd82-4720-a512-976b0feb788e/audit.jsonl`

---

## Entrada 1 — `evidence_register`

```json
{
  "action": "evidence_register",
  "case_id": "f575846e-bd82-4720-a512-976b0feb788e",
  "evidence_id": "a35686e4-359f-4a2a-b55d-a5398548e821",
  "original_basename": "original.raw",
  "source_path": "/evidence/windows7-x64-ram-dump/ram.raw",
  "sha256": "a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240",
  "size": 5368709120,
  "registered_at": "2026-07-28T12:24:54.759Z",
  "ts_utc": "2026-07-28T12:24:54.764230+00:00",
  "entry_hash": "83a111ad10204b9544d8cb140f59e4dfd08dbf320dedf14d5e2a954379f62d96"
}
```

La evidencia entra en custodia. El `source_path` es la ruta **dentro del
contenedor** (`/evidence/…`), que corresponde a `./evidence/…` en el host. El
fichero se copia a `original.raw` bajo el directorio del `evidence_id`.

---

## Entrada 2 — `os_profile_routed`

```json
{
  "action": "os_profile_routed",
  "case_id": "f575846e-bd82-4720-a512-976b0feb788e",
  "evidence_id": "a35686e4-359f-4a2a-b55d-a5398548e821",
  "family": "windows",
  "os_profile": "windows",
  "confidence": "markers",
  "signals": ["pe_scatter=6", "rsds_pdb=3", "page0_zero"],
  "decision": "auto_set",
  "ts_utc": "2026-07-28T12:24:54.768171+00:00",
  "entry_hash": "e4e50ad887a9e68a128bb4e58b0e0798b280ca0dcb39fc15ea9823dc77c3e6b8"
}
```

La determinación del perfil queda auditada con sus tres componentes: familia,
confianza y señales. `decision: auto_set` documenta que se ancló sin
intervención del operador — un dato que hace la decisión revisable a posteriori.

**4 milisegundos** después del registro: la triage es barata, no requiere leer la
imagen entera.

---

## Entrada 3 — `evidence_verify`

```json
{
  "action": "evidence_verify",
  "case_id": "f575846e-bd82-4720-a512-976b0feb788e",
  "evidence_id": "a35686e4-359f-4a2a-b55d-a5398548e821",
  "baseline_sha256": "a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240",
  "current_sha256":  "a0ad93b20cd9294f9d49947e87675c12159e3d96ae0d3c5a547f232630b0b240",
  "verified": true,
  "ts_utc": "2026-07-28T12:25:48.903416+00:00",
  "entry_hash": "a1964f3718f34a2a450973c118c87e70189c01ab5ad46745f95f571e8d08814a"
}
```

Integridad intacta: hash actual idéntico al baseline.

---

## Lo que NO aparece en el audit log

Y por tanto **no ocurrió**:

| Evento ausente | Qué significaría |
|---|---|
| `agent_run_start` | El agente nunca arrancó |
| `agent_cloud_egress` | Ningún byte del caso salió hacia un ejecutor cloud |
| `agent_finding` | Ningún hallazgo registrado |
| `tool_run` / `ArtifactRun` | Ninguna herramienta forense se ejecutó sobre la evidencia |
| `mitre_proposed` / `mitre_adjudicated` | Ninguna técnica ATT&CK propuesta ni dictaminada |
| Registro del segundo fichero | El `.vmdk` nunca entró en el caso |

Ese último punto merece subrayarse: la ausencia de eventos es lo que **prueba**
que el `.vmdk` no está en custodia. No es que se registrara y fallara — es que no
se intentó.

---

## Sobre la cadena de hashes

Cada entrada lleva su `entry_hash` y encadena con la anterior. La propiedad que da
esto: **no se puede insertar, borrar ni reordenar una acción a posteriori** sin
romper la cadena. Es lo que sostiene FORENSIC INVARIANT 4.

Cuando el agente ejecute herramientas, cada run añadirá a esta cadena el **argv
literal ejecutado** — el array de argumentos real, no la intención declarada por
el LLM. Esa distinción es deliberada: lo que se audita es lo que se ejecutó.
