# `evals/` — Casos de prueba (opcional)

El equipo de entrenamiento puede dejar aquí casos sintéticos que el harness
comparativo cloud-vs-local ejecutará contra el agente. Formato pendiente de
cerrar (la implementación del harness no está aún en el esqueleto).

Estructura tentativa:

```yaml
# evals/case-001.yaml
id: case-001
description: "Imagen Linux con webshell PHP escondida en /tmp"
evidence_fixture: fixtures/linux-webshell.raw   # NUNCA datos reales
expected_findings:
  - kind: file
    path_glob: "/tmp/**/*.php"
  - kind: ioc
    pattern: "eval\\("
```

> Las fixtures **nunca** deben contener evidencias reales con datos personales.
