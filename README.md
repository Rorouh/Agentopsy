# FORENSIA

> Herramienta de análisis **forense post-mortem asistida por IA**, de escritorio,
> universal (Windows · macOS · Linux, Intel y Apple Silicon).
> Trabajo Final de Máster — entrega 7 de septiembre de 2026.

Un analista carga evidencias ya extraídas (`.vmdk` / `.raw` / volcados de RAM); un
agente de IA conduce un maletín curado de herramientas forenses para producir un
**informe estructurado** y una **línea temporal**, preservando la cadena de custodia.

## Principios

- **Instalar y usar.** Todo (sidecar Python, Volatility3, plaso, The Sleuth Kit,
  bulk_extractor, …) viaja **dentro del binario compilado**. Sin Docker, sin `pip`,
  sin descargas extra. Ver la regla de bundling en [`CLAUDE.md`](./CLAUDE.md).
- **Privacidad primero.** Modelo **local (Ollama) por defecto**; la nube es opt-in por
  caso, con consentimiento y redacción (las evidencias pueden contener datos personales).
- **Rigor forense.** La evidencia se trata read-only a nivel de bloque, verificada por
  hash antes de exponerse, y cada acción queda en un log encadenado (cadena de custodia).
- **Solo escritorio.** Una única superficie; sin CLI ni web.

## Arquitectura (resumen)

```
Electron (UI, igual en los 3 OS)
   └─ sidecar Python/FastAPI (127.0.0.1 + token)   ← toda la lógica en forensia/*
        └─ vendor/<tool>/<os>-<arch>               ← maletín forense bundleado
```

Detalle en [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md),
[`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) y
[`docs/FORENSIC_SOUNDNESS.md`](./docs/FORENSIC_SOUNDNESS.md).

## Estado

Esqueleto del repositorio + andamiaje de la app de escritorio. Arrancable de extremo a
extremo (ventana ↔ sidecar ↔ capabilities); agentes/herramientas reales aún por implementar.

## Equipo

Enrique · Daniel · Santiago · Luis · Diego · Miguel Ángel

## Cómo arrancar

Ver la sección **Commands** de [`CLAUDE.md`](./CLAUDE.md).

## Licencia

Ver [`LICENSE`](./LICENSE).
