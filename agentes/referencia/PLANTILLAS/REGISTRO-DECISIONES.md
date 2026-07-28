# Fase N — registro de decisiones (asistente)

Documento **del asistente**: decisiones, procedimientos, herramientas y resultados de la
fase. Es el par técnico de [`PETICIONES.md`](PETICIONES.md). Cada entrada importante lleva
un **ancla** (`#a…`) a la que apuntan la petición y el [`FLUJO.md`](FLUJO.md) con `↳`.

Plantilla por entrada:

```
<a id="aN-slug"></a>
### aN · [FECHA] — <resumen corto>

- **Petición:** ↳ [PETICIONES.md](PETICIONES.md) — "<lo que pidió>"
- **Decisión:** qué se decidió y **por qué** (incluidas las alternativas descartadas).
- **Herramienta / script:** comando, función y parámetros clave.
- **Resultado:** qué salió, qué se validó y **qué queda pendiente**.
```

Reglas del registro:

- Orden **cronológico inverso**: la más reciente justo debajo de la línea de abajo.
- Un fallo diagnosticado se apunta aquí **y** añade una fila al *mapa de problemas* del
  [`FLUJO.md`](FLUJO.md).
- Lo que se consolida como método **sube al flujo**; aquí queda el relato de cómo se llegó.
- Lo que se corrige no se borra: se **tacha** y se explica, para que no se repita el intento.

## Piezas del flujo

- **<script / módulo principal>:** <qué hace y qué NO hardcodea>.
- **<dependencia externa>:** <cómo se invoca, dónde falla>.
- **Cómo se enseñan los resultados:** <…>.

---

<!-- entradas nuevas debajo, la más reciente primero -->
