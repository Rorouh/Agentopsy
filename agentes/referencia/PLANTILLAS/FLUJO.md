# Flujo reutilizable — Fase N: <título>

Receta de la fase, **generalizada** (sin nombres, rutas ni valores fijos de un caso).
Es el documento que hay que leer para replicar esto con otro caso.

> Reglas del proyecto: [`../CLAUDE.md`](../CLAUDE.md) ·
> Bitácora: [`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md) ·
> Peticiones del usuario: [`PETICIONES.md`](PETICIONES.md).

---

## 🚀 Arrancar en una sesión nueva (sin contexto)

1. Leer este archivo entero. Los fallos que más rondas costaron están en **"Heurísticas
   aprendidas"**; saltárselos es repetirlos.
2. Leer [`PETICIONES.md`](PETICIONES.md) **hasta la última entrada**. **Manda ese
   documento, no este.**
3. Mirar el estado en [`README.md`](README.md).
4. Abrir la **ficha del caso** (`FICHA-<CASO>.md`); si es nuevo, copiarla de
   [`../PLANTILLAS/FICHA.md`](../PLANTILLAS/FICHA.md).
5. Ir al paso 0 y bajar en orden. Si un paso se atasca, saltar **directo** a la entrada `↳`
   del registro.

### Reglas de trabajo del usuario

| Regla | Por qué |
|---|---|
| **Se arranca desde 0, sin contexto de otros proyectos.** Lo **único** que se toma de Forensia son **sus tools ya montadas en Docker**, usadas como caja negra. | Es el motivo de que exista esta carpeta. Las tools son herramienta, no contexto. |
| **`output/` es organización pura y dura**: carpeta por caso y por tool, salida cruda de **cada** tool **tal cual** (`__raw`) + versión legible (`__vista`) + `_run.md`. | El usuario tiene que poder abrir cualquier salida por su cuenta y ver lo que devolvió la tool sin intermediarios. |
| **Una cosa a la vez.** | Cada entregable tiene su ajuste fino; mezclarlos impide saber qué funcionó. |
| **Si no está definido, no se inventa** — se pregunta. | Un hueco rellenado a ojo es deuda invisible. |
| **Los resultados se enseñan directos.** | Nada de visores ni galerías salvo petición explícita. |
| Cada petición → peticiones **y** registro. | La telaraña del proyecto. |
| Un método **solo sube aquí cuando ha funcionado**. | El flujo es la receta limpia, no el diario. |

### Mapa de problemas → registro

| Si te pasa esto… | Ve a |
|---|---|
| <síntoma observable> | [`#aN`](REGISTRO-DECISIONES.md#aN-slug) (<causa en 4 palabras>) |

---

## 0. Preparar la sesión

- Ver qué hay ya en `output/` y en la ficha: **no rehacer** lo validado.
- Confirmar el **entregable en curso**.
- Dejar claro qué se enseñará y **cómo se decidirá si vale**.

## 1. Inventariar la entrada ANTES de ejecutar nada

- Qué hay exactamente en la entrada (formato, tamaño, campos, casos raros).
- Qué es **de este caso** (→ ficha) y qué es **del método** (→ aquí).
- Qué se asume sin verificar: se escribe, no se guarda en la cabeza.

## 2. Definir el criterio de "esto está bien" antes de producir

Sin criterio previo, cada ronda se juzga a ojo y se itera en círculo.

## 3. <paso de producción>

…

## 4. Revisar con el usuario

- Resultado directo. **Una variante cada vez**, o **A/B explícito y nombrado**.
- El comentario del usuario se anota en [`PETICIONES.md`](PETICIONES.md), no solo en el chat.

## 5. Documentar

**¿lo dijo el usuario?** → peticiones · **¿es lo que pasó y por qué?** → registro ·
**¿es un dato de este caso?** → ficha · **¿serviría con otro caso?** → este flujo.

---

## Heurísticas aprendidas (lo más valioso)

### 1. ⚠️ <título del fallo en una línea>

<Qué falló, **por qué** pasa (la causa real, no el síntoma) y qué se hace en su lugar.>
↳ [aN](REGISTRO-DECISIONES.md#aN-slug)

---

## Herramientas de esta fase

| Herramienta | Para qué |
|---|---|
| | |

---

## Qué NO transfiere de un caso a otro

- <todo lo que hay que **recalcular** con un caso nuevo. Si no está en esta lista, es método.>
