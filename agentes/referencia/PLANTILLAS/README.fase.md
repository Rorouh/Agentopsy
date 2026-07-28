# Fase N — <título de la fase>

Carpeta de trabajo y documentación de la fase: <una frase con qué se persigue>, y que sea
un **flujo reproducible**, no un apaño para un caso concreto.

> Reglas del proyecto e índice: [`../CLAUDE.md`](../CLAUDE.md).
> **Fase N−1:** <qué dejó lista> — docs en [`../faseN-1/`](../faseN-1/).
> **Qué se hereda:** <…>. **Qué NO se hereda:** <…>.

---

## 🎯 Objetivo

Entregables, que se abordan **de uno en uno**:

1. …  ← *en curso*
2. …
3. …

Las referencias que pase el usuario van en [`refs/`](refs/).

## Estado (AAAA-MM-DD)

- **Entrada de la fase:** <qué se recibe y de dónde>
- **Motor del flujo:** <script / módulo principal, en `scripts/`>
- **Entregable 1:** <no empezado / en curso / receta cerrada / validado>
- **Bloqueos abiertos:** <…>
- **Decisiones pendientes del usuario:** <…>

## 📂 Estructura

- [`FLUJO.md`](FLUJO.md) — 🏗️ **la receta reutilizable.** El archivo que hay que leer para
  replicar esto con otro caso. Empieza por "Arrancar en una sesión nueva".
- [`PETICIONES.md`](PETICIONES.md) — 🗣️ **documento del usuario**. Manda sobre el resto.
- [`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md) — 📓 **bitácora del asistente**, con
  anclas `#a…`.
- `FICHA-<CASO>.md` — 🗂️ **ficha de un caso**. Plantilla para el siguiente.
- `scripts/` · `refs/` · `input/` · `output/`.

## 🕸️ Cómo documentar

1. Cada petición del usuario → [`PETICIONES.md`](PETICIONES.md) (la más reciente arriba).
2. Cada decisión técnica → [`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md) con ancla `#a…`.
3. Cada dato **de un caso concreto** → `FICHA-<CASO>.md`.
4. Lo que se consolide como **método** → sube a [`FLUJO.md`](FLUJO.md) generalizado, con
   `↳` a la entrada del registro que lo explica.
