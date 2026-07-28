# PLANTILLAS

Los documentos en blanco del proyecto. **Para abrir una fase nueva o un caso nuevo se
copian de aquí** — así la estructura no se degrada con el tiempo ni se reinventa en cada
fase.

| Plantilla | Se copia a | Papel |
|---|---|---|
| [`README.fase.md`](README.fase.md) | `faseN/README.md` | Estado de la fase: objetivo, en qué punto está, qué contiene la carpeta. |
| [`FLUJO.md`](FLUJO.md) | `faseN/FLUJO.md` | 🏗️ La **receta reutilizable**. Generalizada, sin datos de un caso. |
| [`PETICIONES.md`](PETICIONES.md) | `faseN/PETICIONES.md` | 🗣️ Documento **del usuario**. Manda sobre el resto. |
| [`REGISTRO-DECISIONES.md`](REGISTRO-DECISIONES.md) | `faseN/REGISTRO-DECISIONES.md` | 📓 Bitácora **del asistente**, con anclas `#a…`. |
| [`FICHA.md`](FICHA.md) | `faseN/FICHA-<CASO>.md` | 🗂️ Datos **concretos de un caso**. Nada de aquí vale para otro caso. |

## Abrir una fase nueva

```sh
mkdir -p faseN/{input,output,refs,scripts}
cp PLANTILLAS/README.fase.md          faseN/README.md
cp PLANTILLAS/FLUJO.md                faseN/FLUJO.md
cp PLANTILLAS/PETICIONES.md           faseN/PETICIONES.md
cp PLANTILLAS/REGISTRO-DECISIONES.md  faseN/REGISTRO-DECISIONES.md
cp fase1/input/README.md              faseN/input/README.md    # convención de evidencias
cp fase1/output/README.md             faseN/output/README.md   # convención de resultados
```

Después: rellenar cabeceras, añadir la fase al índice de [`../CLAUDE.md`](../CLAUDE.md) y
escribir en el `README.md` de la fase nueva **qué se hereda de la anterior y qué no**.

## Abrir un caso nuevo dentro de una fase

`cp PLANTILLAS/FICHA.md faseN/FICHA-<CASO>.md` y rellenarla **midiendo sobre ese caso**.
Nunca copiar los valores de la ficha de otro caso.
