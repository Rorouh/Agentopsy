# Hoja de ruta

Lo que queda por hacer, medido sobre los casos reales que hay en `./projects`
(LoneWolf, M57-jean), no sobre estimaciones de sobremesa.

El estado de lo YA implementado vive en `CLAUDE.md`, sección *Status*. Este
fichero es solo lo pendiente: cuando algo de aquí se implementa, se documenta
allí y se borra de aquí.

---

## 0. Contexto: los arreglos del 2026-08-06

Los arreglos del 2026-08-06, ya implementados (el detalle está en `CLAUDE.md`),
quedan aquí resumidos porque son el estado sobre el que se mide lo que falta.

**Los desplegables en tema oscuro.** La lista de un `<select>` la dibuja el
navegador, no el CSS de la aplicación, y hereda el color del control: el campo
del rediseño es un subrayado sobre fondo transparente, así que en oscuro salía
tinta clara sobre el blanco del agente de usuario. La causa de fondo era que
faltaba declarar `color-scheme`, que es lo que le dice al navegador con qué
paleta pintar TODO lo que dibuja él: la lista del desplegable, la barra de
scroll, el aspa de un `input[type=search]`, el anillo de foco y el resalte del
autocompletado. Con `color-scheme: light | dark` por tema, más colores
explícitos para `option`/`optgroup` y para el autocompletado, la familia entera
queda cubierta, no solo el caso que se vio.

**Las dos exportaciones a CSV.** Ninguna se abría bien en una hoja de cálculo, y
por tres motivos del envoltorio, no de los datos: sin BOM (Excel en Windows lee
un `.csv` sin marca con la página de códigos del sistema, y «Exfiltración» salía
«ExfiltraciÃ³n»), separadas por comas (el separador de listas de un Windows en
español es el punto y coma, así que la fila entera caía en la columna A) y sin
bloque de procedencia (una tabla que no dice de qué caso es no se puede adjuntar
a un informe). Ahora las dos salen por `forensia.export_csv`: BOM, `sep=;`,
procedencia de dos columnas, una línea vacía y la tabla, con cabeceras en
castellano y el `argv` literal en la última columna, que es el dato más ancho.

---

## 1. El coste del informe pericial

El encargo dice que el informe lo redacta el modelo de principio a fin y que
solo el índice es común. Eso no está en discusión aquí: lo que sigue es cómo
pagar menos por el MISMO informe, o por uno mejor.

### 1.1 La medición

Informe v0.1 del caso LoneWolf, `claude-code` con Opus, 2026-08-06, entrada
`report_written` + `executor_run_finish` del log encadenado del caso:

| Concepto | Medida | Coste | Peso |
|---|---|---|---|
| Entrada (`cache_creation_input_tokens`) | 36.923 tokens | 0,369 USD | 35 % |
| Entrada leída de caché (`cache_read`) | 0 tokens | 0 USD | 0 % |
| Salida (`output_tokens`) | 26.637 tokens | 0,666 USD | 62 % |
| **Total de UNA llamada** | 5 min 34 s | **1,0659 USD** | |

El prompt son 68.945 caracteres y el informe 46.650 (99 bloques, 12 páginas).
Tarifas deducidas del propio audit y comprobadas contra otras corridas del caso
(cuadran al céntimo): entrada 5 USD/Mtok, escritura de caché de 1 hora 10
USD/Mtok, lectura de caché 0,5 USD/Mtok, salida 25 USD/Mtok.

**Calibración que hay que llevarse de aquí:** 68.945 caracteres son 36.923
tokens, o sea **1,87 caracteres por token**, menos de la mitad de la regla
habitual de 4. La causa está medida: el 29 % del material son identificadores
(100 SHA-256 completos = 6.400 caracteres, 272 UUID = 9.792), y una cadena
hexadecimal tokeniza a razón de un token cada dos o tres caracteres. Contar
caracteres subestima el coste por más del doble; el ahorro hay que medirlo en
IDENTIFICADORES y en tablas, no en prosa.

### 1.2 Hallazgo 1: el material lleva la misma cosa dos y tres veces

Desglose del material del caso LoneWolf (55.548 caracteres):

| Colección | Caracteres | % | Elementos |
|---|---|---|---|
| `traza` | 20.458 | 36,8 % | 28 |
| `trabajos` | 18.514 | 33,3 % | 16 |
| `hallazgos` | 11.931 | 21,5 % | 12 |
| `evidencias` | 2.264 | 4,1 % | 1 |
| resto (`mitre`, `uso_de_tools`, `caso`, `revisiones`, `integridad`, `perito`) | 2.242 | 4,0 % | |

Y medido evento a evento: de los 16 eventos `tool_run` de la traza, **los 16
están ya en `trabajos`** con más campos; de sus 12 eventos `finding`, **los 12
están ya en `hallazgos`**, también con más campos. Lo único que la traza aporta y
no está en ningún otro sitio es el ORDEN CRONOLÓGICO de las dos colecciones
entremezcladas.

El comando, además, viaja tres veces: `trabajos[].argv` como lista (2.487
caracteres), `trabajos[].argv_literal` como cadena (2.245) y `traza[].argv` otra
vez como lista (2.487). La regla 3 del prompt y la puerta 4 de custodia trabajan
sobre `argv_literal`; las dos listas no las lee nadie.

**Fase A.** `traza` pasa a ser un índice cronológico de verdad: marca temporal,
tipo y el identificador (`run_id` o `finding_id`) con el que se busca en
`trabajos`/`hallazgos`. Y `argv` (lista) sale de las dos colecciones. Estimado:
20.458 + 4.974 → unos 3.000 caracteres, es decir el material baja de 55.548 a
unos 35.600. Como lo que se va es la parte densa en UUID y en hashes, la caída en
TOKENS es mayor que en caracteres: 36.923 → del orden de 23.000.

Efecto de segundo orden que importa tanto como el ahorro: el modelo deja de leer
la misma ejecución tres veces con tres formas distintas. Menos material
redundante es también menos ocasión de citarlo mal.

### 1.3 Hallazgo 2: el 43 % de la salida es transcripción

Del informe real, por tipo de bloque:

| Tipo | Bloques | Caracteres | % |
|---|---|---|---|
| `p` (prosa) | 37 | 13.446 | 29,4 % |
| `table` | 7 | 9.757 | 21,4 % |
| `kv` (fichas) | 20 | 9.749 | 21,3 % |
| `finding` | 12 | 9.316 | 20,4 % |
| `list` + `h3` + `quote` | 23 | 3.399 | 7,5 % |

Examinadas una a una, ocho de las nueve tablas y catorce de los veinte `kv` son
COPIA LITERAL de datos que Agentopsy ya tiene exactos: la tabla de versiones del
apartado 1, la de la línea de tiempo del 3, la de técnicas del 4, la ficha de la
evidencia del 5, las DOCE fichas idénticas de procedencia de hallazgo del 6
(`Hallazgo` / `run_id` / `tool_id` / `SHA-256 del artefacto` / `Observado` /
`Confianza`, 4.071 caracteres entre todas), la tabla de uso de herramientas del
7, la tabla de 28 filas de la traza del Anexo A, y la ficha de integridad más la
tabla de nueve segmentos EWF del Anexo B. Suman 12.933 caracteres, el 28 % del
informe, y son la parte más densa en hashes, así que en tokens pesan bastante
más.

Pagar 25 USD por millón de tokens para que un modelo copie a mano una tabla que
Agentopsy tiene exacta es el peor uso posible de la salida. Y no es solo caro:
es la causa número uno de que las puertas 3 y 4 rechacen la redacción, porque un
solo hash mal copiado la tira entera y dispara la ronda de corrección, que
cuesta otra llamada completa.

**Fase B.** Un bloque nuevo que el modelo PIDE y el `writer` EXPANDE en el
servidor desde el material, con la forma
`{"t":"ref","fuente":"trabajos|hallazgo:<id>|evidencia:<id>|mitre|revisiones|integridad|traza"}`.
El modelo sigue decidiendo si la tabla va, dónde va y con qué prosa se
introduce; lo que deja de hacer es teclear su contenido.

Esto **no** es volver a la plantilla determinista que se retiró el 2026-07-30, y
la diferencia es exactamente dónde está la frontera: la plantilla sintetizaba la
NARRATIVA (el mismo molde para todos los casos, con los huecos rellenos); esto
solo garantiza la TRANSCRIPCIÓN de lo que ya está auditado, que es precisamente
lo que Agentopsy nunca delegó (las cuatro puertas existen porque el modelo no es
la autoridad sobre un hash). De hecho es forensemente MÁS fuerte: una tabla que
pinta Agentopsy no puede traer un hash mal copiado, y la puerta 4 deja de tener
nada que validar en esos bloques porque su contenido ES el argv auditado.

Estimado: la salida baja de 26.637 a unos 15.500 tokens.

### 1.4 Hallazgo 3: la entrada se factura al doble, y eso cambia la prioridad

`cache_creation_input_tokens` = 36.923 y `cache_read_input_tokens` = 0: la
redacción es UNA llamada, así que el CLI escribe una caché de una hora (10
USD/Mtok, el doble de la tarifa base) que nadie lee después. Son 0,185 USD de
prima, un 17 % del total.

Los puntos de corte de la caché los pone el CLI y no hay bandera documentada
para pedirle otra cosa, así que **esto no es accionable directamente**, y
conviene no perseguirlo: es el mismo callejón que ya se recorrió en la Fase 0
del chat. Lo que sí cambia son dos cosas:

1. **Cada token que se quita del material vale el doble.** El ahorro de la Fase
   A no se cuenta a 5 USD/Mtok, se cuenta a 10.
2. **La prima es el seguro de la ronda de corrección.** Cuando hay corrección, la
   segunda llamada SÍ lee esa caché a 0,5 USD/Mtok, y la prima se amortiza. Es
   otro argumento para la Fase B: cuanto menos transcriba el modelo, menos
   probable es la corrección, y cuando ocurra saldrá barata.

### 1.5 Estimación conjunta y cómo comprobarla

| | Ahora (medido) | Con A + B (estimado) |
|---|---|---|
| Entrada | 36.923 tok, 0,369 USD | ~23.000 tok, ~0,23 USD |
| Salida | 26.637 tok, 0,666 USD | ~15.500 tok, ~0,39 USD |
| **Total** | **1,066 USD** | **~0,62 USD (−42 %)** |

Son ESTIMACIONES derivadas de una corrida medida, no un A/B. La comprobación es
la que ya se usó en la fase de turnos: ejecutar la redacción del mismo caso por
el código real antes y después, y comparar `executor_run_finish` con
`report_written`. El caso LoneWolf sirve de patrón porque su informe v0.1 ya está
persistido y firmado, así que las dos redacciones son comparables bloque a
bloque.

Dos indicadores de que la Fase B no ha degradado el informe, además del coste:
el número de bloques de prosa (`p`, `h3`, `list`) no debe bajar, y el número de
apartados que pasan las cuatro puertas en el PRIMER intento
(`report_written.attempts == 1`) no debe empeorar.

### 1.6 Lo que NO hay que hacer

- **No trocear el informe en una llamada por apartado.** Parece la optimización
  obvia y es una regresión de un orden de magnitud: cada llamada volvería a
  pagar el material entero (23.000 tokens x 12 apartados), que es exactamente la
  trampa que costó 12,97 USD en el chat y quedó documentada en la fase de
  turnos.
- **No bajar `MAX_HALLAZGOS`, `MAX_TRABAJOS` ni `MAX_TRAZA`.** Eso no es
  optimizar, es un informe con menos caso dentro, y el recorte ya se declara en
  `truncado` porque callarlo sería peor.
- **No pedirle al modelo que sea más breve.** La longitud la decide el caso, es
  el contrato del encargo. Lo que se recorta es lo que el modelo no debería estar
  escribiendo, no lo que escribe.
- **No tocar las cuatro puertas de custodia.** Ninguna de las dos fases relaja
  una validación; la Fase B le quita trabajo a la puerta 4 porque elimina la
  ocasión de fallarla.

---

## 2. Orden sugerido

1. **Fase A del informe** (material sin duplicados). Es la más barata de
   implementar, no toca el contrato de respuesta y se puede medir sola.
2. **Fase B del informe** (bloque `ref` expandido en el servidor). Es la que más
   ahorra y la que toca el contrato, así que va después de tener la medición
   limpia de A.
