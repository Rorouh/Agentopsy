# Prompt para Claude Code — grafo de relaciones legible e interactivo

Copia todo lo que hay debajo de la línea y pégalo en Claude Code, dentro del
repo y con la rama actualizada (`git pull`).

Este documento es un andamio de trabajo: bórralo cuando el trabajo esté hecho.

## Estado (2026-09-03)

**Ya hecho**, en `limpieza`, sin subir:

- Los tres problemas medidos del layout, los tres arreglados
  (`backend/forensia/graph/layout.py` reescrito).
- El relajador determinista de solapamientos y el lienzo que crece con sus
  `notas`, publicadas por el router y pintadas en la vista.
- Zoom, desplazamiento, ajuste de encuadre y teclado (`GraphViewport`), con la
  transformación en el CONTENEDOR para no tocar el PNG exportado.
- Nodo de dos líneas, rótulos de relación horizontales en caja, enfoque de la
  vecindad al pulsar un nodo.
- `backend/tests/test_graph_layout.py` con los cuatro gates medibles.

**Queda**, y es lo que sigue describiendo este documento:

- Plegar y desplegar vecinos (`+` / `−`) y **grupos colapsados con su cuenta**.
  Es la parte que más descongestiona y toca backend y cliente a la vez, porque
  un nodo plegado no se coloca.
- Arrastrar un nodo, con «restablecer disposición».
- El agrupado de la papelera de reciclaje, que depende del colapso.

---

Vas a rehacer el **grafo de relaciones** de Agentopsy (fase 6) para que se lea
como los grafos de investigación de los productos comerciales de seguridad:
espaciado generoso, cero solapamientos, y **explorable con el ratón**. Hoy
produce una maraña ilegible. Lee este documento entero y después `CLAUDE.md`,
en particular la sección de Grafos y las RULE 2, 3 y 7.

## El objetivo, en una frase

Que el perito pueda **explorar** el grafo en pantalla —moverlo, acercarlo,
enfocar un nodo, desplegar sus vecinos— y que al exportarlo obtenga una figura
**idéntica y reproducible** para el informe pericial.

## La tensión central, y cómo se resuelve

Un grafo interactivo se dibuja normalmente con una **simulación de fuerzas**,
que es lo que separa los nodos y evita solapamientos. Pero la figura se adjunta
a un informe pericial y **tiene que dar la misma imagen hoy y dentro de un año**;
por eso hoy la geometría la calcula el servidor de forma determinista y no hay
simulación (`backend/forensia/graph/layout.py`).

**No elijas entre las dos. Haz las dos, separando los dos momentos:**

1. **Geometría base (servidor, determinista).** Sigue siendo la fuente de verdad
   y la que se exporta. Se mejora (ver «Los tres problemas medidos») y además
   pasa por un **relajador de solapamientos determinista**: número FIJO de
   iteraciones, sin aleatoriedad, sin dependencia del reloj. Misma entrada,
   mismas coordenadas, siempre. Eso ya elimina la maraña sin renunciar a nada.

2. **Exploración (cliente, efímera).** Zoom, desplazamiento, enfocar un nodo,
   plegar y desplegar vecinos, arrastrar un nodo. Todo esto vive SOLO en la
   sesión del navegador y **nunca altera la geometría exportada**.

3. **Si el perito reordena y quiere exportar lo que ve**, el PNG lleva las
   posiciones que él dejó y la figura declara dentro de la imagen que la
   disposición fue ajustada a mano. Nunca se exporta una posición manual
   haciéndola pasar por la calculada.

Si en algún momento te ves metiendo `Math.random()`, `Date.now()` o un bucle
`while` sin tope en el camino de la exportación, has roto el requisito
principal.

## Los tres problemas medidos del layout actual

Están calculados sobre el código, no estimados.

### 1. La figura usa la mitad del lienzo

```python
ANCHO = 1000
ALTO = 700
_MARGEN = 110
radio_max = min(ANCHO, ALTO) / 2 - _MARGEN     # = 240
```

`min(1000, 700)/2 - 110 = 240`: un círculo de **480 px de ancho en un lienzo de
1000**, que desperdicia el **52 % del ancho**. El `min` convierte un lienzo
apaisado en uno cuadrado. Por eso hay hueco muerto a los lados y el centro está
apelmazado.

**Arréglalo** con geometría elíptica: radio horizontal contra `ANCHO`, vertical
contra `ALTO`, con márgenes propios (arriba y abajo hace falta menos aire para
la etiqueta que a los lados).

### 2. El radio del anillo ignora cuántos nodos lleva

```python
radio = radio_max * (indice_anillo + 1) / len(presentes)
```

Depende de la posición del anillo, no de su población. En un caso real de tres
tipos:

| anillo  | radio | nodos | arco por nodo |
|---------|------:|------:|--------------:|
| user    |    80 |    12 |        42 px  |
| domain  |   160 |     5 |       201 px  |
| file    |   240 |    18 |        84 px  |

Una etiqueta como `wilsonjimmy8…` necesita unos 90 px. Los usuarios tienen 42 y
se pisan; los dominios tienen 201 y les sobra la mitad. **Está repartido al
revés.**

**Arréglalo**: el radio sale de la población y del ancho de etiqueta
(`radio ≳ (Σ ancho_etiqueta + separación × n) / 2π`), y cada anillo empieza donde
acaba el anterior. Si no cabe, **no comprimas en silencio** (RULE 2): crece el
`viewBox` o parte el tipo más poblado en dos anillos, y deja constancia en la
respuesta del layout de que hubo que hacerlo.

### 3. El tipo más numeroso va en el anillo más corto, por diseño

```python
ANILLOS = ("user", "hostname", "ip", "domain", "file")
# "Las entidades que más aristas concentran (cuentas, equipos) van dentro
#  para que sus aristas crucen lo menos posible."
```

El razonamiento es correcto —lo que concentra aristas va al centro— y el efecto
medido es el contrario: las cuentas son también el tipo más numeroso, así que
doce nodos acaban en la circunferencia más corta. **No fue un descuido**, así que
no lo «arregles» invirtiendo la tupla sin más: decide el orden por **grado medio
real** en ESE grafo, y que la población la absorba el radio del punto 2.
Reemplaza el comentario por el criterio nuevo.

## Qué copiar de las referencias

El operador ha compartido dos productos comerciales como referencia visual.
Copia esto:

**Nodos de dos líneas.** Valor arriba en tinta plena, tipo debajo en gris
pequeño (`i-04c1124ab…` / `EC2 Instance`). Hoy el tipo solo se distingue por
forma y color, lo que obliga a mirar la leyenda en cada nodo.

**Nodo enfocado destacado.** El seleccionado se pinta relleno y en color de
acento; el resto queda en contorno. Da un punto de entrada a la lectura, que es
lo que a un grafo denso le falta.

**Etiquetas de relación horizontales, en caja opaca**, sobre el punto medio de la
arista. Hoy van rotadas siguiendo el ángulo de la línea, a 9,5 px
(`web/src/pages/graphs/RelationGraph.tsx`, ~línea 351), y cruzan por encima de
otros nodos. En un PNG no hay hover que lo salve.

**Insignias de plegar y desplegar** (`+` / `−`) en el borde de cada nodo con
vecinos ocultos, y **grupos colapsados con su cuenta** (un nodo con «28» en vez
de veintiocho nodos). Esto es, de lejos, lo que más descongestiona un grafo
forense real.

**Espaciado generoso.** En las referencias hay quince nodos en el lienzo entero,
no cuarenta apiñados en el centro. Menos densidad por pantalla, más navegación.

**No copies**: los iconos por tipo de activo (Agentopsy tiene cinco tipos, no
cuarenta, y la forma ya los distingue) ni el panel de puntuación de riesgo (aquí
no existe tal cosa y RULE 2 prohíbe inventarla).

## Interacción que hay que añadir

- **Zoom y desplazamiento** sobre el lienzo, con un control de «ajustar a la
  vista».
- **Clic en un nodo**: lo enfoca, atenúa lo que no es su vecindad inmediata, y
  abre su ficha lateral con el valor completo, su tipo y **los hallazgos que lo
  sostienen** (el grafo del caso ya conserva esa lista al fundir; es lo que lo
  hace citable, y es lo que debe llevar a la procedencia).
- **Plegar y desplegar vecinos** desde la insignia del nodo.
- **Arrastrar un nodo** para deshacer un cruce puntual.
- **Deshacer la exploración**: un «restablecer disposición» que vuelve a la
  geometría calculada.

Nada de esto puede alterar el PNG salvo por el punto 3 de la sección anterior.

## Un problema que no es de layout

Entre los nodos `file` aparecen `$RABFQJP.txt`, `$R4JRZ47.mht`, `$R3TS6G4…`:
ficheros de la **papelera de reciclaje de Windows**, compitiendo en peso visual
con `NTUSER.DAT` o `SYSTEM.vhd`, que sí son sustantivos del caso.

**No los filtres.** Un fichero borrado puede ser exactamente la prueba, y
descartarlo en silencio es el tipo de decisión que RULE 2 prohíbe. Agrúpalos con
el mecanismo de colapso, con su cuenta y expandibles, y dilo en la figura.

## Restricciones que no puedes romper

- **La geometría base vive en el backend** (RULE 3: la lógica en `forensia/*`,
  el cliente es una superficie fina). El cliente puede transformar la vista
  (zoom, arrastre), no calcular la disposición canónica.
- **La exportación es determinista.** Ver la tensión central.
- **La medida del texto sigue siendo la constante** `ANCHO_CARACTER = 5.9`, no
  el canvas del navegador: una medida tomada de la tipografía instalada haría
  que el PNG saliera distinto en cada máquina.
- **El texto se pinta como TEXTO**, jamás como HTML (SECURITY INVARIANT 8): el
  contenido sale de evidencia hostil. En todo `web/src` no hay un solo
  `dangerouslySetInnerHTML`.
- **RULE 7**: nada de `§`, raya larga (`—`) ni emojis en `web/src`, comentarios
  incluidos. Hay un test que lo verifica y falla.
- **Accesibilidad**: el grafo tiene que seguir siendo recorrible con teclado y
  conservar su `aria-label`. Un lienzo interactivo solo con ratón excluye a
  quien no puede usarlo.

## Qué NO tocar

- La extracción del grafo por el modelo (`graph/extractor.py`), sus tres
  barreras de literalidad y su ronda de corrección.
- La fusión por par (tipo, valor normalizado) de `graph/fusion.py`, incluida la
  regla de que dos `file` con el mismo nombre en rutas distintas **no** se
  funden.
- El vocabulario cerrado de cinco tipos de nodo y trece de relación.
- El nombre del fichero exportado y el bloque de procedencia dentro de la imagen.

## Verificación antes de dar el trabajo por hecho

Tests de layout en `backend/tests/` que fijen lo medible:

- dos llamadas con la misma entrada devuelven coordenadas **idénticas**;
- **ningún par de nodos** queda a menos de la suma de sus radios más la
  separación mínima, ni ningún par de etiquetas se solapa;
- la figura ocupa más del 80 % del ancho del `viewBox` cuando hay nodos para
  ello;
- el relajador de solapamientos **termina en un número fijo de iteraciones**.

Y los tres gates de CI (RULE 6):

```bash
cd backend && ruff check . && pytest -q
cd web && npm ci && npm run typecheck && npm run build
docker compose config --quiet
```

Comprueba la figura **exportada a PNG**, no solo en pantalla: es su destino real
y es donde las etiquetas rotadas y los solapamientos se vuelven irreparables.

## Entrega

Un commit de código y otro `docs:` aparte si tocas documentación (RULE 4).
**RULE 0: sin atribución a IA en el mensaje.** No hagas `git push`: enseña el
diff y la figura resultante, en pantalla y exportada, y que decida el operador.
