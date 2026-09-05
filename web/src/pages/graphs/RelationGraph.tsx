import { forwardRef } from "react";

import type {
  GraphCanvas,
  GraphEdge,
  GraphInventory,
  GraphNode,
} from "../../api/types";
import { useThemePalette, type Palette } from "../timeline/themePalette";
import {
  NODOS_LEYENDA,
  colorNodo,
  colorRelacion,
  claveNodo,
  claveRelacion,
} from "./vocabulario";
import { useLang } from "../../i18n";

// La FIGURA del grafo de relaciones, en sus DOS modos.
//
// La geometría NO se calcula aquí, viene resuelta del backend
// (`agentopsy.graph.layout`), que es lo que hace que el mismo grafo dé la misma
// imagen en cualquier máquina: una figura que se adjunta a un informe pericial
// tiene que ser reproducible, y una simulación de fuerzas con semilla aleatoria
// dibuja distinto lo mismo en cada render.
//
// Los dos modos existen porque la PANTALLA y el PNG no son el mismo objeto:
//
// - `pantalla` dibuja SOLO el grafo (aristas, rótulos y nodos), en un lienzo del
//   tamaño exacto que calculó el backend. Es lo único que el visor mueve y
//   escala. El rótulo de la figura, el recuento y la leyenda quedan FUERA, como
//   texto fijo de la interfaz, porque son el marco de lectura y no el dato:
//   arrastrarlos con el dibujo sacaba el título de la ventana y dejaba la
//   leyenda lejos de donde se la busca, que es lo que hacía que la sección no
//   pareciese una herramienta acabada.
// - `exportacion` compone la figura ENTERA (cabecera, dibujo, leyenda y
//   procedencia) en un solo SVG, que es el que se serializa al PNG que se
//   adjunta a un informe. Se monta solo en el momento de exportar.
//
// El dibujo es el MISMO en los dos (`Dibujo`), así que lo que el perito explora
// y lo que se lleva al informe no pueden divergir. Y como el zoom y el
// desplazamiento viven en el CONTENEDOR (`GraphViewport`) y no en un `transform`
// dentro del SVG, lo que se serializa sigue siendo la geometría canónica, mire
// el perito donde mire.
//
// Todo el texto entra como nodos de texto del SVG (React los escapa), nunca como
// HTML: el valor de un nodo es contenido DERIVADO DE EVIDENCIA y puede venir
// sembrado por el investigado (SECURITY INVARIANT 8).

//: Márgenes del lienzo en el modo de EXPORTACIÓN. El dibujo ocupa
//: `lienzo.ancho x lienzo.alto`; aquí se le añade la cabecera arriba y la banda
//: de leyenda y procedencia abajo.
const MARGEN_X = 30;
const CABECERA = 92;
//: Pie con UNA línea de nodos y UNA de relaciones. Cuando la leyenda necesita
//: más líneas, crece con ellas (`pie`, calculado en el render).
const PIE_BASE = 128;
//: Alto de cada línea del pie (procedencia, aviso y, si la hay, la vista
//: declarada).
const ALTO_LINEA_PIE = 16;

//: Tiene que coincidir con `RADIO_NODO` y `MAX_CHARS_ETIQUETA` de
//: `agentopsy/graph/layout.py`: allí se reserva el sitio de cada nodo y aquí se
//: pinta, así que si divergen la figura vuelve a solaparse.
const RADIO_NODO = 19;
const MAX_CHARS_ETIQUETA = 22;

//: Las DOS líneas de etiqueta que van bajo el disco: el valor y, más pequeño y
//: en gris, el tipo. Con una sola línea el tipo solo se distinguía por la forma
//: y el color, lo que obliga a bajar a la leyenda en cada nodo.
const LINEA_VALOR = RADIO_NODO + 15;
const LINEA_TIPO = RADIO_NODO + 27;

//: Ancho medio de carácter del rótulo de una relación, a 9,5px. Mismo criterio
//: que `ANCHO_CARACTER`: estimado, no medido con el canvas, para que el PNG
//: salga igual en cualquier máquina.
const ANCHO_CARACTER_RELACION = 5.3;

//: Cuánto se apaga lo que no es la vecindad del nodo enfocado. No se OCULTA: un
//: nodo que desaparece al hacer clic en otro parece un fallo, y en un grafo
//: forense lo que no está conectado también es un dato.
const APAGADO = 0.22;

// ── rejilla de la leyenda ─────────────────────────────────────────────────────
//
// Solo la usa el modo de EXPORTACIÓN: en pantalla la leyenda es HTML y la
// dispone el navegador. Las dos filas comparten UNA rejilla de columnas: la
// muestra de la primera relación cae justo debajo de la del primer tipo de nodo,
// la de la segunda debajo de la segunda, y así. Antes cada fila llevaba su
// propio paso fijo (118 los nodos, 152 las relaciones), de modo que solo
// coincidía la primera entrada y el resto quedaba a la deriva; y como el paso no
// miraba la etiqueta, una larga se comía el hueco de la siguiente
// («Transferencia de ficheros» ocupa 148 de los 152 px de su hueco) y dos
// entradas acababan pegadas mientras otras dos quedaban separadas por un palmo.
//
// El ancho de columna sale de la entrada MÁS ancha de la leyenda, así que
// ninguna invade a la que tiene al lado, y las que no caben en el ancho de la
// figura pasan a la línea siguiente: la leyenda enumera SIEMPRE todo lo que la
// figura pinta, nunca las primeras que quepan.
const LEYENDA_X = MARGEN_X + 88; //: donde acaba el rótulo de la fila
const LEYENDA_LINEA = 24; //: alto de una línea de leyenda
const LEYENDA_AIRE = 26; //: separación mínima entre dos columnas
const MUESTRA_NODO = 15; //: cuadro de color + hueco, antes de la etiqueta
const MUESTRA_RELACION = 20; //: raya de color + hueco, antes de la etiqueta

//: Ancho aproximado de una etiqueta a 10,5px. Se ESTIMA con un ancho medio de
//: carácter en vez de medirlo con el canvas del navegador porque la figura se
//: exporta a PNG y se adjunta a un informe: la rejilla tiene que salir igual en
//: cualquier máquina, y una medida tomada de la tipografía instalada la haría
//: depender del equipo. El valor va por encima del ancho real medido (5,0 a 5,9
//: px por carácter en las etiquetas del vocabulario), que es el lado seguro:
//: sobra aire, nunca falta.
const ANCHO_CARACTER = 5.9;

function anchoEtiqueta(texto: string): number {
  return texto.length * ANCHO_CARACTER;
}

//: Cuántas entradas van en cada línea. Cuando no caben todas, las líneas salen
//: EQUILIBRADAS: cinco relaciones con sitio para cuatro se reparten 3 + 2, no
//: 4 + 1, que deja una entrada suelta debajo de una fila llena y vuelve a
//: romper la lectura en columnas.
function porLinea(entradas: number, cabenPorLinea: number): number {
  if (entradas <= cabenPorLinea) return Math.max(1, entradas);
  return Math.ceil(entradas / Math.ceil(entradas / cabenPorLinea));
}

// Qué tipos y qué relaciones PINTA de verdad esta figura. La leyenda del SVG
// exportado y la de la pantalla salen de esta misma cuenta, para que no puedan
// decir cosas distintas de la misma figura.
export function tiposPresentes(nodos: GraphNode[]): string[] {
  return NODOS_LEYENDA.filter((tipo) => nodos.some((n) => n.tipo === tipo));
}

export function relacionesPresentes(relaciones: GraphEdge[]): string[] {
  return Array.from(new Set(relaciones.map((r) => r.tipo))).sort();
}

export type ModoFigura = "pantalla" | "exportacion";

type Props = {
  modo: ModoFigura;
  titulo: string;
  subtitulo: string;
  nodos: GraphNode[];
  relaciones: GraphEdge[];
  lienzo: GraphCanvas;
  aviso: string;
  // Qué se dice cuando no hay nodos. Lo decide quien la usa, porque «vacío» no
  // significa lo mismo en las dos figuras: en la del caso puede que no se haya
  // extraído nada todavía, y en la de un hallazgo es que ese hallazgo no nombra
  // ninguna entidad, que es un resultado legítimo y distinto.
  vacio: string;
  // Identidad de la figura, resuelta por el backend: va DENTRO del dibujo para
  // que el PNG exportado diga de qué caso es y cuándo se exportó.
  caseName: string;
  exportadoEn: string;
  seleccionado?: string | null;
  onSeleccionar?: (valor: string | null) => void;
  //: FUNCIÓN «INVENTARIO». Las entidades sin ninguna relación. Solo las dibuja
  //: el modo de EXPORTACIÓN, en una banda al pie: en pantalla se leen mejor como
  //: lista, y meterlas en el lienzo lo alargaba hasta devolver los rótulos a los
  //: cuatro píxeles de los que se venía (medido, ver `graph/inventario.py`).
  inventario?: GraphInventory | null;
  //: FUNCIÓN «VISTAS». El corte aplicado, ya redactado. Va DENTRO del PNG: una
  //: figura recortada que no dice que lo está engaña a quien la lee en un
  //: informe.
  vistaDeclarada?: string | null;
  //: FUNCIÓN «LOCALIZADOR». Cuántos saltos de vecindad quedan a plena tinta al
  //: enfocar un nodo. 1 es lo de siempre.
  profundidadFoco?: number;
};

function recorta(valor: string): string {
  return valor.length <= MAX_CHARS_ETIQUETA
    ? valor
    : `${valor.slice(0, MAX_CHARS_ETIQUETA - 1)}…`;
}

//: Abreviatura del tipo, dentro de la forma. Es el «icono» del nodo: no hay
//: pictogramas (RULE 7) y una letra sí rasteriza igual en cualquier visor.
const ABREV: Record<string, string> = {
  ip: "IP",
  domain: "DOM",
  hostname: "EQ",
  user: "USR",
  file: "FIC",
};

//: Forma por tipo, redundante con el color para que la figura siga siendo legible
//: en escala de grises o para quien no distinga dos de los tonos.
function formaNodo(tipo: string, x: number, y: number, color: string) {
  const r = RADIO_NODO;
  switch (tipo) {
    case "user":
      return <circle cx={x} cy={y} r={r} fill={color} />;
    case "domain":
      return (
        <polygon
          points={`${x},${y - r} ${x + r},${y} ${x},${y + r} ${x - r},${y}`}
          fill={color}
        />
      );
    case "ip":
      return (
        <polygon
          points={[0, 1, 2, 3, 4, 5]
            .map((i) => {
              const a = (Math.PI / 3) * i - Math.PI / 6;
              return `${(x + r * Math.cos(a)).toFixed(1)},${(y + r * Math.sin(a)).toFixed(1)}`;
            })
            .join(" ")}
          fill={color}
        />
      );
    case "hostname":
      return <rect x={x - r} y={y - r * 0.8} width={r * 2} height={r * 1.6} fill={color} />;
    default: // file, y cualquier tipo que el backend gane y esta tabla no conozca
      return <rect x={x - r} y={y - r} width={r * 2} height={r * 2} fill={color} />;
  }
}

type DibujoProps = {
  nodos: GraphNode[];
  relaciones: GraphEdge[];
  //: Desplazamiento del dibujo dentro del SVG que lo contiene. Es 0 en pantalla
  //: (el SVG es exactamente el lienzo) y deja sitio a la cabecera al exportar.
  dx: number;
  dy: number;
  oscuro: boolean;
  palette: Palette;
  rotuloNodo: (tipo: string) => string;
  rotuloRelacion: (tipo: string) => string;
  seleccionado?: string | null;
  onSeleccionar?: (valor: string | null) => void;
  profundidad: number;
};

// FUNCIÓN «LOCALIZADOR»: la vecindad de un nodo hasta `profundidad` saltos.
//
// Con un salto se ve con quién habla la entidad; con dos, la cadena en la que
// está metida, que en un caso de exfiltración es lo que se quiere enseñar (la
// cuenta, el fichero que toca y a dónde va). Más de dos, sobre un grafo de 36
// nodos, ya alcanza casi todo y deja de distinguir.
function vecindadHasta(
  origen: string,
  relaciones: GraphEdge[],
  profundidad: number,
): Set<string> {
  const dentro = new Set<string>([origen]);
  let frontera = new Set<string>([origen]);
  for (let salto = 0; salto < profundidad; salto += 1) {
    const siguiente = new Set<string>();
    for (const r of relaciones) {
      if (frontera.has(r.origen) && !dentro.has(r.destino)) siguiente.add(r.destino);
      if (frontera.has(r.destino) && !dentro.has(r.origen)) siguiente.add(r.origen);
    }
    if (siguiente.size === 0) break;
    for (const v of siguiente) dentro.add(v);
    frontera = siguiente;
  }
  return dentro;
}

// El DIBUJO: aristas, sus rótulos y los nodos. Es lo único que el visor mueve, y
// es lo mismo que se compone dentro de la figura exportada.
function Dibujo({
  nodos,
  relaciones,
  dx,
  dy,
  oscuro,
  palette,
  rotuloNodo,
  rotuloRelacion,
  seleccionado,
  onSeleccionar,
  profundidad,
}: DibujoProps) {
  const posicion = new Map(nodos.map((n) => [n.valor, n]));

  // ENFOCAR un nodo: su vecindad queda a plena tinta y el resto se apaga. Es el
  // punto de entrada que a un grafo denso le falta, y es lo que hace legible una
  // figura que de un vistazo es una maraña.
  const hayFoco = Boolean(seleccionado && posicion.has(seleccionado));
  const vecindad =
    hayFoco && seleccionado
      ? vecindadHasta(seleccionado, relaciones, profundidad)
      : new Set<string>();

  // La geometría de cada arista, resuelta UNA vez y compartida por las dos
  // pasadas de pintado (líneas y rótulos).
  const trazos = relaciones.flatMap((r, i) => {
    const a = posicion.get(r.origen);
    const b = posicion.get(r.destino);
    if (!a || !b) return [];
    const x1 = a.x + dx;
    const y1 = a.y + dy;
    const x2 = b.x + dx;
    const y2 = b.y + dy;
    return [
      {
        r,
        i,
        x1,
        y1,
        x2,
        y2,
        angulo: Math.atan2(y2 - y1, x2 - x1),
        color: colorRelacion(r.tipo, oscuro),
        // Encendida cuando los DOS extremos están en la vecindad: con más de
        // un salto, una arista con un extremo fuera apuntaría a un nodo
        // apagado y se leería como que va a ninguna parte.
        tenue: hayFoco && !(vecindad.has(r.origen) && vecindad.has(r.destino)),
      },
    ];
  });

  return (
    <>
      {/* Aristas, en DOS pasadas: primero todas las líneas y luego todos los
          rótulos. Con una sola pasada, la línea de una arista posterior cruzaba
          por encima del rótulo de la anterior y lo tachaba. */}
      {trazos.map(({ r, i, x1, y1, x2, y2, angulo, color, tenue }) => {
        // La línea se acorta en los dos extremos para que la punta de flecha
        // toque el borde del nodo y no su centro.
        const ox = Math.cos(angulo) * (RADIO_NODO + 2);
        const oy = Math.sin(angulo) * (RADIO_NODO + 2);
        const px = x2 - ox;
        const py = y2 - oy;
        const punta = 7;
        return (
          <g
            key={`linea-${r.origen}-${r.destino}-${r.tipo}-${i}`}
            opacity={tenue ? APAGADO : 1}
          >
            <line
              x1={x1 + ox}
              y1={y1 + oy}
              x2={px}
              y2={py}
              stroke={color}
              strokeWidth={tenue ? 1 : 1.4}
            />
            <polygon
              points={[
                `${px},${py}`,
                `${px - punta * Math.cos(angulo - 0.4)},${py - punta * Math.sin(angulo - 0.4)}`,
                `${px - punta * Math.cos(angulo + 0.4)},${py - punta * Math.sin(angulo + 0.4)}`,
              ].join(" ")}
              fill={color}
            />
          </g>
        );
      })}

      {/* Los rótulos de relación, HORIZONTALES y en caja opaca. Antes iban
          girados siguiendo el ángulo de su línea, a 9,5px, y cruzaban por encima
          de otros nodos: en un PNG no hay hover que lo salve. */}
      {trazos.map(({ r, i, x1, y1, x2, y2, tenue }) => {
        const texto = rotuloRelacion(r.tipo);
        const anchoCaja = texto.length * ANCHO_CARACTER_RELACION + 10;
        // A dos tercios hacia el destino, no en el medio: en un concentrador
        // (una cuenta con varias aristas) todos los rótulos se juntaban sobre el
        // nombre del nodo y no se leía ninguno.
        const mx = x1 + (x2 - x1) * 0.62;
        const my = y1 + (y2 - y1) * 0.62;
        return (
          <g
            key={`rotulo-${r.origen}-${r.destino}-${r.tipo}-${i}`}
            opacity={tenue ? APAGADO : 1}
          >
            <rect
              x={mx - anchoCaja / 2}
              y={my - 8}
              width={anchoCaja}
              height={15}
              fill={palette["--surface"]}
              stroke={palette["--hair"]}
              strokeWidth={0.8}
            />
            <text
              x={mx}
              y={my + 3}
              textAnchor="middle"
              fill={palette["--ink-2"]}
              fontFamily="ui-sans-serif, system-ui, sans-serif"
              fontSize={9.5}
            >
              {texto}
            </text>
          </g>
        );
      })}

      {/* nodos */}
      {nodos.map((n) => {
        const color = colorNodo(n.tipo, oscuro);
        const x = n.x + dx;
        const y = n.y + dy;
        const activo = seleccionado === n.valor;
        const tenue = hayFoco && !vecindad.has(n.valor);
        return (
          <g
            key={`${n.tipo}:${n.valor}`}
            // Lo lee el visor para no confundir «pulsar un nodo» con «arrastrar
            // la vista»: sin esto, hacer clic en un nodo empieza un arrastre.
            data-nodo="1"
            opacity={tenue ? APAGADO : 1}
            onClick={() => onSeleccionar?.(activo ? null : n.valor)}
            style={{ cursor: onSeleccionar ? "pointer" : "default" }}
          >
            {activo && (
              <circle
                cx={x}
                cy={y}
                r={RADIO_NODO + 7}
                fill="none"
                stroke={color}
                strokeWidth={2}
              />
            )}
            {formaNodo(n.tipo, x, y, color)}
            <text
              x={x}
              y={y + 4}
              textAnchor="middle"
              fill={palette["--surface"]}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fontSize={9}
              fontWeight={700}
            >
              {ABREV[n.tipo] ?? "?"}
            </text>
            <text
              x={x}
              y={y + LINEA_VALOR}
              textAnchor="middle"
              fill={activo ? color : palette["--ink"]}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fontSize={10.5}
              fontWeight={activo ? 700 : 600}
            >
              {recorta(n.valor)}
            </text>
            <text
              x={x}
              y={y + LINEA_TIPO}
              textAnchor="middle"
              fill={palette["--ink-3"]}
              fontFamily="ui-sans-serif, system-ui, sans-serif"
              fontSize={9}
            >
              {rotuloNodo(n.tipo)}
            </text>
          </g>
        );
      })}
    </>
  );
}

export const RelationGraph = forwardRef<SVGSVGElement, Props>(function RelationGraph(
  {
    modo,
    titulo,
    subtitulo,
    nodos,
    relaciones,
    lienzo,
    aviso,
    vacio,
    caseName,
    exportadoEn,
    seleccionado,
    onSeleccionar,
    inventario,
    vistaDeclarada,
    profundidadFoco = 1,
  },
  ref,
) {
  const palette = useThemePalette();
  const { t } = useLang();
  // Un tipo que el vocabulario no declara sale TAL CUAL (RULE 2).
  const rotuloNodo = (tipo: string) => {
    const k = claveNodo(tipo);
    return k ? t(k) : tipo;
  };
  const rotuloRelacion = (tipo: string) => {
    const k = claveRelacion(tipo);
    return k ? t(k) : tipo;
  };
  const oscuro = document.documentElement.getAttribute("data-theme") === "dark";

  const dibujo = (dx: number, dy: number, extra: GraphNode[] = []) => (
    <Dibujo
      nodos={extra.length ? [...nodos, ...extra] : nodos}
      relaciones={relaciones}
      dx={dx}
      dy={dy}
      oscuro={oscuro}
      palette={palette}
      rotuloNodo={rotuloNodo}
      rotuloRelacion={rotuloRelacion}
      seleccionado={seleccionado}
      onSeleccionar={onSeleccionar}
      profundidad={profundidadFoco}
    />
  );

  // ── modo PANTALLA: solo el dibujo ──────────────────────────────────────────
  //
  // El SVG mide exactamente el lienzo que calculó el backend y no se estira solo
  // (nada de `width: 100%`): quien decide a qué escala se ve es el visor, que
  // así puede ajustar la figura ENTERA a la ventana en vez de ajustar solo su
  // ancho. El rótulo, el recuento y la leyenda los pinta la interfaz alrededor,
  // fijos.
  if (modo === "pantalla") {
    return (
      <svg
        ref={ref}
        width={lienzo.ancho}
        height={lienzo.alto}
        viewBox={`0 0 ${lienzo.ancho} ${lienzo.alto}`}
        xmlns="http://www.w3.org/2000/svg"
        style={{ display: "block" }}
        role="img"
        aria-label={`${titulo}. ${subtitulo}`}
      >
        {/* Sin fondo ni borde PROPIOS. El lienzo los llevaba, y dentro del marco
            del visor eso pintaba un segundo recuadro flotando en el primero. El
            fondo lo pone ahora el marco (`.graph-viewport-frame`), que es el
            único borde de la sección, y el desplazamiento va acotado para que la
            figura no se pueda sacar de él: el tope hace el mismo trabajo que
            hacía ese borde, decir dónde acaba la figura, sin dibujar nada. */}
        {nodos.length === 0 && (
          <text
            x={lienzo.ancho / 2}
            y={lienzo.alto / 2}
            textAnchor="middle"
            fill={palette["--ink-3"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={13}
          >
            {vacio}
          </text>
        )}
        {dibujo(0, 0)}
      </svg>
    );
  }

  // ── modo EXPORTACIÓN: la figura entera, en un solo SVG ─────────────────────

  const ancho = lienzo.ancho + MARGEN_X * 2;
  const dx = MARGEN_X;
  const dy = CABECERA;

  // Solo se pintan en la leyenda los tipos y las relaciones PRESENTES: una
  // leyenda con trece entradas de las que se usan dos no explica, estorba.
  const tipos = tiposPresentes(nodos);
  const relacionesLeyenda = relacionesPresentes(relaciones);

  // La rejilla que comparten las dos filas de la leyenda.
  const anchoColumna =
    Math.max(
      0,
      ...tipos.map((tipo) => MUESTRA_NODO + anchoEtiqueta(rotuloNodo(tipo))),
      ...relacionesLeyenda.map(
        (tipo) => MUESTRA_RELACION + anchoEtiqueta(rotuloRelacion(tipo)),
      ),
    ) + LEYENDA_AIRE;
  //: Cuántas columnas caben. La última no necesita su aire de la derecha, así
  //: que se le devuelve antes de dividir: sin eso, una leyenda que entra por los
  //: pelos se parte en dos líneas sin motivo.
  const caben = Math.max(
    1,
    Math.floor((ancho - MARGEN_X - LEYENDA_X + LEYENDA_AIRE) / anchoColumna),
  );
  const nodosPorLinea = porLinea(tipos.length, caben);
  const relacionesPorLinea = porLinea(relacionesLeyenda.length, caben);
  // Una fila sin entradas ocupa igualmente su línea: ahí va su «n/d».
  const lineasNodos = Math.max(1, Math.ceil(tipos.length / nodosPorLinea));
  const lineasRelaciones = Math.max(
    1,
    Math.ceil(relacionesLeyenda.length / relacionesPorLinea),
  );

  // FUNCIÓN «INVENTARIO»: la banda de entidades sueltas solo la dibuja el PNG, y
  // trae su propio alto de lienzo, calculado por el backend con la MISMA reserva
  // de sitio que usa el dibujo. El ancho no cambia nunca, así que las
  // coordenadas de la red son idénticas a las de la pantalla.
  const banda = inventario && inventario.nodos.length > 0 ? inventario : null;
  const altoDibujo = banda ? banda.lienzo.alto : lienzo.alto;

  // Las líneas del pie, de arriba abajo. La vista declarada (FUNCIÓN «VISTAS»)
  // añade una: un recorte que no se anuncia dentro de la propia imagen es lo que
  // convierte una figura en un argumento tramposo.
  const lineasPie: { texto: string; mono: boolean }[] = [
    {
      texto: t("graph.provenance", {
        case: caseName,
        date: exportadoEn,
        nodes: nodos.length + (banda ? banda.nodos.length : 0),
        edges: relaciones.length,
      }),
      mono: true,
    },
    { texto: aviso, mono: false },
  ];
  if (vistaDeclarada) lineasPie.push({ texto: vistaDeclarada, mono: true });

  const pie =
    PIE_BASE +
    (lineasNodos + lineasRelaciones - 2) * LEYENDA_LINEA +
    (lineasPie.length - 2) * ALTO_LINEA_PIE;
  const alto = altoDibujo + CABECERA + pie;
  //: `y` de la línea `i` de la leyenda, contando desde la de «NODOS».
  const yLinea = (i: number) => alto - pie + 26 + i * LEYENDA_LINEA;
  //: `x` de la entrada que ocupa la columna `c`, la MISMA en las dos filas.
  const xColumna = (c: number) => LEYENDA_X + c * anchoColumna;

  return (
    <svg
      ref={ref}
      width={ancho}
      height={alto}
      viewBox={`0 0 ${ancho} ${alto}`}
      xmlns="http://www.w3.org/2000/svg"
      style={{ maxWidth: "100%", height: "auto", display: "block" }}
      role="img"
      aria-label={`${titulo}. ${subtitulo}`}
    >
      <rect x={0} y={0} width={ancho} height={alto} fill={palette["--surface"]} />
      <rect
        x={0.5}
        y={0.5}
        width={ancho - 1}
        height={alto - 1}
        fill="none"
        stroke={palette["--hair"]}
        strokeWidth={1}
      />

      {/* cabecera */}
      <text
        x={MARGEN_X}
        y={34}
        fill={palette["--ink"]}
        fontFamily="ui-sans-serif, system-ui, sans-serif"
        fontSize={16}
        fontWeight={600}
      >
        {titulo}
      </text>
      <text
        x={MARGEN_X}
        y={54}
        fill={palette["--ink-3"]}
        fontFamily="ui-sans-serif, system-ui, sans-serif"
        fontSize={12}
      >
        {subtitulo}
      </text>
      {/* la píldora del recuento, centrada */}
      <rect
        x={ancho / 2 - 78}
        y={22}
        width={156}
        height={24}
        fill="none"
        stroke={palette["--hair"]}
        strokeWidth={1}
      />
      <text
        x={ancho / 2}
        y={38}
        textAnchor="middle"
        fill={palette["--ink-2"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={11}
      >
        {t("graph.svgCounts", {
          nodes: nodos.length + (banda ? banda.nodos.length : 0),
          edges: relaciones.length,
        })}
      </text>
      <line
        x1={MARGEN_X}
        y1={CABECERA - 20}
        x2={ancho - MARGEN_X}
        y2={CABECERA - 20}
        stroke={palette["--hair"]}
        strokeWidth={1}
      />

      {nodos.length === 0 && (
        <text
          x={ancho / 2}
          y={CABECERA + lienzo.alto / 2}
          textAnchor="middle"
          fill={palette["--ink-3"]}
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          fontSize={13}
        >
          {vacio}
        </text>
      )}

      {dibujo(dx, dy, banda ? banda.nodos : [])}

      {/* FUNCIÓN «INVENTARIO»: la raya y el rótulo que abren la banda. Los nodos
          de la banda los pinta el mismo `Dibujo` que la red, con su forma y su
          color, porque son las mismas entidades: lo único que cambia es que
          ninguna relación las nombra, y eso lo dice el rótulo. */}
      {banda && (
        <>
          <line
            x1={MARGEN_X}
            y1={dy + banda.y}
            x2={ancho - MARGEN_X}
            y2={dy + banda.y}
            stroke={palette["--hair"]}
            strokeWidth={1}
            strokeDasharray="3 3"
          />
          <text
            x={MARGEN_X}
            y={dy + banda.y + 24}
            fill={palette["--ink-2"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={11}
          >
            {t("graph.inventoryBand", { count: banda.total })}
          </text>
        </>
      )}

      {/* leyenda, abajo a la izquierda, DENTRO de la figura */}
      <line
        x1={MARGEN_X}
        y1={alto - pie + 8}
        x2={ancho - MARGEN_X}
        y2={alto - pie + 8}
        stroke={palette["--hair"]}
        strokeWidth={1}
      />
      <text
        x={MARGEN_X}
        y={yLinea(0) + 4}
        fill={palette["--ink-4"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={9}
        letterSpacing={0.6}
      >
        {t("graph.legendNodes")}
      </text>
      {tipos.map((tipo, i) => (
        <g
          key={`leyenda-nodo-${tipo}`}
          transform={`translate(${xColumna(i % nodosPorLinea)}, ${yLinea(
            Math.floor(i / nodosPorLinea),
          )})`}
        >
          <rect x={0} y={-7} width={9} height={9} fill={colorNodo(tipo, oscuro)} />
          <text
            x={MUESTRA_NODO}
            y={1}
            fill={palette["--ink-2"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={10.5}
          >
            {rotuloNodo(tipo)}
          </text>
        </g>
      ))}
      {tipos.length === 0 && (
        <text
          x={LEYENDA_X}
          y={yLinea(0) + 4}
          fill={palette["--ink-3"]}
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          fontSize={10.5}
        >
          {t("common.na")}
        </text>
      )}
      <text
        x={MARGEN_X}
        y={yLinea(lineasNodos) + 4}
        fill={palette["--ink-4"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={9}
        letterSpacing={0.6}
      >
        {t("graph.legendEdges")}
      </text>
      {relacionesLeyenda.map((tipo, i) => (
        <g
          key={`leyenda-rel-${tipo}`}
          transform={`translate(${xColumna(i % relacionesPorLinea)}, ${yLinea(
            lineasNodos + Math.floor(i / relacionesPorLinea),
          )})`}
        >
          <line
            x1={0}
            y1={-3}
            x2={14}
            y2={-3}
            stroke={colorRelacion(tipo, oscuro)}
            strokeWidth={1.6}
          />
          <text
            x={MUESTRA_RELACION}
            y={1}
            fill={palette["--ink-2"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={10.5}
          >
            {rotuloRelacion(tipo)}
          </text>
        </g>
      ))}
      {relacionesLeyenda.length === 0 && (
        <text
          x={LEYENDA_X}
          y={yLinea(lineasNodos) + 4}
          fill={palette["--ink-3"]}
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          fontSize={10.5}
        >
          {t("common.na")}
        </text>
      )}

      {/* procedencia, DENTRO del dibujo: un PNG suelto tiene que decir de qué
          caso es, cuándo se exportó y qué clase de dato es lo que enseña. */}
      {lineasPie.map((linea, i) => (
        <text
          key={`pie-${i}`}
          x={MARGEN_X}
          y={alto - 18 - (lineasPie.length - 1 - i) * ALTO_LINEA_PIE}
          fill={palette["--ink-3"]}
          fontFamily={
            linea.mono
              ? "ui-monospace, SFMono-Regular, Menlo, monospace"
              : "ui-sans-serif, system-ui, sans-serif"
          }
          fontSize={9.5}
        >
          {linea.texto}
        </text>
      ))}
    </svg>
  );
});
