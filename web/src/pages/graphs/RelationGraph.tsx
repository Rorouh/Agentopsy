import { forwardRef } from "react";

import type { GraphCanvas, GraphEdge, GraphNode } from "../../api/types";
import { useThemePalette } from "../timeline/themePalette";
import {
  NODOS_LEYENDA,
  colorNodo,
  colorRelacion,
  etiquetaNodo,
  etiquetaRelacion,
} from "./vocabulario";

// La FIGURA del grafo de relaciones.
//
// Se lee como figura y no como tabla: sin zoom, sin brushing y sin arrastrar
// nodos. La geometría NO se calcula aquí, viene resuelta del backend
// (`forensia.graph.layout`), que es lo que hace que el mismo grafo dé la misma
// imagen en cualquier máquina: una figura que se adjunta a un informe pericial
// tiene que ser reproducible, y una simulación de fuerzas con semilla aleatoria
// dibuja distinto lo mismo en cada render.
//
// Todo el texto entra como nodos de texto del SVG (React los escapa), nunca como
// HTML: el valor de un nodo es contenido DERIVADO DE EVIDENCIA y puede venir
// sembrado por el investigado (SECURITY INVARIANT 8).

//: Márgenes del lienzo. El dibujo del backend ocupa `lienzo.ancho x lienzo.alto`;
//: aquí se le añade la cabecera arriba y la banda de leyenda y procedencia abajo.
const MARGEN_X = 30;
const CABECERA = 92;
const PIE = 128;

const RADIO_NODO = 19;
const MAX_CHARS_ETIQUETA = 22;

type Props = {
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

export const RelationGraph = forwardRef<SVGSVGElement, Props>(function RelationGraph(
  {
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
  },
  ref,
) {
  const palette = useThemePalette();
  const oscuro = document.documentElement.getAttribute("data-theme") === "dark";

  const ancho = lienzo.ancho + MARGEN_X * 2;
  const alto = lienzo.alto + CABECERA + PIE;
  const dx = MARGEN_X;
  const dy = CABECERA;

  const posicion = new Map(nodos.map((n) => [n.valor, n]));
  // Solo se pintan en la leyenda los tipos y las relaciones PRESENTES: una
  // leyenda con trece entradas de las que se usan dos no explica, estorba.
  const tiposPresentes = NODOS_LEYENDA.filter((t) => nodos.some((n) => n.tipo === t));
  const relacionesPresentes = Array.from(new Set(relaciones.map((r) => r.tipo))).sort();

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
        {`${nodos.length} nodos · ${relaciones.length} aristas`}
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

      {/* aristas, debajo de los nodos */}
      {relaciones.map((r, i) => {
        const a = posicion.get(r.origen);
        const b = posicion.get(r.destino);
        if (!a || !b) return null;
        const x1 = a.x + dx;
        const y1 = a.y + dy;
        const x2 = b.x + dx;
        const y2 = b.y + dy;
        const angulo = Math.atan2(y2 - y1, x2 - x1);
        // La línea se acorta en los dos extremos para que la punta de flecha
        // toque el borde del nodo y no su centro.
        const ox = Math.cos(angulo) * (RADIO_NODO + 2);
        const oy = Math.sin(angulo) * (RADIO_NODO + 2);
        const px = x2 - ox;
        const py = y2 - oy;
        const color = colorRelacion(r.tipo, oscuro);
        // La etiqueta no va en el punto medio sino a dos tercios hacia el
        // destino, y separada de la línea: en un concentrador (una cuenta con
        // varias aristas) todas las etiquetas se juntaban sobre el nombre del
        // nodo y no se leía ninguna.
        const t = 0.66;
        const mx = x1 + (x2 - x1) * t;
        const my = y1 + (y2 - y1) * t;
        // La etiqueta sigue el ángulo de su línea, pero nunca cabeza abajo.
        let grados = (angulo * 180) / Math.PI;
        if (grados > 90 || grados < -90) grados += 180;
        const punta = 7;
        return (
          <g key={`${r.origen}-${r.destino}-${r.tipo}-${i}`}>
            <line
              x1={x1 + ox}
              y1={y1 + oy}
              x2={px}
              y2={py}
              stroke={color}
              strokeWidth={1.2}
            />
            <polygon
              points={[
                `${px},${py}`,
                `${px - punta * Math.cos(angulo - 0.4)},${py - punta * Math.sin(angulo - 0.4)}`,
                `${px - punta * Math.cos(angulo + 0.4)},${py - punta * Math.sin(angulo + 0.4)}`,
              ].join(" ")}
              fill={color}
            />
            <text
              x={mx}
              y={my - 6}
              textAnchor="middle"
              transform={`rotate(${grados.toFixed(1)} ${mx} ${my - 6})`}
              fill={palette["--ink-3"]}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fontSize={9.5}
            >
              {etiquetaRelacion(r.tipo)}
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
        return (
          <g
            key={`${n.tipo}:${n.valor}`}
            onClick={() => onSeleccionar?.(activo ? null : n.valor)}
            style={{ cursor: onSeleccionar ? "pointer" : "default" }}
          >
            {activo && (
              <circle
                cx={x}
                cy={y}
                r={RADIO_NODO + 6}
                fill="none"
                stroke={color}
                strokeWidth={1}
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
              y={y + RADIO_NODO + 15}
              textAnchor="middle"
              fill={color}
              fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              fontSize={10.5}
              fontWeight={600}
            >
              {recorta(n.valor)}
            </text>
          </g>
        );
      })}

      {/* leyenda, abajo a la izquierda, DENTRO de la figura */}
      <line
        x1={MARGEN_X}
        y1={alto - PIE + 8}
        x2={ancho - MARGEN_X}
        y2={alto - PIE + 8}
        stroke={palette["--hair"]}
        strokeWidth={1}
      />
      <text
        x={MARGEN_X}
        y={alto - PIE + 30}
        fill={palette["--ink-4"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={9}
        letterSpacing={0.6}
      >
        NODOS
      </text>
      {tiposPresentes.map((t, i) => (
        <g key={`leyenda-nodo-${t}`} transform={`translate(${MARGEN_X + 88 + i * 118}, ${alto - PIE + 26})`}>
          <rect x={0} y={-7} width={9} height={9} fill={colorNodo(t, oscuro)} />
          <text
            x={15}
            y={1}
            fill={palette["--ink-2"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={10.5}
          >
            {etiquetaNodo(t)}
          </text>
        </g>
      ))}
      <text
        x={MARGEN_X}
        y={alto - PIE + 54}
        fill={palette["--ink-4"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={9}
        letterSpacing={0.6}
      >
        RELACIONES
      </text>
      {relacionesPresentes.slice(0, 6).map((t, i) => (
        <g key={`leyenda-rel-${t}`} transform={`translate(${MARGEN_X + 88 + i * 152}, ${alto - PIE + 50})`}>
          <line x1={0} y1={-3} x2={14} y2={-3} stroke={colorRelacion(t, oscuro)} strokeWidth={1.6} />
          <text
            x={20}
            y={1}
            fill={palette["--ink-2"]}
            fontFamily="ui-sans-serif, system-ui, sans-serif"
            fontSize={10.5}
          >
            {etiquetaRelacion(t)}
          </text>
        </g>
      ))}
      {relacionesPresentes.length === 0 && (
        <text
          x={MARGEN_X + 88}
          y={alto - PIE + 54}
          fill={palette["--ink-3"]}
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          fontSize={10.5}
        >
          n/d
        </text>
      )}

      {/* procedencia, DENTRO del dibujo: un PNG suelto tiene que decir de qué
          caso es, cuándo se exportó y qué clase de dato es lo que enseña. */}
      <text
        x={MARGEN_X}
        y={alto - 34}
        fill={palette["--ink-3"]}
        fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
        fontSize={9.5}
      >
        {`Caso: ${caseName} · Exportado: ${exportadoEn} · ${nodos.length} nodos, ${relaciones.length} aristas`}
      </text>
      <text
        x={MARGEN_X}
        y={alto - 18}
        fill={palette["--ink-3"]}
        fontFamily="ui-sans-serif, system-ui, sans-serif"
        fontSize={9.5}
      >
        {aviso}
      </text>
    </svg>
  );
});
