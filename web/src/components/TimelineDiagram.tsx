import { forwardRef, useImperativeHandle, useRef } from "react";
import type {
  DensityMark,
  DiagramLane,
  DiagramTick,
  FilesystemDiagram,
  InvestigationDiagram,
  TimelineDiagramLayout,
} from "../api/types";
import { PHASE_COLOR, useThemePalette } from "../palette";
import type { Palette } from "../palette";

// El PINTOR del dibujo de la línea temporal. La geometría en unidades de dominio
// (segundos desde el origen del eje, conteos, y la FILA de cada barra) la calcula
// `forensia.timeline.diagram`; aquí solo se traduce a píxeles, colores y
// tipografía. Nada de lo que las dos salidas tienen que pintar igual se decide en
// este fichero: si algo hay que cambiar en el eje, en el empaquetado o en el texto
// de la leyenda, se cambia en el backend y las dos figuras cambian juntas.
//
// El SVG se pinta con colores LITERALES (leídos de index.css por `useThemePalette`)
// y con un fondo explícito, porque se descarga: un fichero que se abre en un visor
// o se pega en un informe no tiene las variables CSS de la aplicación.

// ── Geometría, en unidades del viewBox (1 unidad = 1 px al 100 %) ─────────────
const W = 1000;
const PAD_L = 152; // canaleta de las etiquetas de fila (letras MACB, fases)
const PAD_R = 26;
const TITLE_H = 30;
const AXIS_H = 40;
const ROW_H = 19; // fila de barras de ejecución
const BAR_H = 11;
const MARK_ROW_H = 15; // fila de etiquetas de hallazgo
const LANE_HEAD = 22;
const LANE_GAP = 18;
const PHASE_H = 36;
const LEGEND_H = 26;
const CAPTION_LINE = 13;
const PAD_B = 14;

// Dibujo B
const DENSITY_H = 88; // banda del total de eventos por cubeta
const LETTER_H = 19; // cada una de las cuatro franjas por letra MACB
const RELEVANCE_H = 26; // marcas del triage, sobre la banda

const FONT_MONO = "'IBM Plex Mono','SFMono-Regular',Consolas,monospace";
const FONT_SANS = "'IBM Plex Sans',system-ui,-apple-system,sans-serif";

export interface TimelineDiagramHandle {
  /** Descarga la figura como SVG con el nombre que el backend le dio. */
  descargarSvg: () => void;
}

function fmt(n: number): string {
  return n.toLocaleString("es-ES");
}

/** Parte un texto en líneas de como mucho `max` caracteres, sin cortar palabras. */
function envolver(texto: string, max: number): string[] {
  const palabras = texto.split(" ");
  const lineas: string[] = [];
  let actual = "";
  for (const palabra of palabras) {
    if (actual && actual.length + palabra.length + 1 > max) {
      lineas.push(actual);
      actual = palabra;
    } else {
      actual = actual ? `${actual} ${palabra}` : palabra;
    }
  }
  if (actual) lineas.push(actual);
  return lineas;
}

const CAPTION_CHARS = 150;

function lineasDeProcedencia(procedencia: [string, string][]): string[] {
  const lineas: string[] = [];
  for (const [campo, valor] of procedencia) {
    const texto = `${campo}: ${valor}`;
    lineas.push(...envolver(texto, CAPTION_CHARS));
  }
  return lineas;
}

// ── Piezas compartidas ────────────────────────────────────────────────────────
function Eje({
  marcas,
  span,
  y,
  alto,
  paleta,
}: {
  marcas: DiagramTick[];
  span: number;
  y: number;
  alto: number;
  paleta: Palette;
}) {
  const escala = (t: number) => PAD_L + (t / span) * (W - PAD_L - PAD_R);
  return (
    <g>
      {marcas.map((m, i) => {
        const x = escala(m.t_s);
        // Las etiquetas de los extremos se anclan hacia dentro: centradas se
        // saldrían del viewBox y el visor las recortaría.
        const anchor = x < PAD_L + 24 ? "start" : x > W - PAD_R - 24 ? "end" : "middle";
        return (
          <g key={`${m.t_s}-${i}`}>
            <line
              x1={x}
              x2={x}
              y1={y}
              y2={y + alto}
              stroke={paleta["hair"]}
              strokeWidth={1}
            />
            <text
              x={x}
              y={y - 16}
              textAnchor={anchor}
              fontFamily={FONT_MONO}
              fontSize={10.5}
              fill={paleta["ink-3"]}
            >
              {m.etiqueta}
            </text>
            {m.sub && (
              <text
                x={x}
                y={y - 5}
                textAnchor={anchor}
                fontFamily={FONT_MONO}
                fontSize={9}
                fill={paleta["ink-4"]}
              >
                {m.sub}
              </text>
            )}
          </g>
        );
      })}
      <line
        x1={PAD_L}
        x2={W - PAD_R}
        y1={y}
        y2={y}
        stroke={paleta["line"]}
        strokeWidth={1}
      />
    </g>
  );
}

function Leyenda({
  entradas,
  y,
  paleta,
  color,
}: {
  entradas: { clave: string; etiqueta: string }[];
  y: number;
  paleta: Palette;
  color: (clave: string) => string;
}) {
  let x = PAD_L;
  return (
    <g>
      {entradas.map((e) => {
        const inicio = x;
        x += 14 + e.etiqueta.length * 5.4 + 18;
        return (
          <g key={e.clave}>
            <rect x={inicio} y={y - 7} width={9} height={9} fill={color(e.clave)} />
            <text
              x={inicio + 14}
              y={y + 1}
              fontFamily={FONT_MONO}
              fontSize={9.5}
              fill={paleta["ink-3"]}
            >
              {e.etiqueta}
            </text>
          </g>
        );
      })}
    </g>
  );
}

function Pie({
  lineas,
  avisos,
  y,
  paleta,
}: {
  lineas: string[];
  avisos: string[];
  y: number;
  paleta: Palette;
}) {
  let fila = 0;
  return (
    <g>
      <line
        x1={0}
        x2={W - PAD_R}
        y1={y - 10}
        y2={y - 10}
        stroke={paleta["hair"]}
        strokeWidth={1}
      />
      {lineas.map((linea, i) => (
        <text
          key={`p${i}`}
          x={0}
          y={y + fila++ * CAPTION_LINE}
          fontFamily={FONT_MONO}
          fontSize={9}
          fill={paleta["ink-4"]}
        >
          {linea}
        </text>
      ))}
      {avisos.flatMap((aviso, i) =>
        envolver(aviso, CAPTION_CHARS).map((linea, j) => (
          <text
            key={`a${i}-${j}`}
            x={0}
            y={y + fila++ * CAPTION_LINE}
            fontFamily={FONT_MONO}
            fontSize={9}
            fill={paleta["warning"]}
          >
            {j === 0 ? `Aviso: ${linea}` : linea}
          </text>
        )),
      )}
    </g>
  );
}

function Cabecera({
  titulo,
  derecha,
  paleta,
}: {
  titulo: string;
  derecha: string;
  paleta: Palette;
}) {
  return (
    <g>
      <text
        x={0}
        y={16}
        fontFamily={FONT_SANS}
        fontSize={13.5}
        fontWeight={600}
        fill={paleta["ink"]}
      >
        {titulo}
      </text>
      <text
        x={W - PAD_R}
        y={16}
        textAnchor="end"
        fontFamily={FONT_MONO}
        fontSize={9.5}
        fill={paleta["ink-4"]}
      >
        {derecha}
      </text>
    </g>
  );
}

// ── Dibujo A: franja de trabajos ─────────────────────────────────────────────
function alturaDeCarril(carril: DiagramLane): number {
  return (
    LANE_HEAD +
    carril.filas_barras * ROW_H +
    carril.filas_marcas * MARK_ROW_H +
    LANE_GAP
  );
}

function FranjaDeTrabajos({
  dibujo,
  paleta,
}: {
  dibujo: InvestigationDiagram;
  paleta: Palette;
}) {
  const span = dibujo.eje.span_s;
  const plotW = W - PAD_L - PAD_R;
  const escala = (t: number) => PAD_L + (t / span) * plotW;

  const cuerpoY = TITLE_H + AXIS_H;
  const altoCuerpo = dibujo.carriles.reduce((a, c) => a + alturaDeCarril(c), 0);
  const fasesY = cuerpoY + altoCuerpo;
  const leyendaY = fasesY + (dibujo.fases.length ? PHASE_H : 0) + LEGEND_H / 2;
  const pieY = leyendaY + LEGEND_H;
  const lineas = lineasDeProcedencia(dibujo.procedencia);
  const altoTotal =
    pieY +
    (lineas.length + dibujo.avisos.length) * CAPTION_LINE +
    PAD_B;

  const colorDeEstado = (clave: string) =>
    clave === "error"
      ? paleta["danger"]
      : clave === "running"
        ? paleta["ink-5"]
        : clave === "finding"
          ? paleta["accent"]
          : paleta["ink-2"];

  let y = cuerpoY;
  const carriles = dibujo.carriles.map((carril) => {
    const arriba = y;
    const plotTop = arriba + LANE_HEAD;
    const altoBarras = carril.filas_barras * ROW_H;
    const altoMarcas = carril.filas_marcas * MARK_ROW_H;
    y += alturaDeCarril(carril);
    return { carril, arriba, plotTop, altoBarras, altoMarcas };
  });

  return (
    <svg
      viewBox={`0 0 ${W} ${altoTotal}`}
      width={W}
      height={altoTotal}
      role="img"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>{dibujo.titulo}</title>
      <desc>
        {`${dibujo.case_name}. ${dibujo.resumen.ejecuciones} ejecuciones de herramienta y ` +
          `${dibujo.resumen.hallazgos} hallazgos entre ${dibujo.eje.t0} y ${dibujo.eje.t1} (UTC).`}
      </desc>
      <rect x={0} y={0} width={W} height={altoTotal} fill={paleta["surface"]} />
      <Cabecera
        titulo={dibujo.titulo}
        derecha={`${dibujo.case_name} · ${dibujo.eje.duracion} · UTC`}
        paleta={paleta}
      />
      <Eje
        marcas={dibujo.eje.marcas}
        span={span}
        y={cuerpoY}
        alto={altoCuerpo + (dibujo.fases.length ? PHASE_H - 12 : 0)}
        paleta={paleta}
      />

      {carriles.map(({ carril, arriba, plotTop, altoBarras, altoMarcas }) => (
        <g key={carril.clave}>
          <text
            x={0}
            y={arriba + 11}
            fontFamily={FONT_MONO}
            fontSize={11}
            fontWeight={600}
            fill={paleta["ink"]}
          >
            {carril.etiqueta}
          </text>
          <text
            x={W - PAD_R}
            y={arriba + 11}
            textAnchor="end"
            fontFamily={FONT_MONO}
            fontSize={9.5}
            fill={paleta["ink-4"]}
          >
            {`${carril.barras.length} ejecuciones · ${carril.marcas.length} hallazgos`}
          </text>
          <line
            x1={0}
            x2={W - PAD_R}
            y1={arriba + LANE_HEAD - 7}
            y2={arriba + LANE_HEAD - 7}
            stroke={paleta["hair"]}
            strokeWidth={1}
          />

          {/* Hallazgos: línea vertical que ATRAVIESA las barras (el hallazgo sale
              de la ejecución que cruza) y baja hasta su propia etiqueta. */}
          {carril.marcas.map((m) => {
            const x = escala(m.t_s);
            const fuerte = m.severidad === "high" || m.severidad === "critical";
            const abajo = plotTop + altoBarras + (m.fila + 1) * MARK_ROW_H - 4;
            const texto = m.etiqueta;
            // El LADO lo decidió el empaquetado: voltear aquí una etiqueta que el
            // backend contó a la derecha la dejaría encima de la anterior.
            const aDerecha = m.lado === "derecha";
            return (
              <g key={m.finding_id}>
                <title>
                  {`${m.titulo} · ${m.etiqueta_severidad}` +
                    (m.tecnicas.length ? ` · ${m.tecnicas.join(", ")}` : "") +
                    (m.ts ? ` · ${m.ts}` : "")}
                </title>
                <line
                  x1={x}
                  x2={x}
                  y1={plotTop}
                  y2={abajo}
                  stroke={paleta["accent"]}
                  strokeWidth={fuerte ? 1.6 : 1}
                  strokeOpacity={fuerte ? 0.95 : 0.7}
                />
                <path
                  d={`M ${x} ${plotTop - 5} L ${x + 4} ${plotTop} L ${x} ${plotTop + 5} L ${x - 4} ${plotTop} Z`}
                  fill={paleta["accent"]}
                />
                <text
                  x={aDerecha ? x + 6 : x - 6}
                  y={abajo}
                  textAnchor={aDerecha ? "start" : "end"}
                  fontFamily={FONT_MONO}
                  fontSize={9.5}
                  fill={m.tecnicas.length ? paleta["accent"] : paleta["ink-3"]}
                  stroke={paleta["surface"]}
                  strokeWidth={2.6}
                  paintOrder="stroke"
                >
                  {texto}
                </text>
              </g>
            );
          })}

          {/* Ejecuciones: barra de su duración medida. Sin cierre registrado no
              hay barra, hay trazo: el ancho cero se leería como «tardó nada». */}
          {carril.barras.map((b) => {
            const x = escala(b.t_s);
            const ancho =
              b.dur_s === null ? 3 : Math.max(2.5, (b.dur_s / span) * plotW);
            const by = b.fila * ROW_H + (ROW_H - BAR_H) / 2 + plotTop;
            const color = b.ok
              ? paleta["ink-2"]
              : b.estado === "running" || b.exit === null
                ? paleta["ink-5"]
                : paleta["danger"];
            const texto = b.etiqueta;
            const aDerecha = b.lado === "derecha";
            return (
              <g key={b.run_id || `${b.t_s}-${b.tool_id}`}>
                <title>
                  {`${b.tool_id} · ${b.duracion || "sin cierre registrado"} · exit ` +
                    `${b.exit === null ? "n/d" : b.exit}` +
                    (b.artefactos ? ` · ${b.artefactos} artefactos` : "") +
                    (b.run_id ? ` · run ${b.run_id.slice(0, 8)}` : "")}
                </title>
                <rect x={x} y={by} width={ancho} height={BAR_H} fill={color} />
                <text
                  x={aDerecha ? x + ancho + 6 : x - 6}
                  y={by + BAR_H - 2}
                  textAnchor={aDerecha ? "start" : "end"}
                  fontFamily={FONT_MONO}
                  fontSize={10}
                  fill={paleta["ink-3"]}
                  // Halo del color del fondo: las líneas verticales de los
                  // hallazgos atraviesan la franja y cruzaban este texto.
                  stroke={paleta["surface"]}
                  strokeWidth={2.6}
                  paintOrder="stroke"
                >
                  {texto}
                </text>
              </g>
            );
          })}
        </g>
      ))}

      {/* Banda de fases: es lo que convierte el dibujo en una historia. El orden
          de las fases es el de la matriz; los intervalos, los medidos. */}
      {dibujo.fases.length > 0 && (
        <g>
          <text
            x={0}
            y={fasesY + 13}
            fontFamily={FONT_MONO}
            fontSize={9.5}
            fill={paleta["ink-3"]}
          >
            Fases ATT&amp;CK
          </text>
          {dibujo.fases.map((f) => {
            const x = escala(f.t0_s);
            const ancho = Math.max(6, escala(f.t1_s) - x);
            return (
              <g key={f.clave}>
                <title>
                  {`${f.etiqueta} · ${f.hallazgos} hallazgo(s) · ${f.tecnicas.join(", ")}`}
                </title>
                <rect
                  x={x}
                  y={fasesY + 4}
                  width={ancho}
                  height={9}
                  fill={PHASE_COLOR[f.clave] ?? paleta["ink-4"]}
                  fillOpacity={0.75}
                />
                <text
                  x={x}
                  y={fasesY + 26}
                  fontFamily={FONT_MONO}
                  fontSize={9.5}
                  fill={paleta["ink-3"]}
                >
                  {`${f.etiqueta} (${f.hallazgos})`}
                </text>
              </g>
            );
          })}
        </g>
      )}

      <Leyenda
        entradas={dibujo.leyenda}
        y={leyendaY}
        paleta={paleta}
        color={colorDeEstado}
      />
      <Pie
        lineas={lineas}
        avisos={dibujo.avisos}
        y={pieY + 6}
        paleta={paleta}
      />
    </svg>
  );
}

// ── Dibujo B: banda de densidad MACB ─────────────────────────────────────────
function BandaDeDensidad({
  dibujo,
  paleta,
}: {
  dibujo: FilesystemDiagram;
  paleta: Palette;
}) {
  const span = dibujo.eje.span_s;
  const plotW = W - PAD_L - PAD_R;
  const escala = (t: number) => PAD_L + (t / span) * plotW;
  const anchoCubeta = Math.max(1, (dibujo.granularidad.bucket_s / span) * plotW);

  const relevanciaY = TITLE_H + AXIS_H;
  const totalTop = relevanciaY + RELEVANCE_H;
  const totalBase = totalTop + DENSITY_H;
  const letrasY = totalBase + 22;
  const finLetras = letrasY + dibujo.letras.length * LETTER_H;
  const leyendaY = finLetras + LEGEND_H / 2;
  const pieY = leyendaY + LEGEND_H;
  const lineas = lineasDeProcedencia(dibujo.procedencia);
  const altoTotal = pieY + (lineas.length + dibujo.avisos.length) * CAPTION_LINE + PAD_B;

  // Las marcas se pintan TODAS y NINGUNA se rotula: en un disco real caen decenas
  // en cubetas contiguas y sus etiquetas se apilan en una mancha. Lo que hay
  // detrás lo dice el resumen por categoría del bloque de procedencia, y el
  // detalle de cada evento, su tooltip y la pestaña de eventos relevantes.
  const marcaTitulo = (m: DensityMark) =>
    `${m.total} evento(s) relevante(s) · ${m.principal.motivo} · ${m.principal.ruta} · ${m.principal.ts}`;

  return (
    <svg
      viewBox={`0 0 ${W} ${altoTotal}`}
      width={W}
      height={altoTotal}
      role="img"
      xmlns="http://www.w3.org/2000/svg"
    >
      <title>{dibujo.titulo}</title>
      <desc>
        {`${dibujo.case_name}, evidencia ${dibujo.evidence_label}. ${fmt(dibujo.resumen.eventos)} ` +
          `eventos MACB en ${dibujo.granularidad.cubetas} cubetas ${dibujo.granularidad.etiqueta} ` +
          `entre ${dibujo.eje.t0} y ${dibujo.eje.t1} (UTC).`}
      </desc>
      <rect x={0} y={0} width={W} height={altoTotal} fill={paleta["surface"]} />
      <Cabecera
        titulo={dibujo.titulo}
        derecha={`${dibujo.evidence_label} · ${dibujo.eje.duracion} · UTC`}
        paleta={paleta}
      />
      <Eje
        marcas={dibujo.eje.marcas}
        span={span}
        y={relevanciaY}
        alto={finLetras - relevanciaY - 8}
        paleta={paleta}
      />

      {/* Marcas del triage de relevancia, sobre la banda. */}
      {dibujo.marcas.map((m) => {
        const x = escala(m.t_s) + anchoCubeta / 2;
        const opacidad =
          dibujo.max_peso > 0 ? 0.4 + 0.6 * (m.principal.peso / dibujo.max_peso) : 0.6;
        const base = relevanciaY + RELEVANCE_H - 6;
        return (
          <g key={`r${m.cubeta}`}>
            <title>{marcaTitulo(m)}</title>
            <path
              d={`M ${x} ${base - 7} L ${x + 4.5} ${base} L ${x - 4.5} ${base} Z`}
              fill={paleta["accent"]}
              fillOpacity={opacidad}
            />
          </g>
        );
      })}

      {/* Banda del TOTAL por cubeta. La altura es el número de eventos; el
          reparto interno por letra es proporcional dentro de esa altura, para que
          la banda siga leyéndose con una sola escala. */}
      <text
        x={0}
        y={totalTop + 10}
        fontFamily={FONT_MONO}
        fontSize={9.5}
        fill={paleta["ink-3"]}
      >
        Eventos MACB
      </text>
      <text
        x={0}
        y={totalTop + 23}
        fontFamily={FONT_MONO}
        fontSize={9}
        fill={paleta["ink-4"]}
      >
        {`máx. ${fmt(dibujo.max_total)}`}
      </text>
      {dibujo.cubetas.map((c) => {
        if (!c.total) return null;
        const alto = dibujo.max_total ? (c.total / dibujo.max_total) * DENSITY_H : 0;
        return (
          <rect
            key={`t${c.indice}`}
            x={escala(c.t_s)}
            y={totalBase - alto}
            width={Math.max(1, anchoCubeta - 0.6)}
            height={alto}
            fill={paleta["ink-2"]}
          >
            <title>
              {`${c.inicio} · ${fmt(c.total)} eventos` +
                (c.relevantes ? ` · ${c.relevantes} relevantes` : "")}
            </title>
          </rect>
        );
      })}
      <line
        x1={PAD_L}
        x2={W - PAD_R}
        y1={totalBase}
        y2={totalBase}
        stroke={paleta["line"]}
        strokeWidth={1}
      />

      {/* Una franja por letra MACB, todas a la MISMA escala (max_letra) para que
          se puedan comparar entre sí de un golpe. */}
      {dibujo.letras.map((letra, i) => {
        const base = letrasY + i * LETTER_H + LETTER_H - 4;
        const alto = LETTER_H - 6;
        return (
          <g key={letra.clave}>
            <text
              x={0}
              y={base}
              fontFamily={FONT_MONO}
              fontSize={9}
              fill={paleta["ink-3"]}
            >
              {letra.etiqueta}
            </text>
            <line
              x1={PAD_L}
              x2={W - PAD_R}
              y1={base}
              y2={base}
              stroke={paleta["hair-2"]}
              strokeWidth={1}
            />
            {dibujo.cubetas.map((c) => {
              const n = c.letras[letra.clave] ?? 0;
              if (!n) return null;
              const h = dibujo.max_letra ? (n / dibujo.max_letra) * alto : 0;
              return (
                <rect
                  key={`${letra.clave}${c.indice}`}
                  x={escala(c.t_s)}
                  y={base - h}
                  width={Math.max(1, anchoCubeta - 0.6)}
                  height={h}
                  fill={paleta["ink-4"]}
                >
                  <title>{`${c.inicio} · ${letra.etiqueta}: ${fmt(n)}`}</title>
                </rect>
              );
            })}
          </g>
        );
      })}

      <Leyenda
        entradas={dibujo.leyenda}
        y={leyendaY}
        paleta={paleta}
        color={(clave) => (clave === "relevante" ? paleta["accent"] : paleta["ink-4"])}
      />
      <Pie lineas={lineas} avisos={dibujo.avisos} y={pieY + 6} paleta={paleta} />
    </svg>
  );
}

// ── Envoltorio: pinta la capa que toque y sabe descargarse ────────────────────
export const TimelineDiagram = forwardRef<
  TimelineDiagramHandle,
  { diagram: TimelineDiagramLayout }
>(function TimelineDiagram({ diagram }, ref) {
  const paleta = useThemePalette();
  const contenedor = useRef<HTMLDivElement>(null);

  useImperativeHandle(ref, () => ({
    descargarSvg: () => {
      const svg = contenedor.current?.querySelector("svg");
      if (!svg) return;
      // Se serializa el SVG del DOM, que ya lleva los colores literales del tema:
      // el fichero descargado es exactamente la figura que se está viendo.
      const clon = svg.cloneNode(true) as SVGSVGElement;
      clon.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      clon.removeAttribute("style");
      const texto = `<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(clon)}`;
      const url = URL.createObjectURL(
        new Blob([texto], { type: "image/svg+xml;charset=utf-8" }),
      );
      const a = document.createElement("a");
      a.href = url;
      a.download = `${diagram.basename}.svg`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },
  }));

  return (
    <div className="tl-figure" ref={contenedor}>
      {diagram.layer === "investigation" ? (
        <FranjaDeTrabajos dibujo={diagram} paleta={paleta} />
      ) : (
        <BandaDeDensidad dibujo={diagram} paleta={paleta} />
      )}
    </div>
  );
});
