import { forwardRef, useMemo } from "react";
import type { IncidentEvent, IncidentTimeline } from "../../api/types";
import { useThemePalette } from "./themePalette";
import { useLang } from "../../i18n";

// El raíl cronológico del INCIDENTE: qué pasó en el dispositivo investigado, un evento
// por hallazgo con marca del artefacto, de arriba abajo en orden ascendente.
//
// Es una FIGURA, no una vista de análisis: se lee de un golpe y se adjunta. Sin zoom,
// sin brushing, sin selección de rango. Lo que se ve en pantalla es exactamente lo que
// se exporta, porque es el MISMO SVG serializado: el bloque de procedencia y la
// declaración de lo que quedó fuera del eje van dentro del dibujo, no alrededor.
//
// Dos decisiones que existen por la exportación a PNG y se notan al leer el código:
//
//  - los colores se escriben como LITERALES (ver `useThemePalette`): el SVG viaja solo
//    al rasterizarse y no lleva las variables CSS de la aplicación;
//  - la tipografía se declara con familias GENÉRICAS (`monospace` / `sans-serif`) y no
//    con la IBM Plex de la interfaz. Plex entra por `@import` de Google Fonts, y un SVG
//    rasterizado en un `<img>` no tiene acceso a ella: si la pidiéramos, la pantalla
//    mediría el texto con Plex y el PNG con la de respaldo, y el ajuste de línea
//    calculado aquí se desbordaría justo en la copia que se adjunta al informe.

// ── métrica de la figura, toda en px del SVG ──────────────────────────────────
const WIDTH = 1120;
const PAD = 32;
// La marca temporal completa, `01/04/2021, 15:32:11 (UTC)`, son 26 caracteres.
const TIME_W = 200;
const RAIL_X = PAD + TIME_W + 20;
const CONTENT_X = RAIL_X + 24;
const CONTENT_W = WIDTH - PAD - CONTENT_X;

const F_TITLE = 15;
const F_MONO = 12;
const F_SEV = 10.5;
const F_TECH = 12;

// Anchos medios por carácter, medidos a ojo sobre las familias genéricas y con holgura
// deliberada: pasarse de estrecho parte una palabra, pasarse de ancho solo deja aire.
const CH_SANS = 0.55;
const CH_MONO = 0.62;

const H_SEV = 17;
const H_TITLE = 21;
const H_TECH = 18;
const ROW_GAP = 22;
const MARKER_R = 5;

const FONT_SANS = "sans-serif";
const FONT_MONO = "monospace";

const SEV_TOKEN = {
  low: "--sev-low",
  medium: "--sev-medium",
  high: "--sev-high",
  critical: "--sev-critical",
} as const;

// `01/04/2021, 15:32:11 (UTC)`. La zona va ESCRITA en cada marca: una hora sin zona en
// una figura pericial es una hora que hay que ir a buscar a otra parte.
export function fmtIncidentUtc(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}, ` +
    `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} (UTC)`
  );
}

// Ajuste de línea por palabras. SVG no envuelve texto solo, y `foreignObject` no
// sobrevive a la rasterización, así que se parte aquí.
function wrap(text: string, maxWidth: number, fontSize: number, charRatio: number): string[] {
  const perLine = Math.max(8, Math.floor(maxWidth / (fontSize * charRatio)));
  const out: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (!word) continue;
    if (!line) {
      line = word;
    } else if (line.length + 1 + word.length <= perLine) {
      line += ` ${word}`;
    } else {
      out.push(line);
      line = word;
    }
    // Una palabra sola más larga que la línea (una ruta, un hash) se trocea.
    while (line.length > perLine) {
      out.push(line.slice(0, perLine));
      line = line.slice(perLine);
    }
  }
  if (line) out.push(line);
  return out.length ? out : [""];
}

// Cada técnica con su táctica: `T1041 · Exfiltración`. Sin táctica (el catálogo no la
// sitúa) se enseña la técnica sola, nunca una táctica adivinada (RULE 2).
function techLabel(t: IncidentEvent["mitre"][number]): string {
  return t.tactic ? `${t.technique_id} · ${t.tactic}` : t.technique_id;
}

interface Row {
  event: IncidentEvent;
  y: number;
  height: number;
  titleLines: string[];
  techLines: string[];
}

function layoutRows(eventos: IncidentEvent[], top: number): { rows: Row[]; bottom: number } {
  const rows: Row[] = [];
  let y = top;
  for (const event of eventos) {
    const titleLines = wrap(event.title, CONTENT_W, F_TITLE, CH_SANS);
    // UNA técnica por línea. Encadenarlas en la misma línea las vuelve ilegibles: el
    // separador de la pareja (`T1114 · Recolección`) es el mismo punto que separaría
    // una técnica de la siguiente, así que «T1114 · Recolección T1078 · Escalada de
    // privilegios» se lee como si «Recolección T1078» fuese una sola cosa.
    const techLines = event.mitre.flatMap((t) =>
      wrap(techLabel(t), CONTENT_W, F_TECH, CH_MONO),
    );
    const height =
      H_SEV + titleLines.length * H_TITLE + techLines.length * H_TECH + ROW_GAP;
    rows.push({ event, y, height, titleLines, techLines });
    y += height;
  }
  return { rows, bottom: y };
}

interface Props {
  timeline: IncidentTimeline;
}

// El SVG se expone por ref para poder SERIALIZARLO al exportar: se rasteriza el mismo
// nodo que está en pantalla, así la figura adjunta no puede divergir de la que se vio.
export const IncidentRail = forwardRef<SVGSVGElement, Props>(function IncidentRail(
  { timeline },
  ref,
) {
  const palette = useThemePalette();
  const { t } = useLang();

  const { rows, height, fueraLines, bottom } = useMemo(() => {
    // Bloque de procedencia: la figura se basta a sí misma fuera de la aplicación.
    const headTop = PAD + 30;
    const railTop = headTop + 54;
    const { rows, bottom } = layoutRows(timeline.eventos, railTop + 8);

    const fuera: string[] = [];
    if (timeline.sin_observed_at) {
      fuera.push(t("rail.noObservedAt", { count: timeline.sin_observed_at }));
    }
    if (timeline.no_parseable) {
      const valores = timeline.no_parseable_valores.join(", ");
      fuera.push(
        t("rail.unparseable", { count: timeline.no_parseable }) +
          (valores ? `: ${valores}` : "") +
          (timeline.no_parseable_truncado ? t("rail.listTrimmed") : ""),
      );
    }
    const fueraLines = fuera.length
      ? fuera.flatMap((t) => wrap(t, WIDTH - PAD * 2, F_MONO, CH_MONO))
      : [t("rail.allPlaced", { count: timeline.total_hallazgos })];

    return {
      rows,
      bottom,
      height: bottom + 24 + fueraLines.length * 17 + PAD,
      fueraLines,
    };
  }, [timeline, t]);

  // El raíl muere en la ÚLTIMA MARCA, no al final del bloque de texto de la última
  // fila: una línea que sobrepasa el último evento sugiere que la cronología sigue.
  const railEnd = rows.length ? rows[rows.length - 1].y + 8 : PAD;

  return (
    <svg
      ref={ref}
      xmlns="http://www.w3.org/2000/svg"
      width={WIDTH}
      height={height}
      viewBox={`0 0 ${WIDTH} ${height}`}
      role="img"
      aria-label={t("rail.ariaLabel", { count: timeline.eventos.length })}
      style={{ maxWidth: "100%", height: "auto" }}
    >
      <rect x={0} y={0} width={WIDTH} height={height} fill={palette["--surface"]} />

      {/* Procedencia, DENTRO de la imagen */}
      <text
        x={PAD}
        y={PAD + 6}
        fontFamily={FONT_SANS}
        fontSize={17}
        fontWeight={600}
        fill={palette["--ink"]}
      >
        {t("rail.title")}
      </text>
      <text x={PAD} y={PAD + 26} fontFamily={FONT_MONO} fontSize={F_MONO} fill={palette["--ink-3"]}>
        {t("rail.case", { name: timeline.case_name })}
      </text>
      <text x={PAD} y={PAD + 43} fontFamily={FONT_MONO} fontSize={F_MONO} fill={palette["--ink-3"]}>
        {t("rail.exported", {
          date: timeline.exported_at,
          shown: timeline.eventos.length,
          total: timeline.total_hallazgos,
        })}
      </text>
      <line
        x1={PAD}
        y1={PAD + 56}
        x2={WIDTH - PAD}
        y2={PAD + 56}
        stroke={palette["--line"]}
        strokeWidth={1}
      />

      {/* El raíl */}
      {rows.length > 0 && (
        <line
          x1={RAIL_X}
          y1={rows[0].y + 2}
          x2={RAIL_X}
          y2={railEnd}
          stroke={palette["--hair"]}
          strokeWidth={2}
        />
      )}

      {rows.map((row) => {
        const color = palette[SEV_TOKEN[row.event.severity]];
        const markerY = row.y + 8;
        return (
          <g key={row.event.finding_id}>
            <text
              x={RAIL_X - 20}
              y={markerY + 4}
              textAnchor="end"
              fontFamily={FONT_MONO}
              fontSize={F_MONO}
              fill={palette["--ink-2"]}
            >
              {fmtIncidentUtc(row.event.ts)}
            </text>
            <circle cx={RAIL_X} cy={markerY} r={MARKER_R} fill={color} />
            <text
              x={CONTENT_X}
              y={markerY + 4}
              fontFamily={FONT_MONO}
              fontSize={F_SEV}
              letterSpacing="0.08em"
              fill={color}
            >
              {row.event.severity_label.toUpperCase()}
            </text>
            {row.titleLines.map((line, i) => (
              <text
                key={i}
                x={CONTENT_X}
                y={row.y + H_SEV + 14 + i * H_TITLE}
                fontFamily={FONT_SANS}
                fontSize={F_TITLE}
                fill={palette["--ink"]}
              >
                {line}
              </text>
            ))}
            {row.techLines.map((line, i) => (
              <text
                key={i}
                x={CONTENT_X}
                y={row.y + H_SEV + row.titleLines.length * H_TITLE + 12 + i * H_TECH}
                fontFamily={FONT_MONO}
                fontSize={F_TECH}
                fill={palette["--accent"]}
              >
                {line}
              </text>
            ))}
          </g>
        );
      })}

      {/* Lo que no se pudo situar en el eje: dentro de la imagen, no al lado */}
      <line
        x1={PAD}
        y1={bottom + 20}
        x2={WIDTH - PAD}
        y2={bottom + 20}
        stroke={palette["--line"]}
        strokeWidth={1}
      />
      <text
        x={PAD}
        y={bottom + 40}
        fontFamily={FONT_MONO}
        fontSize={F_MONO}
        fill={palette["--ink-3"]}
      >
        Fuera del eje
      </text>
      {fueraLines.map((line, i) => (
        <text
          key={i}
          x={PAD}
          y={bottom + 58 + i * 17}
          fontFamily={FONT_MONO}
          fontSize={F_MONO}
          fill={palette["--ink-4"]}
        >
          {line}
        </text>
      ))}
    </svg>
  );
});

// ── exportación a PNG ─────────────────────────────────────────────────────────

//: Factor de escala del PNG. A 1x el texto de 10,5 px sale borroso en cualquier visor
//: que reescale; a 2x se lee y el fichero sigue pesando poco.
const PNG_SCALE = 2;

/**
 * Rasteriza el SVG que está en pantalla y descarga el PNG.
 *
 * La ruta es SVG serializado -> `Image` -> `canvas` -> `toBlob`, y cada paso tiene una
 * restricción que la condiciona:
 *
 *  - el SVG va como `data:` URI y NO como `blob:`, porque la CSP de la aplicación
 *    declara `img-src 'self' data:` y un `blob:` quedaría bloqueado;
 *  - se codifica con `encodeURIComponent`, no con `btoa`, que revienta con la primera
 *    tilde del título de un hallazgo;
 *  - el `<canvas>` se pinta de fondo antes de dibujar: un PNG con transparencia se ve
 *    negro en la mitad de los visores.
 *
 * El texto del dibujo es contenido derivado de EVIDENCIA y viaja como nodos de texto
 * del SVG (React los escapa), nunca como HTML (SECURITY INVARIANT 8).
 */
export async function exportRailPng(
  svg: SVGSVGElement,
  filename: string,
  background: string,
): Promise<void> {
  const width = svg.width.baseVal.value;
  const height = svg.height.baseVal.value;

  const source = new XMLSerializer().serializeToString(svg);
  const url = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(source)}`;

  const image = new Image();
  image.width = width;
  image.height = height;
  await new Promise<void>((resolve, reject) => {
    image.onload = () => resolve();
    image.onerror = () => reject(new Error("el navegador no pudo rasterizar la figura"));
    image.src = url;
  });

  const canvas = document.createElement("canvas");
  canvas.width = Math.round(width * PNG_SCALE);
  canvas.height = Math.round(height * PNG_SCALE);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("el navegador no expone un contexto 2d para el canvas");
  ctx.scale(PNG_SCALE, PNG_SCALE);
  ctx.fillStyle = background || "#ffffff";
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(image, 0, 0, width, height);

  const blob = await new Promise<Blob | null>((resolve) =>
    canvas.toBlob(resolve, "image/png"),
  );
  if (!blob) throw new Error("el navegador no pudo generar el PNG");

  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(href);
}
