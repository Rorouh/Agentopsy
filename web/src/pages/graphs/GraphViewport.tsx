import { useCallback, useEffect, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";

import { useLang } from "../../i18n";

// El VISOR de la figura: acercar, alejar, mover y volver al encuadre.
//
// Por qué la transformación va aquí y no dentro del SVG. La figura se exporta a
// PNG y se adjunta a un informe pericial, así que lo que se serializa tiene que
// ser la geometría CALCULADA por el backend, no el encuadre en el que el perito
// dejara la vista. Poniendo el `transform` en este contenedor, el elemento `svg`
// que exporta `GraphSection` no lo lleva: explorar no puede cambiar la prueba.
// Es la misma separación que enuncia `forensia/graph/layout.py`.
//
// El encuadre es estado de PANTALLA y no se persiste: al cambiar de figura se
// vuelve al ajuste, que es lo que el perito espera al elegir otro grafo.

const ZOOM_MIN = 0.4;
const ZOOM_MAX = 6;
const PASO = 1.25;
//: Cuánto mueve cada pulsación de flecha. El teclado tiene que llegar a todas
//: partes: un lienzo que solo se explora con el ratón excluye a quien no puede
//: usarlo.
const PASO_TECLADO = 60;

function acota(v: number): number {
  return Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, v));
}

type Props = {
  // Cambiar este valor devuelve la vista al encuadre inicial.
  encuadreDe: string;
  children: ReactNode;
};

export function GraphViewport({ encuadreDe, children }: Props) {
  const { t } = useLang();
  const marco = useRef<HTMLDivElement | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const arrastre = useRef<{ x: number; y: number; px: number; py: number } | null>(null);
  const [arrastrando, setArrastrando] = useState(false);

  const ajustar = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  useEffect(() => {
    ajustar();
  }, [encuadreDe, ajustar]);

  // La rueda acerca alrededor del PUNTERO, no del centro: acercarse a un nodo
  // concreto es el gesto natural y con el centro fijo obliga a recolocar la
  // vista después de cada paso. Va con `addEventListener` y no con `onWheel`
  // porque React registra el suyo como pasivo y no deja llamar a
  // `preventDefault`, y sin eso la rueda hace scroll de la página.
  useEffect(() => {
    const el = marco.current;
    if (!el) return;
    const alRodar = (e: WheelEvent) => {
      e.preventDefault();
      const caja = el.getBoundingClientRect();
      const cx = e.clientX - caja.left;
      const cy = e.clientY - caja.top;
      setZoom((previo) => {
        const siguiente = acota(previo * (e.deltaY < 0 ? PASO : 1 / PASO));
        const factor = siguiente / previo;
        setPan((p) => ({
          x: cx - (cx - p.x) * factor,
          y: cy - (cy - p.y) * factor,
        }));
        return siguiente;
      });
    };
    el.addEventListener("wheel", alRodar, { passive: false });
    return () => el.removeEventListener("wheel", alRodar);
  }, []);

  const escalar = useCallback((factor: number) => {
    const el = marco.current;
    const cx = el ? el.clientWidth / 2 : 0;
    const cy = el ? el.clientHeight / 2 : 0;
    setZoom((previo) => {
      const siguiente = acota(previo * factor);
      const k = siguiente / previo;
      setPan((p) => ({ x: cx - (cx - p.x) * k, y: cy - (cy - p.y) * k }));
      return siguiente;
    });
  }, []);

  const alPulsar = (e: KeyboardEvent<HTMLDivElement>) => {
    const mover = (dx: number, dy: number) => {
      e.preventDefault();
      setPan((p) => ({ x: p.x + dx, y: p.y + dy }));
    };
    switch (e.key) {
      case "+":
      case "=":
        e.preventDefault();
        escalar(PASO);
        break;
      case "-":
        e.preventDefault();
        escalar(1 / PASO);
        break;
      case "0":
        e.preventDefault();
        ajustar();
        break;
      case "ArrowLeft":
        mover(PASO_TECLADO, 0);
        break;
      case "ArrowRight":
        mover(-PASO_TECLADO, 0);
        break;
      case "ArrowUp":
        mover(0, PASO_TECLADO);
        break;
      case "ArrowDown":
        mover(0, -PASO_TECLADO);
        break;
      default:
        break;
    }
  };

  return (
    <div className="graph-viewport">
      <div className="graph-viewport-tools">
        <button
          type="button"
          className="action-outline"
          onClick={() => escalar(1 / PASO)}
          disabled={zoom <= ZOOM_MIN}
        >
          {t("graph.zoomOut")}
        </button>
        <span className="mono graph-viewport-level">
          {t("graph.zoomLevel", { percent: Math.round(zoom * 100) })}
        </span>
        <button
          type="button"
          className="action-outline"
          onClick={() => escalar(PASO)}
          disabled={zoom >= ZOOM_MAX}
        >
          {t("graph.zoomIn")}
        </button>
        <button type="button" className="action-outline" onClick={ajustar}>
          {t("graph.fitView")}
        </button>
      </div>

      <div
        ref={marco}
        className={`graph-viewport-frame${arrastrando ? " is-dragging" : ""}`}
        role="group"
        tabIndex={0}
        aria-label={t("graph.viewportLabel")}
        onKeyDown={alPulsar}
        onPointerDown={(e) => {
          // Solo el botón principal, y no cuando el gesto empieza sobre un nodo:
          // ahí el clic es «enfocar este nodo», no «mover la vista».
          if (e.button !== 0) return;
          if ((e.target as Element).closest("g[data-nodo]")) return;
          arrastre.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
          setArrastrando(true);
          e.currentTarget.setPointerCapture(e.pointerId);
        }}
        onPointerMove={(e) => {
          const a = arrastre.current;
          if (!a) return;
          setPan({ x: a.px + (e.clientX - a.x), y: a.py + (e.clientY - a.y) });
        }}
        onPointerUp={(e) => {
          arrastre.current = null;
          setArrastrando(false);
          // Soltar una captura que no se llegó a tomar (el gesto empezó sobre un
          // nodo) levanta `NotFoundError` en Safari.
          if (e.currentTarget.hasPointerCapture(e.pointerId)) {
            e.currentTarget.releasePointerCapture(e.pointerId);
          }
        }}
        onPointerCancel={() => {
          arrastre.current = null;
          setArrastrando(false);
        }}
      >
        <div
          className="graph-viewport-canvas"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "0 0",
          }}
        >
          {children}
        </div>
      </div>

      <p className="graph-viewport-hint">{t("graph.viewportHint")}</p>
    </div>
  );
}
