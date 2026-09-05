import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";

import { useLang } from "../../i18n";

// El VISOR de la figura: acercar, alejar, mover y volver al encuadre.
//
// Por qué la transformación va aquí y no dentro del SVG. La figura se exporta a
// PNG y se adjunta a un informe pericial, así que lo que se serializa tiene que
// ser la geometría CALCULADA por el backend, no el encuadre en el que el perito
// dejara la vista. Poniendo el `transform` en este contenedor, el SVG que se
// serializa no lo lleva: explorar no puede cambiar la prueba. Es la misma
// separación que enuncia `agentopsy/graph/layout.py`.
//
// Qué se mueve y qué NO. Dentro del marco va SOLO el dibujo (el modo `pantalla`
// de `RelationGraph`). El rótulo de la figura, el recuento y la leyenda son el
// marco de lectura, no el dato, así que entran por `cabecera` y `leyenda` y se
// quedan quietos: arrastrar el dibujo sacaba el título fuera de la ventana y
// alejaba la leyenda de donde se la busca.
//
// El encuadre es estado de PANTALLA y no se persiste: al cambiar de figura se
// vuelve al ajuste, que es lo que el perito espera al elegir otro grafo.

//: Techo del acercamiento. El SUELO no es una constante: es el propio ajuste,
//: porque nunca puede impedirse ver la figura entera, y una figura de 2.600 px
//: de ancho se ajusta por debajo de cualquier suelo que se escribiera aquí.
const ZOOM_MAX = 6;
const ZOOM_MIN_ABSOLUTO = 0.2;
const PASO = 1.25;
//: Cuánto mueve cada pulsación de flecha. El teclado tiene que llegar a todas
//: partes: un lienzo que solo se explora con el ratón excluye a quien no puede
//: usarlo.
const PASO_TECLADO = 60;

type Props = {
  // Cambiar este valor devuelve la vista al encuadre inicial.
  encuadreDe: string;
  //: Tamaño INTRÍNSECO de la figura, el lienzo que calculó el backend. Con él,
  //: «ajustar» ajusta de verdad: antes solo devolvía la escala a 1, que con un
  //: SVG estirado al 100 % del ancho encajaba el ANCHO y dejaba fuera de la
  //: ventana todo el alto de una figura grande.
  ancho: number;
  alto: number;
  //: Lo que va fijo ARRIBA (rótulo de la figura, recuento y localizador) y
  //: ABAJO (leyenda).
  cabecera?: ReactNode;
  leyenda?: ReactNode;
  //: FUNCIÓN «LOCALIZADOR». Un punto del lienzo al que llevar la vista. El
  //: `sello` es lo que hace que buscar dos veces la misma entidad vuelva a
  //: encuadrarla: sin él, el efecto no se volvería a disparar.
  centrarEn?: { x: number; y: number; sello: number } | null;
  children: ReactNode;
};

export function GraphViewport({
  encuadreDe,
  ancho,
  alto,
  cabecera,
  leyenda,
  centrarEn,
  children,
}: Props) {
  const { t } = useLang();
  const marco = useRef<HTMLDivElement | null>(null);
  const [ventana, setVentana] = useState({ ancho: 0, alto: 0 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const arrastre = useRef<{ x: number; y: number; px: number; py: number } | null>(null);
  const [arrastrando, setArrastrando] = useState(false);
  //: El zoom, leído por el encuadre del localizador sin que este dependa de él:
  //: si dependiera, mover la rueda volvería a centrar la vista sobre la última
  //: entidad buscada.
  const zoomRef = useRef(zoom);
  zoomRef.current = zoom;
  const panRef = useRef(pan);
  panRef.current = pan;
  //: Para qué figura se hizo ya el ajuste inicial. Sin esto, redimensionar la
  //: ventana reencuadraría la vista y el perito perdería el detalle que estaba
  //: mirando.
  const ajustadoPara = useRef<string | null>(null);

  // El tamaño del marco se MIDE, no se supone: entra en el cálculo del ajuste y
  // depende del ancho de la página, de si la ficha lateral está abierta y del
  // tamaño de la ventana del navegador.
  useEffect(() => {
    const el = marco.current;
    if (!el) return;
    const observador = new ResizeObserver((entradas) => {
      const caja = entradas[0]?.contentRect;
      if (caja) setVentana({ ancho: caja.width, alto: caja.height });
    });
    observador.observe(el);
    return () => observador.disconnect();
  }, []);

  //: La escala a la que la figura ENTERA cabe en el marco. Nunca por encima de
  //: 1: una figura pequeña se queda a tamaño natural en vez de agrandarse hasta
  //: que sus nodos parezcan botones.
  const escalaAjuste = useMemo(() => {
    if (!ventana.ancho || !ventana.alto || !ancho || !alto) return 1;
    return Math.min(ventana.ancho / ancho, ventana.alto / alto, 1);
  }, [ventana.ancho, ventana.alto, ancho, alto]);

  const acota = useCallback(
    (v: number) => {
      const suelo = Math.min(ZOOM_MIN_ABSOLUTO, escalaAjuste);
      return Math.min(ZOOM_MAX, Math.max(suelo, v));
    },
    [escalaAjuste],
  );

  // El TOPE del desplazamiento, en los dos ejes.
  //
  // Sin él, arrastrar sacaba la figura entera de la ventana y dejaba el marco en
  // blanco, sin ninguna pista de hacia dónde había que volver salvo «Ajustar a
  // la vista». Con él, el borde de la figura no pasa nunca del borde del marco:
  // es lo que hace cualquier visor de imágenes y lo que convierte el arrastre en
  // una exploración en vez de en una forma de perderse.
  //
  // Cuando la figura es MÁS PEQUEÑA que el marco no hay nada que explorar en ese
  // eje, así que queda centrada y el arrastre no la mueve: moverla solo serviría
  // para descuadrarla.
  const acotarPan = useCallback(
    (p: { x: number; y: number }, escala: number) => {
      const w = ancho * escala;
      const h = alto * escala;
      return {
        x:
          w <= ventana.ancho
            ? (ventana.ancho - w) / 2
            : Math.min(0, Math.max(ventana.ancho - w, p.x)),
        y:
          h <= ventana.alto
            ? (ventana.alto - h) / 2
            : Math.min(0, Math.max(ventana.alto - h, p.y)),
      };
    },
    [ancho, alto, ventana.ancho, ventana.alto],
  );

  //: Fija escala y desplazamiento a la vez, los dos acotados. Todo lo que mueve
  //: la vista (la rueda, los botones, el teclado, el arrastre y el localizador)
  //: pasa por aquí, para que no haya un solo camino que se salte el tope.
  const aplicar = useCallback(
    (escala: number, p: { x: number; y: number }) => {
      const z = acota(escala);
      const destino = acotarPan(p, z);
      // Las refs se actualizan AQUÍ, no solo al renderizar. Un trackpad emite
      // varios eventos de rueda dentro del mismo frame, y si la siguiente vuelta
      // leyera la ref antes de que React haya vuelto a pintar, partiría del zoom
      // anterior y se comería pasos.
      zoomRef.current = z;
      panRef.current = destino;
      setZoom(z);
      setPan(destino);
    },
    [acota, acotarPan],
  );

  //: Desplazar sin tocar la escala, acotado y con la ref al día por la misma
  //: razón que `aplicar`.
  const desplazar = useCallback(
    (p: { x: number; y: number }) => {
      const destino = acotarPan(p, zoomRef.current);
      panRef.current = destino;
      setPan(destino);
    },
    [acotarPan],
  );

  const ajustar = useCallback(() => {
    aplicar(escalaAjuste, {
      // Centrada: una figura ajustada pero pegada a la esquina no es un encuadre.
      x: (ventana.ancho - ancho * escalaAjuste) / 2,
      y: (ventana.alto - alto * escalaAjuste) / 2,
    });
  }, [aplicar, escalaAjuste, ventana.ancho, ventana.alto, ancho, alto]);

  // Al cambiar el tamaño del marco, o el de la figura, el desplazamiento que era
  // válido puede dejar de serlo. Se vuelve a acotar sin tocar el zoom: reencuadrar
  // entero al redimensionar la ventana perdería el detalle que se estaba mirando.
  useEffect(() => {
    if (!ventana.ancho || !ventana.alto) return;
    desplazar(panRef.current);
  }, [desplazar, ventana.ancho, ventana.alto]);

  // El ajuste inicial de CADA figura, en cuanto el marco se ha podido medir.
  useEffect(() => {
    if (!ventana.ancho || !ventana.alto) return;
    if (ajustadoPara.current === encuadreDe) return;
    ajustadoPara.current = encuadreDe;
    ajustar();
  }, [encuadreDe, ventana.ancho, ventana.alto, ajustar]);

  // FUNCIÓN «LOCALIZADOR»: llevar la vista a un punto del lienzo.
  //
  // Además de desplazar, ACERCA hasta 1:1 si se estaba más lejos. Encuadrar una
  // entidad con la figura entera a la vista no la enseña: el nodo sigue midiendo
  // los mismos cuatro píxeles, solo que en el centro. Si ya se estaba más cerca
  // se respeta el zoom del perito, que sabrá por qué está donde está.
  useEffect(() => {
    if (!centrarEn || !ventana.ancho || !ventana.alto) return;
    const z = Math.max(zoomRef.current, 1);
    aplicar(z, {
      x: ventana.ancho / 2 - centrarEn.x * z,
      y: ventana.alto / 2 - centrarEn.y * z,
    });
    // Solo el sello: el punto cambia de identidad en cada render y volvería a
    // encuadrar sin que nadie lo haya pedido.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [centrarEn?.sello]);

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
      const previo = zoomRef.current;
      const siguiente = acota(previo * (e.deltaY < 0 ? PASO : 1 / PASO));
      const factor = siguiente / previo;
      const p = panRef.current;
      aplicar(siguiente, {
        x: cx - (cx - p.x) * factor,
        y: cy - (cy - p.y) * factor,
      });
    };
    el.addEventListener("wheel", alRodar, { passive: false });
    return () => el.removeEventListener("wheel", alRodar);
  }, [acota, aplicar]);

  const escalar = useCallback(
    (factor: number) => {
      const cx = ventana.ancho / 2;
      const cy = ventana.alto / 2;
      const previo = zoomRef.current;
      const siguiente = acota(previo * factor);
      const k = siguiente / previo;
      const p = panRef.current;
      aplicar(siguiente, { x: cx - (cx - p.x) * k, y: cy - (cy - p.y) * k });
    },
    [acota, aplicar, ventana.ancho, ventana.alto],
  );

  const alPulsar = (e: KeyboardEvent<HTMLDivElement>) => {
    const mover = (dx: number, dy: number) => {
      e.preventDefault();
      const p = panRef.current;
      desplazar({ x: p.x + dx, y: p.y + dy });
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
      {cabecera}

      <div className="graph-viewport-tools">
        <button
          type="button"
          className="action-outline"
          onClick={() => escalar(1 / PASO)}
          disabled={zoom <= Math.min(ZOOM_MIN_ABSOLUTO, escalaAjuste)}
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
          desplazar({ x: a.px + (e.clientX - a.x), y: a.py + (e.clientY - a.y) });
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

      {leyenda}

      <p className="graph-viewport-hint">{t("graph.viewportHint")}</p>
    </div>
  );
}
