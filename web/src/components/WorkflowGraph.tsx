import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCaseFrom } from "../state/activeCase";

// Grafo de nodos del "Flujo de trabajo" (estética ElevenLabs): tarjetas-nodo
// redondeadas sobre un lienzo, unidas por curvas bezier SVG, cuyo estado REFLEJA
// el caso activo real (RULE 3: la lógica de derivación vive aquí en el surface,
// leyendo del cliente api; no hay orquestación de negocio). Nada se inventa: un
// paso sin datos reales aparece "pendiente" (RULE 2), nunca "hecho" a la fuerza.

type NodeStatus = "done" | "current" | "pending" | "blocked";

interface WorkflowNode {
  id: string;
  n: number;
  title: string;
  sub: string;
  view: ViewId;
  // Posición de la esquina superior-izquierda en % del lienzo (layout horizontal).
  pos: { x: number; y: number };
}

// El DAG fijo: cadena principal 1→2→3 y, tras investigar, las tres ramas que
// consumen los hallazgos (4 timeline, 5 documentos, 6 MITRE).
const NODES: WorkflowNode[] = [
  {
    id: "1",
    n: 1,
    title: "Crear caso",
    sub: "Registra el caso y el examinador responsable.",
    view: "repository",
    pos: { x: 1, y: 40 },
  },
  {
    id: "2",
    n: 2,
    title: "Registrar evidencia",
    sub: "Imagen o volcado + hash baseline en solo lectura.",
    view: "repository",
    pos: { x: 20.5, y: 40 },
  },
  {
    id: "3",
    n: 3,
    title: "Investigar con el agente",
    sub: "El agente ejecuta el maletín forense sobre la evidencia.",
    view: "investigation",
    pos: { x: 40, y: 40 },
  },
  {
    id: "4",
    n: 4,
    title: "Revisar timeline",
    sub: "Secuencia cronológica de los eventos detectados.",
    view: "timeline",
    pos: { x: 73, y: 4 },
  },
  {
    id: "5",
    n: 5,
    title: "Documentos / reportes",
    sub: "Informes con su metadata de integridad (hash).",
    view: "document-viewer",
    pos: { x: 73, y: 40 },
  },
  {
    id: "6",
    n: 6,
    title: "Correlacionar MITRE",
    sub: "Vincula hallazgos con tácticas y técnicas ATT&CK.",
    view: "mitre",
    pos: { x: 73, y: 76 },
  },
];

const EDGES: { from: string; to: string }[] = [
  { from: "1", to: "2" },
  { from: "2", to: "3" },
  { from: "3", to: "4" },
  { from: "3", to: "5" },
  { from: "3", to: "6" },
];

const STATUS_LABEL: Record<NodeStatus, string> = {
  done: "Hecho",
  current: "En curso",
  pending: "Pendiente",
  blocked: "Pendiente",
};

// Estado real del caso activo, derivado de endpoints por caso. Cada flag es un
// hecho comprobable; si una llamada falla o el caso no tiene ese dato → false
// (se degrada a "pendiente", nunca peta).
interface CaseSignals {
  hasCase: boolean;
  hasEvidence: boolean;
  hasInvestigation: boolean;
  jobRunning: boolean;
  hasTimeline: boolean;
  hasDocuments: boolean;
  hasMitre: boolean;
}

const EMPTY_SIGNALS: CaseSignals = {
  hasCase: false,
  hasEvidence: false,
  hasInvestigation: false,
  jobRunning: false,
  hasTimeline: false,
  hasDocuments: false,
  hasMitre: false,
};

function doneFor(id: string, s: CaseSignals): boolean {
  switch (id) {
    case "1":
      return s.hasCase;
    case "2":
      return s.hasEvidence;
    case "3":
      return s.hasInvestigation;
    case "4":
      return s.hasTimeline;
    case "5":
      return s.hasDocuments;
    case "6":
      return s.hasMitre;
    default:
      return false;
  }
}

// ¿Está hecho el prerrequisito para poder abordar este paso?
function prereqDone(id: string, s: CaseSignals): boolean {
  switch (id) {
    case "1":
      return true;
    case "2":
      return s.hasCase;
    case "3":
      return s.hasEvidence;
    case "4":
    case "5":
    case "6":
      return s.hasInvestigation;
    default:
      return false;
  }
}

function statusFor(id: string, s: CaseSignals): NodeStatus {
  // Sin ningún caso todavía: todo pendiente, el operador debe crear uno primero.
  if (!s.hasCase) return "pending";
  // Investigar aparece "en curso" mientras haya un job del agente corriendo,
  // aunque aún no haya persistido hallazgos.
  if (id === "3" && s.jobRunning) return "current";
  if (doneFor(id, s)) return "done";
  if (!prereqDone(id, s)) return "blocked";
  // Prerrequisito listo y este paso sin hacer: es la frontera accionable.
  return "current";
}

interface Anchor {
  cx: number;
  cy: number;
  left: number;
  right: number;
  top: number;
  bottom: number;
}

interface EdgePath {
  from: string;
  to: string;
  d: string;
  active: boolean;
}

export interface WorkflowGraphProps {
  onNavigate?: (view: ViewId) => void;
}

export function WorkflowGraph({ onNavigate }: WorkflowGraphProps) {
  const [cases, setCases] = useState<Case[]>([]);
  const activeCase = useActiveCaseFrom(cases);
  const [signals, setSignals] = useState<CaseSignals>(EMPTY_SIGNALS);

  const canvasRef = useRef<HTMLDivElement | null>(null);
  const nodeRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const [edges, setEdges] = useState<EdgePath[]>([]);
  const [dims, setDims] = useState<{ w: number; h: number }>({ w: 0, h: 0 });

  // Lista de casos (para resolver el caso activo global). Un fallo → sin casos,
  // todo pendiente.
  useEffect(() => {
    let alive = true;
    api.cases
      .list()
      .then((list) => alive && setCases(list))
      .catch(() => alive && setCases([]));
    return () => {
      alive = false;
    };
  }, []);

  // Señales del caso activo. Se recarga al cambiar de caso activo. Cada endpoint
  // se aísla con allSettled: un 404/500 en uno no impide leer los demás.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setSignals(EMPTY_SIGNALS);
      return;
    }
    let alive = true;
    (async () => {
      const [evidence, findings, tools, jobs, timeline, documents, mitre] =
        await Promise.allSettled([
          api.cases.listEvidence(caseId),
          api.cases.listFindings(caseId),
          api.cases.listToolUsage(caseId),
          api.listCaseJobs(caseId),
          api.cases.timeline(caseId),
          api.cases.listDocuments(caseId),
          api.cases.listMitreCoverage(caseId),
        ]);
      if (!alive) return;

      const ok = <T,>(r: PromiseSettledResult<T>): T | null =>
        r.status === "fulfilled" ? r.value : null;

      const ev = ok(evidence) ?? [];
      const fi = ok(findings) ?? [];
      const tu = ok(tools) ?? [];
      const jb = ok(jobs) ?? [];
      const tl = ok(timeline);
      const dc = ok(documents) ?? [];
      const mi = ok(mitre) ?? [];

      setSignals({
        hasCase: true,
        hasEvidence: ev.some((e) => !!e.sha256),
        hasInvestigation: fi.length > 0 || tu.length > 0,
        jobRunning: jb.some((j) => j.status === "running"),
        hasTimeline: (tl?.events.length ?? 0) > 0,
        hasDocuments: dc.length > 0,
        hasMitre: mi.some((c) => c.proposed_by.length > 0 || c.status != null),
      });
    })().catch(() => {
      if (alive) setSignals({ ...EMPTY_SIGNALS, hasCase: true });
    });
    return () => {
      alive = false;
    };
  }, [activeCase?.id]);

  // Mide los nodos en el DOM y traza las curvas bezier entre ellos. Al derivar
  // los edges de la posición REAL de cada tarjeta, las curvas siguen a los nodos
  // aunque el CSS los reordene (layout vertical en pantallas estrechas).
  const recompute = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const cRect = canvas.getBoundingClientRect();
    setDims({ w: cRect.width, h: cRect.height });

    const anchors: Record<string, Anchor> = {};
    for (const node of NODES) {
      const el = nodeRefs.current[node.id];
      if (!el) continue;
      const r = el.getBoundingClientRect();
      anchors[node.id] = {
        left: r.left - cRect.left,
        right: r.right - cRect.left,
        top: r.top - cRect.top,
        bottom: r.bottom - cRect.top,
        cx: r.left - cRect.left + r.width / 2,
        cy: r.top - cRect.top + r.height / 2,
      };
    }

    const next: EdgePath[] = [];
    for (const e of EDGES) {
      const a = anchors[e.from];
      const b = anchors[e.to];
      if (!a || !b) continue;
      const dx = b.cx - a.cx;
      const dy = b.cy - a.cy;
      let sx: number, sy: number, tx: number, ty: number, c1x: number, c1y: number, c2x: number, c2y: number;
      if (Math.abs(dx) >= Math.abs(dy)) {
        // Anclaje horizontal: sale por el lado derecho, entra por el izquierdo.
        sx = a.right;
        sy = a.cy;
        tx = b.left;
        ty = b.cy;
        const k = Math.max(30, Math.abs(tx - sx) * 0.5);
        c1x = sx + k;
        c1y = sy;
        c2x = tx - k;
        c2y = ty;
      } else {
        // Anclaje vertical (pila responsive): sale por abajo, entra por arriba.
        sx = a.cx;
        sy = a.bottom;
        tx = b.cx;
        ty = b.top;
        const k = Math.max(24, Math.abs(ty - sy) * 0.5);
        c1x = sx;
        c1y = sy + k;
        c2x = tx;
        c2y = ty - k;
      }
      next.push({
        from: e.from,
        to: e.to,
        d: `M ${sx},${sy} C ${c1x},${c1y} ${c2x},${c2y} ${tx},${ty}`,
        active: doneFor(e.from, signals),
      });
    }
    setEdges(next);
  }, [signals]);

  // Recalcula tras cada render que pueda mover nodos y ante cualquier resize del
  // lienzo (incluye el salto al layout vertical por media query).
  useLayoutEffect(() => {
    recompute();
  }, [recompute]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => recompute());
    ro.observe(canvas);
    window.addEventListener("resize", recompute);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", recompute);
    };
  }, [recompute]);

  return (
    <div className="wf-canvas" ref={canvasRef}>
      <svg
        className="wf-edges"
        width={dims.w || undefined}
        height={dims.h || undefined}
        viewBox={dims.w && dims.h ? `0 0 ${dims.w} ${dims.h}` : undefined}
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <defs>
          <marker
            id="wf-arrow-active"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="wf-arrowhead wf-arrowhead--active" />
          </marker>
          <marker
            id="wf-arrow-muted"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" className="wf-arrowhead wf-arrowhead--muted" />
          </marker>
        </defs>
        {edges.map((e) => (
          <path
            key={`${e.from}-${e.to}`}
            d={e.d}
            className={`wf-edge ${e.active ? "wf-edge--active" : "wf-edge--muted"}`}
            markerEnd={e.active ? "url(#wf-arrow-active)" : "url(#wf-arrow-muted)"}
          />
        ))}
      </svg>

      {NODES.map((node) => {
        const status = statusFor(node.id, signals);
        const showHint = node.id === "1" && !signals.hasCase;
        return (
          <button
            type="button"
            key={node.id}
            ref={(el) => {
              nodeRefs.current[node.id] = el;
            }}
            className={`wf-node wf-node--${status}`}
            style={{ left: `${node.pos.x}%`, top: `${node.pos.y}%` }}
            onClick={() => onNavigate?.(node.view)}
            aria-label={`Paso ${node.n}: ${node.title} — ${STATUS_LABEL[status]}`}
          >
            <div className="wf-node-head">
              <span className="wf-node-num">{node.n}</span>
              <span className={`wf-node-dot wf-node-dot--${status}`}>
                {status === "done" ? "✓" : ""}
              </span>
            </div>
            <div className="wf-node-title">{node.title}</div>
            <div className="wf-node-sub">{node.sub}</div>
            <div className="wf-node-foot">
              <span className={`wf-node-badge wf-node-badge--${status}`}>
                {STATUS_LABEL[status]}
              </span>
              {showHint && <span className="wf-node-hint">crea un caso</span>}
            </div>
          </button>
        );
      })}
    </div>
  );
}
