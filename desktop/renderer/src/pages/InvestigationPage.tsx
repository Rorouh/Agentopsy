import { useEffect, useState } from "react";
import type { Capabilities, Case, EvidenceHandle } from "../global";
import type { ViewId } from "../navigation/navItems";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { ChatPage } from "./ChatPage";

interface InvestigationPageProps {
  caps: Capabilities | null;
  onNavigate?: (view: ViewId) => void;
}

type Phase = "loading" | "ready" | "no-case" | "error";

// Envuelve el ChatPage añadiendo contexto real de caso/evidencia leído del
// backend (POST /api/cases + /api/cases/{id}/evidence). El ChatPage es el único
// componente con lógica de red conversacional y se mantiene como dueño de su
// estado de chat; solo recibe el caso activo para que el agente pueda anclar
// los tool runs a un evidence_id real.
export function InvestigationPage({ caps, onNavigate }: InvestigationPageProps) {
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [activeEvidence, setActiveEvidence] = useState<EvidenceHandle | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await window.forensia.cases.list();
        if (cancelled) return;
        if (list.length === 0) {
          setPhase("no-case");
          return;
        }
        const newest = list[0];
        setActiveCase(newest);
        const evidences = await window.forensia.cases.listEvidence(newest.id);
        if (cancelled) return;
        if (evidences.length > 0) {
          setActiveEvidence(evidences[0]);
        }
        setPhase("ready");
      } catch (err) {
        if (cancelled) return;
        setError(String(err instanceof Error ? err.message : err));
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (phase === "loading") {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando contexto del caso…</span>
        </div>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
        <div className="error-state">
          <strong>No se pudo cargar el caso activo:</strong> {error}
        </div>
      </div>
    );
  }

  if (phase === "no-case" || !activeCase) {
    return (
      <div style={{ height: "100%", display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="empty-state" style={{ padding: 28 }}>
          Aún no hay ningún caso abierto. Crea uno desde <strong>Casos y evidencias</strong>{" "}
          antes de empezar a investigar.
        </div>
        {onNavigate && (
          <div>
            <Button variant="chip" onClick={() => onNavigate("repository")}>
              Ir a Casos y evidencias →
            </Button>
          </div>
        )}
      </div>
    );
  }

  const evidenceLabel = activeEvidence
    ? `${activeEvidence.original_path.split("/").pop() ?? activeEvidence.original_path}`
    : "sin evidencia registrada todavía";

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 12,
          marginBottom: 4,
          flexShrink: 0,
        }}
      >
        <div style={{ flex: 1 }}>
          <div className="context-banner">
            <div className="context-banner-main">
              Caso activo: <strong>{activeCase.name}</strong>
              <span className="context-banner-evidence">
                {" · "}
                {activeCase.examiner}
                {" · perfil "}
                <strong>{activeCase.os_profile}</strong>
                {" · evidencia: "}
                <strong>{evidenceLabel}</strong>
                {activeEvidence && (
                  <>
                    {" · SHA-256 "}
                    <code>{activeEvidence.sha256.slice(0, 8)}…</code>
                  </>
                )}
              </span>
            </div>
            <Badge variant={activeCase.status === "active" ? "low" : "neutral"}>
              {activeCase.status === "active" ? "Abierto" : "Cerrado"}
            </Badge>
          </div>
        </div>
        {onNavigate && (
          <Button
            variant="chip"
            onClick={() => onNavigate("timeline")}
            style={{ flexShrink: 0 }}
          >
            Ver Timeline →
          </Button>
        )}
      </div>

      <div className="investigation-layout" style={{ flex: 1, minHeight: 0 }}>
        <ChatPage
          caps={caps}
          activeCase={activeCase}
          activeEvidence={activeEvidence}
        />

        <div className="findings-panel">
          <div className="findings-panel-title">Hallazgos del caso</div>
          <div className="empty-state" style={{ padding: "20px 12px" }}>
            Aún no hay hallazgos registrados para este caso. Aparecerán aquí a medida que el
            agente ejecute herramientas y persista resultados en{" "}
            <code>artifacts/&lt;run-id&gt;/manifest.json</code>.
          </div>
        </div>
      </div>
    </div>
  );
}
