import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  Case,
  DocumentBlock,
  DocumentFull,
  DocumentMeta,
  DocumentVerifyResult,
} from "../api/types";
import { EmptyState } from "../ui/EmptyState";
import { PageHeader } from "../ui/PageHeader";

// Documentos / informes del caso. Almacén real (forensia.reports): cada
// documento lleva su SHA-256 y las acciones del perito (verificar integridad,
// firmar como final, eliminar borrador) operan sobre ficheros reales y quedan en
// el audit. El motor que REDACTA informes desde los hallazgos aún no existe, así
// que la lista sale vacía hasta que el agente cree documentos.

type Phase = "loading" | "ready" | "no-case" | "error";
type StatusFilter = "all" | "draft" | "final";
type GroupBy = "evidence" | "type" | "none";

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}
const shortHash = (h: string) => (h ? `${h.slice(0, 10)}…` : "");

function typeIcon(type: string): { label: string; cls: string } {
  if (type.toLowerCase().includes("final")) return { label: "FIN", cls: "fin" };
  if (type.toLowerCase().includes("anexo")) return { label: "ANX", cls: "anx" };
  return { label: "PRE", cls: "pre" };
}

export function DocumentsPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState("");

  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedDoc, setSelectedDoc] = useState<DocumentFull | null>(null);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [groupBy, setGroupBy] = useState<GroupBy>("evidence");
  const [sortDesc, setSortDesc] = useState(true);

  const [busy, setBusy] = useState(false);
  const [verify, setVerify] = useState<DocumentVerifyResult | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const activeCase = cases[0] ?? null;

  const showToast = useCallback((t: string) => {
    setToast(t);
    window.setTimeout(() => setToast(null), 2800);
  }, []);

  const refreshDocs = useCallback(async (caseId: string) => {
    setDocuments(await api.cases.listDocuments(caseId));
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.cases.list();
        if (cancelled) return;
        setCases(list);
        if (list.length === 0) {
          setPhase("no-case");
          return;
        }
        setDocuments(await api.cases.listDocuments(list[0].id));
        if (!cancelled) setPhase("ready");
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
          setPhase("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Al seleccionar, trae el documento completo (con secciones).
  useEffect(() => {
    setVerify(null);
    if (!activeCase || !selectedId) {
      setSelectedDoc(null);
      return;
    }
    let cancelled = false;
    api.cases
      .getDocument(activeCase.id, selectedId)
      .then((d) => {
        if (!cancelled) setSelectedDoc(d);
      })
      .catch(() => {
        if (!cancelled) setSelectedDoc(null);
      });
    return () => {
      cancelled = true;
    };
  }, [activeCase, selectedId]);

  const matches = useCallback(
    (d: DocumentMeta) => {
      if (statusFilter !== "all" && d.status !== statusFilter) return false;
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return `${d.title} ${d.evidence_id ?? ""} ${d.sha256} ${d.type}`
        .toLowerCase()
        .includes(q);
    },
    [search, statusFilter],
  );

  const filtered = useMemo(() => {
    const out = documents.filter(matches).slice();
    out.sort((a, b) =>
      sortDesc
        ? b.created_at.localeCompare(a.created_at)
        : a.created_at.localeCompare(b.created_at),
    );
    return out;
  }, [documents, matches, sortDesc]);

  const groups = useMemo(() => {
    if (groupBy === "none") return [{ label: "", docs: filtered }];
    const keyOf = (d: DocumentMeta) =>
      groupBy === "evidence" ? d.evidence_id ?? "Sin evidencia" : d.type;
    const map = new Map<string, DocumentMeta[]>();
    filtered.forEach((d) => {
      const k = keyOf(d);
      if (!map.has(k)) map.set(k, []);
      map.get(k)!.push(d);
    });
    return Array.from(map.entries()).map(([label, docs]) => ({ label, docs }));
  }, [filtered, groupBy]);

  const runAction = useCallback(
    async (fn: () => Promise<void>) => {
      setBusy(true);
      try {
        await fn();
      } catch (err) {
        showToast(err instanceof ApiError ? err.detail : String(err));
      } finally {
        setBusy(false);
      }
    },
    [showToast],
  );

  const onVerify = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      const res = await api.cases.verifyDocument(activeCase.id, selectedDoc.id);
      setVerify(res);
      showToast(res.ok ? "Integridad verificada ✓" : "¡El hash NO coincide!");
    });

  const onDownload = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      await api.cases.downloadDocumentPdf(
        activeCase.id,
        selectedDoc.id,
        `${selectedDoc.title.slice(0, 60)}.pdf`,
      );
    });

  const onSign = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      const signed = await api.cases.signDocument(activeCase.id, selectedDoc.id);
      setSelectedDoc(signed);
      await refreshDocs(activeCase.id);
      showToast("Documento firmado y marcado como versión final.");
    });

  const onDelete = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      await api.cases.deleteDocument(activeCase.id, selectedDoc.id);
      setSelectedId(null);
      setSelectedDoc(null);
      await refreshDocs(activeCase.id);
      showToast("Borrador eliminado del caso.");
    });

  // ── estados degradados ────────────────────────────────────────────────────
  if (phase === "loading") {
    return <PageHeader title="Documentos" subtitle="Cargando informes del caso…" />;
  }
  if (phase === "error") {
    return (
      <div>
        <PageHeader title="Documentos" subtitle="No se pudieron cargar los documentos." />
        <EmptyState title="Error" description={error} />
      </div>
    );
  }
  if (phase === "no-case" || !activeCase) {
    return (
      <div>
        <PageHeader
          title="Documentos"
          subtitle="Informes y reportes generados a partir de la evidencia analizada."
        />
        <EmptyState
          title="Sin caso abierto"
          description="Abre un caso: los informes se generan y firman dentro del caso."
        />
      </div>
    );
  }

  const totalLabel =
    filtered.length === documents.length
      ? `${documents.length} documentos`
      : `${filtered.length} de ${documents.length} documentos`;

  return (
    <div className="docs-page">
      <PageHeader
        title="Documentos"
        subtitle="Informes y reportes generados a partir de la evidencia analizada, con su metadata de integridad."
      />

      <div className="mitre-context">
        <span>
          Caso activo: <strong>{activeCase.name}</strong> · {activeCase.examiner}
          {activeCase.os_profile ? ` · perfil ${activeCase.os_profile}` : ""}
        </span>
        <span className={`docs-badge ${activeCase.status === "active" ? "open" : "closed"}`}>
          {activeCase.status === "active" ? "Abierto" : "Cerrado"}
        </span>
      </div>

      {documents.length === 0 && (
        <div className="docs-note">
          Aún no hay documentos en este caso. El almacén y el visor están listos:
          los informes aparecerán aquí cuando el agente los genere (con su SHA-256,
          descarga en PDF y firma del perito).
        </div>
      )}

      <div className="docs-layout">
        {/* ── Lista ── */}
        <div className="docs-list">
          <div className="docs-list-head">
            <input
              className="docs-search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Buscar por título, evidencia o hash…"
            />
            <div className="docs-filters">
              {(["all", "draft", "final"] as StatusFilter[]).map((f) => (
                <button
                  key={f}
                  className={`docs-chip${statusFilter === f ? " is-active" : ""}`}
                  onClick={() => setStatusFilter(f)}
                >
                  {f === "all" ? "Todos" : f === "draft" ? "Borrador" : "Final"}
                </button>
              ))}
            </div>
            <div className="docs-grouprow">
              <select
                className="docs-select"
                value={groupBy}
                onChange={(e) => setGroupBy(e.target.value as GroupBy)}
              >
                <option value="evidence">Agrupar: por evidencia</option>
                <option value="type">Agrupar: por tipo de informe</option>
                <option value="none">Agrupar: sin agrupar</option>
              </select>
              <button
                className="docs-sortbtn"
                onClick={() => setSortDesc((v) => !v)}
                title="Cambiar orden"
              >
                {sortDesc ? "↓ Recientes" : "↑ Antiguos"}
              </button>
            </div>
            <div className="docs-count">{totalLabel}</div>
          </div>

          <div className="docs-list-body">
            {filtered.length === 0 ? (
              <div className="docs-empty-list">
                Sin resultados para la búsqueda o filtro actual.
              </div>
            ) : (
              groups.map((g) => (
                <div className="docs-group" key={g.label || "all"}>
                  {groupBy !== "none" && <div className="docs-group-label">{g.label}</div>}
                  {g.docs.map((d) => {
                    const icon = typeIcon(d.type);
                    return (
                      <button
                        key={d.id}
                        className={`docs-item${selectedId === d.id ? " is-active" : ""}`}
                        onClick={() => setSelectedId(d.id)}
                      >
                        <span className={`docs-item-icon docs-item-icon--${icon.cls}`}>
                          {icon.label}
                        </span>
                        <span className="docs-item-body">
                          <span className="docs-item-title">{d.title}</span>
                          <span className="docs-item-meta">
                            {fmtDate(d.created_at)} · {d.page_count} pág. ·{" "}
                            {d.evidence_id ?? "sin evidencia"}
                          </span>
                          <span className="docs-item-status">
                            <span
                              className={`docs-dot ${d.status === "final" ? "final" : "draft"}`}
                            />
                            {d.status === "final" ? "Final" : "Borrador"} · {d.version}
                          </span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              ))
            )}
          </div>
        </div>

        {/* ── Visor ── */}
        <div className="docs-viewer">
          {!selectedDoc ? (
            <div className="docs-viewer-empty">
              <div className="docs-empty-box">Selecciona un documento de la lista.</div>
            </div>
          ) : (
            <>
              <div className="docs-toolbar">
                <button className="docs-btn docs-btn--primary" disabled={busy} onClick={onVerify}>
                  {busy ? "…" : "Verificar integridad"}
                </button>
                <button className="docs-btn" disabled={busy} onClick={onDownload}>
                  Descargar PDF
                </button>
                <span className="docs-toolbar-spacer" />
                {selectedDoc.status === "draft" && (
                  <>
                    <button className="docs-btn docs-btn--sign" disabled={busy} onClick={onSign}>
                      Firmar y marcar final
                    </button>
                    <button className="docs-btn docs-btn--del" disabled={busy} onClick={onDelete}>
                      Eliminar borrador
                    </button>
                  </>
                )}
              </div>

              {verify && (
                <div className={`docs-verify ${verify.ok ? "ok" : "bad"}`}>
                  {verify.ok
                    ? `✓ Integridad verificada · SHA-256 recalculado coincide con el de registro · ${shortHash(verify.registered_sha256)}`
                    : `✗ El SHA-256 recalculado (${shortHash(verify.recomputed_sha256)}) NO coincide con el de registro (${shortHash(verify.registered_sha256)}).`}
                </div>
              )}

              <div className="docs-body">
                <div className="docs-metarow">
                  <span>Evidencia: <strong>{selectedDoc.evidence_id ?? "—"}</strong></span>
                  <span>Fecha: <strong>{fmtDate(selectedDoc.created_at)}</strong></span>
                  <span title={selectedDoc.sha256}>
                    Hash: <strong>{shortHash(selectedDoc.sha256)}</strong>
                  </span>
                  <span>Páginas: <strong>{selectedDoc.page_count}</strong></span>
                  <span>Versión: <strong>{selectedDoc.version}</strong></span>
                  <span>Perito: <strong>{selectedDoc.author}</strong></span>
                  <span className={`docs-badge ${selectedDoc.status === "final" ? "open" : "closed"}`}>
                    {selectedDoc.status === "final" ? "Final" : "Borrador"}
                  </span>
                </div>

                <h3 className="docs-title">{selectedDoc.title}</h3>
                {selectedDoc.summary && <p className="docs-summary">{selectedDoc.summary}</p>}

                {selectedDoc.sections.map((sec, si) => (
                  <div className="docs-section" key={si}>
                    <div className="docs-section-head">
                      <span className="docs-section-num">{sec.num}</span>
                      <h4 className="docs-section-title">{sec.title}</h4>
                    </div>
                    {sec.blocks.map((b, bi) => (
                      <Block key={bi} b={b} />
                    ))}
                  </div>
                ))}

                <div className="docs-signfoot">
                  <span>
                    Generado por FORENSIA · {selectedDoc.status === "final" ? "Firmado" : "Borrador"} ·{" "}
                    {fmtDate(selectedDoc.created_at)}
                  </span>
                  <span className="docs-mono">SHA-256 {shortHash(selectedDoc.sha256)}</span>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {toast && <div className="docs-toast">{toast}</div>}
    </div>
  );
}

const SEV_LABEL: Record<string, string> = {
  critical: "Crítico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
};

function Block({ b }: { b: DocumentBlock }) {
  switch (b.t) {
    case "p":
      return <p className="docs-p">{b.text}</p>;
    case "h3":
      return <h5 className="docs-h3">{b.text}</h5>;
    case "quote":
      return <div className="docs-quote">{b.text}</div>;
    case "list": {
      const items = b.items ?? [];
      return b.ordered ? (
        <ol className="docs-ul">
          {items.map((it, i) => (
            <li key={i}>{it}</li>
          ))}
        </ol>
      ) : (
        <ul className="docs-ul">
          {items.map((it, i) => (
            <li key={i}>{it}</li>
          ))}
        </ul>
      );
    }
    case "code":
      return <pre className="docs-code">{b.text}</pre>;
    case "kv":
      return (
        <div className="docs-kv">
          {(b.pairs ?? []).map((kv, i) => (
            <div className="docs-kv-row" key={i}>
              <span className="docs-kv-k">{kv.k}</span>
              <span className="docs-kv-v">{kv.v}</span>
            </div>
          ))}
        </div>
      );
    case "table":
      return (
        <div className="docs-table-wrap">
          <table className="docs-table">
            {b.headers && b.headers.length > 0 && (
              <thead>
                <tr>
                  {b.headers.map((h, i) => (
                    <th key={i}>{h}</th>
                  ))}
                </tr>
              </thead>
            )}
            <tbody>
              {(b.rows ?? []).map((row, ri) => (
                <tr key={ri}>
                  {row.map((c, ci) => (
                    <td key={ci}>{c}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "finding":
      return (
        <div className={`docs-finding docs-finding--${b.sev ?? "low"}`}>
          <div className="docs-finding-head">
            <span className="docs-finding-title">{b.title}</span>
            <span className={`docs-sev docs-sev--${b.sev ?? "low"}`}>
              {SEV_LABEL[b.sev ?? "low"] ?? b.sev}
            </span>
          </div>
          {b.text && <p className="docs-finding-text">{b.text}</p>}
          {b.tags && b.tags.length > 0 && (
            <div className="docs-finding-tags">
              {b.tags.map((t, i) => (
                <span className="docs-tag" key={i}>
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      );
    default:
      return null;
  }
}
