import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  Capabilities,
  DocumentBlock,
  DocumentFull,
  DocumentMeta,
  DocumentVerifyResult,
  ExecutorId,
  ExecutorStatus,
  GenerateReportRequest,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";

// FASE 5 · Informe pericial. Almacén real (forensia.reports): cada documento
// lleva su SHA-256 y las acciones del perito (verificar integridad, firmar como
// final, eliminar borrador) operan sobre ficheros reales y quedan en el audit.

type StatusFilter = "all" | "draft" | "final";
type GroupBy = "evidence" | "type" | "none";

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}
const shortHash = (h: string) => (h ? `${h.slice(0, 8)}` : "");

const PERITO_FIELDS: { key: keyof GenerateReportRequest; label: string; placeholder: string }[] = [
  { key: "name", label: "Perito", placeholder: "" },
  { key: "colegiado", label: "Nº de colegiado", placeholder: "p. ej. COL-1234" },
  { key: "organization", label: "Organización", placeholder: "Laboratorio / empresa" },
  { key: "email", label: "Contacto", placeholder: "correo@dominio" },
  { key: "version", label: "Versión", placeholder: "v0.1" },
];

export function DocumentsPage() {
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();

  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedDoc, setSelectedDoc] = useState<DocumentFull | null>(null);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [groupBy, setGroupBy] = useState<GroupBy>("evidence");

  const [busy, setBusy] = useState(false);
  const [verify, setVerify] = useState<DocumentVerifyResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [perito, setPerito] = useState<GenerateReportRequest>({});
  // Redacción del informe: "" = narrativa determinista (sin llamada a ningún
  // modelo); un ExecutorId = prosa de resumen/conclusiones humanizada por ese
  // ejecutor y VALIDADA por el backend. Selección explícita, nunca un default.
  const [redactor, setRedactor] = useState<ExecutorId | "">("");
  const [caps, setCaps] = useState<Capabilities | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .capabilities()
      .then((c) => {
        if (!cancelled) setCaps(c);
      })
      .catch(() => {
        if (!cancelled) setCaps(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const showNotice = useCallback((t: string) => {
    setNotice(t);
    window.setTimeout(() => setNotice(null), 3200);
  }, []);

  const refreshDocs = useCallback(async (caseId: string) => {
    setDocuments(await api.cases.listDocuments(caseId));
  }, []);

  // Documentos del caso activo. Se recargan al cambiar de caso y se limpia la
  // selección para no arrastrar un documento del caso anterior.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setDocuments([]);
      setSelectedId(null);
      return;
    }
    let cancelled = false;
    setSelectedId(null);
    (async () => {
      try {
        const docs = await api.cases.listDocuments(caseId);
        if (!cancelled) setDocuments(docs);
      } catch {
        if (!cancelled) setDocuments([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

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
  }, [activeCase?.id, selectedId]);

  const matches = useCallback(
    (d: DocumentMeta) => {
      if (statusFilter !== "all" && d.status !== statusFilter) return false;
      const q = search.trim().toLowerCase();
      if (!q) return true;
      return `${d.title} ${d.evidence_id ?? ""} ${d.sha256} ${d.type}`.toLowerCase().includes(q);
    },
    [search, statusFilter],
  );

  const filtered = useMemo(() => {
    const out = documents.filter(matches).slice();
    out.sort((a, b) => b.created_at.localeCompare(a.created_at));
    return out;
  }, [documents, matches]);

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
        showNotice(err instanceof ApiError ? err.detail : String(err));
      } finally {
        setBusy(false);
      }
    },
    [showNotice],
  );

  const onVerify = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      const res = await api.cases.verifyDocument(activeCase.id, selectedDoc.id);
      setVerify(res);
    });

  // El PDF NO es un enlace: pasa por fetch con X-Forensia-Token y
  // URL.createObjectURL. Convertirlo en <a href> por estética da un 401.
  const onDownload = useCallback(
    () =>
      runAction(async () => {
        if (!activeCase || !selectedDoc) return;
        await api.cases.downloadDocumentPdf(
          activeCase.id,
          selectedDoc.id,
          `${selectedDoc.title.slice(0, 60)}.pdf`,
        );
      }),
    [activeCase, selectedDoc, runAction],
  );

  const onSign = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      const signed = await api.cases.signDocument(activeCase.id, selectedDoc.id);
      setSelectedDoc(signed);
      await refreshDocs(activeCase.id);
      showNotice("Documento firmado y marcado como versión final.");
    });

  const onDelete = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      await api.cases.deleteDocument(activeCase.id, selectedDoc.id);
      setSelectedId(null);
      setSelectedDoc(null);
      await refreshDocs(activeCase.id);
      showNotice("Borrador eliminado del caso.");
    });

  // Síntesis: el backend redacta el informe pericial desde los hallazgos, la
  // custodia y la correlación MITRE REALES del caso. Los campos del perito son
  // opcionales; sin ellos figura el examinador del caso.
  const onGenerate = () =>
    runAction(async () => {
      if (!activeCase) return;
      const payload: GenerateReportRequest = {};
      (["name", "colegiado", "organization", "email", "version"] as const).forEach((k) => {
        const v = perito[k]?.trim();
        if (v) payload[k] = v;
      });
      if (redactor) payload.executor = redactor;
      const doc = await api.cases.generateReport(activeCase.id, payload);
      await refreshDocs(activeCase.id);
      setSelectedId(doc.id);
      showNotice(
        redactor
          ? "Informe generado con redacción humanizada validada."
          : "Informe pericial generado como borrador.",
      );
    });

  const drafts = documents.filter((d) => d.status === "draft").length;
  const finals = documents.length - drafts;

  usePublishShellHeader(
    {
      title: "Informe pericial",
      meta: activeCase
        ? `${documents.length} documento${documents.length === 1 ? "" : "s"} · ${finals} firmado${finals === 1 ? "" : "s"}`
        : "sin caso seleccionado",
      action: selectedDoc ? (
        <button type="button" disabled={busy} onClick={() => void onDownload()}>
          Descargar PDF
        </button>
      ) : undefined,
    },
    [activeCase?.id, documents.length, finals, selectedDoc?.id, busy, onDownload],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>Cargando informes del caso…</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>No se pudieron cargar los documentos:</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">Sin caso abierto</div>
          <div className="empty-rail-body">
            Los informes se generan y se firman dentro de un caso. Abre uno desde el lateral.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="report">
      <div className="report-list">
        <div className="eyebrow eyebrow--section">Documentos del caso</div>

        <label className="visually-hidden" htmlFor="docs-search">
          Buscar documento
        </label>
        <input
          id="docs-search"
          className="field-input field-input--sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Buscar por título, evidencia o hash…"
        />

        <div className="report-filters">
          {(["all", "draft", "final"] as StatusFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              className={`toggle-link${statusFilter === f ? " is-on" : ""}`}
              aria-pressed={statusFilter === f}
              onClick={() => setStatusFilter(f)}
            >
              {f === "all" ? "Todos" : f === "draft" ? "Borrador" : "Final"}
            </button>
          ))}
          <label className="visually-hidden" htmlFor="docs-group">
            Agrupar documentos
          </label>
          <select
            id="docs-group"
            className="field-select report-group"
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as GroupBy)}
          >
            <option value="evidence">por evidencia</option>
            <option value="type">por tipo</option>
            <option value="none">sin agrupar</option>
          </select>
        </div>

        <div className="report-docs">
          {documents.length === 0 ? (
            <div className="inv-empty">
              Aún no hay documentos. El almacén y el visor están listos: genera un borrador
              abajo y aparecerá aquí con su SHA-256, su PDF y la firma del perito.
            </div>
          ) : filtered.length === 0 ? (
            <div className="inv-empty">Ningún documento coincide con la búsqueda o el filtro.</div>
          ) : (
            groups.map((g) => (
              <div className="report-group-block" key={g.label || "all"}>
                {groupBy !== "none" && <div className="eyebrow">{g.label}</div>}
                {g.docs.map((d) => (
                  <button
                    key={d.id}
                    type="button"
                    className={`report-doc${selectedId === d.id ? " is-active" : ""}`}
                    onClick={() => setSelectedId(d.id)}
                  >
                    <span className="report-doc-title">{d.title}</span>
                    <span className="report-doc-meta">
                      {d.status === "final" ? "final" : "borrador"} · {d.page_count} pág. ·{" "}
                      {fmtDate(d.created_at)}
                    </span>
                  </button>
                ))}
              </div>
            ))
          )}
        </div>

        <div className="dashed-panel report-gen">
          <div className="dashed-panel-main">
            <div className="dashed-panel-title">Generar borrador</div>
            <div className="dashed-panel-body">
              Se redacta desde los hallazgos, la cadena de custodia y la correlación MITRE
              reales del caso, con el relato de la investigación como hilo conductor. Los
              datos del perito son opcionales; sin ellos figura el examinador.
            </div>
          </div>
          <div className="report-gen-fields">
            {PERITO_FIELDS.map((f) => (
              <div className="field" key={f.key}>
                <label className="eyebrow" htmlFor={`perito-${f.key}`}>
                  {f.label}
                </label>
                <input
                  id={`perito-${f.key}`}
                  className="field-input field-input--sm"
                  value={perito[f.key] ?? ""}
                  onChange={(e) => setPerito((p) => ({ ...p, [f.key]: e.target.value }))}
                  placeholder={f.key === "name" ? activeCase.examiner : f.placeholder}
                />
              </div>
            ))}
            <div className="field">
              <label className="eyebrow" htmlFor="report-redactor">
                Redacción
              </label>
              {/* Selección EXPLÍCITA del operador: la opción por defecto es la
                  narrativa determinista (cero llamadas a modelos). Un ejecutor
                  no disponible se lista deshabilitado con su nombre — nunca se
                  sustituye por otro (RULE 2). */}
              <select
                id="report-redactor"
                className="field-input field-input--sm"
                value={redactor}
                onChange={(e) => setRedactor(e.target.value as ExecutorId | "")}
              >
                <option value="">Determinista (sin ejecutor)</option>
                {caps
                  ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][]).map(
                      ([id, st]) => (
                        <option key={id} value={id} disabled={!st.available}>
                          {st.available
                            ? `Humanizada · ${st.name}`
                            : `${st.name} (no disponible)`}
                        </option>
                      ),
                    )
                  : null}
              </select>
            </div>
          </div>
          <button
            type="button"
            className="action-accent report-gen-btn"
            disabled={busy}
            onClick={() => void onGenerate()}
          >
            {busy ? "Generando…" : "Generar borrador"}
          </button>
        </div>
      </div>

      <div className="report-viewer">
        {notice && <div className="inline-note report-notice">{notice}</div>}

        {!selectedDoc ? (
          <div className="empty-rail">
            <div className="empty-rail-title">Ningún documento abierto</div>
            <div className="empty-rail-body">
              Elige un documento de la lista para leerlo, verificar su integridad y descargarlo
              en PDF.
            </div>
          </div>
        ) : (
          <div className="report-doc-body">
            <div className="report-metarow">
              <span>
                {selectedDoc.id.slice(0, 8)} · {selectedDoc.status === "final" ? "final" : "borrador"}
              </span>
              <span>{selectedDoc.page_count} páginas</span>
              <span title={selectedDoc.sha256}>sha256 {shortHash(selectedDoc.sha256)}</span>
              <span>{selectedDoc.version}</span>
              <span>{selectedDoc.author}</span>
            </div>

            <div className="report-actions">
              <button type="button" className="link-action" disabled={busy} onClick={onVerify}>
                Verificar integridad
              </button>
              {/* Un documento FINAL no se borra: es cadena de custodia. */}
              {selectedDoc.status === "draft" && (
                <>
                  <button type="button" className="link-action" disabled={busy} onClick={onSign}>
                    Firmar y marcar final
                  </button>
                  <button
                    type="button"
                    className="link-action link-action--danger"
                    disabled={busy}
                    onClick={onDelete}
                  >
                    Eliminar borrador
                  </button>
                </>
              )}
            </div>

            {/* El resultado de verificar tiene DOS caras, y la mala —hash
                recalculado ≠ registrado— es la que importa. No puede quedarse
                en un icono. */}
            {verify && (
              <div className={`verify-line${verify.ok ? " is-ok" : " is-bad"}`}>
                {verify.ok
                  ? `✓ Integridad verificada · el SHA-256 recalculado coincide con el de registro (${shortHash(verify.registered_sha256)})`
                  : `✗ El SHA-256 recalculado (${shortHash(verify.recomputed_sha256)}) NO coincide con el de registro (${shortHash(verify.registered_sha256)}). El documento ha cambiado desde que se registró.`}
              </div>
            )}

            <div>
              <h2 className="report-title">{selectedDoc.title}</h2>
              {selectedDoc.summary && <p className="report-summary">{selectedDoc.summary}</p>}
            </div>

            {selectedDoc.sections.map((sec, si) => (
              <section className="report-section" key={si}>
                <div className="report-section-head">
                  <span className="report-section-num">{sec.num}</span>
                  <span className="eyebrow eyebrow--section">{sec.title}</span>
                </div>
                {sec.blocks.map((b, bi) => (
                  <Block key={bi} b={b} />
                ))}
              </section>
            ))}

            <div className="report-foot">
              <span>
                Generado por Agentopsy ·{" "}
                {selectedDoc.status === "final" ? "Firmado" : "Borrador"} ·{" "}
                {fmtDate(selectedDoc.created_at)}
              </span>
              <span>SHA-256 {shortHash(selectedDoc.sha256)}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const SEV_LABEL: Record<string, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

// Bloques del documento. SEC INV 8: todo se pinta como TEXTO.
function Block({ b }: { b: DocumentBlock }) {
  switch (b.t) {
    case "p":
      return <p className="report-p">{b.text}</p>;
    case "h3":
      return <h3 className="report-h3">{b.text}</h3>;
    case "quote":
      return <div className="report-quote">{b.text}</div>;
    case "list": {
      const items = b.items ?? [];
      return b.ordered ? (
        <ol className="report-list-block">
          {items.map((it, i) => (
            <li key={i}>{it}</li>
          ))}
        </ol>
      ) : (
        <ul className="report-list-block">
          {items.map((it, i) => (
            <li key={i}>{it}</li>
          ))}
        </ul>
      );
    }
    case "code":
      return <pre className="report-code">{b.text}</pre>;
    case "kv":
      return (
        <div className="report-kv">
          {(b.pairs ?? []).map((kv, i) => (
            <div className="report-kv-row" key={i}>
              <span className="report-kv-k">{kv.k}</span>
              <span className="report-kv-v">{kv.v}</span>
            </div>
          ))}
        </div>
      );
    case "table":
      return (
        <div className="table-scroll">
          <table className="data-table">
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
                    <td key={ci} className="cell-text">
                      {c}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "finding":
      return (
        <div
          className={`report-finding${
            b.sev === "critical" || b.sev === "high" ? " is-hot" : ""
          }`}
        >
          <div className="report-finding-head">
            <span className="tag tag--accent">{SEV_LABEL[b.sev ?? "low"] ?? b.sev}</span>
            <span className="report-finding-title">{b.title}</span>
            {b.tags && b.tags.length > 0 && (
              <span className="report-finding-tags">{b.tags.join(" · ")}</span>
            )}
          </div>
          {b.text && <p className="report-finding-text">{b.text}</p>}
        </div>
      );
    default:
      return null;
  }
}
