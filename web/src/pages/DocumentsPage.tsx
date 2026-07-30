import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  Capabilities,
  DocumentBlock,
  DocumentFull,
  DocumentMeta,
  DocumentVerifyResult,
  ExecutorId,
  ExecutorStatus,
  FinalizeInvestigationRequest,
  ReportJob,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { useActiveCase } from "../state/activeCase";

// FASE 5 · Informe pericial. Almacén real (forensia.reports): cada documento
// lleva su SHA-256 y las acciones del perito (verificar integridad, firmar como
// final, eliminar borrador) operan sobre ficheros reales y quedan en el audit.
//
// El informe NO se rellena desde una plantilla (retirada el 2026-07-30): se
// redacta ÍNTEGRO por el ejecutor que el operador seleccione, una sola vez, al
// FINALIZAR la investigación. Lo único que este informe comparte con el de
// cualquier otro caso es el índice. Por eso esta vista tiene UNA acción de
// emisión —«Finalizar investigación»— y ninguna opción de "modo de redacción":
// no hay alternativa determinista que elegir.

type StatusFilter = "all" | "draft" | "final";
type GroupBy = "evidence" | "type" | "none";

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString("es-ES");
}
const shortHash = (h: string) => (h ? `${h.slice(0, 8)}` : "");

// Cada cuánto se pregunta por el estado de la redacción en curso.
const JOB_POLL_MS = 1500;

// El ejecutor elegido se recuerda como DEFAULT_EXECUTOR, igual que en el chat:
// es agencia del operador, no un default inventado (RULE 2).
const EXECUTOR_CONFIG_KEY = "DEFAULT_EXECUTOR";

const PERITO_FIELDS: {
  key: keyof FinalizeInvestigationRequest;
  label: string;
  placeholder: string;
}[] = [
  { key: "name", label: "Perito", placeholder: "" },
  { key: "colegiado", label: "Nº de colegiado", placeholder: "p. ej. COL-1234" },
  { key: "organization", label: "Organización", placeholder: "Laboratorio / empresa" },
  { key: "email", label: "Contacto", placeholder: "correo@dominio" },
  { key: "version", label: "Versión", placeholder: "se deriva de las revisiones" },
];

// Fases del redactor (forensia.reports.writer emite `report_phase`). Es
// progreso OBSERVACIONAL: sin él, una llamada de minutos parece colgada.
const PHASE_LABEL: Record<string, string> = {
  material: "Reuniendo el material del caso…",
  redactando: "El modelo está redactando el informe…",
  validando: "Validando índice, referentes y comandos auditados…",
  listo: "Informe redactado.",
};

function elapsed(fromIso: string, now: number): string {
  const start = new Date(fromIso).getTime();
  if (isNaN(start)) return "";
  const s = Math.max(0, Math.floor((now - start) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

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
  const [perito, setPerito] = useState<FinalizeInvestigationRequest>({});
  const [caps, setCaps] = useState<Capabilities | null>(null);

  // Ejecutor que REDACTA el informe. Vacío = sin selección: el botón no se
  // pulsa y el motivo se dice (nunca se elige uno por el perito — RULE 2).
  const [executor, setExecutor] = useState<ExecutorId | "">("");
  // Cuántos hallazgos sostiene el caso: sin ninguno no hay informe que emitir.
  const [findingCount, setFindingCount] = useState<number | null>(null);

  // Redacción en curso (job en segundo plano) y su último evento de fase.
  const [job, setJob] = useState<ReportJob | null>(null);
  const [jobPhase, setJobPhase] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const pollRef = useRef<number | null>(null);

  const showNotice = useCallback((t: string) => {
    setNotice(t);
    window.setTimeout(() => setNotice(null), 6000);
  }, []);

  const refreshDocs = useCallback(async (caseId: string) => {
    setDocuments(await api.cases.listDocuments(caseId));
  }, []);

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
    // Recupera la selección de ejecutor que el operador fijó explícitamente.
    api.config
      .get()
      .then((snap) => {
        const def = snap.keys[EXECUTOR_CONFIG_KEY];
        if (!cancelled && def?.set && def.preview) {
          setExecutor((prev) => prev || (def.preview as ExecutorId));
        }
      })
      .catch(() => {
        /* sin config aún — el perito elige a mano */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Documentos + hallazgos del caso activo. Se recargan al cambiar de caso y se
  // limpia la selección para no arrastrar un documento del caso anterior.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId) {
      setDocuments([]);
      setSelectedId(null);
      setFindingCount(null);
      setJob(null);
      return;
    }
    let cancelled = false;
    setSelectedId(null);
    setJob(null);
    setJobPhase(null);
    (async () => {
      try {
        const docs = await api.cases.listDocuments(caseId);
        if (!cancelled) setDocuments(docs);
      } catch {
        if (!cancelled) setDocuments([]);
      }
      try {
        const findings = await api.cases.listFindings(caseId);
        if (!cancelled) setFindingCount(findings.length);
      } catch {
        if (!cancelled) setFindingCount(null);
      }
      // Reengancha una redacción que siguiera en curso: cerrar la pestaña no la
      // aborta, así que al volver debe verse su progreso, no un botón inerte.
      try {
        const jobs = await api.cases.listReportJobs(caseId);
        const running = jobs.find((j) => j.status === "running");
        if (!cancelled && running) setJob(running);
      } catch {
        /* sin jobs: el botón queda listo */
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

  // Sondeo de la redacción en curso. El cronómetro se ancla al `created_at` del
  // job en el SERVIDOR, así que cambiar de sección o recargar no lo reinicia.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId || !job || job.status !== "running") return;
    let cancelled = false;

    const tick = async () => {
      try {
        const snap = await api.cases.reportJob(caseId, job.job_id);
        if (cancelled) return;
        const last = (snap.events ?? [])
          .filter((e) => e.type === "report_phase" && e.phase)
          .pop();
        if (last?.phase) setJobPhase(last.phase);
        setJob(snap);
        if (snap.status === "done" && snap.result) {
          await refreshDocs(caseId);
          setSelectedId(snap.result.doc_id);
          showNotice(
            `Informe ${snap.result.version} redactado (${snap.result.page_count} pág.). ` +
              "Nace en BORRADOR: revísalo y fírmalo para darle validez pericial.",
          );
        } else if (snap.status === "error") {
          showNotice(snap.error ?? "La redacción del informe no pudo completarse.");
        }
      } catch (err) {
        if (!cancelled) {
          showNotice(err instanceof ApiError ? err.detail : String(err));
          setJob(null);
        }
      }
    };

    pollRef.current = window.setInterval(() => {
      setNow(Date.now());
      void tick();
    }, JOB_POLL_MS);
    setNow(Date.now());
    void tick();
    return () => {
      cancelled = true;
      if (pollRef.current !== null) window.clearInterval(pollRef.current);
      pollRef.current = null;
    };
  }, [activeCase?.id, job?.job_id, job?.status, refreshDocs, showNotice]);

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

  const selectExecutor = (id: ExecutorId | "") => {
    setExecutor(id);
    if (id) {
      api.config.set(EXECUTOR_CONFIG_KEY, id).catch(() => {
        /* persistencia best-effort */
      });
    }
  };

  // «Finalizar investigación»: el acto que emite el informe. Arranca la
  // redacción en segundo plano y devuelve el job; el documento aparece cuando
  // el modelo termina y las cuatro validaciones del backend pasan.
  const onFinalize = () =>
    runAction(async () => {
      if (!activeCase) return;
      const payload: FinalizeInvestigationRequest = { executor: executor || undefined };
      (["name", "colegiado", "organization", "email", "version"] as const).forEach((k) => {
        const v = perito[k]?.trim();
        if (v) payload[k] = v;
      });
      const started = await api.cases.finalizeInvestigation(activeCase.id, payload);
      setJobPhase(null);
      setJob(started);
    });

  const drafts = documents.filter((d) => d.status === "draft").length;
  const finals = documents.length - drafts;
  const running = job?.status === "running";
  const executorStatus: ExecutorStatus | null =
    executor && caps ? caps.executors[executor] ?? null : null;
  const executorEntries: [ExecutorId, ExecutorStatus][] = caps
    ? (Object.entries(caps.executors) as [ExecutorId, ExecutorStatus][])
    : [];

  // Por qué NO se puede finalizar todavía. Un motivo concreto, nunca un botón
  // apagado sin explicación (RULE 2: el error nombra la dependencia que falta).
  const blocker: string | null = running
    ? null
    : !executor
      ? "Elige el modelo que redactará el informe: sin selección Agentopsy no llama a ninguno."
      : executorStatus && !executorStatus.available
        ? executorStatus.reason ?? `${executorStatus.name} no está disponible.`
        : findingCount === 0
          ? "El caso no tiene ningún hallazgo registrado: no hay investigación que informar. Analiza la evidencia en Investigación primero."
          : null;

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
            Los informes se redactan y se firman dentro de un caso. Abre uno desde el lateral.
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
              Aún no hay ningún informe. Se emite al finalizar la investigación, aquí abajo.
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
            <div className="dashed-panel-title">Finalizar investigación</div>
            <div className="dashed-panel-body">
              El modelo que elijas redacta el informe pericial COMPLETO a partir de todos los
              hallazgos, evidencias, ejecuciones auditadas y veredictos ATT&CK del caso. Cada
              informe es único: solo el índice es común. Agentopsy valida que el índice esté
              entero, que ningún identificador ni hash sea inventado y que cada comando citado
              sea el argv literal del log de auditoría.
            </div>
          </div>

          <div className="report-gen-fields">
            <div className="field">
              <label className="eyebrow" htmlFor="report-executor">
                Modelo que redacta
              </label>
              {/* Selección EXPLÍCITA del operador. Un ejecutor no disponible se
                  lista deshabilitado con su nombre — nunca se sustituye por
                  otro (RULE 2), y no hay opción "determinista": la plantilla ya
                  no existe. */}
              <select
                id="report-executor"
                className="field-input field-input--sm"
                value={executor}
                disabled={running}
                onChange={(e) => selectExecutor(e.target.value as ExecutorId | "")}
              >
                <option value="">Elige un ejecutor…</option>
                {executorEntries.map(([id, st]) => (
                  <option key={id} value={id} disabled={!st.available}>
                    {st.available ? st.name : `${st.name} (no disponible)`}
                    {st.local ? " · local" : ""}
                  </option>
                ))}
              </select>
            </div>

            <div className="eyebrow">Datos del perito (opcionales)</div>
            {PERITO_FIELDS.map((f) => (
              <div className="field" key={f.key}>
                <label className="eyebrow" htmlFor={`perito-${f.key}`}>
                  {f.label}
                </label>
                <input
                  id={`perito-${f.key}`}
                  className="field-input field-input--sm"
                  value={perito[f.key] ?? ""}
                  disabled={running}
                  onChange={(e) => setPerito((p) => ({ ...p, [f.key]: e.target.value }))}
                  placeholder={f.key === "name" ? activeCase.examiner : f.placeholder}
                />
              </div>
            ))}
          </div>

          {/* Progreso REAL de la redacción: es una llamada de minutos a un
              modelo, y sin esto parecería colgada. El cronómetro sale del
              `created_at` del job en el servidor. */}
          {running && job && (
            <div className="progress-block">
              <div className="progress-head">
                <span>{jobPhase ? PHASE_LABEL[jobPhase] ?? jobPhase : PHASE_LABEL.material}</span>
                <span className="mono">{elapsed(job.created_at, now)}</span>
              </div>
              <div className="progress-track">
                <div className="progress-fill progress-fill--indeterminate" />
              </div>
              <div className="progress-note">
                Puedes cambiar de sección o cerrar la pestaña: la redacción corre en el servidor
                y al volver aquí se retoma su progreso.
              </div>
            </div>
          )}

          {blocker && <div className="inline-note">{blocker}</div>}

          <button
            type="button"
            className="action-accent report-gen-btn"
            disabled={busy || running || blocker !== null}
            onClick={() => void onFinalize()}
          >
            {running ? "Redactando informe…" : "Finalizar investigación"}
          </button>
        </div>
      </div>

      <div className="report-viewer">
        {notice && <div className="inline-note report-notice">{notice}</div>}

        {!selectedDoc ? (
          <div className="empty-rail">
            <div className="empty-rail-title">
              {documents.length === 0 ? "Sin informe todavía" : "Ningún documento abierto"}
            </div>
            <div className="empty-rail-body">
              {documents.length === 0
                ? "El informe pericial se emite una sola vez, cuando la investigación termina: pulsa «Finalizar investigación» en el panel de la izquierda y el modelo seleccionado lo redactará de principio a fin desde los hallazgos y las evidencias del caso."
                : "Elige un documento de la lista para leerlo, verificar su integridad y descargarlo en PDF."}
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
          {b.meta && <div className="report-finding-meta">{b.meta}</div>}
        </div>
      );
    default:
      return null;
  }
}
