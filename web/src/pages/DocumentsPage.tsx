import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  ApprovalSource,
  Capabilities,
  DocumentBlock,
  BlockCitation,
  DocumentChecks,
  DocumentCitation,
  DocumentFull,
  DocumentMeta,
  DocumentVerifyResult,
  ExecutorId,
  ExecutorStatus,
  FinalizeInvestigationRequest,
  ReportJob,
} from "../api/types";
import { usePublishShellHeader } from "../layout/shellHeader";
import { SourceCard } from "../components/SourceCard";
import { useLang, type MessageKey } from "../i18n";
import { useActiveCase } from "../state/activeCase";
import { useCaseStream } from "../state/casePulse";
import { Icon } from "../ui/Icon";

// FASE 7 · Informe pericial. Almacén real (agentopsy.reports): cada documento
// lleva su SHA-256 y las acciones del perito (verificar integridad, firmar como
// final, eliminar borrador) operan sobre ficheros reales y quedan en el audit.
//
// El informe NO se rellena desde una plantilla (retirada el 2026-07-30): se
// redacta ÍNTEGRO por el ejecutor que el operador seleccione, una sola vez, al
// FINALIZAR la investigación. Lo único que este informe comparte con el de
// cualquier otro caso es el índice. Por eso esta vista tiene UNA acción de
// emisión, «Finalizar investigación», y ninguna opción de "modo de redacción":
// no hay alternativa determinista que elegir.

type StatusFilter = "all" | "draft" | "final";
type GroupBy = "evidence" | "type" | "none";

function fmtDate(iso: string, locale: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString(locale);
}
const shortHash = (h: string) => (h ? `${h.slice(0, 8)}` : "");

// Cada cuánto se pregunta por el estado de la redacción en curso.
const JOB_POLL_MS = 1500;

// El ejecutor elegido se recuerda como DEFAULT_EXECUTOR, igual que en el chat:
// es agencia del operador, no un default inventado (RULE 2).
const EXECUTOR_CONFIG_KEY = "DEFAULT_EXECUTOR";

const PERITO_FIELDS: {
  key: keyof FinalizeInvestigationRequest;
  labelKey: MessageKey;
  placeholderKey: MessageKey | null;
}[] = [
  // El de `name` no lleva placeholder de catálogo: el suyo es el examinador
  // del CASO, que es dato, no texto de interfaz.
  { key: "name", labelKey: "doc.perito.name", placeholderKey: null },
  { key: "colegiado", labelKey: "doc.perito.colegiado", placeholderKey: "doc.perito.colegiadoPh" },
  { key: "organization", labelKey: "doc.perito.organization", placeholderKey: "doc.perito.organizationPh" },
  { key: "email", labelKey: "doc.perito.email", placeholderKey: "doc.perito.emailPh" },
  { key: "version", labelKey: "doc.perito.version", placeholderKey: "doc.perito.versionPh" },
];

// Fases del redactor (agentopsy.reports.writer emite `report_phase`). Es
// progreso OBSERVACIONAL: sin él, una llamada de minutos parece colgada.
// La FASE la emite el redactor del backend (`report_phase`). Una que esta tabla
// no declare se pinta tal cual (RULE 2), nunca traducida a lo que se le parezca.
const PHASE_KEY: Record<string, MessageKey> = {
  material: "doc.phase.material",
  redactando: "doc.phase.redactando",
  validando: "doc.phase.validando",
  corrigiendo: "doc.phase.corrigiendo",
  listo: "doc.phase.listo",
};

function elapsed(fromIso: string, now: number): string {
  const start = new Date(fromIso).getTime();
  if (isNaN(start)) return "";
  const s = Math.max(0, Math.floor((now - start) / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

export function DocumentsPage() {
  const { t, tn, locale } = useLang();
  const fecha = (iso: string) => fmtDate(iso, locale);
  const { activeCase, phase: casesPhase, error: casesError } = useActiveCase();
  // Una redacción corre en el servidor durante minutos: cuando publica el
  // informe, la lista lo enseña sin que haya que recargar la página. Los
  // hallazgos porque son la precondición para poder finalizar la investigación.
  const revDocuments = useCaseStream("documents", "findings");

  const [documents, setDocuments] = useState<DocumentMeta[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedDoc, setSelectedDoc] = useState<DocumentFull | null>(null);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [groupBy, setGroupBy] = useState<GroupBy>("evidence");

  const [busy, setBusy] = useState(false);
  const [verify, setVerify] = useState<DocumentVerifyResult | null>(null);
  // La pantalla de APROBACIÓN: qué revisión se va a aprobar y qué la bloquea.
  const [approving, setApproving] = useState(false);
  const [checks, setChecks] = useState<DocumentChecks | null>(null);
  // La CITA abierta: qué revisión de qué hallazgo se está mirando, y lo que el
  // backend devolvió al abrirla. `null` cuando no hay ninguna abierta.
  const [cita, setCita] = useState<BlockCitation | null>(null);
  const [citaData, setCitaData] = useState<DocumentCitation | null>(null);
  const [citaError, setCitaError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [perito, setPerito] = useState<FinalizeInvestigationRequest>({});
  const [caps, setCaps] = useState<Capabilities | null>(null);

  // Ejecutor que REDACTA el informe. Vacío = sin selección: el botón no se
  // pulsa y el motivo se dice (nunca se elige uno por el perito, RULE 2).
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
        /* sin config aún, el perito elige a mano */
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
      // Reengancha la última redacción del caso: si sigue en curso, para ver su
      // progreso en vez de un botón inerte; si terminó RECHAZADA, para que el
      // motivo no se pierda con la pestaña, un intento que no dejó informe
      // tiene que poder leerse después, no solo en el instante en que falla.
      try {
        const jobs = await api.cases.listReportJobs(caseId);
        const last = jobs[0];
        if (!cancelled && last && (last.status === "running" || last.status === "error")) {
          setJob(last);
        }
      } catch {
        /* sin jobs: el botón queda listo */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id]);

  // Reposición EN SILENCIO: la redacción termina en el servidor y publica el
  // informe, o el análisis añade hallazgos. Sin cerrar el documento que el
  // perito esté leyendo ni soltar el job que se está sondeando.
  useEffect(() => {
    const caseId = activeCase?.id;
    if (!caseId || revDocuments === 0) return;
    let cancelled = false;
    (async () => {
      const [docs, findings] = await Promise.all([
        api.cases.listDocuments(caseId).catch(() => null),
        api.cases.listFindings(caseId).catch(() => null),
      ]);
      if (cancelled) return;
      if (docs) setDocuments(docs);
      if (findings) setFindingCount(findings.length);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase?.id, revDocuments]);

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
            t("doc.written", {
              version: snap.result.version,
              pages: snap.result.page_count,
            }),
          );
        } else if (snap.status === "error") {
          showNotice(snap.error ?? t("doc.writeFailed"));
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

  // Cambiar de documento cierra la pantalla de aprobación: lo que se aprueba
  // tiene que ser lo que se está mirando.
  useEffect(() => {
    setApproving(false);
    setChecks(null);
  }, [selectedId]);

  const onVerify = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      const res = await api.cases.verifyDocument(activeCase.id, selectedDoc.id);
      setVerify(res);
    });

  // El PDF NO es un enlace: pasa por fetch con X-Agentopsy-Token y
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

  // «Aprobar como final» es DOS pasos, y esa es la parte importante: primero se
  // lee QUÉ se va a aprobar y qué lo bloquea, y solo después se aprueba, atando
  // el acto al hash de la revisión que se acaba de mirar. Pulsar un botón sin
  // ver la revisión es exactamente lo que la comprobación (h) impide.
  const onOpenApproval = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc) return;
      setChecks(await api.cases.documentChecks(activeCase.id, selectedDoc.id));
      setApproving(true);
    });

  const onApprove = () =>
    runAction(async () => {
      if (!activeCase || !selectedDoc || !checks) return;
      const approved = await api.cases.signDocument(activeCase.id, selectedDoc.id, {
        // El hash de la revisión REVISADA, no «el actual»: si el contenido
        // cambió entre la lectura y esta llamada, el backend lo rechaza.
        sha256: checks.sha256_actual,
        approved_by: activeCase.examiner,
      });
      setSelectedDoc(approved);
      setApproving(false);
      setChecks(null);
      await refreshDocs(activeCase.id);
      showNotice(t("doc.approved"));
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
      ? t("doc.blockNoExecutor")
      : executorStatus && !executorStatus.available
        ? executorStatus.reason ?? t("executor.notAvailable", { name: executorStatus.name })
        : findingCount === 0
          ? t("doc.blockNoFindings")
          : null;

  usePublishShellHeader(
    {
      title: t("nav.report"),
      // Con cero documentos la cuenta no informa: el vacío ya lo dicen la
      // columna de la izquierda y el centro de la vista. Con documentos reales
      // sí es progreso, y cuántos están firmados es lo que separa un borrador
      // de un entregable.
      meta: !activeCase
        ? t("common.noCase")
        : documents.length === 0
          ? undefined
          : t("doc.headerMeta", {
              docs: tn("count.documents", documents.length),
              signed: tn("count.signed", finals),
            }),
      action: selectedDoc ? (
        <button type="button" disabled={busy} onClick={() => void onDownload()}>
          {t("doc.downloadPdf")}
        </button>
      ) : undefined,
    },
    [activeCase?.id, documents.length, finals, selectedDoc?.id, busy, onDownload, t, tn],
  );

  // Abrir la fuente de una conclusión. La resolución la hace el BACKEND: aquí se
  // manda el documento, el hallazgo y la revisión, nunca una ruta ni un hash
  // (SECURITY INVARIANT 5). Un fallo se dice; no se pinta una ficha vacía, que
  // se leería como «esta conclusión no tiene fuente».
  const onOpenCita = useCallback(
    async (ref: BlockCitation) => {
      if (!activeCase || !selectedDoc) return;
      setCita(ref);
      setCitaData(null);
      setCitaError(null);
      try {
        setCitaData(
          await api.cases.documentCitation(
            activeCase.id,
            selectedDoc.id,
            ref.finding_id,
            ref.revision,
          ),
        );
      } catch (e) {
        setCitaError(e instanceof Error ? e.message : String(e));
      }
    },
    [activeCase, selectedDoc],
  );

  if (casesPhase === "loading") {
    return (
      <div className="view-scroll">
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          <span>{t("doc.loading")}</span>
        </div>
      </div>
    );
  }

  if (casesPhase === "error") {
    return (
      <div className="view-scroll">
        <div className="error-state">
          <strong>{t("doc.loadFailed")}</strong> {casesError}
        </div>
      </div>
    );
  }

  if (!activeCase) {
    return (
      <div className="view-scroll">
        <div className="empty-rail">
          <div className="empty-rail-title">{t("findings.noCase")}</div>
          <div className="empty-rail-body">{t("doc.noCaseBody")}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="report">
      <div className="report-list">
        <div className="eyebrow eyebrow--section">{t("doc.section")}</div>

        <label className="visually-hidden" htmlFor="docs-search">
          {t("doc.searchLabel")}
        </label>
        <input
          id="docs-search"
          className="field-input field-input--sm"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={t("doc.searchPlaceholder")}
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
              {t(f === "all" ? "doc.filterAll" : f === "draft" ? "doc.statusDraft" : "doc.statusFinal")}
            </button>
          ))}
          <label className="visually-hidden" htmlFor="docs-group">
            {t("doc.groupLabel")}
          </label>
          <select
            id="docs-group"
            className="field-select report-group"
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as GroupBy)}
          >
            <option value="evidence">{t("doc.groupEvidence")}</option>
            <option value="type">{t("doc.groupType")}</option>
            <option value="none">{t("doc.groupNone")}</option>
          </select>
        </div>

        <div className="report-docs">
          {documents.length === 0 ? (
            <div className="inv-empty">{t("doc.none")}</div>
          ) : filtered.length === 0 ? (
            <div className="inv-empty">{t("doc.noMatch")}</div>
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
                      {t(d.status === "final" ? "doc.statusFinalLower" : "doc.statusDraftLower")} ·{" "}
                      {d.page_count} {t("doc.pagesShort")} · {fecha(d.created_at)}
                    </span>
                  </button>
                ))}
              </div>
            ))
          )}
        </div>

        <div className="dashed-panel report-gen">
          <div className="dashed-panel-main">
            <div className="dashed-panel-title">{t("doc.finalize")}</div>
            <div className="dashed-panel-body">{t("doc.finalizeBody")}</div>
          </div>

          <div className="report-gen-fields">
            <div className="field">
              <label className="eyebrow" htmlFor="report-executor">
                {t("doc.writingModel")}
              </label>
              {/* Selección EXPLÍCITA del operador. Un ejecutor no disponible se
                  lista deshabilitado con su nombre, nunca se sustituye por
                  otro (RULE 2), y no hay opción "determinista": la plantilla ya
                  no existe. */}
              <select
                id="report-executor"
                className="field-input field-input--sm"
                value={executor}
                disabled={running}
                onChange={(e) => selectExecutor(e.target.value as ExecutorId | "")}
              >
                <option value="">{t("executor.pick")}</option>
                {executorEntries.map(([id, st]) => (
                  <option key={id} value={id} disabled={!st.available}>
                    {st.available ? st.name : t("executor.unavailable", { name: st.name })}
                    {st.local ? ` · ${t("executor.local")}` : ""}
                  </option>
                ))}
              </select>
            </div>

            <div className="eyebrow">{t("doc.peritoFields")}</div>
            {PERITO_FIELDS.map((f) => (
              <div className="field" key={f.key}>
                <label className="eyebrow" htmlFor={`perito-${f.key}`}>
                  {t(f.labelKey)}
                </label>
                <input
                  id={`perito-${f.key}`}
                  className="field-input field-input--sm"
                  value={perito[f.key] ?? ""}
                  disabled={running}
                  onChange={(e) => setPerito((p) => ({ ...p, [f.key]: e.target.value }))}
                  placeholder={
                    f.key === "name"
                      ? activeCase.examiner
                      : f.placeholderKey
                        ? t(f.placeholderKey)
                        : ""
                  }
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
                <span>
                  {jobPhase
                    ? PHASE_KEY[jobPhase]
                      ? t(PHASE_KEY[jobPhase])
                      : jobPhase
                    : t("doc.phase.material")}
                </span>
                <span className="mono">{elapsed(job.created_at, now)}</span>
              </div>
              <div className="progress-track">
                <div className="progress-fill progress-fill--indeterminate" />
              </div>
              <div className="progress-note">
                {t("doc.backgroundNote")}
              </div>
            </div>
          )}

          {/* Un rechazo de custodia NO deja documento. Si eso solo se dijera en
              un aviso que se desvanece, la vista quedaría idéntica a «no ha
              pasado nada» y el perito buscaría un informe que no existe. */}
          {job?.status === "error" && (
            <div className="danger-notice report-failure">
              <strong>{t("doc.notPublished")}</strong>
              <div className="report-failure-reason">{job.error}</div>
              <div className="report-failure-reason">
                {t("doc.notPublishedBody")}
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
            {t(running ? "doc.writing" : "doc.finalize")}
          </button>
        </div>
      </div>

      <div className="report-viewer">
        {notice && <div className="inline-note report-notice">{notice}</div>}

        {!selectedDoc ? (
          <div className="empty-rail">
            <div className="empty-rail-title">
              {t(documents.length === 0 ? "doc.noReportYet" : "doc.noneOpen")}
            </div>
            <div className="empty-rail-body">
              {t(documents.length === 0 ? "doc.noReportYetBody" : "doc.pickToRead")}
            </div>
          </div>
        ) : (
          <div className="report-doc-body">
            <div className="report-metarow">
              <span>
                {selectedDoc.id.slice(0, 8)} ·{" "}
                {t(selectedDoc.status === "final" ? "doc.statusFinalLower" : "doc.statusDraftLower")}
              </span>
              <span>{t("doc.pages", { count: selectedDoc.page_count })}</span>
              <span title={selectedDoc.sha256}>sha256 {shortHash(selectedDoc.sha256)}</span>
              <span>{selectedDoc.version}</span>
              <span>{selectedDoc.author}</span>
            </div>

            <div className="report-actions">
              <button type="button" className="link-action" disabled={busy} onClick={onVerify}>
                {t("doc.verifyIntegrity")}
              </button>
              {/* Un documento FINAL no se borra: es cadena de custodia. */}
              {selectedDoc.status === "draft" && (
                <>
                  <button
                    type="button"
                    className="link-action"
                    disabled={busy}
                    onClick={onOpenApproval}
                    data-testid="abrir-aprobacion"
                  >
                    {t("doc.approve")}
                  </button>
                  <button
                    type="button"
                    className="link-action link-action--danger"
                    disabled={busy}
                    onClick={onDelete}
                  >
                    {t("doc.deleteDraft")}
                  </button>
                </>
              )}
            </div>

            {approving && checks && (
              <ApprovalPanel
                checks={checks}
                busy={busy}
                onCancel={() => {
                  setApproving(false);
                  setChecks(null);
                }}
                onConfirm={onApprove}
              />
            )}

            {/* El resultado de verificar tiene DOS caras, y la mala, hash
                recalculado ≠ registrado, es la que importa. No puede quedarse
                en un icono. */}
            {verify && (
              <div className={`verify-line${verify.ok ? " is-ok" : " is-bad"}`}>
                <Icon name={verify.ok ? "check" : "cross"} size={13} />{" "}
                {verify.ok
                  ? t("doc.verifyOk", { hash: shortHash(verify.registered_sha256) })
                  : t("doc.verifyBad", {
                      got: shortHash(verify.recomputed_sha256),
                      want: shortHash(verify.registered_sha256),
                    })}
              </div>
            )}

            <div>
              <h2 className="report-title">{selectedDoc.title}</h2>
              {selectedDoc.summary && <p className="report-summary">{selectedDoc.summary}</p>}
            </div>

            {cita && (
              <CitationPanel
                cita={cita}
                data={citaData}
                error={citaError}
                onClose={() => {
                  setCita(null);
                  setCitaData(null);
                  setCitaError(null);
                }}
              />
            )}

            {selectedDoc.sections.map((sec, si) => (
              <section className="report-section" key={si}>
                <div className="report-section-head">
                  <span className="report-section-num">{sec.num}</span>
                  <span className="eyebrow eyebrow--section">{sec.title}</span>
                </div>
                {sec.blocks.map((b, bi) => (
                  <Block key={bi} b={b} onOpenCita={onOpenCita} />
                ))}
              </section>
            ))}

            <div className="report-foot">
              <span>
                {t("doc.footGenerated")} ·{" "}
                {t(selectedDoc.status === "final" ? "doc.footSigned" : "doc.statusDraft")} ·{" "}
                {fecha(selectedDoc.created_at)}
              </span>
              <span>SHA-256 {shortHash(selectedDoc.sha256)}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const SEV_KEY: Record<string, MessageKey> = {
  critical: "tl.sev.critical",
  high: "tl.sev.high",
  medium: "tl.sev.medium",
  low: "tl.sev.low",
};

// Bloques del documento. SEC INV 8: todo se pinta como TEXTO.

// La pantalla de APROBACIÓN. Su trabajo es que nadie apruebe sin ver qué
// aprueba: identifica la REVISIÓN exacta (por su hash), enumera los bloqueos
// pendientes y dice qué es y qué no es esta aprobación.
//
// El botón deshabilitado NO es la garantía: el backend vuelve a comprobarlo
// todo aunque el cliente llame a la ruta directamente. Esto es la parte que
// hace que el perito pueda decidir con información, no la que impide el fallo.
export function ApprovalPanel({
  checks,
  busy,
  onCancel,
  onConfirm,
}: {
  checks: DocumentChecks;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { t } = useLang();
  return (
    <section className="report-section aprobacion" data-testid="panel-aprobacion">
      <div className="report-section-head">
        <span className="eyebrow">{t("doc.approveTitle")}</span>
      </div>

      <p className="report-p report-p--muted">{t("doc.approveWhatItIs")}</p>

      <div className="report-kv">
        <div className="report-kv-row">
          <span className="report-kv-k">{t("doc.approveRevision")}</span>
          <span className="report-kv-v" data-testid="revision-aprobada">
            {checks.version} · sha256 {checks.sha256_actual}
          </span>
        </div>
      </div>

      {checks.bloqueos.length === 0 ? (
        <p className="report-p" data-testid="sin-bloqueos">
          {t("doc.approveNoBlockers")}
        </p>
      ) : (
        <div className="aprobacion-bloqueos" data-testid="bloqueos">
          <span className="eyebrow">{t("doc.approveBlockers")}</span>
          <ul className="report-list-ul">
            {checks.bloqueos.map((b) => (
              <li key={`${b.codigo}-${b.detalle}`} data-testid={`bloqueo-${b.codigo}`}>
                {b.mensaje}
              </li>
            ))}
          </ul>
        </div>
      )}

      {checks.fuentes.length > 0 && (
        <div className="aprobacion-fuentes">
          <span className="eyebrow">{t("doc.approveSources")}</span>
          <ul className="report-list-ul">
            {checks.fuentes.map((f: ApprovalSource, i) => (
              <li key={`${f.tipo}-${i}`}>
                {f.tipo}: {f.run_id ?? f.evidence_id ?? f.finding_id}{" "}
                <span className={`fuente-badge fuente-badge--${f.estado}`}>
                  {t(`doc.sourceState.${f.estado}` as never)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="report-actions">
        <button type="button" className="link-action" onClick={onCancel} disabled={busy}>
          {t("doc.approveCancel")}
        </button>
        <button
          type="button"
          className="link-action"
          onClick={onConfirm}
          // Deshabilitado por comodidad, NO por seguridad: la comprobación que
          // cuenta la hace el backend en cada llamada.
          disabled={busy || !checks.aprobable}
          data-testid="confirmar-aprobacion"
        >
          {busy ? t("doc.approveChecking") : t("doc.approveConfirm")}
        </button>
      </div>
    </section>
  );
}

// El panel que enseña el RESPALDO de una conclusión: qué revisión de qué
// hallazgo la sostiene y, dentro, cada fuente con su localizador y su extracto
// verificado. Reutiliza la misma ficha que la pantalla de Hallazgos: una fuente
// es una fuente, y dos fichas distintas acabarían diciendo cosas distintas.
export function CitationPanel({
  cita,
  data,
  error,
  onClose,
}: {
  cita: BlockCitation;
  data: DocumentCitation | null;
  error: string | null;
  onClose: () => void;
}) {
  const { t } = useLang();
  return (
    <section className="report-section cita-panel" data-testid="panel-cita">
      <div className="report-section-head">
        <span className="eyebrow">{t("doc.citationTitle")}</span>
        <button
          type="button"
          className="link-action"
          onClick={onClose}
          data-testid="cerrar-cita"
        >
          {t("doc.citationClose")}
        </button>
      </div>

      {error ? (
        // Una fuente que no se puede abrir NO se presenta como verificada ni
        // como inexistente: se dice qué ha pasado.
        <div className="fuente-error" data-testid="cita-error">
          <p className="report-p">{t("doc.citationFailed")}</p>
          <p className="report-p report-p--muted">{error}</p>
        </div>
      ) : !data ? (
        <p className="report-p report-p--muted" data-testid="cita-cargando">
          {t("doc.citationLoading")}
        </p>
      ) : (
        <>
          <div className="report-kv">
            <div className="report-kv-row">
              <span className="report-kv-k">{t("doc.citationFinding")}</span>
              <span className="report-kv-v" data-testid="cita-hallazgo">
                {data.titulo} · {t("doc.citationRevision", { n: data.revision })}
              </span>
            </div>
          </div>
          <p className="report-p">{data.resumen}</p>

          {!data.integridad_ok && (
            <div className="fuente-error" data-testid="cita-alterada">
              <p className="report-p">{t("doc.citationFindingTampered")}</p>
            </div>
          )}
          {!data.en_manifiesto && (
            <div className="fuente-error" data-testid="cita-fuera">
              <p className="report-p">{t("doc.citationOutsideManifest")}</p>
            </div>
          )}

          {data.fuentes.length === 0 ? (
            <p className="report-p report-p--muted">{t("doc.citationNoSources")}</p>
          ) : (
            data.fuentes.map((f, i) => <SourceCard key={i} source={f} />)
          )}

          {/* Integridad técnica no es suficiencia interpretativa: que la fuente
              exista y su hash case no demuestra que respalde la conclusión. */}
          <p className="report-p report-p--muted">{t("doc.citationHumanReview")}</p>
        </>
      )}
    </section>
  );
}

// El pie de RESPALDO de un bloque: en qué se apoya lo que acaba de afirmar, con
// la acción de abrirlo. Es lo que convierte una conclusión en algo que se puede
// comprobar sin salir del informe.
function BlockRefs({
  refs,
  onOpenCita,
}: {
  refs?: BlockCitation[];
  onOpenCita?: (ref: BlockCitation) => void;
}) {
  const { t } = useLang();
  if (!refs || refs.length === 0) return null;
  return (
    <div className="bloque-refs" data-testid="bloque-refs">
      <span className="bloque-refs-label">{t("doc.blockSupport")}</span>
      {refs.map((r) => (
        <button
          key={`${r.finding_id}-${r.revision}`}
          type="button"
          className="link-action"
          onClick={() => onOpenCita?.(r)}
          data-testid="abrir-cita"
          title={r.finding_id}
        >
          {r.finding_id.slice(0, 8)} · {t("doc.citationRevision", { n: r.revision })}
        </button>
      ))}
    </div>
  );
}

function Block({
  b,
  onOpenCita,
}: {
  b: DocumentBlock;
  onOpenCita?: (ref: BlockCitation) => void;
}) {
  // El bloque y, debajo, su respaldo. Se compone aquí y no dentro de cada rama
  // del switch para que ningún tipo de bloque se quede sin él por olvido: una
  // conclusión sin su pie de respaldo se lee como una conclusión sin fuente.
  return (
    <>
      <BlockBody b={b} />
      <BlockRefs refs={b.refs} onOpenCita={onOpenCita} />
    </>
  );
}

function BlockBody({ b }: { b: DocumentBlock }) {
  const { t } = useLang();
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
            <span className="tag tag--accent">
              {SEV_KEY[b.sev ?? "low"] ? t(SEV_KEY[b.sev ?? "low"]) : b.sev}
            </span>
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
