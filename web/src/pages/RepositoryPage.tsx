import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  Case,
  CustodyAct,
  EvidenceHandle,
  EvidenceMetadata,
  EvidenceSource,
} from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { useActiveCase } from "../state/activeCase";
import { ActiveCaseHeader } from "../components/ActiveCaseHeader";
import { CaseSearchModal } from "../components/CaseSearchModal";
import { EvidenceInbox } from "../components/EvidenceInbox";
import { EvidenceTable } from "../components/EvidenceTable";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Modal } from "../ui/Modal";
import { PageHeader } from "../ui/PageHeader";
import { PageSection } from "../ui/PageSection";
import { formatBytes, formatDate, shortHash } from "../utils/format";
import { isEwfFirstSegment } from "../utils/evidence";

// Etiqueta corta del nivel de solo-lectura para la lista de custodia. La fuente
// AUTORITATIVA es el backend (metadata.read_only_label / acta.read_only.label);
// esto es solo la insignia compacta por fila. Honesta: FS (chmod 0444), el
// bloqueo a nivel de bloque es Fase 2 (RULE 2 — no se anuncia lo que no se aplica).
const READ_ONLY_BADGE = "Solo lectura: FS (chmod 0444)";

function evidenceFileName(ev: EvidenceHandle): string {
  return ev.original_path.split("/").pop() ?? ev.original_path;
}

interface RepositoryPageProps {
  onNavigate?: (view: ViewId) => void;
}

type LoadingPhase = "loading" | "ready" | "error";

interface FormState {
  name: string;
  examiner: string;
  notes: string;
}

const EMPTY_FORM: FormState = {
  name: "",
  examiner: "",
  notes: "",
};

// Workspace del caso activo a ancho completo (header + métricas + registrar
// evidencia + tabla). Los casos se localizan con el CaseSearchModal (botón
// «Buscar casos» del header, estilo command-palette) — ya no hay panel
// lateral. Toda la carga/persistencia vive aquí; components/ es presentacional.
export function RepositoryPage({ onNavigate }: RepositoryPageProps) {
  const [cases, setCases] = useState<Case[]>([]);
  // Caso activo GLOBAL (compartido con Investigación / Timeline / Documentos /
  // MITRE). Cambiarlo aquí — o desde cualquier otra vista — sincroniza a todas.
  const { activeCaseId, setActiveCaseId } = useActiveCase();
  const [evidence, setEvidence] = useState<EvidenceHandle[]>([]);
  const [phase, setPhase] = useState<LoadingPhase>("loading");
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [newCaseOpen, setNewCaseOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  // Ancla del scroll-to tras crear un caso: baja directo a la zona de
  // "Registrar evidencia" del caso recién creado — encadena crear → registrar
  // como un flujo guiado sin fusionar las dos operaciones en un solo formulario.
  const evidenceCardRef = useRef<HTMLDivElement>(null);

  // Panel de detalle del caso activo: ver / editar (nombre, examinador, notas
  // — no el os_profile, que lo deriva el orquestador) y cerrar/reabrir.
  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState({ name: "", examiner: "", notes: "" });
  const [editSaving, setEditSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [caseActionBusy, setCaseActionBusy] = useState(false);
  const [confirmCloseOpen, setConfirmCloseOpen] = useState(false);
  // Borrado PERMANENTE del caso: modal tipo-a-confirmar (el operador escribe el
  // nombre exacto). El backend re-valida `confirm_name` (RULE 2) y responde 409
  // si no cuadra, sin borrar nada.
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  const [deleteConfirmName, setDeleteConfirmName] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const [registering, setRegistering] = useState(false);
  // Flash de éxito de registro (2 s) — aria-live en EvidenceInbox.
  const [registerSuccess, setRegisterSuccess] = useState(false);
  const successTimer = useRef<number | undefined>(undefined);
  // Bandeja de entrada de evidencias (/api/evidence/sources — ./evidence del
  // host): el operador copia el fichero a la bandeja y lo ELIGE aquí
  // (RULE 2: nunca "el único" ni "el más reciente").
  const [sources, setSources] = useState<EvidenceSource[] | null>(null);
  const [loadingSources, setLoadingSources] = useState(false);
  const [selectedSourcePath, setSelectedSourcePath] = useState("");
  const [verifyingIds, setVerifyingIds] = useState<Set<string>>(new Set());
  // Subida de evidencia a la bandeja (drag-and-drop / examinar). Deposita el
  // fichero; el registro (hash-gate) es un paso aparte.
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState<string | null>(null);
  // Resumen informativo de la última tanda (p. ej. segmentos EWF que ya estaban
  // en la bandeja: 409 del backend, que NUNCA sobrescribe evidencia). No es un
  // error — el operador puede seguir adelante y registrar.
  const [uploadNotice, setUploadNotice] = useState<string | null>(null);

  // Acta de adquisición: modal por evidencia con la metadata de custodia + el
  // acta estructurada (cadena hash-encadenada), ambas del backend.
  const [actaOpen, setActaOpen] = useState(false);
  const [actaEvidence, setActaEvidence] = useState<EvidenceHandle | null>(null);
  const [actaMeta, setActaMeta] = useState<EvidenceMetadata | null>(null);
  const [acta, setActa] = useState<CustodyAct | null>(null);
  const [actaLoading, setActaLoading] = useState(false);
  const [actaError, setActaError] = useState<string | null>(null);
  // Tagged so the toast can label the failure honestly. Mixing both in one
  // string slot used to mean a verify 404 showed up as "No se pudo registrar
  // la evidencia: …" which was wrong both ways.
  const [evidenceError, setEvidenceError] = useState<
    { kind: "register" | "verify"; message: string } | null
  >(null);

  const activeCase = useMemo(
    () => cases.find((c) => c.id === activeCaseId) ?? null,
    [cases, activeCaseId]
  );

  // Mirror of activeCaseId in a ref. The register call is async (hashing a
  // multi-GB image takes a while) and the user may create/switch case while it
  // runs; the closure of registerSelectedSource would otherwise anchor the
  // evidence to a stale case_id. The ref always carries the latest value at
  // the moment each await resolves.
  const activeCaseIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeCaseIdRef.current = activeCaseId;
  }, [activeCaseId]);

  useEffect(() => {
    return () => window.clearTimeout(successTimer.current);
  }, []);

  // Initial load (y Reintentar del navegador de casos): lista casos y activa
  // el más reciente. El fetch de evidencias lo gobierna el effect de abajo,
  // keyed en activeCaseId, para que cualquier cambio refetchee uniformemente.
  const loadCases = useCallback(async () => {
    setPhase("loading");
    setError(null);
    try {
      const list = await api.cases.list();
      setCases(list);
      // Conserva el caso activo global si sigue existiendo; si el guardado ya no
      // está (o no hay ninguno), cae al más reciente (list[0]).
      setActiveCaseId((prev) =>
        prev && list.some((c) => c.id === prev) ? prev : list[0]?.id ?? null,
      );
      setPhase("ready");
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    void loadCases();
  }, [loadCases]);

  // Single source of truth for the evidence list: it follows activeCaseId.
  // We clear immediately so the UI never paints zombie rows from the previous
  // case (the source of the 404 from /verify when stale rows pointed at the
  // wrong case). cancelled flag prevents a slow listEvidence from a previous
  // case_id overwriting a newer fetch.
  useEffect(() => {
    if (!activeCaseId) {
      setEvidence([]);
      return;
    }
    let cancelled = false;
    setEvidence([]);
    (async () => {
      try {
        const ev = await api.cases.listEvidence(activeCaseId);
        if (!cancelled) setEvidence(ev);
      } catch (err) {
        if (!cancelled) {
          setEvidenceError({
            kind: "register",
            message: String(err instanceof Error ? err.message : err),
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCaseId]);

  const switchCase = useCallback(
    (caseId: string) => {
      if (caseId === activeCaseId) return;
      setActiveCaseId(caseId);
      // Evidence refetch happens automatically via the useEffect above.
    },
    [activeCaseId]
  );

  // El modo edición es por caso: si el operador cambia de caso a mitad de
  // edición, se descarta el borrador en vez de guardarlo contra el caso nuevo.
  useEffect(() => {
    setEditing(false);
    setEditError(null);
  }, [activeCaseId]);

  const submitCase = useCallback(async () => {
    setCreating(true);
    setCreateError(null);
    try {
      // os_profile se omite a propósito — lo deriva el orquestador del
      // contenido de la evidencia al registrarla (auto-detección de SO).
      const created = await api.cases.create({
        name: form.name.trim(),
        examiner: form.examiner.trim(),
        notes: form.notes.trim(),
      });
      setCases((prev) => [created, ...prev]);
      setActiveCaseId(created.id);
      // Evidence is reset by the activeCaseId effect (it always clears first).
      setForm(EMPTY_FORM);
      setNewCaseOpen(false);
      // Guía al operador directo al siguiente paso: registrar evidencia para
      // el caso que acaba de crear.
      requestAnimationFrame(() => {
        evidenceCardRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (err) {
      setCreateError(String(err instanceof Error ? err.message : err));
    } finally {
      setCreating(false);
    }
  }, [form]);

  // Devuelve la bandeja recién leída (además de fijarla en el estado) para que
  // quien la refresca pueda decidir sobre la lista NUEVA sin esperar al render.
  const loadSources = useCallback(async (): Promise<EvidenceSource[] | null> => {
    setLoadingSources(true);
    setEvidenceError(null);
    try {
      const res = await api.evidence.listSources();
      setSources(res.sources);
      // Si el fichero seleccionado desapareció de la bandeja, deselecciona —
      // jamás se registra una ruta que ya no está (el backend la rechazaría).
      setSelectedSourcePath((prev) =>
        res.sources.some((s) => s.path === prev) ? prev : ""
      );
      return res.sources;
    } catch (err) {
      setSources(null);
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
      return null;
    } finally {
      setLoadingSources(false);
    }
  }, []);

  // Sube una TANDA de ficheros a la bandeja, en serie. Un EWF partido son N
  // ficheros (.E01 … .E0N) y la bandeja los necesita todos para que ewfmount
  // reensamble la imagen; por eso se sube el conjunto, no solo el primero.
  // Un 409 («ya está en la bandeja») NO es un fallo: el backend nunca
  // sobrescribe evidencia, así que re-soltar un set del que ya había parte es
  // el caso normal — se cuenta como informativo. Al terminar refresca la
  // bandeja y autoselecciona el .E01 de la tanda (lo único registrable de un
  // set), para que al operador solo le quede pulsar «Registrar».
  const uploadSources = useCallback(
    async (files: File[]) => {
      if (files.length === 0) return;
      setUploading(true);
      setUploadProgress(0);
      setUploadError(null);
      setUploadNotice(null);

      const uploaded: EvidenceSource[] = [];
      const already: string[] = [];
      const failed: string[] = [];
      try {
        for (let i = 0; i < files.length; i += 1) {
          const file = files[i];
          try {
            const src = await api.evidence.uploadSource(file, (fraction) =>
              // Progreso agregado sobre la tanda completa.
              setUploadProgress((i + fraction) / files.length),
            );
            uploaded.push(src);
          } catch (err) {
            if (err instanceof ApiError && err.status === 409) {
              already.push(file.name);
            } else {
              failed.push(
                `${file.name}: ${String(err instanceof Error ? err.message : err)}`,
              );
            }
          }
        }
      } finally {
        setUploading(false);
        setUploadProgress(1);
      }

      if (failed.length > 0) setUploadError(failed.join(" · "));
      const notes: string[] = [];
      if (uploaded.length > 0) {
        notes.push(
          `${uploaded.length} ${uploaded.length === 1 ? "fichero subido" : "ficheros subidos"} a la bandeja`,
        );
      }
      if (already.length > 0) {
        notes.push(
          `${already.length} ya ${already.length === 1 ? "estaba" : "estaban"} en la bandeja (${already.join(", ")}); no se sobrescribe evidencia`,
        );
      }
      setUploadNotice(notes.length > 0 ? `${notes.join(" · ")}.` : null);

      // Refresca SIEMPRE (incluso si todo eran duplicados: la bandeja ya los
      // tiene y el operador debe poder registrarlos).
      const refreshed = await loadSources();
      if (!refreshed) return;
      const batch = new Set(files.map((f) => f.name));
      const inBatch = refreshed.filter((s) => batch.has(s.name.split(/[\\/]/).pop() ?? s.name));
      // Punto de entrada del set: el primer segmento EWF de la tanda. Si no hay
      // ninguno y la tanda era un único fichero, se selecciona ese.
      const entry =
        inBatch.find((s) => isEwfFirstSegment(s.name)) ??
        (files.length === 1 ? inBatch[0] : undefined);
      if (entry) setSelectedSourcePath(entry.path);
    },
    [loadSources],
  );

  const registerSelectedSource = useCallback(async () => {
    // Snapshot the case at the moment the user CLICKED "Registrar": hashing a
    // multi-GB image takes a while and the user may switch cases meanwhile.
    const intendedCaseId = activeCase?.id;
    if (!intendedCaseId || !selectedSourcePath) return;
    setEvidenceError(null);
    setRegistering(true);
    try {
      const handle = await api.cases.registerEvidence(intendedCaseId, selectedSourcePath);
      // Only append if the user hasn't navigated away in the meantime; if they
      // did, the effect on activeCaseId already refetched and will reflect
      // reality next time they come back to this case.
      if (activeCaseIdRef.current === intendedCaseId) {
        setEvidence((prev) => [handle, ...prev]);
      }
      setSelectedSourcePath("");
      // El caso puede haber cambiado en el servidor (triage deriva os_profile
      // al registrar la primera evidencia enrutable) — refresca la fila.
      try {
        const refreshed = await api.cases.get(intendedCaseId);
        setCases((prev) => prev.map((c) => (c.id === refreshed.id ? refreshed : c)));
      } catch {
        /* refresco best-effort; la evidencia ya quedó registrada */
      }
      setRegisterSuccess(true);
      window.clearTimeout(successTimer.current);
      successTimer.current = window.setTimeout(() => setRegisterSuccess(false), 2000);
    } catch (err) {
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    } finally {
      setRegistering(false);
    }
  }, [activeCase, selectedSourcePath]);

  const verifyOne = useCallback(
    async (evidenceId: string) => {
      const intendedCaseId = activeCase?.id;
      if (!intendedCaseId) return;
      setEvidenceError(null);
      setVerifyingIds((prev) => {
        const next = new Set(prev);
        next.add(evidenceId);
        return next;
      });
      try {
        const updated = await api.cases.verifyEvidence(intendedCaseId, evidenceId);
        // The router returns the full handle with last_verification freshly
        // persisted (verification.json + audit.jsonl). Replace the row in place
        // — but only if the active case hasn't changed under us.
        if (activeCaseIdRef.current === intendedCaseId) {
          setEvidence((prev) =>
            prev.map((ev) => (ev.evidence_id === evidenceId ? { ...ev, ...updated } : ev))
          );
        }
      } catch (err) {
        setEvidenceError({
          kind: "verify",
          message: String(err instanceof Error ? err.message : err),
        });
      } finally {
        setVerifyingIds((prev) => {
          const next = new Set(prev);
          next.delete(evidenceId);
          return next;
        });
      }
    },
    [activeCase]
  );

  const openActa = useCallback(
    async (ev: EvidenceHandle) => {
      const caseId = activeCase?.id;
      if (!caseId) return;
      setActaEvidence(ev);
      setActaOpen(true);
      setActa(null);
      setActaMeta(null);
      setActaError(null);
      setActaLoading(true);
      try {
        // Metadata + acta en paralelo — ambas son lecturas puras del backend.
        const [meta, actaRes] = await Promise.all([
          api.cases.evidenceMetadata(caseId, ev.evidence_id),
          api.cases.custodyAct(caseId, ev.evidence_id),
        ]);
        setActaMeta(meta);
        setActa(actaRes);
      } catch (err) {
        setActaError(String(err instanceof Error ? err.message : err));
      } finally {
        setActaLoading(false);
      }
    },
    [activeCase]
  );

  const downloadActa = useCallback(() => {
    if (!acta) return;
    const blob = new Blob([JSON.stringify(acta, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `acta-adquisicion-${acta.evidence.evidence_id}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }, [acta]);

  const closeActiveCase = useCallback(async () => {
    if (!activeCase) return;
    setCaseActionBusy(true);
    try {
      const updated = await api.cases.close(activeCase.id);
      setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      setConfirmCloseOpen(false);
    } catch (err) {
      // Cierre de caso comparte el slot de errores con register/verify; el copy
      // "no se pudo verificar" cuadra peor que el de register, así que va aquí.
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
      setConfirmCloseOpen(false);
    } finally {
      setCaseActionBusy(false);
    }
  }, [activeCase]);

  const reopenActiveCase = useCallback(async () => {
    if (!activeCase) return;
    setCaseActionBusy(true);
    try {
      const updated = await api.cases.reopen(activeCase.id);
      setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
    } catch (err) {
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    } finally {
      setCaseActionBusy(false);
    }
  }, [activeCase]);

  const openDeleteModal = useCallback(() => {
    setDeleteConfirmName("");
    setDeleteError(null);
    setConfirmDeleteOpen(true);
  }, []);

  // Borrado PERMANENTE del caso activo. El backend exige el nombre exacto y
  // borra el directorio entero (evidencia, audit, hallazgos, artefactos); aquí
  // solo se recarga la lista, que deselecciona el caso si era el activo.
  const deleteActiveCase = useCallback(async () => {
    if (!activeCase) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.cases.delete(activeCase.id, deleteConfirmName);
      setConfirmDeleteOpen(false);
      setDeleteConfirmName("");
      // El caso ya no existe: limpia lo que colgaba de él antes de recargar.
      setEvidence([]);
      setSources(null);
      setSelectedSourcePath("");
      setActiveCaseId((prev) => (prev === activeCase.id ? null : prev));
      await loadCases();
    } catch (err) {
      setDeleteError(String(err instanceof Error ? err.message : err));
    } finally {
      setDeleting(false);
    }
  }, [activeCase, deleteConfirmName, loadCases, setActiveCaseId]);

  const startEdit = useCallback(() => {
    if (!activeCase) return;
    setEditForm({
      name: activeCase.name,
      examiner: activeCase.examiner,
      notes: activeCase.notes,
    });
    setEditError(null);
    setEditing(true);
  }, [activeCase]);

  const cancelEdit = useCallback(() => {
    setEditing(false);
    setEditError(null);
  }, []);

  const saveEdit = useCallback(async () => {
    if (!activeCase) return;
    setEditSaving(true);
    setEditError(null);
    try {
      const updated = await api.cases.update(activeCase.id, {
        name: editForm.name.trim(),
        examiner: editForm.examiner.trim(),
        notes: editForm.notes.trim(),
      });
      setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      setEditing(false);
    } catch (err) {
      setEditError(String(err instanceof Error ? err.message : err));
    } finally {
      setEditSaving(false);
    }
  }, [activeCase, editForm]);

  const verifiedCount = useMemo(
    () => evidence.filter((e) => e.last_verification?.verified === true).length,
    [evidence]
  );
  const pendingCount = evidence.length - verifiedCount;

  const formValid =
    form.name.trim().length > 0 &&
    form.name.trim().length <= 200 &&
    form.examiner.trim().length > 0 &&
    form.examiner.trim().length <= 200;

  const editValid =
    editForm.name.trim().length > 0 &&
    editForm.name.trim().length <= 200 &&
    editForm.examiner.trim().length > 0 &&
    editForm.examiner.trim().length <= 200;

  const caseClosed = activeCase?.status === "closed";

  if (phase === "loading") {
    return (
      <div>
        <PageHeader title="Casos y evidencias" subtitle="Cargando casos del servicio api…" />
        <LoadingState label="Cargando casos…" />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Casos y evidencias"
        subtitle="Crea el caso, registra la evidencia y deja que FORENSIA calcule el hash baseline antes de exponerla a cualquier herramienta."
        actions={
          <>
            <Button variant="chip" onClick={() => setSearchOpen(true)}>
              Buscar casos
            </Button>
            <Button variant="primary" onClick={() => setNewCaseOpen(true)}>
              + Abrir caso nuevo
            </Button>
          </>
        }
      />

      <section className="case-workspace">
          {phase === "error" ? (
            // RULE 2: el fallo del listado se muestra aquí mismo, no solo
            // dentro del modal de búsqueda que quizá nadie abra.
            <>
              <ErrorState message={error ?? "no se pudo listar los casos"} />
              <div className="cta-row">
                <Button variant="chip" onClick={loadCases}>
                  Reintentar
                </Button>
              </div>
            </>
          ) : !activeCase ? (
            <EmptyState
              title="Sin caso activo"
              description="Busca un caso existente o crea uno nuevo para empezar."
              action={
                <div style={{ display: "flex", gap: 10 }}>
                  <Button variant="chip" onClick={() => setSearchOpen(true)}>
                    Buscar casos
                  </Button>
                  <Button variant="primary" onClick={() => setNewCaseOpen(true)}>
                    + Abrir caso nuevo
                  </Button>
                </div>
              }
            />
          ) : (
            <>
              <Card fullWidth>
                {editing ? (
                  <>
                    <h3>Editar caso</h3>
                    <div className="form-grid">
                      <div className="form-field full-width">
                        <label className="form-label" htmlFor="edit-case-name">
                          Nombre del caso
                        </label>
                        <input
                          id="edit-case-name"
                          className="form-input"
                          value={editForm.name}
                          onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                          maxLength={200}
                        />
                      </div>
                      <div className="form-field">
                        <label className="form-label" htmlFor="edit-case-examiner">
                          Examinador
                        </label>
                        <input
                          id="edit-case-examiner"
                          className="form-input"
                          value={editForm.examiner}
                          onChange={(e) =>
                            setEditForm({ ...editForm, examiner: e.target.value })
                          }
                          maxLength={200}
                        />
                      </div>
                      <div className="form-field full-width">
                        <label className="form-label" htmlFor="edit-case-notes">
                          Descripción / notas
                        </label>
                        <textarea
                          id="edit-case-notes"
                          className="form-textarea"
                          rows={3}
                          value={editForm.notes}
                          onChange={(e) => setEditForm({ ...editForm, notes: e.target.value })}
                        />
                      </div>
                    </div>
                    {editError && (
                      <div className="error-state" style={{ marginTop: 8 }}>
                        <strong>No se pudo guardar:</strong> {editError}
                      </div>
                    )}
                    <div className="cta-row">
                      <Button
                        variant="primary"
                        disabled={!editValid || editSaving}
                        onClick={saveEdit}
                      >
                        {editSaving ? "Guardando…" : "Guardar cambios"}
                      </Button>
                      <Button variant="chip" disabled={editSaving} onClick={cancelEdit}>
                        Cancelar
                      </Button>
                    </div>
                  </>
                ) : (
                  <ActiveCaseHeader
                    c={activeCase}
                    busy={caseActionBusy}
                    onInvestigate={
                      onNavigate ? () => onNavigate("investigation") : undefined
                    }
                    onEdit={startEdit}
                    onRequestClose={() => setConfirmCloseOpen(true)}
                    onRequestDelete={openDeleteModal}
                    onReopen={reopenActiveCase}
                  />
                )}
              </Card>

              <div className="metrics-inline">
                <div className="metrics-inline-item">
                  <strong>{evidence.length}</strong> Evidencias
                </div>
                <div className="metrics-inline-item metrics-inline-item--success">
                  <strong>{verifiedCount}</strong> ✓ Verificadas
                </div>
                <div
                  className={
                    pendingCount > 0
                      ? "metrics-inline-item metrics-inline-item--warning"
                      : "metrics-inline-item"
                  }
                >
                  <strong>{pendingCount}</strong> ◷ Pendientes
                </div>
              </div>

              <div ref={evidenceCardRef}>
                <PageSection title="Registrar evidencia">
                  <EvidenceInbox
                    caseClosed={caseClosed}
                    sources={sources}
                    loadingSources={loadingSources}
                    selectedSourcePath={selectedSourcePath}
                    registering={registering}
                    registerError={
                      evidenceError?.kind === "register" ? evidenceError.message : null
                    }
                    registerSuccess={registerSuccess}
                    uploading={uploading}
                    uploadProgress={uploadProgress}
                    uploadError={uploadError}
                    uploadNotice={uploadNotice}
                    onSelectSource={setSelectedSourcePath}
                    onLoadSources={() => void loadSources()}
                    onRegister={registerSelectedSource}
                    onUploadFiles={uploadSources}
                  />
                </PageSection>
              </div>

              <PageSection title={`Evidencias del caso (${evidence.length})`}>
                <EvidenceTable
                  evidence={evidence}
                  verifyingIds={verifyingIds}
                  onVerify={verifyOne}
                  verifyError={
                    evidenceError?.kind === "verify" ? evidenceError.message : null
                  }
                />
              </PageSection>

              {evidence.length > 0 && (
                <PageSection title="Cadena de custodia">
                  <div className="dropzone-hint" style={{ marginBottom: 10 }}>
                    Solo lectura a nivel de sistema de ficheros (chmod 0444); el
                    bloqueo a nivel de bloque está pendiente (Fase 2). Genera el
                    acta de adquisición de cada evidencia con su hash baseline,
                    tamaño y el enlace de la cadena hash-encadenada.
                  </div>
                  <div className="custody-list">
                    {evidence.map((ev) => (
                      <Card key={ev.evidence_id}>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 12,
                            flexWrap: "wrap",
                          }}
                        >
                          <div style={{ minWidth: 0 }}>
                            <strong
                              title={evidenceFileName(ev)}
                              style={{ display: "block", overflowWrap: "anywhere" }}
                            >
                              {evidenceFileName(ev)}
                            </strong>
                            <div style={{ marginTop: 4, display: "flex", gap: 8, flexWrap: "wrap" }}>
                              <Badge variant="neutral">{formatBytes(ev.size)}</Badge>
                              <span title={ev.sha256}>
                                <Badge variant="neutral">SHA-256 {shortHash(ev.sha256)}</Badge>
                              </span>
                              <Badge variant="medium">{READ_ONLY_BADGE}</Badge>
                            </div>
                          </div>
                          <Button variant="chip" onClick={() => openActa(ev)}>
                            Acta de adquisición
                          </Button>
                        </div>
                      </Card>
                    ))}
                  </div>
                </PageSection>
              )}
            </>
          )}
      </section>

      <CaseSearchModal
        open={searchOpen}
        onClose={() => setSearchOpen(false)}
        cases={cases}
        activeCaseId={activeCaseId}
        onSelect={switchCase}
        error={phase === "error" ? error : null}
        onRetry={loadCases}
      />

      <Modal open={newCaseOpen} title="Nuevo caso" onClose={() => setNewCaseOpen(false)}>
        <div className="form-grid">
          <div className="form-field full-width">
            <label className="form-label" htmlFor="case-name">Nombre del caso</label>
            <input
              id="case-name"
              className="form-input"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              maxLength={200}
              placeholder="Nombre o referencia del caso"
              autoFocus
            />
          </div>
          <div className="form-field full-width">
            <label className="form-label" htmlFor="case-examiner">Examinador</label>
            <input
              id="case-examiner"
              className="form-input"
              value={form.examiner}
              onChange={(e) => setForm({ ...form, examiner: e.target.value })}
              maxLength={200}
              placeholder="Nombre completo"
            />
          </div>
          <div className="form-field full-width">
            <label className="form-label" htmlFor="case-notes">Descripción / notas</label>
            <textarea
              id="case-notes"
              className="form-textarea"
              rows={3}
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              onKeyDown={(e) => {
                // Enter en el último campo = enviar (Shift+Enter para salto de línea,
                // mismo gesto que el composer del chat).
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  if (formValid && !creating) void submitCase();
                }
              }}
              placeholder="Descripción breve del caso (opcional)"
            />
          </div>
        </div>
        <div className="dropzone-hint" style={{ marginTop: 4 }}>
          El perfil de sistema operativo no se elige aquí — el orquestador lo deriva
          automáticamente del contenido de la evidencia al registrarla.
        </div>
        {createError && (
          <div className="error-state" style={{ marginTop: 8 }}>
            <strong>No se pudo crear el caso:</strong> {createError}
          </div>
        )}
        <div className="cta-row">
          <Button variant="primary" disabled={!formValid || creating} onClick={submitCase}>
            {creating ? "Guardando…" : "Guardar caso"}
          </Button>
          <Button variant="chip" disabled={creating} onClick={() => setNewCaseOpen(false)}>
            Cancelar
          </Button>
        </div>
      </Modal>

      <Modal
        open={actaOpen}
        title="Acta de adquisición"
        onClose={() => setActaOpen(false)}
      >
        {actaEvidence && (
          <p style={{ marginTop: 0, wordBreak: "break-word" }}>
            <strong>{evidenceFileName(actaEvidence)}</strong>
          </p>
        )}
        {actaLoading ? (
          <LoadingState label="Generando acta…" />
        ) : actaError ? (
          <ErrorState message={actaError} />
        ) : acta && actaMeta ? (
          <div className="acta-detail">
            <dl className="acta-grid">
              <dt>Caso</dt>
              <dd>
                {acta.case.name} · Examinador: {acta.case.examiner}
              </dd>
              <dt>Origen</dt>
              <dd style={{ overflowWrap: "anywhere" }}>
                {acta.evidence.source_path ?? "—"}
              </dd>
              <dt>SHA-256 (baseline)</dt>
              <dd style={{ overflowWrap: "anywhere" }} title={acta.evidence.sha256}>
                {acta.evidence.sha256}
              </dd>
              <dt>Tamaño</dt>
              <dd>
                {acta.evidence.size_human} ({acta.evidence.size_bytes.toLocaleString("es-ES")} bytes)
              </dd>
              <dt>Registrada</dt>
              <dd>{formatDate(acta.evidence.registered_at)}</dd>
              <dt>Nivel de solo-lectura</dt>
              <dd>{actaMeta.read_only_label}</dd>
              <dt>Cadena de custodia</dt>
              <dd style={{ overflowWrap: "anywhere" }}>
                entry_hash:{" "}
                <code>{acta.chain_of_custody.register_entry_hash ?? "—"}</code>
                <div style={{ marginTop: 6 }}>
                  {acta.chain_of_custody.hash_chain_verified ? (
                    <Badge variant="success">✓ Cadena hash verificada</Badge>
                  ) : (
                    <Badge variant="critical">⚠ Cadena hash NO verifica</Badge>
                  )}
                </div>
              </dd>
              <dt>Verificación</dt>
              <dd>
                {acta.verification ? (
                  acta.verification.verified ? (
                    <Badge variant="success">
                      ✓ Verificada {formatDate(acta.verification.verified_at)}
                    </Badge>
                  ) : (
                    <Badge variant="critical">⚠ Hash MISMATCH</Badge>
                  )
                ) : (
                  <Badge variant="neutral">Sin verificar</Badge>
                )}
              </dd>
              <dt>Herramienta</dt>
              <dd>
                {acta.tool.name} {acta.tool.version} · {acta.tool.method}
              </dd>
            </dl>
            <div className="cta-row">
              <Button variant="primary" onClick={downloadActa}>
                Descargar acta (JSON)
              </Button>
              <Button variant="chip" onClick={() => setActaOpen(false)}>
                Cerrar
              </Button>
            </div>
          </div>
        ) : null}
      </Modal>

      <Modal
        open={confirmCloseOpen}
        title="Cerrar caso"
        onClose={() => setConfirmCloseOpen(false)}
      >
        <p style={{ marginTop: 0 }}>
          ¿Deseas cerrar «{activeCase?.name}»? Las evidencias registradas no serán
          eliminadas.
        </p>
        <div className="cta-row">
          <Button
            variant="chip"
            disabled={caseActionBusy}
            onClick={() => setConfirmCloseOpen(false)}
          >
            Cancelar
          </Button>
          <Button variant="primary" disabled={caseActionBusy} onClick={closeActiveCase}>
            {caseActionBusy ? "Cerrando…" : "Cerrar caso"}
          </Button>
        </div>
      </Modal>

      <Modal
        open={confirmDeleteOpen}
        title="Eliminar caso"
        onClose={() => {
          if (!deleting) setConfirmDeleteOpen(false);
        }}
      >
        <div className="danger-notice">
          <strong>Esta acción es irreversible.</strong> Se borrará de forma
          PERMANENTE todo el caso «{activeCase?.name}» y con él su cadena de
          custodia completa: las copias de evidencia registradas, el log de
          auditoría hash-encadenado, los hallazgos, los artefactos, los chats y
          los informes. No hay papelera ni deshacer.
        </div>
        <div className="form-field full-width">
          <label className="form-label" htmlFor="delete-case-confirm">
            Escribe el nombre del caso ({activeCase?.name}) para confirmar
          </label>
          <input
            id="delete-case-confirm"
            className="form-input"
            value={deleteConfirmName}
            onChange={(e) => setDeleteConfirmName(e.target.value)}
            placeholder={activeCase?.name ?? ""}
            autoComplete="off"
            autoFocus
          />
        </div>
        {deleteError && (
          <div className="error-state" style={{ marginTop: 8 }}>
            <strong>No se pudo eliminar el caso:</strong> {deleteError}
          </div>
        )}
        <div className="cta-row">
          <Button
            variant="chip"
            disabled={deleting}
            onClick={() => setConfirmDeleteOpen(false)}
          >
            Cancelar
          </Button>
          <Button
            variant="primary"
            className="btn-danger"
            // Habilitado solo con el nombre EXACTO; el backend lo re-valida.
            disabled={deleting || deleteConfirmName !== (activeCase?.name ?? "")}
            onClick={deleteActiveCase}
          >
            {deleting ? "Eliminando…" : "Eliminar permanentemente"}
          </Button>
        </div>
      </Modal>
    </div>
  );
}
