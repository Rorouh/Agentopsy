import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import type { Case, EvidenceHandle, EvidenceSource } from "../api/types";
import type { ViewId } from "../navigation/navItems";
import { ActiveCaseHeader } from "../components/ActiveCaseHeader";
import { CaseSearchModal } from "../components/CaseSearchModal";
import { EvidenceInbox } from "../components/EvidenceInbox";
import { EvidenceTable } from "../components/EvidenceTable";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { EmptyState } from "../ui/EmptyState";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { Modal } from "../ui/Modal";
import { PageHeader } from "../ui/PageHeader";
import { PageSection } from "../ui/PageSection";

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
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
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
      setActiveCaseId((prev) => prev ?? (list.length > 0 ? list[0].id : null));
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

  const loadSources = useCallback(async () => {
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
    } catch (err) {
      setSources(null);
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    } finally {
      setLoadingSources(false);
    }
  }, []);

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
                    onSelectSource={setSelectedSourcePath}
                    onLoadSources={loadSources}
                    onRegister={registerSelectedSource}
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
    </div>
  );
}
