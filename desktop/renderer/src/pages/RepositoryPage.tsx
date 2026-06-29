import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Case, EvidenceHandle } from "../global";
import type { ViewId } from "../navigation/navItems";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { ErrorState } from "../ui/ErrorState";
import { LoadingState } from "../ui/LoadingState";
import { MetricCard } from "../ui/MetricCard";
import { PageHeader } from "../ui/PageHeader";
import { formatBytes, formatDate, shortHash } from "../utils/format";

interface RepositoryPageProps {
  onNavigate?: (view: ViewId) => void;
}

type LoadingPhase = "loading" | "ready" | "error";

function rowStatus(ev: EvidenceHandle): "unknown" | "verified" | "mismatch" {
  const lv = ev.last_verification;
  if (!lv) return "unknown";
  return lv.verified ? "verified" : "mismatch";
}

interface FormState {
  name: string;
  examiner: string;
  os_profile: "unix" | "windows";
  notes: string;
}

const EMPTY_FORM: FormState = {
  name: "",
  examiner: "",
  os_profile: "unix",
  notes: "",
};

export function RepositoryPage({ onNavigate }: RepositoryPageProps) {
  const [cases, setCases] = useState<Case[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceHandle[]>([]);
  const [phase, setPhase] = useState<LoadingPhase>("loading");
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [registering, setRegistering] = useState(false);
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

  // Mirror of activeCaseId in a ref. The native file-dialog (pickEvidenceFile)
  // is async and the user may create/switch case while it's open; the closure
  // of pickAndRegisterEvidence would otherwise register the evidence against
  // a stale case_id. The ref always carries the latest value at the moment
  // the dialog resolves.
  const activeCaseIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeCaseIdRef.current = activeCaseId;
  }, [activeCaseId]);

  // Initial load: list cases and pick the most recent as active. Evidence
  // fetching is owned by the useEffect below — keyed on activeCaseId — so
  // any subsequent change (switch chip, submitCase) refetches uniformly.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await window.forensia.cases.list();
        if (cancelled) return;
        setCases(list);
        if (list.length > 0) {
          setActiveCaseId(list[0].id);
        }
        setPhase("ready");
      } catch (err) {
        if (!cancelled) {
          setError(String(err instanceof Error ? err.message : err));
          setPhase("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

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
        const ev = await window.forensia.cases.listEvidence(activeCaseId);
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

  const submitCase = useCallback(async () => {
    setCreating(true);
    setCreateError(null);
    try {
      const created = await window.forensia.cases.create({
        name: form.name.trim(),
        examiner: form.examiner.trim(),
        os_profile: form.os_profile,
        notes: form.notes.trim(),
      });
      setCases((prev) => [created, ...prev]);
      setActiveCaseId(created.id);
      // Evidence is reset by the activeCaseId effect (it always clears first).
      setForm(EMPTY_FORM);
    } catch (err) {
      setCreateError(String(err instanceof Error ? err.message : err));
    } finally {
      setCreating(false);
    }
  }, [form]);

  const pickAndRegisterEvidence = useCallback(async () => {
    // Snapshot the case at the moment the user CLICKED "Seleccionar archivo".
    // The dialog is async; if the user switches cases (or creates one) while
    // it's open, we abort instead of registering the file against whatever
    // case ends up active when the dialog resolves. activeCaseIdRef holds the
    // current value so we can detect the change after the await.
    const intendedCaseId = activeCase?.id;
    if (!intendedCaseId) return;
    setEvidenceError(null);
    try {
      const sourcePath = await window.forensia.cases.pickEvidenceFile();
      if (!sourcePath) return; // user cancelled the dialog
      if (activeCaseIdRef.current !== intendedCaseId) {
        setEvidenceError({
          kind: "register",
          message:
            "El caso activo cambió mientras el diálogo de archivo estaba abierto. " +
            "Cancelado para no anclar la evidencia al caso equivocado. " +
            "Vuelve a seleccionar el archivo con el caso correcto activo.",
        });
        return;
      }
      setRegistering(true);
      const handle = await window.forensia.cases.registerEvidence(intendedCaseId, sourcePath);
      // Only append if the user hasn't navigated away in the meantime; if they
      // did, the effect on activeCaseId already refetched and will reflect
      // reality next time they come back to this case.
      if (activeCaseIdRef.current === intendedCaseId) {
        setEvidence((prev) => [handle, ...prev]);
      }
    } catch (err) {
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    } finally {
      setRegistering(false);
    }
  }, [activeCase]);

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
        const updated = await window.forensia.cases.verifyEvidence(
          intendedCaseId,
          evidenceId
        );
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
    try {
      const updated = await window.forensia.cases.close(activeCase.id);
      setCases((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
    } catch (err) {
      // Cierre de caso comparte el slot de errores con register/verify; el copy
      // "no se pudo verificar" cuadra peor que el de register, así que va aquí.
      setEvidenceError({
        kind: "register",
        message: String(err instanceof Error ? err.message : err),
      });
    }
  }, [activeCase]);

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

  if (phase === "loading") {
    return (
      <div>
        <PageHeader title="Casos y evidencias" subtitle="Cargando casos del sidecar…" />
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
          onNavigate &&
          activeCase && (
            <Button variant="chip" onClick={() => onNavigate("investigation")}>
              Investigar este caso →
            </Button>
          )
        }
      />

      {error && <ErrorState message={error} />}

      {activeCase ? (
        <div className="context-banner">
          <div className="context-banner-main">
            Caso activo: <strong>{activeCase.name}</strong>
            <span className="context-banner-evidence">
              {" · "}
              {activeCase.examiner}
              {" · "}
              perfil <strong>{activeCase.os_profile}</strong>
            </span>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <Badge variant={activeCase.status === "active" ? "low" : "neutral"}>
              {activeCase.status === "active" ? "Abierto" : "Cerrado"}
            </Badge>
            {activeCase.status === "active" && (
              <Button variant="chip" onClick={closeActiveCase}>
                Cerrar caso
              </Button>
            )}
          </div>
        </div>
      ) : (
        <div className="empty-state">
          Aún no hay casos. Crea uno con el formulario inferior para empezar.
        </div>
      )}

      {cases.length > 1 && (
        <div className="filters-row" style={{ marginBottom: 18 }}>
          {cases.map((c) => (
            <Button
              key={c.id}
              variant="chip"
              onClick={() => switchCase(c.id)}
              className={c.id === activeCaseId ? "chip active" : undefined}
            >
              {c.name}
            </Button>
          ))}
        </div>
      )}

      <div className="metric-row">
        <MetricCard label="Evidencias registradas" value={String(evidence.length)} />
        <MetricCard
          label="Verificadas (hash OK)"
          value={String(verifiedCount)}
          variant="success"
        />
        <MetricCard
          label="Pendientes / sin verificar"
          value={String(pendingCount)}
          variant={pendingCount > 0 ? "warning" : "neutral"}
        />
      </div>

      <div className="status-grid">
        <Card>
          <h3>Nuevo caso</h3>
          <div className="form-grid">
            <div className="form-field full-width">
              <label className="form-label">Nombre del caso</label>
              <input
                className="form-input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                maxLength={200}
                placeholder="Caso 2026-014 · Estación de trabajo comprometida"
              />
            </div>
            <div className="form-field">
              <label className="form-label">Examinador</label>
              <input
                className="form-input"
                value={form.examiner}
                onChange={(e) => setForm({ ...form, examiner: e.target.value })}
                maxLength={200}
                placeholder="S. Bravo"
              />
            </div>
            <div className="form-field">
              <label className="form-label">Perfil de SO</label>
              <select
                className="form-select"
                value={form.os_profile}
                onChange={(e) =>
                  setForm({ ...form, os_profile: e.target.value as "unix" | "windows" })
                }
              >
                <option value="unix">Unix-like</option>
                <option value="windows">Windows</option>
              </select>
            </div>
            <div className="form-field full-width">
              <label className="form-label">Descripción / notas</label>
              <textarea
                className="form-textarea"
                rows={3}
                value={form.notes}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                placeholder="Imagen forense de disco + volcado de memoria de un equipo Windows 11 con sospecha de exfiltración."
              />
            </div>
          </div>
          {createError && (
            <div className="error-state" style={{ marginTop: 8 }}>
              <strong>No se pudo crear el caso:</strong> {createError}
            </div>
          )}
          <div className="cta-row">
            <Button variant="chip" disabled={!formValid || creating} onClick={submitCase}>
              {creating ? "Guardando…" : "Guardar caso"}
            </Button>
          </div>
        </Card>

        <Card>
          <h3>Registrar evidencia</h3>
          <div className="dropzone">
            <div className="dropzone-title">
              {activeCase
                ? "Selecciona la imagen forense desde disco"
                : "Crea un caso antes de registrar evidencia"}
            </div>
            <div className="dropzone-hint">
              .E01 · .raw · .vmdk · volcado de memoria — la copia interna queda en read-only y
              FORENSIA calcula el SHA-256 baseline antes de exponerla.
            </div>
            <div className="cta-row" style={{ justifyContent: "center" }}>
              <Button
                variant="chip"
                disabled={!activeCase || registering}
                onClick={pickAndRegisterEvidence}
              >
                {registering ? "Registrando (hashing)…" : "Seleccionar archivo"}
              </Button>
            </div>
          </div>
          {evidenceError && (
            <div className="error-state" style={{ marginTop: 8 }}>
              <strong>
                {evidenceError.kind === "register"
                  ? "No se pudo registrar la evidencia:"
                  : "No se pudo verificar la evidencia:"}
              </strong>{" "}
              {evidenceError.message}
            </div>
          )}
        </Card>

        <Card fullWidth>
          <h3>Evidencias del caso ({evidence.length})</h3>
          {evidence.length === 0 ? (
            <div className="empty-state">
              {activeCase
                ? "Aún no hay evidencia registrada en este caso."
                : "Selecciona o crea un caso para ver sus evidencias."}
            </div>
          ) : (
            <div className="file-list">
              {evidence.map((ev) => {
                const status = rowStatus(ev);
                const verifying = verifyingIds.has(ev.evidence_id);
                const fileName = ev.original_path.split("/").pop() ?? ev.original_path;
                return (
                  <div className="file-row" key={ev.evidence_id}>
                    <div className="file-row-main">
                      <div>
                        <div className="file-row-name">{fileName}</div>
                        <div className="file-row-meta">
                          {formatBytes(ev.size)} · añadido {formatDate(ev.registered_at)} ·{" "}
                          {ev.evidence_id.slice(0, 8)}
                          {ev.last_verification && (
                            <>
                              {" · "}último verify {formatDate(ev.last_verification.verified_at)}
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="file-row-side">
                      <span className="file-row-hash" title={ev.sha256}>
                        SHA-256: {shortHash(ev.sha256)}
                      </span>
                      {status === "verified" && <Badge variant="success">Verificado</Badge>}
                      {status === "mismatch" && <Badge variant="critical">Hash MISMATCH</Badge>}
                      {status === "unknown" && !verifying && (
                        <Badge variant="neutral">Sin verificar</Badge>
                      )}
                      {verifying && <Badge variant="medium">Re-hasheando…</Badge>}
                      <Button
                        variant="chip"
                        disabled={verifying}
                        onClick={() => verifyOne(ev.evidence_id)}
                      >
                        {verifying
                          ? "Verificando…"
                          : ev.last_verification
                            ? "Re-verificar"
                            : "Verificar ahora"}
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
