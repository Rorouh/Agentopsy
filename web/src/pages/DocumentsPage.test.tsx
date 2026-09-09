/**
 * La pantalla de APROBACIÓN: qué revisión se aprueba y qué la bloquea.
 *
 * F04 pedía que la pantalla identifique la revisión exacta que se va a aprobar
 * y muestre los bloqueos pendientes, y que la comprobación del backend siga
 * siendo obligatoria aunque el cliente mande la petición directamente.
 *
 * Aquí se comprueba lo primero renderizando de verdad: se abre la aprobación,
 * se lee la revisión que se ofrece y se comprueba que un bloqueo se pinta y que
 * el botón de confirmar no está disponible. Lo segundo (que el backend manda) no
 * se puede demostrar desde el navegador y no se finge que sí: lo demuestran
 * `backend/tests/test_aprobacion.py` y `test_recorrido_procedencia.py`, que
 * llaman a la ruta saltándose la interfaz.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  DocumentChecks,
  DocumentCitation,
  DocumentFull,
  DocumentMeta,
} from "../api/types";

const listDocuments = vi.fn<() => Promise<DocumentMeta[]>>();
const getDocument = vi.fn<() => Promise<DocumentFull>>();
const documentChecks = vi.fn<() => Promise<DocumentChecks>>();
const signDocument = vi.fn<() => Promise<DocumentFull>>();
const documentCitation = vi.fn<() => Promise<DocumentCitation>>();

vi.mock("../api/client", () => ({
  api: {
    cases: {
      listDocuments: () => listDocuments(),
      getDocument: () => getDocument(),
      documentChecks: () => documentChecks(),
      signDocument: () => signDocument(),
      documentCitation: () => documentCitation(),
      listReportJobs: () => Promise.resolve([]),
      capabilities: () => Promise.resolve({ executors: [] }),
    },
    capabilities: () => Promise.resolve({ executors: [] }),
  },
}));

vi.mock("../state/activeCase", () => ({
  useActiveCase: () => ({
    activeCase: { id: "caso-1", name: "Caso", examiner: "ramos" },
    phase: "ready",
    error: null,
  }),
}));
vi.mock("../state/casePulse", () => ({ useCaseStream: () => 0 }));
vi.mock("../layout/shellHeader", () => ({ usePublishShellHeader: () => {} }));
vi.mock("../i18n", () => ({
  useLang: () => ({
    t: (k: string, p?: Record<string, unknown>) =>
      p ? `${k}:${Object.values(p).join(",")}` : k,
    lang: "es",
  }),
}));

import { CitationPanel } from "./DocumentsPage";
import { ApprovalPanel } from "./DocumentsPage";

const FINDING_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

const CITA_OK: DocumentCitation = {
  case_id: "caso-1",
  document_id: "doc-1",
  finding_id: FINDING_ID,
  revision: 1,
  conclusiones: [
    {
      num: "9",
      titulo: "Conclusiones y limitaciones",
      bloque: 0,
      tipo: "p",
      texto: "Se confirma la persistencia en el perfil de jcloudy.",
    },
  ],
  titulo: "Ejecutable de persistencia",
  resumen: "updater.exe en el perfil de jcloudy.",
  severidad: "high",
  finding_kind: "afirmacion",
  observed_at: "2026-03-14T08:12:44Z",
  alcance_examinado: null,
  provenance_state: "verificada",
  content_sha256: "d".repeat(64),
  content_sha256_recomputado: "d".repeat(64),
  integridad_ok: true,
  en_manifiesto: true,
  fuentes: [
    {
      run_id: "run-1",
      tool_id: "tsk_fls",
      evidence_id: "ev-1",
      artefacto: "stdout",
      relpath: null,
      sha256_registrado: "e".repeat(64),
      sha256: "e".repeat(64),
      anclaje: "anclado",
      localizador: { tipo: "lineas", desde: 2, hasta: 2 },
      estado: "verificada",
      estado_registrado: "verificada",
      extracto: "r/r 512-128-3: Users/jcloudy/AppData/updater.exe",
      resultado_parcial: false,
      exit_code: 0,
    },
  ],
};

const CHECKS_OK: DocumentChecks = {
  document_id: "doc-1",
  case_id: "caso-1",
  status: "draft",
  version: "v1.0",
  aprobable: true,
  sha256_actual: "b".repeat(64),
  sha256_registrado: "b".repeat(64),
  bloqueos: [],
  fuentes: [
    { tipo: "artefacto", estado: "verificada", run_id: "run-1", referencia: "stdout" },
  ],
  citas: [
    {
      num: "9",
      bloque: 0,
      finding_id: FINDING_ID,
      revision: 1,
      en_manifiesto: true,
      estado: "verificada",
    },
  ],
  procedencia: {
    schema_version: 3,
    digest_declarado: "c".repeat(64),
    digest_actual: "c".repeat(64),
    digest_anclado: "c".repeat(64),
  },
};

const CHECKS_BLOQUEADO: DocumentChecks = {
  ...CHECKS_OK,
  aprobable: false,
  bloqueos: [
    {
      codigo: "fuente_alterada",
      mensaje: "la fuente 'stdout' de la ejecución run-1 ya no casa con su hash",
      detalle: "",
    },
    {
      codigo: "limitaciones_ausentes",
      mensaje: "el informe no declara sus limitaciones y este caso las tiene",
      detalle: "material_truncado:hallazgos",
    },
  ],
  fuentes: [
    { tipo: "artefacto", estado: "alterada", run_id: "run-1", referencia: "stdout" },
  ],
};

describe("pantalla de aprobación de un informe", () => {
  beforeEach(() => {
    documentChecks.mockReset();
    signDocument.mockReset();
  });

  it("identifica la revisión EXACTA que se va a aprobar", async () => {
    render(
      <ApprovalPanel
        checks={CHECKS_OK}
        busy={false}
        onCancel={() => {}}
        onConfirm={() => {}}
      />,
    );
    const revision = await screen.findByTestId("revision-aprobada");
    expect(revision.textContent).toContain("v1.0");
    // El hash del contenido: es lo que ata la aprobación a lo que se ha leído.
    expect(revision.textContent).toContain("b".repeat(64));
    // Y dice qué es esta aprobación, para que nadie la lea como una firma.
    expect(screen.getByTestId("panel-aprobacion").textContent).toContain(
      "doc.approveWhatItIs",
    );
  });

  it("muestra los bloqueos pendientes y no deja confirmar", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(
      <ApprovalPanel
        checks={CHECKS_BLOQUEADO}
        busy={false}
        onCancel={() => {}}
        onConfirm={onConfirm}
      />,
    );

    // Los DOS bloqueos, cada uno con su motivo: se ven todos de una vez, no de
    // uno en uno.
    expect(screen.getByTestId("bloqueo-fuente_alterada").textContent).toContain(
      "ya no casa",
    );
    expect(
      screen.getByTestId("bloqueo-limitaciones_ausentes").textContent,
    ).toContain("limitaciones");

    const confirmar = screen.getByTestId("confirmar-aprobacion") as HTMLButtonElement;
    expect(confirmar.disabled).toBe(true);
    await user.click(confirmar);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("sin bloqueos, confirmar aprueba la revisión leída", async () => {
    const onConfirm = vi.fn();
    const user = userEvent.setup();
    render(
      <ApprovalPanel
        checks={CHECKS_OK}
        busy={false}
        onCancel={() => {}}
        onConfirm={onConfirm}
      />,
    );
    expect(screen.getByTestId("sin-bloqueos").textContent).toBe(
      "doc.approveNoBlockers",
    );
    await user.click(screen.getByTestId("confirmar-aprobacion"));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});

// ── RA07: abrir la fuente de una conclusión ──────────────────────────────────
//
// Lo que la reauditoría de 2026-09-08 echaba en falta: la pantalla enseñaba
// identificadores y estados, pero desde una conclusión no se podía llegar a la
// línea concreta que la sostiene. Aquí se comprueba renderizando de verdad.

describe("la fuente de una conclusión", () => {
  it("enseña la revisión citada, el localizador y el extracto verificado", () => {
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={CITA_OK}
        error={null}
        onClose={() => {}}
      />,
    );
    expect(screen.getByTestId("cita-hallazgo").textContent).toContain(
      "Ejecutable de persistencia",
    );
    // El EXTRACTO que hay en esa posición, no un resumen de él.
    expect(screen.getByTestId("fuente-extracto").textContent).toContain(
      "updater.exe",
    );
    // Y la separación que no puede difuminarse: integridad técnica no es
    // suficiencia interpretativa.
    expect(screen.getByTestId("panel-cita").textContent).toContain(
      "doc.citationHumanReview",
    );
  });

  it("mientras carga lo dice, y no finge una ficha vacía", () => {
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={null}
        error={null}
        onClose={() => {}}
      />,
    );
    expect(screen.getByTestId("cita-cargando")).toBeTruthy();
  });

  it("si la fuente no se puede abrir, dice el motivo", () => {
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={null}
        error="404: el documento no cita esa revisión"
        onClose={() => {}}
      />,
    );
    const error = screen.getByTestId("cita-error");
    expect(error.textContent).toContain("doc.citationFailed");
    expect(error.textContent).toContain("no cita esa revisión");
    // Y no se enseña ningún extracto: presentarlo sería darlo por comprobado.
    expect(screen.queryByTestId("fuente-extracto")).toBeNull();
  });

  it("un hallazgo reescrito se marca, no se sirve como verificado", () => {
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={{
          ...CITA_OK,
          integridad_ok: false,
          content_sha256_recomputado: "f".repeat(64),
        }}
        error={null}
        onClose={() => {}}
      />,
    );
    expect(screen.getByTestId("cita-alterada").textContent).toContain(
      "doc.citationFindingTampered",
    );
  });

  it("una cita fuera del manifiesto del informe se declara", () => {
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={{ ...CITA_OK, en_manifiesto: false }}
        error={null}
        onClose={() => {}}
      />,
    );
    expect(screen.getByTestId("cita-fuera").textContent).toContain(
      "doc.citationOutsideManifest",
    );
  });

  it("se cierra con el teclado, como cualquier acción de la pantalla", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <CitationPanel
        cita={{ finding_id: FINDING_ID, revision: 1 }}
        data={CITA_OK}
        error={null}
        onClose={onClose}
      />,
    );
    // Tabulando se llega al botón y con Enter se activa: no hace falta ratón.
    await user.tab();
    expect(document.activeElement).toBe(screen.getByTestId("cerrar-cita"));
    await user.keyboard("{Enter}");
    expect(onClose).toHaveBeenCalled();
  });
});
