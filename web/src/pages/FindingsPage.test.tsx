/**
 * Abrir una cita, de verdad.
 *
 * La auditoría (F03/F04) pedía que un hallazgo pueda ABRIR su fuente y enseñar
 * la evidencia, la ejecución, la herramienta, el artefacto, el localizador, el
 * extracto y su estado de integridad, y que ante una fuente alterada muestre un
 * error concreto en vez de un extracto que parecería comprobado.
 *
 * Esto se comprueba RENDERIZANDO el componente y pulsando el botón, no buscando
 * cadenas en el fichero: un texto que existe en el .tsx pero que la interfaz
 * nunca llega a pintar no cumple nada. El backend se sustituye por un doble del
 * cliente HTTP, así que no se llama a ningún servicio ni sale un byte de aquí.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AgentFinding, FindingSources } from "../api/types";

const listFindings = vi.fn<() => Promise<AgentFinding[]>>();
const findingSources = vi.fn<() => Promise<FindingSources>>();

vi.mock("../api/client", () => ({
  api: {
    cases: {
      listFindings: () => listFindings(),
      findingSources: () => findingSources(),
    },
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

// El catálogo real no aporta nada a esta prueba: `t` devuelve la CLAVE con sus
// parámetros, de modo que las aserciones fijan qué mensaje se elige, no cómo
// está redactado (la redacción la gobierna el typecheck de los dos catálogos).
vi.mock("../i18n", () => ({
  useLang: () => ({
    t: (k: string, p?: Record<string, unknown>) =>
      p ? `${k}:${Object.values(p).join(",")}` : k,
    lang: "es",
  }),
}));
vi.mock("../utils/format", () => ({
  useFormat: () => ({ formatDate: (iso: string) => iso, na: "n/d" }),
}));

import { FindingsPage } from "./FindingsPage";

const HALLAZGO: AgentFinding = {
  id: "f-1",
  case_id: "caso-1",
  title: "Ejecutable de persistencia",
  summary: "updater.exe vive en el perfil de jcloudy.",
  severity: "high",
  evidence_id: "ev-1",
  tool_id: "tsk_fls",
  run_id: "run-1",
  created_at: "2026-03-14T08:12:44Z",
  mitre_hints: [],
  finding_kind: "afirmacion",
  provenance_state: "verificada",
  revision: 1,
  content_sha256: "c".repeat(64),
  references: [],
};

const FUENTE_OK: FindingSources = {
  finding_id: "f-1",
  revision: 1,
  content_sha256: "c".repeat(64),
  finding_kind: "afirmacion",
  provenance_state: "verificada",
  alcance_examinado: null,
  fuentes: [
    {
      run_id: "run-1",
      tool_id: "tsk_fls",
      evidence_id: "ev-1",
      artefacto: "stdout",
      relpath: null,
      sha256_registrado: "a".repeat(64),
      sha256: "a".repeat(64),
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

const FUENTE_ROTA: FindingSources = {
  ...FUENTE_OK,
  fuentes: [
    {
      ...FUENTE_OK.fuentes[0],
      estado: "alterada",
      extracto: null,
      motivo: "el artefacto ya no casa con el SHA-256 de su manifiesto",
    },
  ],
};

async function abrirElHallazgo() {
  const user = userEvent.setup();
  render(<FindingsPage />);
  await user.click(await screen.findByRole("button", { name: /persistencia/i }));
  return user;
}

describe("abrir la cita de un hallazgo", () => {
  beforeEach(() => {
    listFindings.mockReset();
    findingSources.mockReset();
    listFindings.mockResolvedValue([HALLAZGO]);
  });

  it("muestra evidencia, ejecución, herramienta, artefacto, localizador y extracto", async () => {
    findingSources.mockResolvedValue(FUENTE_OK);
    const user = await abrirElHallazgo();
    await user.click(await screen.findByTestId("abrir-cita"));

    const ficha = await screen.findByTestId("fuente");
    // El extracto que se pinta es el que devolvió el backend, no uno construido
    // en el cliente a partir de lo que el modelo escribió.
    expect((await screen.findByTestId("fuente-extracto")).textContent).toContain(
      "updater.exe",
    );
    // Y la ficha nombra las coordenadas completas de la cita.
    expect(ficha.textContent).toContain("run-1");
    expect(ficha.textContent).toContain("tsk_fls");
    expect(ficha.textContent).toContain("ev-1");
    expect(ficha.textContent).toContain("source.locatorLines:2,2");
    // La distinción que no puede difuminarse: esto es validación TÉCNICA, no la
    // revisión humana de si la fuente sostiene la conclusión.
    expect(ficha.textContent).toContain("source.technicalOnly");
  });

  it("ante una fuente alterada muestra el error concreto y NO el extracto", async () => {
    findingSources.mockResolvedValue(FUENTE_ROTA);
    const user = await abrirElHallazgo();
    await user.click(await screen.findByTestId("abrir-cita"));

    const error = await screen.findByTestId("fuente-error");
    expect(error.textContent).toContain("source.blocked.alterada");
    // El motivo concreto, para que el perito sepa qué mirar.
    expect(error.textContent).toContain("SHA-256");
    // Dice que esto BLOQUEA la aprobación, en vez de dejarlo en un aviso suelto.
    expect(error.textContent).toContain("source.blocksApproval");
    // Y lo que NO se pinta: el extracto. Enseñarlo sería darlo por comprobado.
    expect(screen.queryByTestId("fuente-extracto")).toBeNull();
  });

  it("un hallazgo histórico dice que su procedencia no está verificada", async () => {
    listFindings.mockResolvedValue([
      { ...HALLAZGO, provenance_state: "no_verificada" },
    ]);
    await abrirElHallazgo();

    expect((await screen.findByTestId("procedencia-historica")).textContent).toBe(
      "source.legacy",
    );
    // Y no se ofrece abrir una cita que nunca se verificó.
    expect(screen.queryByTestId("abrir-cita")).toBeNull();
    expect(findingSources).not.toHaveBeenCalled();
  });

  it("un descarte enseña QUÉ se examinó y con qué límite", async () => {
    listFindings.mockResolvedValue([
      {
        ...HALLAZGO,
        finding_kind: "descarte",
        alcance_examinado:
          "Se recorrió la super-timeline con tsk_mactime. Limite: sin ficheros borrados.",
      },
    ]);
    await abrirElHallazgo();

    const alcance = await screen.findByTestId("alcance");
    expect(alcance.textContent).toContain("tsk_mactime");
    expect(alcance.textContent).toContain("Limite");
  });
});
