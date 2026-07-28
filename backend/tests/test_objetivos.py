"""CP-A/B — La ruta del agente entra por OBJETIVO, no por tipo de evidencia.

El `playbook.md` se borró el 2026-07-28. Era una marcha numerada por tipo de
evidencia («1. contenedor, 2. particiones, 3. timeline completa, 4. $MFT…») y el
agente la seguía al pie de la letra: en la corrida #001, para responder «¿se
accedió a los documentos confidenciales?», ejecutó `mmls` → `fls` → `fls -m` →
`mactime`, que son literalmente los pasos 2 y 3. No estaba improvisando mal —
estaba obedeciendo.

Lo sustituye `objetivos:`, el método destilado a mano: *no se elige la
herramienta, se elige el ARTEFACTO que responde la pregunta, y el artefacto dice
la herramienta*.

Gates:
- El manifiesto valida los objetivos al CARGAR (una herramienta inexistente
  revienta el arranque del api, no un análisis a mitad).
- El índice viaja SIEMPRE en el system prompt y es compacto.
- El playbook es opcional y ya no existe en los paquetes reales.
- El `kind` del triage es INFORMATIVO: dice qué soporte es la evidencia, ya no
  ordena «salta a la sección A».
- Existe una fila para «acceso a documentos» que NO pasa por la timeline — el
  fallo concreto de la corrida #001.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from forensia.agent.agent import ForensicAgent
from forensia.agent.loader import AgentPackageError, load_package
from forensia.models.base import ModelBackend, ModelCapabilities

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTES_DIR = REPO_ROOT / "agentes"


class _Noop(ModelBackend):
    name = "fake"

    def capabilities(self) -> ModelCapabilities:
        return ModelCapabilities(
            supports_native_tools=False, json_mode=True, max_context=0, is_local=True
        )

    def next_action(self, state, tools):  # pragma: no cover
        raise AssertionError("no se usa")


def _prompt(pkg, detected_kind: str = "disk") -> str:
    agent = ForensicAgent(pkg, _Noop(), SimpleNamespace())
    return agent._system_prompt(
        "11111111-1111-4111-8111-111111111111",
        "original.raw",
        ("tsk_fls",),
        pkg.os_profile,
        detected_kind,
    )


# ── el playbook ya no está ──────────────────────────────────────────────────


@pytest.mark.parametrize("pkg_id", ["forensia-unix", "forensia-windows"])
def test_los_paquetes_reales_ya_no_traen_playbook(pkg_id) -> None:
    assert not (AGENTES_DIR / pkg_id / "prompts" / "playbook.md").exists()
    pkg = load_package(AGENTES_DIR / pkg_id)
    assert pkg.prompts.playbook == ""


def test_un_paquete_sin_playbook_carga(tmp_path) -> None:
    d = tmp_path / "pkg"
    (d / "prompts").mkdir(parents=True)
    (d / "policy").mkdir(parents=True)
    for n in ("system", "identity"):
        (d / "prompts" / f"{n}.md").write_text(f"# {n}\n", encoding="utf-8")
    (d / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["file_info"]}), encoding="utf-8"
    )
    (d / "policy" / "redaction.yaml").write_text(
        yaml.safe_dump({"patterns": []}), encoding="utf-8"
    )
    (d / "agent.yaml").write_text(
        yaml.safe_dump({
            "id": "p", "name": "P", "version": "0.1.0", "os_profile": "unix",
            "model": {"name": "m", "temperature": 0.1, "max_iterations": 4},
            "prompts": {"system": "prompts/system.md", "identity": "prompts/identity.md"},
            "policy": {"tools": "policy/tools.yaml", "redaction": "policy/redaction.yaml"},
        }),
        encoding="utf-8",
    )
    pkg = load_package(d)
    assert pkg.prompts.playbook == ""
    assert pkg.objetivos == ()


# ── validación del manifiesto ───────────────────────────────────────────────


def _pkg_con_objetivos(tmp_path, objetivos):
    d = tmp_path / "pkg"
    (d / "prompts").mkdir(parents=True)
    (d / "policy").mkdir(parents=True)
    for n in ("system", "identity"):
        (d / "prompts" / f"{n}.md").write_text("x", encoding="utf-8")
    (d / "policy" / "tools.yaml").write_text(
        yaml.safe_dump({"allowed": ["file_info"]}), encoding="utf-8"
    )
    (d / "policy" / "redaction.yaml").write_text(
        yaml.safe_dump({"patterns": []}), encoding="utf-8"
    )
    (d / "agent.yaml").write_text(
        yaml.safe_dump({
            "id": "p", "name": "P", "version": "0.1.0", "os_profile": "unix",
            "model": {"name": "m", "temperature": 0.1, "max_iterations": 4},
            "prompts": {"system": "prompts/system.md", "identity": "prompts/identity.md"},
            "policy": {"tools": "policy/tools.yaml", "redaction": "policy/redaction.yaml"},
            "objetivos": objetivos,
        }),
        encoding="utf-8",
    )
    return d


def test_una_herramienta_inexistente_revienta_al_cargar(tmp_path) -> None:
    """Fallar en la frontera correcta: al arrancar el api, no en mitad de un
    análisis con el perito esperando (RULE 2)."""
    with pytest.raises(AgentPackageError, match="no existe en el catálogo"):
        load_package(
            _pkg_con_objetivos(tmp_path, [{
                "id": "x", "pregunta": "¿?", "artefactos": "y",
                "herramientas": ["herramienta_inventada"],
            }])
        )


@pytest.mark.parametrize(
    "objetivo",
    [
        {"id": "x", "pregunta": "¿?", "artefactos": "y", "herramientas": []},
        {"id": "x", "pregunta": "¿?", "artefactos": "y"},
        {"id": "x", "pregunta": "¿?", "herramientas": ["file_info"]},
        {"id": "MAYUS", "pregunta": "¿?", "artefactos": "y", "herramientas": ["file_info"]},
    ],
)
def test_objetivo_mal_formado_falla(tmp_path, objetivo) -> None:
    with pytest.raises(AgentPackageError):
        load_package(_pkg_con_objetivos(tmp_path, [objetivo]))


def test_ids_duplicados_fallan(tmp_path) -> None:
    o = {"id": "x", "pregunta": "¿?", "artefactos": "y", "herramientas": ["file_info"]}
    with pytest.raises(AgentPackageError, match="duplicate"):
        load_package(_pkg_con_objetivos(tmp_path, [o, dict(o)]))


# ── los paquetes reales ─────────────────────────────────────────────────────


@pytest.mark.parametrize("pkg_id", ["forensia-unix", "forensia-windows"])
def test_los_paquetes_reales_declaran_su_ruta(pkg_id) -> None:
    pkg = load_package(AGENTES_DIR / pkg_id)
    assert len(pkg.objetivos) >= 8
    ids = {o.id for o in pkg.objetivos}
    # Sin objetivo de reconocimiento, un caso sin pregunta no tiene por dónde entrar.
    assert "reconocimiento" in ids
    # El huso horario es la precondición de cualquier cronología.
    assert "perfil-y-huso" in ids
    # Toda herramienta declarada está en la allowlist del propio paquete.
    permitidas = set(pkg.policy.allowed_tools)
    for o in pkg.objetivos:
        assert set(o.herramientas) <= permitidas, f"{o.id} usa tools fuera del allowlist"


def test_acceso_a_documentos_no_pasa_por_la_timeline() -> None:
    """El fallo concreto de la corrida #001: se fue a construir la super-timeline
    de un disco de 20 GB para fechar dos documentos. La ruta correcta es
    RecentDocs/LNK/JumpLists, y la timeline queda como objetivo aparte y caro."""
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    doc = next(o for o in pkg.objetivos if o.id == "acceso-a-documentos")
    assert "tsk_mactime" not in doc.herramientas
    assert "plaso_log2timeline" not in doc.herramientas
    assert "regripper" in doc.herramientas
    assert "lecmd" in doc.herramientas and "jlecmd" in doc.herramientas

    linea = next(o for o in pkg.objetivos if o.id == "linea-temporal")
    assert "caro" in linea.pregunta.lower()


# ── el prompt ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("pkg_id", ["forensia-unix", "forensia-windows"])
def test_el_indice_de_objetivos_viaja_en_el_prompt(pkg_id) -> None:
    pkg = load_package(AGENTES_DIR / pkg_id)
    prompt = _prompt(pkg)
    assert "Objetivo → artefacto → herramienta" in prompt
    assert "elige el artefacto" in prompt
    for o in pkg.objetivos:
        assert o.pregunta in prompt


def test_el_prompt_ya_no_manda_seguir_una_seccion_del_playbook() -> None:
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    for kind in ("disk", "container_disk", "memory", "unknown"):
        prompt = _prompt(pkg, kind)
        assert "Ruta del playbook" not in prompt
        assert "sección A" not in prompt
        assert "sección B" not in prompt


@pytest.mark.parametrize(
    "kind,esperado",
    [
        ("memory", "VOLCADO DE MEMORIA"),
        ("disk", "IMAGEN DE DISCO"),
        ("container_disk", "IMAGEN DE DISCO"),
    ],
)
def test_el_triage_informa_del_soporte_sin_ordenar_una_ruta(kind, esperado) -> None:
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    prompt = _prompt(pkg, kind)
    assert f"Soporte de la evidencia — {esperado}" in prompt


def test_un_kind_desconocido_no_recorta_nada() -> None:
    pkg = load_package(AGENTES_DIR / "forensia-windows")
    prompt = _prompt(pkg, "unknown")
    assert "Soporte de la evidencia" not in prompt
    # …pero la ruta por objetivo sigue estando entera.
    assert "Objetivo → artefacto → herramienta" in prompt
