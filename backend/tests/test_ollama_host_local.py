"""El Ollama del perito: el que corre en SU equipo, no el que levanta el compose.

El caso real: el examinador ya tiene un modelo grande servido en su máquina
(`ollama run qwen2.5:32b`), sobre su propia GPU y con los modelos que se ha
descargado. Quiere usar ESE. Escribe `http://localhost:11434` en Ajustes y espera
que Agentopsy hable con él. Antes de esta tanda había dos cosas que lo impedían, y
cada una es un test de aquí:

1. **Lo que guardaba en Ajustes no ganaba.** `config.get` leía primero el entorno,
   y el compose fija `OLLAMA_HOST=http://ollama:11434` en el servicio api. El
   valor del perito quedaba escrito en `config.json` sin efecto ninguno y sin
   decir nada, que es justo el silencio que RULE 2 existe para evitar: el único
   síntoma era un modelo que nunca se usaba. Ahora `config.json` va primero y
   `config.source` declara qué capa contestó.
2. **`localhost`, dentro del contenedor api, es el contenedor.** Ahí no escucha
   nadie. El nombre por el que se alcanza la máquina anfitriona lo declara el
   DESPLIEGUE en `AGENTOPSY_HOST_GATEWAY` (el compose pone `host.docker.internal`
   y el `extra_hosts` que lo resuelve también en Linux); sin esa declaración no
   se reescribe nada, porque Agentopsy no se inventa una pasarela (RULE 2).

La reescritura no es silenciosa, y eso también se fija aquí: viaja en el motivo
de indisponibilidad (con la pista que de verdad hace falta, que Ollama escuche
fuera de loopback) y en el evento de auditoría, que guarda la petición LITERAL y,
al lado, lo que escribió el perito (FORENSIC INVARIANT 4).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentopsy.config import config
from agentopsy.executors.ollama import HOST_GATEWAY_ENV, OllamaExecutor, resolve_host
from agentopsy.server import create_app

PORT = 50993


@pytest.fixture
def client() -> TestClient:
    app = create_app(PORT)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def sin_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutraliza el `config.json` y el entorno de la máquina de desarrollo."""
    for key in ("OLLAMA_HOST", "OLLAMA_MODEL", HOST_GATEWAY_ENV):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(config, "_data", {})


# ---- resolución de la URL ----------------------------------------------------


def test_sin_pasarela_declarada_la_url_viaja_intacta(sin_config: None) -> None:
    """Ejecución standalone: no hay frontera de contenedor que cruzar."""
    resuelto = resolve_host("http://localhost:11434")
    assert resuelto.effective == "http://localhost:11434"
    assert resuelto.rewritten is False


def test_el_servicio_del_compose_nunca_se_reescribe(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ollama` es un nombre de la red interna, no loopback: se deja como está."""
    monkeypatch.setenv(HOST_GATEWAY_ENV, "host.docker.internal")
    resuelto = resolve_host("http://ollama:11434")
    assert resuelto.effective == "http://ollama:11434"
    assert resuelto.rewritten is False


@pytest.mark.parametrize(
    "escrito",
    ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"],
)
def test_loopback_se_resuelve_a_la_maquina_del_perito(
    sin_config: None, monkeypatch: pytest.MonkeyPatch, escrito: str
) -> None:
    monkeypatch.setenv(HOST_GATEWAY_ENV, "host.docker.internal")
    resuelto = resolve_host(escrito)
    assert resuelto.effective == "http://host.docker.internal:11434"
    assert resuelto.configured == escrito
    assert resuelto.rewritten is True


def test_la_reescritura_solo_toca_el_nombre_de_maquina(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Esquema, puerto y ruta son del perito: se cambia el HOST y nada más."""
    monkeypatch.setenv(HOST_GATEWAY_ENV, "pasarela")
    resuelto = resolve_host("https://127.0.0.1:8443/ollama/")
    assert resuelto.effective == "https://pasarela:8443/ollama"


def test_un_host_remoto_no_se_toca(sin_config: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HOST_GATEWAY_ENV, "host.docker.internal")
    resuelto = resolve_host("http://192.168.1.40:11434")
    assert resuelto.rewritten is False


# ---- precedencia: Ajustes por delante del entorno del despliegue --------------


def test_ajustes_gana_sobre_la_variable_del_compose(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El bug de origen: el perito guardaba su host y el compose seguía ganando."""
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    monkeypatch.setattr(config, "_data", {"OLLAMA_HOST": "http://localhost:11434"})
    assert config.get("OLLAMA_HOST") == "http://localhost:11434"
    assert config.source("OLLAMA_HOST") == "config"


def test_sin_valor_guardado_contesta_la_linea_base_del_despliegue(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    assert config.get("OLLAMA_HOST") == "http://ollama:11434"
    assert config.source("OLLAMA_HOST") == "env"


def test_una_clave_que_nadie_fija_no_tiene_fuente(sin_config: None) -> None:
    assert config.get("OLLAMA_HOST") is None
    assert config.source("OLLAMA_HOST") is None


def test_api_config_declara_de_donde_sale_cada_valor(
    client: TestClient, sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La interfaz tiene que poder distinguir «lo puso el compose» de «lo puse yo»."""
    monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
    r = client.get("/api/config", headers={"X-Agentopsy-Token": client.app.state.token})
    assert r.status_code == 200
    clave = r.json()["keys"]["OLLAMA_HOST"]
    assert clave == {"set": True, "preview": "http://ollama:11434", "source": "env"}


# ---- lo que ve el perito cuando no responde ----------------------------------


def test_el_motivo_nombra_las_dos_urls_y_la_pista_que_hace_falta(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un Ollama del anfitrión atado a loopback no lo alcanza ningún contenedor,
    así que el motivo dice eso y no un «no responde» a secas."""
    # Puerto 1 en la pasarela: nada escucha, el sondeo falla rápido.
    monkeypatch.setenv(HOST_GATEWAY_ENV, "127.0.0.1")
    monkeypatch.setattr(config, "_data", {"OLLAMA_HOST": "http://localhost:1"})
    disponibilidad = OllamaExecutor().is_available()
    assert disponibilidad.available is False
    assert "http://localhost:1" in disponibilidad.reason      # lo que escribió
    assert "http://127.0.0.1:1" in disponibilidad.reason      # lo que se contactó
    assert "0.0.0.0" in disponibilidad.reason                 # cómo arreglarlo


def test_sin_reescritura_el_motivo_es_el_de_siempre(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "_data", {"OLLAMA_HOST": "http://127.0.0.1:1"})
    disponibilidad = OllamaExecutor().is_available()
    assert disponibilidad.available is False
    assert "http://127.0.0.1:1" in disponibilidad.reason
    assert "0.0.0.0" not in disponibilidad.reason


# ---- custodia: la petición literal, y lo que el perito escribió --------------


class _AuditFalso:
    def __init__(self) -> None:
        self.eventos: list[dict[str, Any]] = []

    def append(self, evento: dict[str, Any]) -> None:
        self.eventos.append(evento)


class _RespuestaFalsa:
    def __init__(self, cuerpo: str) -> None:
        self._cuerpo = cuerpo.encode("utf-8")

    def read(self) -> bytes:
        return self._cuerpo

    def __enter__(self) -> "_RespuestaFalsa":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False


def test_la_auditoria_guarda_la_peticion_literal_y_lo_que_escribio_el_perito(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(HOST_GATEWAY_ENV, "host.docker.internal")
    monkeypatch.setattr(config, "_data", {"OLLAMA_HOST": "http://localhost:11434"})

    pedidas: list[str] = []

    def _urlopen(req: Any, timeout: float | None = None) -> _RespuestaFalsa:  # noqa: ARG001
        pedidas.append(req.full_url)
        return _RespuestaFalsa(json.dumps({"response": "ok"}))

    monkeypatch.setattr("agentopsy.executors.ollama.urllib.request.urlopen", _urlopen)

    audit = _AuditFalso()
    resultado = OllamaExecutor().run(
        "hola", {"model": "qwen2.5:32b", "audit": audit, "case_id": "CASO-1"}
    )
    assert resultado.text == "ok"
    # La petición sale hacia la máquina del perito, no hacia el contenedor.
    assert pedidas == ["http://host.docker.internal:11434/api/generate"]
    inicio = audit.eventos[0]
    assert inicio["http"]["url"] == "http://host.docker.internal:11434/api/generate"
    assert inicio["http"]["configured_host"] == "http://localhost:11434"


def test_sin_reescritura_la_auditoria_no_inventa_un_host_configurado(
    sin_config: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "_data", {"OLLAMA_HOST": "http://ollama:11434"})

    def _urlopen(req: Any, timeout: float | None = None) -> _RespuestaFalsa:  # noqa: ARG001
        return _RespuestaFalsa(json.dumps({"response": "ok"}))

    monkeypatch.setattr("agentopsy.executors.ollama.urllib.request.urlopen", _urlopen)

    audit = _AuditFalso()
    OllamaExecutor().run("hola", {"model": "llama3.1:8b", "audit": audit})
    assert audit.eventos[0]["http"] == {
        "url": "http://ollama:11434/api/generate",
        "model": "llama3.1:8b",
    }
