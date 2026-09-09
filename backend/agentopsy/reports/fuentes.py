"""El SNAPSHOT de procedencia de un informe: su forma, su digest y su contrato.

Un informe no se sostiene en «lo que el caso tenga hoy». Se sostiene en lo que
había cuando se redactó: estas evidencias con estos hashes, estas ejecuciones con
estos artefactos, estas revisiones de hallazgo con estos localizadores. Ese
conjunto es el manifiesto de fuentes (``Document.fuentes``), y este módulo define
qué forma tiene, cómo se resume en un digest y qué bloques del contenido están
obligados a citarlo.

**Por qué el digest.** Hasta 2026-09-09 el hash del documento se calculaba sobre
el contenido EXCLUYENDO las fuentes, así que sustituir el manifiesto entero por
``{"case_id": "..."}`` dejaba el texto intacto, el hash válido y el informe
aprobable: se le había retirado el respaldo sin que nada lo notase, porque la
comprobación recorría únicamente las fuentes que el propio objeto declaraba, y
ese objeto ya no declaraba ninguna (reauditoría 2026-09-08, RA01).

Ahora el manifiesto tiene su propio digest canónico y versionado
(``digest_de_fuentes``), ese digest entra en el contenido canónico del documento
(``reports.store._canonical_content``, esquema 3) y viaja al audit encadenado con
el ``document_created``. Los tres tienen que casar: el manifiesto con su digest,
el digest con el hash del documento y el hash del documento con su ancla. Quitar,
sustituir o vaciar el manifiesto rompe la primera; recalcular el digest en local
rompe la segunda; recalcular también el hash del documento rompe la tercera, y
repararla exige reescribir la cadena entera, que es el límite externo declarado y
no una comprobación que se haya olvidado.

**Compatibilidad.** Un documento de esquema anterior no tiene digest de
procedencia y NO se le recalcula uno: se lee y se exporta como borrador, y la
comprobación de aprobación dice exactamente eso. Fabricarle un digest hoy sería
firmar que se comprobó algo que nunca se comprobó.

Lógica pura (RULE 3): solo datos y funciones deterministas. Sin I/O, sin red.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

#: Versión del esquema del SNAPSHOT. Sube cuando cambia lo que el digest cubre,
#: para que un manifiesto antiguo no se compare contra una forma que no tenía.
#: Va DENTRO del digest: dos manifiestos idénticos de esquemas distintos no
#: pueden dar el mismo resumen.
PROCEDENCIA_SCHEMA = 1

#: La versión de esquema de DOCUMENTO a partir de la cual el hash del documento
#: cubre su manifiesto y el audit lo ancla. Por debajo de ella un documento se
#: lee y se exporta como borrador, y su procedencia no se puede volver a
#: comprobar porque nunca quedó anclada. Se nombra aquí, junto al digest, para
#: que la comprobación de aprobación no tenga que conocer el almacén.
ESQUEMA_DOCUMENTO_ANCLADO = 3

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

#: Tope de citas por bloque. Un bloque con cincuenta hallazgos detrás no está
#: mejor respaldado, está sin redactar.
MAX_REFS_POR_BLOQUE = 12


def _texto(valor: Any) -> str:
    return str(valor or "").strip()


# -- referencias del CONTENIDO -------------------------------------------------


def refs_de_bloque(bloque: Any) -> list[dict[str, Any]]:
    """Las citas estructuradas que un bloque declara, normalizadas.

    Una cita del contenido nombra una REVISIÓN concreta de un hallazgo
    (``{"finding_id": ..., "revision": n}``), no «el hallazgo». Es lo que
    convierte una conclusión en algo que se puede abrir: conclusión, hallazgo y
    revisión, y de ahí a la ejecución, el artefacto y el localizador que ya viven
    en la propia revisión.

    Devuelve ``[]`` cuando el bloque no cita nada. Distinguir «no cita» de «cita
    mal» es cosa de :func:`validar_refs`, que es la que levanta.
    """
    if not isinstance(bloque, dict):
        return []
    crudas = bloque.get("refs")
    if not isinstance(crudas, list):
        return []
    salida: list[dict[str, Any]] = []
    for ref in crudas:
        if not isinstance(ref, dict):
            continue
        fid = _texto(ref.get("finding_id"))
        if not fid:
            continue
        try:
            revision = int(ref.get("revision") or 1)
        except (TypeError, ValueError):
            revision = 0
        salida.append({"finding_id": fid, "revision": revision})
    return salida


def validar_refs(bloque: Any, *, num: str) -> list[dict[str, Any]]:
    """Valida la FORMA de las citas de un bloque y las devuelve normalizadas.

    Levanta ``ValueError`` con el motivo exacto: un ``finding_id`` que no es un
    UUID4 o una revisión que no es un entero positivo no son una cita, y
    aceptarlos dejaría que la comprobación de aprobación fallase más tarde por
    algo que se podía ver aquí.
    """
    if not isinstance(bloque, dict) or bloque.get("refs") is None:
        return []
    crudas = bloque.get("refs")
    if not isinstance(crudas, list) or not crudas:
        raise ValueError(f"apartado {num}: `refs` tiene que ser una lista no vacía")
    if len(crudas) > MAX_REFS_POR_BLOQUE:
        raise ValueError(
            f"apartado {num}: un bloque cita {len(crudas)} revisiones de hallazgo; "
            f"el máximo es {MAX_REFS_POR_BLOQUE}"
        )
    salida: list[dict[str, Any]] = []
    for ref in crudas:
        if not isinstance(ref, dict):
            raise ValueError(f"apartado {num}: una cita de `refs` no es un objeto")
        fid = _texto(ref.get("finding_id"))
        if not _UUID4_RE.match(fid):
            raise ValueError(
                f"apartado {num}: `finding_id` {fid!r} no es un identificador de "
                f"hallazgo (UUID4)"
            )
        bruto = ref.get("revision", 1)
        if isinstance(bruto, bool) or not isinstance(bruto, int) or bruto < 1:
            raise ValueError(
                f"apartado {num}: la revisión citada de {fid} es {bruto!r}; tiene "
                f"que ser un entero desde 1"
            )
        salida.append({"finding_id": fid, "revision": bruto})
    return salida


def limitacion_de_bloque(bloque: Any) -> str:
    """El CÓDIGO de limitación que un bloque declara, o cadena vacía.

    Una limitación obligatoria no se comprueba leyendo prosa: se declara con un
    código, y la comprobación de aprobación cruza los códigos declarados con los
    exigidos por el material. Sin esto, «el apartado 9 tiene texto» valía como
    «el informe declara sus limitaciones», que es lo que permitía aprobar un
    informe que se callaba una ejecución fallida.
    """
    if not isinstance(bloque, dict):
        return ""
    return _texto(bloque.get("limitacion"))[:120]


def citas_del_contenido(sections: Any) -> list[dict[str, Any]]:
    """TODAS las citas declaradas por los bloques del documento, con su apartado."""
    salida: list[dict[str, Any]] = []
    for sec in sections or []:
        if not isinstance(sec, dict):
            continue
        num = _texto(sec.get("num"))
        for indice, bloque in enumerate(sec.get("blocks") or []):
            for ref in refs_de_bloque(bloque):
                salida.append({**ref, "num": num, "bloque": indice})
    return salida


def limitaciones_declaradas(sections: Any) -> set[str]:
    """Los códigos de limitación que el documento declara, en cualquier apartado."""
    codigos: set[str] = set()
    for sec in sections or []:
        if not isinstance(sec, dict):
            continue
        for bloque in sec.get("blocks") or []:
            codigo = limitacion_de_bloque(bloque)
            if codigo:
                codigos.add(codigo)
    return codigos


# -- el manifiesto -------------------------------------------------------------


def _artefacto_canonico(ref: Any) -> dict[str, Any]:
    if not isinstance(ref, dict):
        return {}
    localizadores = ref.get("localizadores")
    return {
        "run_id": _texto(ref.get("run_id")),
        "referencia": _texto(ref.get("referencia")) or "stdout",
        "sha256": _texto(ref.get("sha256")),
        "tool_id": _texto(ref.get("tool_id")),
        "evidence_id": _texto(ref.get("evidence_id")),
        # Los localizadores CITADOS sobre ese artefacto. Entran en el digest
        # porque forman parte de lo que el informe dice haber leído: cambiar un
        # rango cambia lo que se afirma, aunque el fichero sea el mismo.
        "localizadores": sorted(
            json.dumps(loc, sort_keys=True, ensure_ascii=False, default=str)
            for loc in (localizadores or [])
            if isinstance(loc, dict)
        ),
    }


def normalizar(fuentes: Any) -> dict[str, Any]:
    """La forma CANÓNICA del manifiesto: mismo contenido, mismo resultado.

    Ordena lo que es un conjunto (evidencias, artefactos, hallazgos, códigos de
    limitación) y fija el tipo de cada campo, para que el digest no dependa del
    orden en que se construyó el manifiesto ni de si un entero llegó como cadena.
    """
    if not isinstance(fuentes, dict):
        fuentes = {}
    evidencias = sorted({_texto(e) for e in (fuentes.get("evidencias") or []) if _texto(e)})
    evidencias_sha = {
        _texto(k): _texto(v)
        for k, v in (fuentes.get("evidencias_sha256") or {}).items()
        if _texto(k)
    }
    artefactos = [
        _artefacto_canonico(a)
        for a in (fuentes.get("artefactos") or [])
        if isinstance(a, dict)
    ]
    artefactos = sorted(
        (a for a in artefactos if a),
        key=lambda a: (a["run_id"], a["referencia"]),
    )
    hallazgos = []
    for h in fuentes.get("hallazgos") or []:
        if not isinstance(h, dict):
            continue
        try:
            revision = int(h.get("revision") or 1)
        except (TypeError, ValueError):
            revision = 0
        hallazgos.append(
            {
                "finding_id": _texto(h.get("finding_id")),
                "revision": revision,
                "content_sha256": _texto(h.get("content_sha256")),
                "procedencia": _texto(h.get("procedencia")) or "no_verificada",
            }
        )
    hallazgos = sorted(hallazgos, key=lambda h: (h["finding_id"], h["revision"]))
    return {
        "schema": PROCEDENCIA_SCHEMA,
        "case_id": _texto(fuentes.get("case_id")),
        "evidencias": evidencias,
        "evidencias_sha256": {k: evidencias_sha[k] for k in sorted(evidencias_sha)},
        "artefactos": artefactos,
        "hallazgos": hallazgos,
        "limitaciones_exigidas": sorted(
            {_texto(x) for x in (fuentes.get("limitaciones_exigidas") or []) if _texto(x)}
        ),
        "cadena_entry_hash": _texto(fuentes.get("cadena_entry_hash")),
    }


def digest_de_fuentes(fuentes: Any) -> str:
    """SHA-256 del manifiesto canónico. Determinista y estable.

    Es lo que ata el snapshot al documento: entra en el contenido canónico de un
    documento de esquema 3, así que el hash del documento CUBRE sus fuentes.
    Retirarlas, sustituirlas o vaciarlas cambia este digest y, con él, el hash
    del documento, que ya no casa con su ancla auditada.
    """
    payload = json.dumps(
        normalizar(fuentes),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def validar_manifiesto(fuentes: Any, *, case_id: str) -> list[str]:
    """Los problemas ESTRUCTURALES del manifiesto, como claves de mensaje.

    Comprueba que sea lo que dice ser, no solo que sea un objeto no vacío: un
    ``{"case_id": "..."}`` pasaba la comprobación anterior y no declaraba una
    sola fuente. Devuelve la lista de motivos (vacía si está bien) en vez de
    levantar, porque la comprobación de aprobación los acumula todos.

    No comprueba que las fuentes EXISTAN ni que estén íntegras: eso es
    ``agentopsy.reports.aprobacion``, que las abre. Aquí solo se mira la forma.
    """
    problemas: list[str] = []
    if not isinstance(fuentes, dict) or not fuentes:
        return ["approval.manifestNotAnObject"]

    declarado = _texto(fuentes.get("case_id"))
    if not declarado:
        problemas.append("approval.manifestNoCase")
    elif declarado != case_id:
        problemas.append("approval.manifestForeignCase")

    for clave in ("evidencias", "artefactos", "hallazgos", "limitaciones_exigidas"):
        if clave in fuentes and not isinstance(fuentes[clave], list):
            problemas.append("approval.manifestBadShape")
            break
    if "evidencias_sha256" in fuentes and not isinstance(
        fuentes.get("evidencias_sha256"), dict
    ):
        problemas.append("approval.manifestBadShape")

    # Un informe se sostiene en HALLAZGOS: sin uno solo no hay peritaje que
    # aprobar, y un manifiesto que no declara ninguno no es un manifiesto
    # incompleto, es un manifiesto vaciado.
    hallazgos = fuentes.get("hallazgos")
    if not isinstance(hallazgos, list) or not hallazgos:
        problemas.append("approval.manifestNoFindings")
    else:
        for h in hallazgos:
            if not isinstance(h, dict):
                problemas.append("approval.manifestBadFinding")
                break
            if not _UUID4_RE.match(_texto(h.get("finding_id"))):
                problemas.append("approval.manifestBadFinding")
                break
            revision = h.get("revision")
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                problemas.append("approval.manifestBadFinding")
                break
            if not _SHA256_RE.match(_texto(h.get("content_sha256"))):
                problemas.append("approval.manifestBadFinding")
                break

    for a in fuentes.get("artefactos") or []:
        if not isinstance(a, dict) or not _UUID4_RE.match(_texto(a.get("run_id"))):
            problemas.append("approval.manifestBadArtifact")
            break

    for ev in fuentes.get("evidencias") or []:
        if not _UUID4_RE.match(_texto(ev)):
            problemas.append("approval.manifestBadEvidence")
            break

    return problemas


__all__ = [
    "ESQUEMA_DOCUMENTO_ANCLADO",
    "MAX_REFS_POR_BLOQUE",
    "PROCEDENCIA_SCHEMA",
    "citas_del_contenido",
    "digest_de_fuentes",
    "limitacion_de_bloque",
    "limitaciones_declaradas",
    "normalizar",
    "refs_de_bloque",
    "validar_manifiesto",
    "validar_refs",
]
