"""Generación del informe forense estructurado a partir de la sesión.

[proceed-to-report] del documento: el modelo redacta un informe en Markdown con
los hallazgos recopilados (herramientas usadas, salidas y su interpretación). Se
guarda en el HOST, bajo la carpeta de casos (./projects por defecto).
"""
from __future__ import annotations

import datetime as _dt
import os
import re

_REPORT_INSTRUCTION = """A partir EXCLUSIVAMENTE de los resultados de las herramientas y el análisis de
esta sesión, redacta un INFORME FORENSE en Markdown con estas secciones:

1. Resumen ejecutivo
2. Evidencia analizada y cadena de custodia (rutas /evidence, hashes si se calcularon)
3. Hallazgos (cada uno con: herramienta y comando usados, dato observado y su
   significado forense)
4. Línea temporal (si hay datos para ello)
5. Conclusiones
6. Recomendaciones / próximos pasos

No inventes datos que no aparezcan en la sesión. Sé preciso y objetivo.
Devuelve solo el Markdown del informe."""


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", text).strip("-")[:40] or "caso"


def write_report(cfg, agent: str, model_label: str, case: str,
                 markdown: str, fmt: str = "md") -> str:
    """Escribe el informe (Markdown, y PDF opcional) en el host y devuelve la ruta."""
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(cfg.cases_host, _slug(case))
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, f"informe_{ts}.md")
    header = (f"# Informe forense FORENSIA\n\n"
              f"- Agente: **{agent}**\n"
              f"- Modelo: **{model_label}**\n"
              f"- Fecha: {ts}\n\n---\n\n")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(header + markdown + "\n")
    if fmt == "pdf":
        pdf_path = _to_pdf(md_path, header + markdown)
        if pdf_path:
            return pdf_path
    return md_path


def generate_report(orch, case: str, fmt: str = "md") -> str:
    """Genera el informe a partir de una sesión con proveedor 'clásico' (providers.py)."""
    if orch.provider is not None:
        # Pedimos el informe SIN herramientas (solo redacción sobre lo ya hecho).
        convo = list(orch.transcript) + [{"role": "user", "content": _REPORT_INSTRUCTION}]
        turn = orch.provider.generate(convo, tools=[])
        markdown = turn.text or "(El modelo no devolvió contenido para el informe.)"
        model_label = f"{getattr(orch.provider, 'model', 'n/d')} ({orch.cfg.provider})"
    else:
        markdown = _fallback_report(orch)
        model_label = "sin modelo"
    return write_report(orch.cfg, orch.agent, model_label, case, markdown, fmt)


def _fallback_report(orch) -> str:
    """Informe básico (volcado de la sesión) cuando no hay modelo configurado."""
    lines = ["## Transcripción de la sesión (sin modelo)\n"]
    for e in orch.transcript:
        if e["role"] == "system":
            continue
        if e["role"] == "user":
            lines.append(f"**Prompt:** {e['content']}\n")
        elif e["role"] == "assistant" and e.get("content"):
            lines.append(f"**Análisis:** {e['content']}\n")
        elif e["role"] == "tool":
            lines.append(f"```\n{e['content'][:3000]}\n```\n")
    return "\n".join(lines)


def _to_pdf(md_path: str, markdown_text: str):
    """Convierte a PDF si están disponibles `markdown` y `weasyprint` (opcional)."""
    try:
        import markdown as _md
        from weasyprint import HTML
    except Exception:
        return None
    html = _md.markdown(markdown_text, extensions=["tables", "fenced_code"])
    pdf_path = os.path.splitext(md_path)[0] + ".pdf"
    HTML(string=f"<meta charset='utf-8'>{html}").write_pdf(pdf_path)
    return pdf_path
