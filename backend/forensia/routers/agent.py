from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from forensia.security import require_token

router = APIRouter()


class QueryRequest(BaseModel):
    os_profile: Optional[str] = "unix"
    evidence_id: Optional[str] = ""
    prompt: str


@router.post("/api/agent/query", dependencies=[Depends(require_token)])
def query(req: QueryRequest) -> dict:
    prompt = req.prompt.strip().lower()
    
    # Simple rule-based mock responder for testing capabilities
    if not prompt:
        reply = "Por favor, escribe un mensaje o pregunta."
    elif any(word in prompt for word in ("hola", "saludos", "buenos", "buenas")):
        reply = (
            "¡Hola! Soy **FORENSIA AI**, tu asistente inteligente para análisis forense post-mortem.\n\n"
            "Puedo ayudarte a examinar evidencias de disco (`.vmdk`/`.raw`), analizar volcados de memoria RAM, "
            "buscar palabras clave o reconstruir líneas temporales de incidentes de seguridad.\n\n"
            "Para comenzar, selecciona o carga una evidencia en el panel correspondiente."
        )
    elif any(word in prompt for word in ("herramienta", "tools", "toolkit", "maletín")):
        reply = (
            "Tengo a mi disposición un **maletín forense local** con herramientas integradas listas para usar:\n\n"
            "*   **Análisis de Archivos:** Sleuth Kit (`tsk_fls`, `tsk_icat`, `tsk_mmls`), `foremost`, `bulk_extractor`.\n"
            "*   **Volcados de RAM:** `volatility3` para reconstruir procesos, sockets y controladores cargados.\n"
            "*   **Sistemas de Archivos y Logs:** `plaso_log2timeline` y `plaso_psort` para generar líneas temporales completas.\n"
            "*   **Análisis de Windows:** `regripper` para registro, `hayabusa` y `chainsaw` para logs de eventos EVTX.\n\n"
            "Todas estas herramientas se ejecutan de manera local e integrada sin dependencias externas."
        )
    elif any(word in prompt for word in ("analizar", "evidencia", "image", "disco", "raw", "vmdk")):
        reply = (
            "Para **analizar una evidencia**, el proceso sigue estos estrictos pasos de rigor forense:\n\n"
            "1.  **Registro e Ingesta:** Se calcula el hash baseline (SHA-256) de la evidencia.\n"
            "2.  **Protección de Escritura:** Se expone un manejador de lectura a nivel de bloque (read-only).\n"
            "3.  **Ejecución de Capabilidades:** Los agentes de IA pueden invocar herramientas del maletín sobre este manejador.\n"
            "4.  **Generación de Reportes:** Se crea un reporte estructurado y una línea de tiempo con hash-chaining para auditoría.\n\n"
            "¿Tienes una ruta de imagen de disco o volcado para registrar?"
        )
    elif any(word in prompt for word in ("log", "auditoría", "custodia", "audit")):
        reply = (
            "El sistema mantiene un **registro de auditoría inmutable** encadenado por hash (cadena de custodia).\n\n"
            "Cada comando ejecutado por la IA registra el array exacto de argumentos ejecutados (`argv`), "
            "la versión de la herramienta utilizada, los hashes de los archivos de salida generados, "
            "así como el hash del estado anterior. Esto asegura que la evidencia no pueda ser alterada "
            "y que todo el proceso de análisis sea 100% reproducible ante un tribunal."
        )
    else:
        reply = (
            f"He recibido tu consulta: *\"{req.prompt}\"*\n\n"
            "En esta entrega del esqueleto de FORENSIA, el agente está simulando el procesamiento de tu solicitud.\n"
            "Una vez cargada una evidencia real, podré invocar herramientas específicas en base al "
            f"perfil de sistema operativo seleccionado (`{req.os_profile}`)."
        )
    
    return {
        "status": "success",
        "reply": reply,
        "evidence_id": req.evidence_id,
        "os_profile": req.os_profile,
    }

