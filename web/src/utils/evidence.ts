// Conocimiento compartido sobre ficheros de evidencia, en UN solo sitio.
// Fuente de los formatos: backend/forensia/toolkit/catalog.py y forensia/triage.py.

import type { EvidenceHandle } from "../api/types";

export const SUPPORTED_EXTENSIONS = [
  ".raw",
  ".dd",
  ".img",
  ".vmdk",
  ".vmem",
  ".E01",
  ".e01",
  ".aff",
  ".vhd",
  ".mem",
  ".lime",
  ".dmp",
];

export function fileExtension(name: string): string {
  const idx = name.lastIndexOf(".");
  // idx <= 0 cubre "sin punto" y dotfiles (".bashrc" no tiene extensión).
  return idx <= 0 ? "" : name.slice(idx);
}

// ── Segmentos EWF ────────────────────────────────────────────────────────────
// Un EWF puede venir partido en N ficheros: `.E01`, `.E02` … `.E99` (y el
// esquema EWF2 `.Ex01`, `.Ex02` …). libewf reensambla la imagen desde el
// PRIMERO descubriendo a sus hermanos co-localizados, así que:
//   - la bandeja necesita TODOS los segmentos (todos son subibles), y
//   - solo el PRIMERO es registrable (registrarlo ingiere el set completo).
// La continuación ALFA (`.EAA` …, del segmento 100 en adelante) se deja fuera a
// propósito: suelta no se distingue de una extensión corriente (.exe, .eml…).
// Un set de >99 segmentos se deposita copiándolo a ./evidence en el host.
// Espejo de backend/forensia/evidence.py (_EWF_FIRST_RE / _is_ewf_numeric_segment,
// is_uploadable_evidence_ext / is_registrable_evidence_ext), que re-valida siempre.
const EWF_FIRST_RE = /^\.(ex?)01$/i;
const EWF_NUMERIC_RE = /^\.(ex?)(\d{2})$/i;

// Un segmento EWF numerado (primero o continuación). `.E00` no es un segmento.
export function isEwfSegment(name: string): boolean {
  const match = EWF_NUMERIC_RE.exec(fileExtension(name));
  return match !== null && Number(match[2]) >= 1;
}

// Primer segmento: `.E01` / `.Ex01` — el punto de entrada del set.
export function isEwfFirstSegment(name: string): boolean {
  return EWF_FIRST_RE.test(fileExtension(name));
}

// Continuación (`.E02` …): vive en la bandeja pero NO se registra por sí sola.
export function isEwfContinuationSegment(name: string): boolean {
  return isEwfSegment(name) && !isEwfFirstSegment(name);
}

// Validación client-side de la bandeja: el backend re-valida siempre (RULE 2).
// SUBIR admite cualquier segmento EWF además de los formatos single-file, para
// poder depositar el CONJUNTO de un EWF segmentado desde el navegador.
export function isSupportedEvidence(name: string): boolean {
  const ext = fileExtension(name).toLowerCase();
  if (!ext) return false;
  return SUPPORTED_EXTENSIONS.some((s) => s.toLowerCase() === ext);
}

export function isUploadableEvidence(name: string): boolean {
  return isSupportedEvidence(name) || isEwfSegment(name);
}

// REGISTRAR solo es posible sobre un formato single-file soportado o el PRIMER
// segmento de un EWF (el backend ingiere el set entero a partir de él).
export function isRegistrableEvidence(name: string): boolean {
  return isSupportedEvidence(name) || isEwfFirstSegment(name);
}

// Extensiones que ofrece el diálogo «Examinar…». Además de los formatos
// single-file, las continuaciones numéricas `.E02` … `.E99`: sin ellas el
// selector nativo no dejaría elegir los segmentos de un EWF partido.
export const FILE_INPUT_ACCEPT_EXTENSIONS = Array.from(
  new Set([
    ...SUPPORTED_EXTENSIONS,
    ...Array.from({ length: 99 }, (_, i) => `.E${String(i + 1).padStart(2, "0")}`),
  ]),
);

// Etiquetas de la clasificación de triage (detected_kind) para la tabla de
// evidencias. El valor lo computa el backend DESPUÉS de registrar.
export const DETECTED_KIND_LABEL: Record<EvidenceHandle["detected_kind"], string> = {
  disk: "Imagen de disco",
  memory: "Volcado de memoria",
  container_disk: "Disco VM",
  unknown: "Desconocido",
};
