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

// Validación client-side de la bandeja: solo se puede REGISTRAR una fuente
// cuya extensión esté soportada por el toolkit. El backend re-valida siempre.
export function isSupportedEvidence(name: string): boolean {
  const ext = fileExtension(name).toLowerCase();
  if (!ext) return false;
  return SUPPORTED_EXTENSIONS.some((s) => s.toLowerCase() === ext);
}

// Etiquetas de la clasificación de triage (detected_kind) para la tabla de
// evidencias. El valor lo computa el backend DESPUÉS de registrar.
export const DETECTED_KIND_LABEL: Record<EvidenceHandle["detected_kind"], string> = {
  disk: "Imagen de disco",
  memory: "Volcado de memoria",
  container_disk: "Disco VM",
  unknown: "Desconocido",
};
