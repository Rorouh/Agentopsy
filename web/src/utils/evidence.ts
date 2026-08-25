// Conocimiento compartido sobre ficheros de evidencia, en UN solo sitio.
// Fuente de los formatos: backend/forensia/evidence.py, que RE-VALIDA siempre;
// lo de aquí sólo evita hacer subir un fichero que el backend va a rechazar.

import type { EvidenceHandle } from "../api/types";
import type { MessageKey } from "../i18n/en";

// ── Las dos familias de evidencia ────────────────────────────────────────────
// La distinción no es burocrática, cambia lo que Agentopsy hace después:
//
//   IMÁGENES Y VOLCADOS: un sistema entero capturado. Lo abren TSK /
//   Volatility / plaso y de su CONTENIDO se determina el perfil de SO del caso.
//
//   MATERIAL APORTADO: un fichero suelto que el perito recibe, el PDF de un
//   contrato, la foto que alguien envió, el CSV que exportó un sistema, el
//   .evtx que entregó el cliente, la muestra de malware. Entra por el MISMO
//   hash-gate y la misma cadena de custodia, se clasifica `kind=document` y
//   NUNCA fija el perfil del caso: un documento no es el sistema investigado.
//
// Espejo de _IMAGE_AND_DUMP_EXTENSIONS / SUPPORTED_MATERIAL_EXTENSIONS.
export const IMAGE_AND_DUMP_EXTENSIONS = [
  ".raw",
  ".dd",
  ".img",
  ".iso",
  ".vmdk",
  ".vdi",
  ".qcow",
  ".qcow2",
  ".vhd",
  ".vhdx",
  ".E01",
  ".Ex01",
  ".aff",
  ".aff4",
  ".s01",
  ".l01",
  ".vmem",
  ".mem",
  ".lime",
  ".dmp",
  ".core",
];

export const MATERIAL_EXTENSIONS = [
  // Documentos de texto y ofimática
  ".pdf", ".doc", ".docx", ".odt", ".rtf", ".pages",
  ".xls", ".xlsx", ".ods", ".csv", ".tsv",
  ".ppt", ".pptx", ".odp",
  // Texto plano, notas, exportaciones y configuración
  ".txt", ".md", ".log", ".json", ".xml", ".yaml", ".yml", ".ini", ".conf",
  ".html", ".htm",
  // Correo y mensajería
  ".eml", ".msg", ".mbox", ".pst", ".ost", ".vcf", ".ics",
  // Imagen fija
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp",
  ".heic", ".heif", ".svg",
  // Vídeo y audio
  ".mp4", ".mov", ".avi", ".mkv", ".webm", ".wmv",
  ".mp3", ".wav", ".m4a", ".ogg", ".flac", ".aac",
  // Empaquetados
  ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
  // Artefactos sueltos que un cliente entrega sin el disco entero
  ".evtx", ".evt", ".etl", ".reg", ".pf", ".lnk", ".jls", ".plist",
  ".sqlite", ".sqlite3", ".db", ".journal",
  // Capturas de red
  ".pcap", ".pcapng", ".cap", ".har",
  // Muestras y binarios bajo estudio
  ".exe", ".dll", ".sys", ".so", ".jar", ".apk", ".ps1", ".vbs", ".bat",
  ".sh", ".py", ".bin", ".dat",
];

export const SUPPORTED_EXTENSIONS = [...IMAGE_AND_DUMP_EXTENSIONS, ...MATERIAL_EXTENSIONS];

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
//   - registrar el PRIMERO ingiere el set completo, mientras que una
//     continuación suelta no puede ensamblar nada y el backend la rechaza.
// La continuación ALFA (`.EAA` …, del segmento 100 en adelante) NO se decide por
// el nombre: `.exe` es literalmente «e» + dos letras, o sea la misma forma, y
// tratarla como segmento haría irregistrable una muestra de malware. Dentro de
// un set anclado en su `.E01` sí se contempla, porque allí manda la numeración.
// Espejo de backend/forensia/evidence.py (_EWF_FIRST_RE / _is_ewf_numeric_segment,
// is_uploadable_evidence_ext / is_registrable_evidence_ext), que re-valida siempre.
const EWF_FIRST_RE = /^\.(ex?)01$/i;
const EWF_NUMERIC_RE = /^\.(ex?)(\d{2})$/i;

// Un segmento EWF numerado (primero o continuación). `.E00` no es un segmento.
export function isEwfSegment(name: string): boolean {
  const match = EWF_NUMERIC_RE.exec(fileExtension(name));
  return match !== null && Number(match[2]) >= 1;
}

// Primer segmento: `.E01` / `.Ex01`, el punto de entrada del set.
export function isEwfFirstSegment(name: string): boolean {
  return EWF_FIRST_RE.test(fileExtension(name));
}

// Continuación (`.E02` …): vive en la bandeja pero NO se registra por sí sola.
export function isEwfContinuationSegment(name: string): boolean {
  return isEwfSegment(name) && !isEwfFirstSegment(name);
}

// Validación client-side de la bandeja: el backend re-valida siempre (RULE 2).
export function isSupportedEvidence(name: string): boolean {
  const ext = fileExtension(name).toLowerCase();
  if (!ext) return false;
  return SUPPORTED_EXTENSIONS.some((s) => s.toLowerCase() === ext);
}

// SUBIR admite además cualquier segmento EWF numerado (para depositar el
// CONJUNTO de un EWF partido desde el navegador) y los ficheros SIN extensión,
// porque medio Unix no la usa: `syslog`, `authorized_keys`, `passwd` o
// `known_hosts` son artefactos de pleno derecho.
export function isUploadableEvidence(name: string): boolean {
  return isSupportedEvidence(name) || isEwfSegment(name) || fileExtension(name) === "";
}

// REGISTRAR es posible sobre CUALQUIER fichero de la bandeja menos una
// continuación EWF: quien decide si algo aporta al caso es el perito, no una
// lista de extensiones. Por eso la lista gobierna la SUBIDA (el camino de
// escritura acotado) y no el registro, que opera sobre un fichero que el
// operador ya ha puesto en ./evidence a conciencia.
export function isRegistrableEvidence(name: string): boolean {
  return !isEwfContinuationSegment(name);
}

// Extensiones que ofrece el diálogo «Examinar…». Además de los formatos
// declarados, las continuaciones numéricas `.E02` … `.E99`: sin ellas el
// selector nativo no dejaría elegir los segmentos de un EWF partido.
export const FILE_INPUT_ACCEPT_EXTENSIONS = Array.from(
  new Set([
    ...SUPPORTED_EXTENSIONS,
    ...Array.from({ length: 99 }, (_, i) => `.E${String(i + 1).padStart(2, "0")}`),
  ]),
);

// Clasificación de triage (detected_kind) para la tabla de evidencias. El VALOR
// lo computa el backend después de registrar (es un dato del caso, determinado
// por contenido); lo que hay aquí es sólo cómo se NOMBRA en cada idioma.
export const DETECTED_KIND_KEY: Record<EvidenceHandle["detected_kind"], MessageKey> = {
  disk: "kind.disk",
  memory: "kind.memory",
  container_disk: "kind.container_disk",
  document: "kind.document",
  unknown: "kind.unknown",
};
