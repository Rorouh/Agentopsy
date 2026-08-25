import type { GraphEdgeType, GraphNodeType } from "../../api/types";
import type { MessageKey } from "../../i18n/en";

// Las etiquetas y los colores del grafo, en UNA tabla.
//
// Misma regla que `forensia/timeline/vocabulario.py`: un valor que no esté en la
// tabla sale TAL CUAL, nunca traducido a lo que se le parezca. Si el backend
// gana un tipo y esta tabla no se entera, la figura enseña el `snake_case`
// literal, que es feo y verdadero, en vez de una etiqueta inventada (RULE 2).
//
// Los `snake_case` son DATOS (la enum cerrada que valida el servidor), así que
// se enseñan tal cual donde hace falta citarlos; el ROTULO de cada uno vive en
// el catálogo de idiomas, porque lo lee una persona en la leyenda y la ficha.
//
// La tabla es de CLAVES, no de texto, y las dos funciones devuelven `null` para
// un tipo que no esté declarado: quien pinta lo interpreta como «enseña el valor
// crudo». Es la misma regla de siempre y ahora es del TIPO: no hay forma de
// devolver una etiqueta inventada.

export const NODO_KEY: Record<GraphNodeType, MessageKey> = {
  ip: "graphNode.ip",
  domain: "graphNode.domain",
  hostname: "graphNode.hostname",
  user: "graphNode.user",
  file: "graphNode.file",
};

export const RELACION_KEY: Record<GraphEdgeType, MessageKey> = {
  connection: "graphEdge.connection",
  process_spawn: "graphEdge.process_spawn",
  network_connection: "graphEdge.network_connection",
  lateral_move: "graphEdge.lateral_move",
  malware: "graphEdge.malware",
  c2: "graphEdge.c2",
  exfiltration: "graphEdge.exfiltration",
  beacon: "graphEdge.beacon",
  persistence: "graphEdge.persistence",
  priv_esc: "graphEdge.priv_esc",
  rce: "graphEdge.rce",
  logon: "graphEdge.logon",
  file_transfer: "graphEdge.file_transfer",
};

export function claveNodo(tipo: string): MessageKey | null {
  return NODO_KEY[tipo as GraphNodeType] ?? null;
}

export function claveRelacion(tipo: string): MessageKey | null {
  return RELACION_KEY[tipo as GraphEdgeType] ?? null;
}

// ── color ─────────────────────────────────────────────────────────────────────
//
// El color es SEMÁNTICO (dice de qué tipo es la entidad), así que se mantiene el
// esquema de la referencia y no se sustituye por el acento del rediseño. Lo que
// sí cambia es el tono en oscuro: los mismos colores sobre fondo oscuro pierden
// contraste, igual que le pasaba al botón de borrar un caso, así que cada tipo
// declara su par claro/oscuro.
//
// Van como LITERALES y no como `var(--token)` porque el SVG se serializa y se
// rasteriza FUERA del documento para exportarlo a PNG: allí una variable CSS no
// resuelve y el nodo saldría sin pintar.

type Par = { claro: string; oscuro: string };

const NODO_COLOR: Record<GraphNodeType, Par> = {
  ip: { claro: "#2f7d4f", oscuro: "#5cb47c" },
  domain: { claro: "#b26206", oscuro: "#e0913c" },
  hostname: { claro: "#0f7b8a", oscuro: "#4fb8c9" },
  user: { claro: "#6b4bab", oscuro: "#a98ce0" },
  file: { claro: "#4a4a52", oscuro: "#9a9aa6" },
};

const RELACION_COLOR: Record<GraphEdgeType, Par> = {
  connection: { claro: "#7a7a84", oscuro: "#9a9aa6" },
  process_spawn: { claro: "#6b4bab", oscuro: "#a98ce0" },
  network_connection: { claro: "#3d7fb8", oscuro: "#6fb0e0" },
  lateral_move: { claro: "#b26206", oscuro: "#e0913c" },
  malware: { claro: "#c4553f", oscuro: "#e08a75" },
  c2: { claro: "#a51f3d", oscuro: "#e06a86" },
  exfiltration: { claro: "#8c3a2b", oscuro: "#d4826f" },
  beacon: { claro: "#0f7b8a", oscuro: "#4fb8c9" },
  persistence: { claro: "#9a7a10", oscuro: "#d4b64a" },
  priv_esc: { claro: "#7d2b3f", oscuro: "#c47a8c" },
  rce: { claro: "#a51f3d", oscuro: "#e06a86" },
  logon: { claro: "#2f7d4f", oscuro: "#5cb47c" },
  file_transfer: { claro: "#3d7fb8", oscuro: "#6fb0e0" },
};

// Un tipo desconocido se pinta con el gris neutro: no se le inventa un color
// semántico que afirmaría algo sobre él.
const NEUTRO: Par = { claro: "#7a7a84", oscuro: "#9a9aa6" };

export function colorNodo(tipo: string, oscuro: boolean): string {
  const par = NODO_COLOR[tipo as GraphNodeType] ?? NEUTRO;
  return oscuro ? par.oscuro : par.claro;
}

export function colorRelacion(tipo: string, oscuro: boolean): string {
  const par = RELACION_COLOR[tipo as GraphEdgeType] ?? NEUTRO;
  return oscuro ? par.oscuro : par.claro;
}

// Orden de la leyenda: el mismo que la enum del backend, para que quien compare
// la figura con el contrato los lea en el mismo orden.
export const NODOS_LEYENDA: GraphNodeType[] = [
  "ip",
  "domain",
  "hostname",
  "user",
  "file",
];
