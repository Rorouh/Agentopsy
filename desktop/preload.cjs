"use strict";

const { contextBridge, ipcRenderer } = require("electron");

// The session token lives ONLY in the main process. The renderer asks main to proxy
// calls to the sidecar; it never receives the token (THREAT_MODEL gate 12).
contextBridge.exposeInMainWorld("forensia", {
  connection: () => ipcRenderer.invoke("forensia:connection"),
  health: () => ipcRenderer.invoke("forensia:health"),
  capabilities: () => ipcRenderer.invoke("forensia:capabilities"),
  agents: () => ipcRenderer.invoke("forensia:agents"),
  query: (req) => ipcRenderer.invoke("forensia:query", req),
  cases: {
    create: (body) => ipcRenderer.invoke("forensia:cases-create", body),
    list: () => ipcRenderer.invoke("forensia:cases-list"),
    get: (caseId) => ipcRenderer.invoke("forensia:cases-get", caseId),
    close: (caseId) => ipcRenderer.invoke("forensia:cases-close", caseId),
    registerEvidence: (caseId, source_path) =>
      ipcRenderer.invoke("forensia:cases-register-evidence", { caseId, source_path }),
    listEvidence: (caseId) => ipcRenderer.invoke("forensia:cases-list-evidence", caseId),
    verifyEvidence: (caseId, evidenceId) =>
      ipcRenderer.invoke("forensia:cases-verify-evidence", { caseId, evidenceId }),
    pickEvidenceFile: () => ipcRenderer.invoke("forensia:pick-evidence-file"),
  },
});
