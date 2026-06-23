"use strict";

const { contextBridge, ipcRenderer } = require("electron");

// The session token lives ONLY in the main process. The renderer asks main to proxy
// calls to the sidecar; it never receives the token (THREAT_MODEL gate 12).
contextBridge.exposeInMainWorld("forensia", {
  connection: () => ipcRenderer.invoke("forensia:connection"),
  health: () => ipcRenderer.invoke("forensia:health"),
  capabilities: () => ipcRenderer.invoke("forensia:capabilities"),
  query: (req) => ipcRenderer.invoke("forensia:query", req),
});
