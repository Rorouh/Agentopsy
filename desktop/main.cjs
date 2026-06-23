"use strict";

const { app, BrowserWindow, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");
const process = require("node:process");

let sidecar = null;
let connection = null;

function sidecarCommand() {
  if (app.isPackaged) {
    const dir = path.join(process.resourcesPath, "forensia-sidecar");
    const bin = process.platform === "win32" ? "forensia-sidecar.exe" : "forensia-sidecar";
    return { cmd: path.join(dir, bin), args: [], cwd: dir };
  }
  const backend = path.join(__dirname, "..", "backend");
  const py =
    process.platform === "win32"
      ? path.join(backend, ".venv", "Scripts", "python.exe")
      : path.join(backend, ".venv", "bin", "python");
  return { cmd: py, args: ["-m", "forensia.server"], cwd: backend };
}

function startSidecar() {
  return new Promise((resolve, reject) => {
    const { cmd, args, cwd } = sidecarCommand();
    sidecar = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });

    let buffer = "";
    const timer = setTimeout(() => reject(new Error("sidecar startup timeout")), 20000);

    sidecar.stdout.on("data", (chunk) => {
      buffer += chunk.toString();
      const line = buffer.split("\n").find((l) => l.startsWith("FORENSIA_SIDECAR_READY "));
      if (line) {
        clearTimeout(timer);
        resolve(JSON.parse(line.slice("FORENSIA_SIDECAR_READY ".length)));
      }
    });
    sidecar.stderr.on("data", (d) => console.error("[sidecar]", d.toString().trim()));
    sidecar.on("exit", (code) => {
      if (!connection) reject(new Error(`sidecar exited early (${code})`));
    });
    sidecar.on("error", reject);
  });
}

function stopSidecar() {
  if (sidecar && !sidecar.killed) {
    sidecar.kill();
    sidecar = null;
  }
}

async function sidecarFetch(pathname) {
  const res = await fetch(connection.url + pathname, {
    headers: { "X-Forensia-Token": connection.token, Host: new URL(connection.url).host },
  });
  if (!res.ok) throw new Error(`${pathname} -> ${res.status}`);
  return res.json();
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  if (app.isPackaged) {
    win.loadFile(path.join(__dirname, "renderer", "dist", "index.html"));
  } else {
    win.loadURL(process.env.FORENSIA_RENDERER_URL || "http://localhost:5173");
  }
}

ipcMain.handle("forensia:connection", () => ({ url: connection.url }));
ipcMain.handle("forensia:health", () => sidecarFetch("/api/health"));
ipcMain.handle("forensia:capabilities", () => sidecarFetch("/api/capabilities"));

app.whenReady().then(async () => {
  try {
    connection = await startSidecar();
  } catch (err) {
    console.error("failed to start sidecar:", err);
    app.quit();
    return;
  }
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopSidecar();
  if (process.platform !== "darwin") app.quit();
});
app.on("quit", stopSidecar);
