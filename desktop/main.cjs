"use strict";

const { app, BrowserWindow, ipcMain } = require("electron");
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
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

async function sidecarPost(pathname, body) {
  const res = await fetch(connection.url + pathname, {
    method: "POST",
    headers: {
      "X-Forensia-Token": connection.token,
      "Content-Type": "application/json",
      Host: new URL(connection.url).host,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${pathname} -> ${res.status}`);
  return res.json();
}

function imagesDir() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, "images");
  }
  return path.join(__dirname, "resources", "images");
}

function findOciRuntime() {
  const candidates = ["docker", "podman", "nerdctl"];
  for (const cmd of candidates) {
    try {
      const result = spawnSync(cmd, ["--version"], { stdio: "ignore" });
      if (result.status === 0) return cmd;
    } catch {
      // try next candidate
    }
  }
  return null;
}

function loadBundledImages() {
  const dir = imagesDir();
  if (!fs.existsSync(dir)) {
    console.log("[images] no bundled images directory; skipping");
    return;
  }

  const runtime = findOciRuntime();
  if (!runtime) {
    console.log(
      "[images] no OCI runtime; skipping (capabilities will report tools as unavailable)"
    );
    return;
  }

  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (err) {
    console.warn("[images] could not read images directory:", err.message);
    return;
  }

  const tarballs = entries.filter((name) => name.endsWith(".tar"));
  for (const file of tarballs) {
    const tarPath = path.join(dir, file);
    const base = file.slice(0, -".tar".length);
    const tag = `forensia/${base}:latest`;

    const inspect = spawnSync(runtime, ["image", "inspect", tag], { stdio: "ignore" });
    if (inspect.status === 0) {
      console.log(`[images] ${tag} already loaded`);
      continue;
    }

    const load = spawnSync(runtime, ["load", "-i", tarPath], { stdio: "inherit" });
    if (load.status !== 0) {
      console.warn(`[images] warning: failed to load ${tag} from ${tarPath} (exit ${load.status})`);
      continue;
    }
    console.log(`[images] loaded ${tag}`);
  }
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
ipcMain.handle("forensia:query", (event, req) => sidecarPost("/api/agent/query", req));

app.whenReady().then(async () => {
  try {
    connection = await startSidecar();
  } catch (err) {
    console.error("failed to start sidecar:", err);
    app.quit();
    return;
  }
  try {
    await loadBundledImages();
  } catch (err) {
    console.warn("[images] loadBundledImages failed:", err && err.message ? err.message : err);
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
