#!/usr/bin/env node
// Copy a host-installed forensic binary into vendor/<tool>/<os>-<arch>/ (CLAUDE.md RULE 1).
// Build-machine helper: the build host installs the tool once (brew/apt/cargo); users get
// it from the bundle. Native-lib relocation (macOS dylibbundler, Linux patchelf) is a TODO
// flagged per tool — this does the straightforward single-binary copy.
//
//   node scripts/bundle-tool.mjs <binary-name> [--as <tool-id>]

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function platformKey() {
  const os = { darwin: "mac", win32: "win" }[process.platform] ?? process.platform;
  const arch = { x64: "x64", arm64: "arm64" }[process.arch] ?? process.arch;
  return `${os}-${arch}`;
}

function which(binary) {
  const cmd = process.platform === "win32" ? "where" : "which";
  try {
    return execFileSync(cmd, [binary], { encoding: "utf8" }).split("\n")[0].trim();
  } catch {
    return null;
  }
}

const binary = process.argv[2];
if (!binary) {
  console.error("usage: node scripts/bundle-tool.mjs <binary-name> [--as <tool-id>]");
  process.exit(1);
}
const asIndex = process.argv.indexOf("--as");
const toolId = asIndex !== -1 ? process.argv[asIndex + 1] : binary;

const src = which(binary);
if (!src) {
  console.error(`'${binary}' not found on PATH. Install it on this build machine first.`);
  process.exit(2);
}

const destDir = join(ROOT, "vendor", toolId, platformKey());
const dest = join(destDir, binary + (process.platform === "win32" ? ".exe" : ""));
mkdirSync(destDir, { recursive: true });
copyFileSync(src, dest);
console.log(`bundled ${binary} (${src}) -> ${dest}`);
console.log("TODO: relocate native libs if any (macOS dylibbundler / Linux patchelf).");
