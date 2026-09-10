#!/usr/bin/env node
const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const exe = process.platform === "win32" ? "skill-doctor.exe" : "skill-doctor";
const candidates = [
  path.join(__dirname, exe),
  path.join(__dirname, "..", "target", "release", exe),
  path.join(__dirname, "..", "bin", exe)
];

const binaryPath = candidates.find((p) => fs.existsSync(p));

if (!binaryPath) {
  console.error("skill-doctor: binary not found. Please compile with `cargo build --release` or run `npm install`.");
  process.exit(1);
}

const res = spawnSync(binaryPath, process.argv.slice(2), { stdio: "inherit" });
process.exit(res.status ?? 0);
