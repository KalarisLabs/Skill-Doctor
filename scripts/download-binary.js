#!/usr/bin/env node
/**
 * scripts/download-binary.js
 * Thin installer: downloads official prebuilt skill-doctor binary for the host platform.
 * Pure Node.js (>= 18) built-ins only.
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const { execSync } = require("child_process");

const pkg = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")
);
const VERSION = pkg.version;
const REPO = "kalarislabs/skill-doctor";

function getTargetTriple() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === "linux") {
    if (arch === "x64") return "x86_64-unknown-linux-musl";
    if (arch === "arm64") return "aarch64-unknown-linux-musl";
  } else if (platform === "darwin") {
    if (arch === "x64") return "x86_64-apple-darwin";
    if (arch === "arm64") return "aarch64-apple-darwin";
  } else if (platform === "win32") {
    if (arch === "x64") return "x86_64-pc-windows-msvc";
  }
  return null;
}

function getBinaryName() {
  return process.platform === "win32" ? "skill-doctor.exe" : "skill-doctor";
}

function fetchWithRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }
    https
      .get(url, { headers: { "User-Agent": "skill-doctor-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return resolve(fetchWithRedirects(res.headers.location, maxRedirects - 1));
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        }
        resolve(res);
      })
      .on("error", reject);
  });
}

async function main() {
  const target = getTargetTriple();
  const exeName = getBinaryName();
  const binDir = path.join(__dirname, "..", "bin");
  const destPath = path.join(binDir, exeName);

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // If binary already present, skip download
  if (fs.existsSync(destPath)) {
    console.log(`skill-doctor: binary already exists at ${destPath}`);
    return;
  }

  // Also check if built locally in target/release
  const localTarget = path.join(__dirname, "..", "target", "release", exeName);
  if (fs.existsSync(localTarget)) {
    console.log(`skill-doctor: using existing local binary from ${localTarget}`);
    try {
      fs.copyFileSync(localTarget, destPath);
      if (process.platform !== "win32") {
        fs.chmodSync(destPath, 0o755);
      }
      return;
    } catch (_) {
      // ignore copy error, wrapper will search target/release anyway
      return;
    }
  }

  if (!target) {
    console.warn(
      `skill-doctor: unsupported platform/arch (${process.platform}-${process.arch}). ` +
      `Install from source with: cargo install skill-doctor`
    );
    return;
  }

  const ext = process.platform === "win32" ? "zip" : "tar.gz";
  const assetName = `skill-doctor-v${VERSION}-${target}.${ext}`;
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  console.log(`skill-doctor: downloading prebuilt release ${assetName}...`);

  try {
    const stream = await fetchWithRedirects(downloadUrl);
    const tempArchive = path.join(binDir, `temp-${assetName}`);
    const fileStream = fs.createWriteStream(tempArchive);

    await new Promise((resolve, reject) => {
      stream.pipe(fileStream);
      fileStream.on("finish", resolve);
      fileStream.on("error", reject);
    });

    // Extract archive
    if (ext === "zip") {
      // On Windows PowerShell / tar
      try {
        execSync(`tar -xf "${tempArchive}" -C "${binDir}"`, { stdio: "ignore" });
      } catch (_) {
        execSync(`powershell -command "Expand-Archive -Path '${tempArchive}' -DestinationPath '${binDir}' -Force"`, { stdio: "ignore" });
      }
    } else {
      execSync(`tar -xzf "${tempArchive}" -C "${binDir}"`, { stdio: "ignore" });
    }

    // Clean up temporary archive
    if (fs.existsSync(tempArchive)) {
      fs.unlinkSync(tempArchive);
    }

    if (process.platform !== "win32" && fs.existsSync(destPath)) {
      fs.chmodSync(destPath, 0o755);
    }

    console.log(`skill-doctor: successfully installed to ${destPath}`);
  } catch (err) {
    console.warn(
      `skill-doctor: prebuilt binary download unavailable (${err.message}). ` +
      `You can build from source with: cargo install skill-doctor`
    );
  }
}

main().catch((err) => {
  console.warn(`skill-doctor postinstall notice: ${err.message}`);
});
