#!/usr/bin/env node
/**
 * scripts/download-binary.js
 * Secure installer for skill-doctor prebuilt binaries.
 * Validates SHA-256 checksums from official SHA256SUMS.txt before extraction.
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
const REPO = "KalarisLabs/Skill-Doctor";

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
    if (arch === "arm64") return "aarch64-pc-windows-msvc";
  }
  return null;
}

function getBinaryName() {
  return process.platform === "win32" ? "skill-doctor.exe" : "skill-doctor";
}

function fetchWithRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error(`Too many redirects fetching ${url}`));
    }
    https
      .get(url, { headers: { "User-Agent": "skill-doctor-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return resolve(fetchWithRedirects(res.headers.location, maxRedirects - 1));
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage} (${url})`));
        }
        resolve(res);
      })
      .on("error", reject);
  });
}

function fetchText(url) {
  return fetchWithRedirects(url).then((stream) => {
    return new Promise((resolve, reject) => {
      let data = "";
      stream.on("data", (chunk) => (data += chunk.toString("utf8")));
      stream.on("end", () => resolve(data));
      stream.on("error", reject);
    });
  });
}

function computeSha256(filePath) {
  const hash = crypto.createHash("sha256");
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest("hex").toLowerCase();
}

function findFileRecursive(dir, filename) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findFileRecursive(full, filename);
      if (found) return found;
    } else if (entry.name === filename) {
      return full;
    }
  }
  return null;
}

async function main() {
  const exeName = getBinaryName();
  const binDir = path.join(__dirname, "..", "bin");
  const destPath = path.join(binDir, exeName);

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // 1. If binary already present, skip download
  if (fs.existsSync(destPath)) {
    console.log(`skill-doctor: verified binary already present at ${destPath}`);
    return;
  }

  // 2. Check if built locally in target/release
  const localTarget = path.join(__dirname, "..", "target", "release", exeName);
  if (fs.existsSync(localTarget)) {
    console.log(`skill-doctor: using existing local binary from ${localTarget}`);
    fs.copyFileSync(localTarget, destPath);
    if (process.platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }
    return;
  }

  // 3. Check for explicit skip environment variable (offline / source install)
  if (process.env.SKILL_DOCTOR_SKIP_DOWNLOAD === "1" || process.env.npm_config_build_from_source === "true") {
    console.log("skill-doctor: SKILL_DOCTOR_SKIP_DOWNLOAD is set. Skipping prebuilt binary download.");
    return;
  }

  const target = getTargetTriple();
  if (!target) {
    throw new Error(
      `Unsupported platform/architecture (${process.platform}-${process.arch}). ` +
      `Please build from source using: cargo install --path crates/skill-doctor-cli`
    );
  }

  const ext = process.platform === "win32" ? "zip" : "tar.gz";
  const assetName = `skill-doctor-v${VERSION}-${target}.${ext}`;
  const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;
  const sumsUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/SHA256SUMS.txt`;

  console.log(`skill-doctor: fetching SHA256SUMS.txt for release v${VERSION}...`);
  const sumsText = await fetchText(sumsUrl);
  let expectedHash = null;
  for (const line of sumsText.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      const hash = parts[0];
      const filename = parts[1].replace(/^\*/, "");
      if (filename === assetName) {
        expectedHash = hash.toLowerCase();
        break;
      }
    }
  }

  if (!expectedHash) {
    throw new Error(`Checksum for ${assetName} was not found in release SHA256SUMS.txt`);
  }

  console.log(`skill-doctor: downloading ${assetName}...`);
  const tempArchive = path.join(binDir, `temp-${Date.now()}-${process.pid}-${assetName}`);
  const tempExtractDir = path.join(binDir, `temp-extract-${Date.now()}-${process.pid}`);

  try {
    const stream = await fetchWithRedirects(downloadUrl);
    const fileStream = fs.createWriteStream(tempArchive);

    await new Promise((resolve, reject) => {
      stream.on("error", reject);
      fileStream.on("error", reject);
      fileStream.on("finish", resolve);
      stream.pipe(fileStream);
    });

    console.log(`skill-doctor: verifying SHA-256 digest...`);
    const actualHash = computeSha256(tempArchive);
    if (actualHash !== expectedHash) {
      throw new Error(
        `SHA-256 verification failed for ${assetName}!\n` +
        `  Expected: ${expectedHash}\n` +
        `  Actual:   ${actualHash}`
      );
    }
    console.log(`skill-doctor: checksum OK (${actualHash.slice(0, 16)}...)`);

    // Extract archive to isolated temporary folder
    fs.mkdirSync(tempExtractDir, { recursive: true });
    if (ext === "zip") {
      try {
        execSync(`tar -xf "${tempArchive}" -C "${tempExtractDir}"`, { stdio: "ignore" });
      } catch (_) {
        execSync(
          `powershell -NoProfile -Command "Expand-Archive -Path '${tempArchive}' -DestinationPath '${tempExtractDir}' -Force"`,
          { stdio: "ignore" }
        );
      }
    } else {
      execSync(`tar -xzf "${tempArchive}" -C "${tempExtractDir}"`, { stdio: "ignore" });
    }

    // Locate the executable (either at root of archive or nested)
    const foundExe = findFileRecursive(tempExtractDir, exeName);
    if (!foundExe) {
      throw new Error(`Extracted archive did not contain expected binary: ${exeName}`);
    }

    // Move only the executable into bin/
    fs.copyFileSync(foundExe, destPath);
    if (process.platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }

    console.log(`skill-doctor: successfully installed to ${destPath}`);
  } finally {
    // Cleanup temporary archive and extracted directory
    if (fs.existsSync(tempArchive)) {
      try { fs.unlinkSync(tempArchive); } catch (_) {}
    }
    if (fs.existsSync(tempExtractDir)) {
      try { fs.rmSync(tempExtractDir, { recursive: true, force: true }); } catch (_) {}
    }
  }

  if (!fs.existsSync(destPath)) {
    throw new Error(`Failed to place executable at ${destPath}`);
  }
}

main().catch((err) => {
  console.error(`\n❌ skill-doctor install failed: ${err.message}`);
  process.exit(1);
});
