const os = require('os');
const https = require('https');
const fs = require('fs');
const path = require('path');

const VERSION = '1.0.0';
const REPO = 'KalarisLabs/Skill-Doctor';

const platform = os.platform();
let arch = os.arch();

if (arch === 'x64') arch = 'amd64';
if (arch === 'arm64') arch = 'arm64';

let assetName = `skill-doctor-${platform === 'win32' ? 'windows' : platform === 'darwin' ? 'darwin' : 'linux'}-${arch}`;
if (platform === 'win32') assetName += '.exe';

const downloadUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

const binDir = path.join(__dirname, 'bin');
if (!fs.existsSync(binDir)) {
  fs.mkdirSync(binDir);
}

const dest = path.join(binDir, platform === 'win32' ? 'skill-doctor.exe' : 'skill-doctor');

console.log(`Downloading Skill Doctor ${VERSION} for ${platform}-${arch}...`);

function downloadFile(url, targetPath, callback) {
  https.get(url, (res) => {
    if (res.statusCode === 301 || res.statusCode === 302) {
      downloadFile(res.headers.location, targetPath, callback);
    } else if (res.statusCode === 200) {
      const file = fs.createWriteStream(targetPath);
      res.pipe(file);
      file.on('finish', () => {
        file.close(callback);
      });
    } else {
      console.error(`Failed to download binary: HTTP ${res.statusCode}`);
      process.exit(1);
    }
  }).on('error', (err) => {
    console.error('Error downloading binary:', err.message);
    process.exit(1);
  });
}

downloadFile(downloadUrl, dest, () => {
  if (platform !== 'win32') {
    fs.chmodSync(dest, 0o755);
  }
  console.log('Skill Doctor installed successfully.');
});
