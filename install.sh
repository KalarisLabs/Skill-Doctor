#!/bin/sh
# Skill Doctor Install Script for Linux and macOS

set -e

REPO="KalarisLabs/Skill-Doctor"

echo "Installing Skill Doctor..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

ASSET_NAME="skill-doctor-$OS-$ARCH"
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$ASSET_NAME"

echo "Downloading Skill Doctor ($ASSET_NAME)..."
if ! curl -fsSL "$DOWNLOAD_URL" -o /tmp/skill-doctor; then
    echo "Direct download failed, querying GitHub releases API..."
    LATEST_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url.*$ASSET_NAME\"" | cut -d '"' -f 4 | head -n 1)
    if [ -z "$LATEST_URL" ]; then
        echo "Error: Could not find release asset for $OS-$ARCH"
        exit 1
    fi
    curl -fsSL "$LATEST_URL" -o /tmp/skill-doctor
    DOWNLOAD_URL="$LATEST_URL"
fi

echo "Downloading SHA256 checksum..."
if curl -fsSL "${DOWNLOAD_URL}.sha256" -o /tmp/skill-doctor.sha256; then
    echo "Verifying checksum..."
    cd /tmp
    if ! sha256sum -c skill-doctor.sha256; then
        echo "Error: Checksum verification failed!"
        rm -f /tmp/skill-doctor /tmp/skill-doctor.sha256
        exit 1
    fi
    echo "Checksum verified successfully."
else
    echo "Warning: Could not download checksum file. Skipping verification."
fi

chmod +x /tmp/skill-doctor

# Install to /usr/local/bin
INSTALL_DIR="/usr/local/bin"
echo "Installing to $INSTALL_DIR (may require sudo password)..."
sudo mv /tmp/skill-doctor "$INSTALL_DIR/skill-doctor"

echo "✅ Skill Doctor installed successfully!"
echo "Run 'skill-doctor --help' to get started."
