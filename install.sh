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

# Fetch latest release URL
LATEST_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep "browser_download_url.*$ASSET_NAME" | cut -d '"' -f 4 | head -n 1)

if [ -z "$LATEST_URL" ]; then
    echo "Error: Could not find release asset for $OS-$ARCH"
    exit 1
fi

echo "Downloading from $LATEST_URL..."
curl -sL "$LATEST_URL" -o /tmp/skill-doctor
chmod +x /tmp/skill-doctor

# Install to /usr/local/bin
INSTALL_DIR="/usr/local/bin"
echo "Installing to $INSTALL_DIR (may require sudo password)..."
sudo mv /tmp/skill-doctor "$INSTALL_DIR/skill-doctor"

echo "✅ Skill Doctor installed successfully!"
echo "Run 'skill-doctor --help' to get started."
