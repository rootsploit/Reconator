#!/bin/bash
# Reconator Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/rootsploit/reconator/main/scripts/install.sh | bash

set -e

REPO="rootsploit/reconator"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="reconator"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "    ____                             __            "
    echo "   / __ \\___  _________  ____  ___ _/ /_____  _____"
    echo "  / /_/ / _ \\/ ___/ __ \\/ __ \\/ _ \`/ __/ __ \\/ ___/"
    echo " / _, _/  __/ /__/ /_/ / / / / /_/ / /_/ /_/ / /    "
    echo "/_/ |_|\\___/\\___/\\____/_/ /_/\\__,_/\\__/\\____/_/     "
    echo ""
    echo "  AI-Powered Reconnaissance Framework"
    echo -e "${NC}"
}

info() {
    echo -e "${BLUE}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    exit 1
}

detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac

    case "$OS" in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            error "Unsupported OS: $OS"
            ;;
    esac

    info "Detected: $OS/$ARCH"
}

get_latest_version() {
    info "Fetching latest version..."
    VERSION=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest version"
    fi
    info "Latest version: $VERSION"
}

download_binary() {
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}_${VERSION#v}_${OS}_${ARCH}.tar.gz"

    info "Downloading from: $DOWNLOAD_URL"

    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT

    curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/reconator.tar.gz" || error "Download failed"

    info "Extracting..."
    tar -xzf "$TMP_DIR/reconator.tar.gz" -C "$TMP_DIR" || error "Extraction failed"

    # Install binary
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        warn "Need sudo to install to $INSTALL_DIR"
        sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi

    success "Installed to $INSTALL_DIR/$BINARY_NAME"
}

install_via_go() {
    if command -v go &> /dev/null; then
        info "Installing via go install..."
        go install "github.com/${REPO}@latest"
        success "Installed via go install"
        return 0
    fi
    return 1
}

verify_installation() {
    if command -v reconator &> /dev/null; then
        VERSION_OUTPUT=$(reconator version 2>/dev/null | head -1)
        success "Installation verified: $VERSION_OUTPUT"
    else
        warn "Binary installed but not in PATH"
        echo "Add $INSTALL_DIR to your PATH:"
        echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
}

print_next_steps() {
    echo ""
    echo -e "${GREEN}Installation complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Install dependencies:  reconator install --extras"
    echo "  2. Run your first scan:   reconator scan example.com"
    echo ""
    echo "For AI features, set an API key:"
    echo "  export OPENAI_API_KEY=\"sk-...\""
    echo "  export GROQ_API_KEY=\"gsk_...\""
    echo ""
    echo "Documentation: https://github.com/${REPO}"
}

main() {
    print_banner

    # Check if already installed
    if command -v reconator &> /dev/null; then
        CURRENT=$(reconator version 2>/dev/null | head -1 || echo "unknown")
        warn "Reconator is already installed: $CURRENT"
        read -p "Do you want to upgrade? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi

    detect_os

    # Try go install first if Go is available
    if install_via_go 2>/dev/null; then
        verify_installation
        print_next_steps
        exit 0
    fi

    # Fall back to binary download
    get_latest_version
    download_binary
    verify_installation
    print_next_steps
}

main "$@"
