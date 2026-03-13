#!/bin/bash
#
# Reconator - Install Optional Tools
# This script installs non-Go tools that provide additional capabilities
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           Reconator - Optional Tools Installer            ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM=linux;;
    Darwin*)    PLATFORM=macos;;
    *)          PLATFORM=unknown;;
esac

echo "[*] Detected platform: $PLATFORM"
echo ""

# Check for package managers
check_pip() {
    if command -v pip3 &> /dev/null; then
        echo "pip3"
    elif command -v pip &> /dev/null; then
        echo "pip"
    else
        echo ""
    fi
}

check_pipx() {
    if command -v pipx &> /dev/null; then
        echo "pipx"
    else
        echo ""
    fi
}

check_cargo() {
    if command -v cargo &> /dev/null; then
        echo "cargo"
    else
        echo ""
    fi
}

check_brew() {
    if command -v brew &> /dev/null; then
        echo "brew"
    else
        echo ""
    fi
}

# Install waymore (Python)
install_waymore() {
    echo -e "${YELLOW}[+] Installing waymore (Python)...${NC}"

    PIPX=$(check_pipx)
    PIP=$(check_pip)

    if [ -n "$PIPX" ]; then
        pipx install waymore && echo -e "${GREEN}    ✓ waymore installed via pipx${NC}" || echo -e "${RED}    ✗ Failed to install waymore${NC}"
    elif [ -n "$PIP" ]; then
        $PIP install --user waymore && echo -e "${GREEN}    ✓ waymore installed via pip${NC}" || echo -e "${RED}    ✗ Failed to install waymore${NC}"
    else
        echo -e "${RED}    ✗ pip/pipx not found. Install Python first.${NC}"
    fi
}

# Install vita (Rust)
install_vita() {
    echo -e "${YELLOW}[+] Installing vita (Rust)...${NC}"

    CARGO=$(check_cargo)

    if [ -n "$CARGO" ]; then
        cargo install vita && echo -e "${GREEN}    ✓ vita installed via cargo${NC}" || echo -e "${RED}    ✗ Failed to install vita${NC}"
    else
        echo -e "${RED}    ✗ cargo not found. Install Rust first: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    fi
}

# Install findomain (Rust)
install_findomain() {
    echo -e "${YELLOW}[+] Installing findomain (Rust)...${NC}"

    CARGO=$(check_cargo)
    BREW=$(check_brew)

    if [ "$PLATFORM" = "macos" ] && [ -n "$BREW" ]; then
        brew install findomain && echo -e "${GREEN}    ✓ findomain installed via brew${NC}" || echo -e "${RED}    ✗ Failed to install findomain${NC}"
    elif [ -n "$CARGO" ]; then
        cargo install findomain && echo -e "${GREEN}    ✓ findomain installed via cargo${NC}" || echo -e "${RED}    ✗ Failed to install findomain${NC}"
    else
        echo -e "${RED}    ✗ Neither brew nor cargo found.${NC}"
    fi
}

# Install massdns (required for puredns)
install_massdns() {
    echo -e "${YELLOW}[+] Installing massdns...${NC}"

    BREW=$(check_brew)

    if [ "$PLATFORM" = "macos" ] && [ -n "$BREW" ]; then
        brew install massdns && echo -e "${GREEN}    ✓ massdns installed via brew${NC}" || echo -e "${RED}    ✗ Failed to install massdns${NC}"
    elif [ "$PLATFORM" = "linux" ]; then
        # Build from source on Linux
        if command -v git &> /dev/null && command -v make &> /dev/null; then
            TMP_DIR=$(mktemp -d)
            cd "$TMP_DIR"
            git clone https://github.com/blechschmidt/massdns.git
            cd massdns
            make
            sudo make install
            cd /
            rm -rf "$TMP_DIR"
            echo -e "${GREEN}    ✓ massdns installed from source${NC}"
        else
            echo -e "${RED}    ✗ git or make not found. Install them first.${NC}"
        fi
    else
        echo -e "${RED}    ✗ Could not install massdns automatically.${NC}"
        echo "    Visit: https://github.com/blechschmidt/massdns"
    fi
}

# Download resolvers
download_resolvers() {
    echo -e "${YELLOW}[+] Downloading DNS resolvers...${NC}"

    RESOLVERS_DIR="$HOME/.config/reconator"
    mkdir -p "$RESOLVERS_DIR"

    # Download resolvers from trickest
    curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS_DIR/resolvers.txt" 2>/dev/null

    if [ -f "$RESOLVERS_DIR/resolvers.txt" ]; then
        COUNT=$(wc -l < "$RESOLVERS_DIR/resolvers.txt" | tr -d ' ')
        echo -e "${GREEN}    ✓ Downloaded $COUNT resolvers to $RESOLVERS_DIR/resolvers.txt${NC}"
    else
        echo -e "${RED}    ✗ Failed to download resolvers${NC}"
    fi
}

# Main menu
echo "Select what to install:"
echo ""
echo "  1) All optional tools"
echo "  2) waymore only (Python - more wayback sources)"
echo "  3) vita only (Rust - additional subdomain sources)"
echo "  4) findomain only (Rust - subdomain enumeration)"
echo "  5) massdns only (required for puredns)"
echo "  6) Download DNS resolvers"
echo "  7) Exit"
echo ""
read -p "Enter choice [1-7]: " choice

case $choice in
    1)
        install_waymore
        echo ""
        install_vita
        echo ""
        install_findomain
        echo ""
        install_massdns
        echo ""
        download_resolvers
        ;;
    2)
        install_waymore
        ;;
    3)
        install_vita
        ;;
    4)
        install_findomain
        ;;
    5)
        install_massdns
        ;;
    6)
        download_resolvers
        ;;
    7)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[+] Installation complete!${NC}"
echo "    Run 'reconator check' to verify installed tools"
