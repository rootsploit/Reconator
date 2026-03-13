#!/bin/bash

# Build script for Reconator with embedded web assets
# This script builds the web dashboard and then compiles the Go binary with embedded assets

set -e  # Exit on error

echo "🔨 Building Reconator with embedded web dashboard"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Check if Node.js and npm are installed
echo -e "${BLUE}[1/4] Checking dependencies...${NC}"
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Warning: Node.js not found. Web dashboard will not be rebuilt.${NC}"
    echo -e "${YELLOW}The binary will use existing web/dist if available, or run without UI.${NC}"
    SKIP_WEB_BUILD=true
else
    echo "✓ Node.js $(node --version) found"
    if ! command -v npm &> /dev/null; then
        echo -e "${YELLOW}Warning: npm not found. Skipping web build.${NC}"
        SKIP_WEB_BUILD=true
    else
        echo "✓ npm $(npm --version) found"
    fi
fi
echo ""

# Step 2: Build web dashboard (if dependencies available)
if [ "$SKIP_WEB_BUILD" != "true" ]; then
    echo -e "${BLUE}[2/4] Building web dashboard...${NC}"
    cd web

    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        echo "Installing npm dependencies..."
        npm install
    fi

    # Build the dashboard
    echo "Building React app..."
    npm run build

    # Verify build output
    if [ ! -f "dist/index.html" ]; then
        echo -e "${YELLOW}Error: Web build failed! dist/index.html not found.${NC}"
        exit 1
    fi

    echo "✓ Web dashboard built successfully"
    echo "  Output: web/dist/ ($(du -sh dist | cut -f1))"
    cd ..
else
    echo -e "${YELLOW}[2/4] Skipping web build (Node.js/npm not available)${NC}"
    # Check if dist exists from previous build
    if [ -d "web/dist" ] && [ -f "web/dist/index.html" ]; then
        echo "✓ Using existing web/dist from previous build"
    else
        echo -e "${YELLOW}Warning: No web/dist found. Binary will have no web UI.${NC}"
    fi
fi
echo ""

# Step 3: Build Go binary with embedded assets
echo -e "${BLUE}[3/4] Building Go binary...${NC}"

# Get version from git tag or use default
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build with ldflags to set version info
echo "Building reconator..."
go build -o reconator \
    -ldflags="-X github.com/rootsploit/reconator/internal/version.Version=${VERSION} \
              -X github.com/rootsploit/reconator/internal/version.Commit=${COMMIT} \
              -X github.com/rootsploit/reconator/internal/version.BuildDate=${BUILD_DATE}" \
    ./cmd/reconator

# Verify binary was created
if [ ! -f "reconator" ]; then
    echo -e "${YELLOW}Error: Go build failed! Binary not found.${NC}"
    exit 1
fi

echo "✓ Binary built successfully"
echo "  Output: ./reconator ($(du -sh reconator | cut -f1))"
echo "  Version: ${VERSION}"
echo "  Commit: ${COMMIT}"
echo ""

# Step 4: Verify embedded assets
echo -e "${BLUE}[4/4] Verifying embedded assets...${NC}"

# Try to detect if assets are embedded (this is a simple check)
if ./reconator server --help &> /dev/null; then
    echo "✓ Binary is executable"
else
    echo -e "${YELLOW}Warning: Binary may not be properly built${NC}"
fi

# Check binary size (embedded assets should make it larger)
BINARY_SIZE=$(stat -f%z reconator 2>/dev/null || stat -c%s reconator 2>/dev/null || echo 0)
if [ $BINARY_SIZE -gt 10000000 ]; then  # > 10MB suggests assets are embedded
    echo "✓ Binary size suggests assets are embedded ($(du -sh reconator | cut -f1))"
else
    echo -e "${YELLOW}Warning: Binary is small ($(du -sh reconator | cut -f1)), assets may not be embedded${NC}"
fi
echo ""

# Final summary
echo "=================================================="
echo -e "${GREEN}✅ Build complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Test the binary: ./reconator server"
echo "  2. Check version: ./reconator version"
echo "  3. Install tools: ./reconator install --extras"
echo ""
echo "To create a release build:"
echo "  ./build.sh"
echo "  # Binary is ready for distribution"
echo ""
