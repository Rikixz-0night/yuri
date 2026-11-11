#!/bin/sh
# ==============================================================================
# Yuri - Blazing-Fast Port Scanner & OS Detection Engine
# Linux Installation Script
# Repository: https://github.com/Rikixz-0night/yuri.git
# ==============================================================================

set -e

# Color helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo "${MAGENTA}${BOLD}"
cat << "EOF"
  __     __           _ 
  \ \   / /   _ _ __ (_)
   \ \ / / | | | '__|| |
    \ V /| |_| | |   | |
     \_/  \__,_|_|   |_|
EOF
echo "${NC}"
echo "${CYAN}${BOLD}⚡ Yuri - Ultra-Fast Port Scanner & OS Engine Installer${NC}"
echo "${BLUE}Repository: https://github.com/Rikixz-0night/yuri.git${NC}\n"

# Check operating system
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    echo "${YELLOW}[!] Warning: This installer is optimized for Linux (detected $OS). Proceeding...${NC}"
fi

# Detect installation target directory
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        INSTALL_DIR="/usr/local/bin"
        SUDO="sudo"
    else
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        SUDO=""
    fi
fi

# 1. Check for Rust / Cargo
if ! command -v cargo >/dev/null 2>&1; then
    echo "${YELLOW}[+] Cargo / Rust toolchain not detected. Installing Rustup...${NC}"
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y
    else
        echo "${RED}[-] Error: Neither curl nor wget found. Please install curl or rust manually.${NC}"
        exit 1
    fi

    # Source cargo environment
    if [ -f "$HOME/.cargo/env" ]; then
        . "$HOME/.cargo/env"
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "${RED}[-] Error: Cargo could not be found after rustup installation.${NC}"
    echo "    Please run: source $HOME/.cargo/env and re-run this script."
    exit 1
fi

echo "${GREEN}[✓] Rust toolchain detected: $(rustc --version)${NC}"

# 2. Check if running inside cloned repo or need to clone
TMP_DIR=""
if [ -f "./Cargo.toml" ] && grep -q 'name = "yuri"' "./Cargo.toml" 2>/dev/null; then
    echo "${CYAN}[+] Detected local Yuri repository directory.${NC}"
    BUILD_DIR="$(pwd)"
else
    echo "${CYAN}[+] Cloning Yuri from GitHub...${NC}"
    TMP_DIR="$(mktemp -d -t yuri-build-XXXXXX)"
    git clone --depth 1 https://github.com/Rikixz-0night/yuri.git "$TMP_DIR"
    BUILD_DIR="$TMP_DIR"
fi

# 3. Build optimized release binary
echo "${CYAN}[+] Building optimized release binary with Link-Time Optimization (LTO)...${NC}"
cd "$BUILD_DIR"
cargo build --release

# 4. Install binary
echo "${CYAN}[+] Installing binary to ${INSTALL_DIR}/yuri...${NC}"
if [ "$INSTALL_DIR" = "/usr/local/bin" ] && [ -n "$SUDO" ]; then
    $SUDO cp target/release/yuri "$INSTALL_DIR/yuri"
    $SUDO chmod 755 "$INSTALL_DIR/yuri"
else
    cp target/release/yuri "$INSTALL_DIR/yuri"
    chmod 755 "$INSTALL_DIR/yuri"
fi

# 5. Clean up temporary directory if created
if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
fi

# 6. Verify PATH
if [ "$INSTALL_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            echo "${YELLOW}[!] Note: $HOME/.local/bin is not in your PATH.${NC}"
            echo "    Add this to your ~/.bashrc or ~/.zshrc: export PATH=\"\$HOME/.local/bin:\$PATH\""
            export PATH="$HOME/.local/bin:$PATH"
            ;;
    esac
fi

# 7. Verification
echo ""
if command -v yuri >/dev/null 2>&1 || [ -x "$INSTALL_DIR/yuri" ]; then
    echo "${GREEN}${BOLD}======================================================${NC}"
    echo "${GREEN}${BOLD}  ✨ Yuri installed successfully!                      ${NC}"
    echo "${GREEN}${BOLD}======================================================${NC}"
    echo ""
    echo "${CYAN}${BOLD}Quick Start Guide:${NC}"
    echo "  ${YELLOW}yuri 127.0.0.1${NC}                       # Scan top 1000 ports on localhost"
    echo "  ${YELLOW}yuri 192.168.1.1 -p 1-65535${NC}         # Scan all 65,535 ports"
    echo "  ${YELLOW}yuri 192.168.1.0/24${NC}                 # Subnet sweep / CIDR range scan"
    echo "  ${YELLOW}yuri target.com -p 80,443 --json${NC}    # JSON output for automation"
    echo "  ${YELLOW}yuri target.com --pipe-nmap${NC}         # Fast discover + pipe to Nmap scripts"
    echo ""
    echo "${MAGENTA}Run 'yuri --help' to see all advanced options.${NC}"
else
    echo "${RED}[-] Installation verification failed. Please check permissions.${NC}"
    exit 1
fi
