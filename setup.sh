#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  WAFFLE — setup script (Linux / macOS)
#  Run once after cloning the repo.
# ─────────────────────────────────────────────────────────────
set -e

BOLD="\033[1m"; GREEN="\033[92m"; YELLOW="\033[93m"
RED="\033[91m"; CYAN="\033[96m"; RESET="\033[0m"

info()    { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}!${RESET}   $*"; }
error()   { echo -e "  ${RED}✖${RESET}  $*"; exit 1; }
heading() { echo -e "\n  ${BOLD}$*${RESET}"; }

echo -e "\n  ${BOLD}${CYAN}WAFFLE${RESET} — Web Access Filter & Firewall"
echo -e "  Setup script\n"

# ── 1. Python check ───────────────────────────────────────────
heading "1. Checking Python..."
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install it first: sudo apt install python3"
fi
PY_VER=$(python3 -c 'import sys; print(sys.version_info[:2])')
info "Found $(python3 --version)"

# ── 2. openssl check ─────────────────────────────────────────
heading "2. Checking openssl..."
if command -v openssl &>/dev/null; then
    info "Found $(openssl version)"
else
    warn "openssl not found — will use cryptography fallback"
    warn "To install: sudo apt install openssl"
fi

# ── 3. certutil check (for Chrome NSS install) ───────────────
heading "3. Checking certutil (needed for Chrome CA install)..."
if command -v certutil &>/dev/null; then
    info "certutil found"
else
    warn "certutil not found — installing libnss3-tools..."
    if command -v apt &>/dev/null; then
        sudo apt install -y libnss3-tools && info "certutil installed"
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nss && info "certutil installed"
    elif command -v brew &>/dev/null; then
        brew install nss && info "certutil installed"
    else
        warn "Could not install certutil automatically."
        warn "You will need to import the CA into Chrome manually."
    fi
fi

# ── 4. cryptography pip package (optional fallback) ──────────
heading "4. Installing Python dependencies..."
python3 -m pip install cryptography --break-system-packages -q \
    && info "cryptography installed" \
    || warn "Could not install cryptography (openssl will be used instead)"

# ── 5. Generate CA cert ───────────────────────────────────────
heading "5. Generating local CA certificate..."
python3 waffle.py --generate-ca
info "CA certificate created"

# ── 6. Install CA into Chrome NSS store ──────────────────────
heading "6. Installing CA into Chrome..."
echo -e "  ${YELLOW}Close Chrome completely (Ctrl+Q) before continuing.${RESET}"
read -rp "  Press Enter when Chrome is closed... "
python3 waffle.py --install-ca

# ── 7. Verify ────────────────────────────────────────────────
heading "7. Verifying CA install..."
python3 waffle.py --check-ca

# ── 8. Install waffle to PATH (optional) ─────────────────────
heading "8. Install waffle to /usr/local/bin (optional)..."
read -rp "  Install so you can run 'waffle' from anywhere? [Y/n] " ans
ans="${ans:-y}"
if [[ "$ans" =~ ^[Yy] ]]; then
    sudo cp waffle.py /usr/local/bin/waffle
    sudo chmod +x /usr/local/bin/waffle
    # Fix shebang in-place so it runs as a script from PATH
    sudo sed -i '1s|.*|#!/usr/bin/env python3|' /usr/local/bin/waffle
    info "Installed to /usr/local/bin/waffle"
else
    info "Skipped — run with: python3 waffle.py <command>"
fi

# ── Done ─────────────────────────────────────────────────────
echo -e "\n  ${BOLD}${GREEN}Setup complete!${RESET}\n"
echo -e "  Start WAFFLE:         ${CYAN}waffle --activate${RESET}"
echo -e "  Add a site:           ${CYAN}waffle -a https://example.com${RESET}"
echo -e "  Check status:         ${CYAN}waffle --status${RESET}"
echo -e "  Then set your browser proxy to ${CYAN}127.0.0.1:8080${RESET}\n"