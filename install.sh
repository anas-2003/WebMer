#!/bin/bash

# =================================================================
# WebMer v5.0 - Project Prometheus Installation Script
# Advanced Defense Evasion Engine Installer
# =================================================================

set -e  


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'


INSTALL_DIR="/opt/webmer"
VENV_DIR="${INSTALL_DIR}/venv"
COMMAND_NAME="webmer"
SYMLINK_PATH="/usr/local/bin/${COMMAND_NAME}"

# Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
████████╗███████╗███████╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ███████╗███████╗
╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔════╝██╔════╝
   ██║   █████╗  ███████╗█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  ███████╗
   ██║   ██╔══╝  ╚════██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══╝  ╚════██║
   ██║   ███████╗███████║███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║███████╗███████║
   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${PURPLE}Project Prometheus - Advanced Defense Evasion Engine${NC}"
    echo -e "${YELLOW}Installation Script v5.0${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo
}

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

loading_animation() {
    local pid=$1
    local delay=0.1
    local spin_chars="/-\|"
    local i=0
    tput civis 
    while kill -0 $pid 2>/dev/null; do
        local char=${spin_chars:$((i++ % ${#spin_chars})):1}
        printf "\r${CYAN}[*] %s${NC} " "$char"
        sleep "$delay"
    done
    tput cnorm 
    printf "\r" 
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="debian"
            INSTALL_CMD="apt-get"
        elif command -v yum &> /dev/null; then
            OS="redhat"
            INSTALL_CMD="yum"
        elif command -v pacman &> /dev/null; then
            OS="arch"
            INSTALL_CMD="pacman"
        else
            OS="linux"
            INSTALL_CMD=""
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        INSTALL_CMD="brew"
    else
        OS="unknown"
        INSTALL_CMD=""
    fi
    
    log "Detected OS: $OS"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run with sudo privileges."
        info "Please run: sudo ./install.sh"
        exit 1
    fi
    warning "Running with administrative privileges"
}

# Check Python version
check_python() {
    log "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print("." .join(map(str, sys.version_info[:2])))')
        log "Found Python $PYTHON_VERSION"
        
        # Check if version is 3.8 or higher
        if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
            log "Python version is compatible"
        else
            error "Python 3.8+ is required. Found Python $PYTHON_VERSION"
            exit 1
        fi
    else
        error "Python3 is not installed. Please install Python 3.8+ first."
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    log "Installing system dependencies..."
    
    case $OS in
        "debian")
            (
                apt-get update && \
                apt-get install -y \
                    libpcap-dev \
                    libffi-dev \
                    libssl-dev \
                    libxml2-dev \
                    libxslt1-dev \
                    libjpeg-dev \
                    zlib1g-dev \
                    build-essential \
                    git \
                    curl \
                    wget \
                    nmap \
                    python3-pip \
                    python3-venv \
                    python3-dev
            ) & loading_animation $!
            ;;
        "redhat")
            (
                yum update -y && \
                yum install -y \
                    libpcap-devel \
                    libffi-devel \
                    openssl-devel \
                    libxml2-devel \
                    libxslt-devel \
                    libjpeg-devel \
                    zlib-devel \
                    gcc \
                    gcc-c++ \
                    make \
                    git \
                    curl \
                    wget \
                    nmap \
                    python3-pip \
                    python3-devel
            ) & loading_animation $!
            ;;
        "arch")
            (
                pacman -Sy --noconfirm \
                    libpcap \
                    libffi \
                    openssl \
                    libxml2 \
                    libxslt \
                    libjpeg-turbo \
                    zlib \
                    base-devel \
                    git \
                    curl \
                    wget \
                    nmap \
                    python-pip
            ) & loading_animation $!
            ;;
        *)
            warning "Unknown OS. Installing basic dependencies..."
            if command -v apt-get &> /dev/null; then
                (
                    apt-get update && \
                    apt-get install -y python3-pip python3-venv git build-essential
                ) & loading_animation $!
            fi
            ;;
    esac
    
    echo "${GREEN}Done.${NC}"
    log "System dependencies installed"
}

# Prepare installation directory
prepare_installation_dir() {
    log "Preparing installation directory at ${INSTALL_DIR}..."
    
    (
        # Check 
        if [ -d "$INSTALL_DIR" ]; then
            rm -rf "$INSTALL_DIR"
        fi
        
        mkdir -p "$INSTALL_DIR"
        

        cp -r ./* "$INSTALL_DIR/" 2>/dev/null || true

        chown -R root:root "$INSTALL_DIR"
        chmod -R 755 "$INSTALL_DIR"
        
        mkdir -p "$INSTALL_DIR/sessions"
        mkdir -p "$INSTALL_DIR/logs"
        mkdir -p "$INSTALL_DIR/reports"
        
    ) & loading_animation $!
    
    echo "${GREEN}Done.${NC}"
    log "Installation directory prepared"
}

# Install WebMer
install_webmer() {
    log "Installing WebMer and dependencies..."
    
    (
        cd "$INSTALL_DIR" && \
        python3 -m venv venv && \
        "${VENV_DIR}/bin/pip" install --upgrade pip && \
        "${VENV_DIR}/bin/pip" install wheel setuptools && \
        "${VENV_DIR}/bin/pip" install -r requirements.txt && \
        "${VENV_DIR}/bin/pip" install -e .
    ) & loading_animation $!
    
    echo "${GREEN}Done.${NC}"
    log "WebMer installed successfully"
}

# Create system-wide command
create_system_command() {
    log "Creating system-wide command..."
    
    (
        # Remove existing symlink
        if [ -L "$SYMLINK_PATH" ]; then
            rm "$SYMLINK_PATH"
        fi
        
        # Create new symlink
        ln -s "${VENV_DIR}/bin/${COMMAND_NAME}" "$SYMLINK_PATH"
        
        # Make it executable
        chmod +x "$SYMLINK_PATH"
        
    ) & loading_animation $!
    
    echo "${GREEN}Done.${NC}"
    log "System command created at $SYMLINK_PATH"
}

# Setup bash completion
setup_completion() {
    log "Setting up command completion..."
    
    # Create completion script
    cat > "$INSTALL_DIR/webmer_completion.sh" << 'EOF'
# WebMer command completion
_webmer_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="--url --list --api-spec --proxy --cookies --concurrency --delay --output --verbose --resume --dump --multi-process --network-scan --tls-audit --ddos --vuln-scan --wifi-scan --help --version"
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _webmer_completion webmer
EOF
    
    # Install system-wide completion
    if [ -d "/etc/bash_completion.d" ]; then
        cp "$INSTALL_DIR/webmer_completion.sh" /etc/bash_completion.d/webmer
        log "Bash completion installed system-wide"
    fi
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Test if command exists
    if command -v webmer &> /dev/null; then
        log "✓ WebMer command is available"
        
        # Test version
        version_output=$(webmer --version 2>&1 || echo "Version check failed")
        log "✓ Version: $version_output"
        
        info "Testing basic functionality..."
        if timeout 30 webmer --url "https://httpbin.org/get" --verbose >/dev/null 2>&1; then
            log "✓ Basic functionality test passed"
        else
            warning "Basic functionality test failed (this might be due to network issues)"
        fi
        
    else
        error "WebMer command not found in PATH"
        exit 1
    fi
}

# Show final instructions
show_final_instructions() {
    echo
    echo -e "${GREEN}======================================================================${NC}"
    echo -e "${CYAN}🎉 WebMer v5.0 Installation Complete! 🎉${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo
    echo -e "${YELLOW}📋 Installation Summary:${NC}"
    echo -e "   ✓ Installed to: ${CYAN}$INSTALL_DIR${NC}"
    echo -e "   ✓ System command: ${CYAN}$SYMLINK_PATH${NC}"
    echo -e "   ✓ Virtual environment: ${CYAN}$VENV_DIR${NC}"
    echo -e "   ✓ Bash completion: ${CYAN}/etc/bash_completion.d/webmer${NC}"
    echo
    echo -e "${YELLOW}🚀 Quick Start:${NC}"
    echo -e "   1. Test installation: ${CYAN}webmer --version${NC}"
    echo -e "   2. Basic scan: ${CYAN}webmer --url https://httpbin.org/get --verbose${NC}"
    echo -e "   3. Help menu: ${CYAN}webmer --help${NC}"
    echo -e "   4. Advanced scan: ${CYAN}webmer --url https://example.com --vuln-scan${NC}"
    echo
    echo -e "${YELLOW}📚 Documentation:${NC}"
    echo -e "   - Configuration: ${CYAN}$INSTALL_DIR/config.yaml${NC}"
    echo -e "   - Logs: ${CYAN}$INSTALL_DIR/logs/${NC}"
    echo -e "   - Reports: ${CYAN}$INSTALL_DIR/reports/${NC}"
    echo -e "   - Sessions: ${CYAN}$INSTALL_DIR/sessions/${NC}"
    echo
    echo -e "${RED}⚠️  IMPORTANT LEGAL NOTICE:${NC}"
    echo -e "   - Only use WebMer for ${YELLOW}authorized security testing${NC}"
    echo -e "   - Always obtain ${YELLOW}proper written permission${NC} before testing"
    echo -e "   - Respect ${YELLOW}responsible disclosure practices${NC}"
    echo -e "   - Use this tool ${YELLOW}ethically and legally${NC}"
    echo
    echo -e "${PURPLE}💻 Developer: Anas Erami${NC}"
    echo -e "${PURPLE}📧 Email: anaserami17@gmail.com${NC}"
    echo -e "${PURPLE}🔗 GitHub: https://github.com/anas-2003/WebMer${NC}"
    echo
    echo -e "${GREEN}Happy Ethical Hacking! 🚀${NC}"
    echo
}

# Main installation function
main() {
    show_banner
    
    # Pre-installation checks
    check_root
    detect_os
    check_python
    
    # Installation steps
    install_system_deps
    prepare_installation_dir
    install_webmer
    create_system_command
    setup_completion
    
    # Post-installation
    verify_installation
    show_final_instructions
}

# Error handling
trap 'error "Installation failed! Check the error messages above."' ERR

# Run main function
main "$@"
