#!/bin/bash

# Define colors for output 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Progress bar characters
PROG_BAR_START="["
PROG_BAR_END="]"
PROG_BAR_FILL="="
PROG_BAR_EMPTY=" "

# Spinner characters
SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display progress bar
show_progress_bar() {
    local progress=$1
    local total=$2
    local bar_width=50
    local filled=$(printf "%0.0f" $(echo "scale=0; $progress * $bar_width / $total" | bc))
    local remaining=$(($bar_width - $filled))
    local percentage=$((100 * $progress / $total))

    # Ensure progress bar values are within valid range
    if [ "$percentage" -gt 100 ]; then
        percentage=100
    elif [ "$percentage" -lt 0 ]; then
        percentage=0
    fi

    # Move the cursor to the start of the progress bar line
    printf "\r"

    # Print the progress bar
    if [ "$remaining" -ge 0 ]; then
        printf "[%-*s] %3d%%\r" "$bar_width" "${PROG_BAR_FILL:0:$filled}${PROG_BAR_EMPTY:0:$remaining}" "$percentage"
    else
        printf "[%-*s] %3d%%\r" "$bar_width" "${PROG_BAR_FILL:0:$bar_width}" "$percentage"
    fi
}

# Function to display spinner animation
show_spinner() {
    local spin_index=0
    local spin_delay=0.1
    while true; do
        printf "\r${YELLOW}${SPINNER[$spin_index]}${NC}"
        sleep $spin_delay
        ((spin_index = (spin_index + 1) % ${#SPINNER[@]}))
    done
}

# Function to display progress
show_progress() {
    local step=$1
    local total_steps=$2
    local progress=$3
    printf "\r${YELLOW}Installing $step ($progress/$total_steps)...${NC} "
    show_progress_bar $progress $total_steps
    show_spinner &
    spinner_pid=$!
}

# Function to display success
show_success() {
    kill $spinner_pid 2>/dev/null
    printf "\r${GREEN}✓ $1 installed successfully${NC}\n"
}

# Function to display error
show_error() {
    kill $spinner_pid 2>/dev/null
    printf "\r${RED}✗ Error installing $1${NC}\n"
}

# Function to install a package or tool
install_package() {
    local package=$1
    local install_cmd=$2
    local check_cmd=$3
    local step=$4
    local total_steps=$5

    if eval "$check_cmd" > /dev/null 2>&1; then
        show_success "$package is already installed"
    else
        show_progress "$package" $step $total_steps
        bash -c "$install_cmd" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            show_success "$package"
        else
            show_error "$package"
        fi
    fi
}

# Function to set Go environment variables
set_go_env_vars() {
    local shell_config_file="$1"
    local go_version=$(go version | awk '{print $3}' 2> /dev/null)

    if [ -n "$go_version" ]; then
        echo "export GOROOT=/usr/local/go" >> "$shell_config_file"
        echo "export GOPATH=\$HOME/go" >> "$shell_config_file"
        echo "export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH" >> "$shell_config_file"
        show_success "Go environment variables set in $shell_config_file"
    else
        show_error "Go is not installed or not properly configured"
    fi
}

# Update package lists and upgrade installed packages
show_progress "Updating package lists and upgrading packages" 1 22
sudo apt-get update -qq -y > /dev/null
sudo apt-get upgrade -qq -y > /dev/null
show_success "Package lists updated and packages upgraded"

# Add the massdns repository
install_package "massdns repository" "sudo apt-get install -qq -y software-properties-common && sudo add-apt-repository -y ppa:massdns-project/prod" "command -v massdns" 2 22

# Install massdns
install_package "massdns" "sudo apt-get install -qq -y massdns" "command -v massdns" 3 22

# Install required packages
required_packages=(
    "gcc pipx python3 python3-pip nmap nodejs npm chromium-browser libpcap-dev unzip clang llvm"
)
install_cmd="sudo apt-get install -qq -y ${required_packages[*]}"
install_package "Required packages" "$install_cmd" "command -v ${required_packages[*]}" 4 22

# Install Snap packages
snap_packages=(amass rustup)
step=5
for package in "${snap_packages[@]}"; do
    install_package "$package" "sudo snap install $package" "command -v $package" $step 22
    ((step++))
done

# Install Cargo
install_package "Cargo" "sudo apt-get install -qq -y cargo" "command -v cargo" $step 22
((step++))

# Install Rust stable
install_package "Rust stable" "rustup install stable && rustup default stable" "rustup --version" $step 22
((step++))

# Install global Node.js packages
install_package "Global Node.js packages" "sudo npm install -g broken-link-checker" "command -v broken-link-checker" $step 22
((step++))

# Install Python packages
install_package "Python packages" "pipx install bbot --force" "command -v bbot" $step 22
((step++))

# Create tools directory
install_package "Tools directory" "mkdir -p ~/tools && cd ~/tools" "[ -d ~/tools ]" $step 22
((step++))

# Download and install Go
install_package "Go" "wget -q 'https://go.dev/dl/go1.22.2.linux-amd64.tar.gz' && sudo tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz && rm go1.22.2.linux-amd64.tar.gz" "command -v go" $step 22
((step++))

# Set Go environment variables
shell_config_file=""
if [ -n "$BASH_VERSION" ]; then
    shell_config_file="$HOME/.bashrc"
elif [ -n "$ZSH_VERSION" ]; then
    shell_config_file="$HOME/.zshrc"
else
    show_error "Unsupported shell environment"
    exit 1
fi

show_progress "Setting Go environment variables" $step 22
set_go_env_vars "$shell_config_file"
((step++))

# Install Go tools
go_tools=(
    "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/jaeles-project/jaeles@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/d3mondev/puredns/v2@latest"
    "github.com/Josue87/gotator@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/meg@latest"
    "github.com/hakluke/hakrawler@latest"
)

# Check if any Go tool is already installed
go_tools_installed=false
for tool in "${go_tools[@]}"; do
    if command_exists "$tool"; then
        go_tools_installed=true
        break
    fi
done

if $go_tools_installed; then
    show_success "Some Go tools are already installed"
else
    install_package "Go tools" "go install -v ${go_tools[*]} && pdtm -ia" "true" $step 22
    ((step++))
fi

# Install Findomain
install_package "Findomain" "wget -q 'https://github.com/Findomain/Findomain/releases/download/9.0.4/findomain-linux.zip' && unzip -q findomain-linux.zip && sudo mv findomain /usr/local/bin/ && rm findomain-linux.zip" "command -v findomain" $step 22
((step++))

# Install Nuclei Templates
install_package "Nuclei Templates" "git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates" "[ -d ~/nuclei-templates ]" $step 22
((step++))

# Install Python packages
install_package "Additional Python packages" "pip3 install waymore arjun" "command -v waymore && command -v arjun" $step 22
((step++))

# Install Vita
install_package "Vita" "git clone https://github.com/junnlikestea/vita && cd vita && cargo build --release && sudo cp target/release/vita /usr/local/bin/ && cd .. && rm -rf vita" "command -v vita" $step 22

echo -e "${GREEN}Installation completed successfully.${NC}"
