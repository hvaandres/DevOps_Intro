#!/usr/bin/env bash
###############################################################################
# setup.sh — Install everything you need to work with this module
#
# Supports: macOS (Homebrew) and Linux (Ubuntu/Debian)
#
# What it installs:
#   1. Homebrew        (macOS only, if not present)
#   2. Terraform       (latest version)
#   3. Azure CLI       (latest version)
#   4. Python 3        (if not present)
#   5. jq              (JSON helper, used by scripts)
#   6. Git             (if not present)
#
# Usage:
#   chmod +x begin_journey/setup.sh
#   ./begin_journey/setup.sh
###############################################################################

set -uo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

ok()   { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }

OS="$(uname -s)"

echo "=============================================="
echo " Private Link Network — Environment Setup"
echo "=============================================="
echo ""
echo "Detected OS: ${OS}"
echo ""

###############################################################################
# 1. Package manager
###############################################################################
if [ "$OS" = "Darwin" ]; then
  if ! command -v brew &>/dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ok "Homebrew installed"
  else
    ok "Homebrew already installed"
  fi
  PKG_INSTALL="brew install"
  PKG_UPDATE="brew update"

elif [ "$OS" = "Linux" ]; then
  if command -v apt-get &>/dev/null; then
    PKG_INSTALL="sudo apt-get install -y"
    PKG_UPDATE="sudo apt-get update -y"
  else
    fail "Unsupported Linux distro. This script supports Ubuntu/Debian (apt)."
  fi
else
  fail "Unsupported OS: ${OS}. This script supports macOS and Linux."
fi

echo ""
echo "Updating package manager..."
$PKG_UPDATE 2>/dev/null
echo ""

###############################################################################
# 2. Git
###############################################################################
echo "--- Git ---"
if command -v git &>/dev/null; then
  ok "Git $(git --version | awk '{print $3}')"
else
  echo "Installing Git..."
  $PKG_INSTALL git
  ok "Git installed"
fi

###############################################################################
# 3. Terraform (latest)
###############################################################################
echo ""
echo "--- Terraform ---"
if command -v terraform &>/dev/null; then
  CURRENT_TF=$(terraform version -json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1 | awk '{print $2}')
  echo "Current version: ${CURRENT_TF}"
fi

if [ "$OS" = "Darwin" ]; then
  # Use HashiCorp tap for latest version
  brew tap hashicorp/tap 2>/dev/null
  brew install hashicorp/tap/terraform 2>/dev/null || brew upgrade hashicorp/tap/terraform 2>/dev/null
else
  # Linux — install via HashiCorp APT repo
  sudo apt-get install -y gnupg software-properties-common
  wget -O- https://apt.releases.hashicorp.com/gpg | \
    gpg --dearmor | \
    sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
    https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
    sudo tee /etc/apt/sources.list.d/hashicorp.list
  sudo apt-get update -y
  sudo apt-get install -y terraform
fi

TF_VERSION=$(terraform version -json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1)
ok "Terraform ${TF_VERSION}"

###############################################################################
# 4. Azure CLI
###############################################################################
echo ""
echo "--- Azure CLI ---"
if command -v az &>/dev/null; then
  AZ_VER=$(az version --query '"azure-cli"' -o tsv 2>/dev/null)
  echo "Current version: ${AZ_VER}"
  echo "Upgrading to latest..."
  if [ "$OS" = "Darwin" ]; then
    brew upgrade azure-cli 2>/dev/null || true
  else
    az upgrade --yes 2>/dev/null || true
  fi
else
  echo "Installing Azure CLI..."
  if [ "$OS" = "Darwin" ]; then
    brew install azure-cli
  else
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
  fi
fi
AZ_VER=$(az version --query '"azure-cli"' -o tsv 2>/dev/null)
ok "Azure CLI ${AZ_VER}"

###############################################################################
# 5. Python 3
###############################################################################
echo ""
echo "--- Python 3 ---"
if command -v python3 &>/dev/null; then
  PY_VER=$(python3 --version | awk '{print $2}')
  ok "Python ${PY_VER}"
else
  echo "Installing Python 3..."
  $PKG_INSTALL python3
  ok "Python 3 installed"
fi

###############################################################################
# 6. jq
###############################################################################
echo ""
echo "--- jq ---"
if command -v jq &>/dev/null; then
  ok "jq $(jq --version)"
else
  echo "Installing jq..."
  $PKG_INSTALL jq
  ok "jq installed"
fi

###############################################################################
# Summary
###############################################################################
echo ""
echo "=============================================="
echo " All tools installed! Versions:"
echo "=============================================="
echo ""
echo "  Git:       $(git --version | awk '{print $3}')"
echo "  Terraform: $(terraform version -json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1)"
echo "  Azure CLI: $(az version --query '"azure-cli"' -o tsv 2>/dev/null)"
echo "  Python:    $(python3 --version | awk '{print $2}')"
echo "  jq:        $(jq --version)"
echo ""
echo "=============================================="
echo " Next steps:"
echo "=============================================="
echo ""
echo "  1. az login"
echo "  2. az account set --subscription <YOUR_SUBSCRIPTION_ID>"
echo "  3. chmod +x scripts/setup-test-env.sh"
echo "  4. ./scripts/setup-test-env.sh"
echo "  5. Edit terraform.tfvars with the output values"
echo "  6. terraform init -backend-config=..."
echo "  7. terraform plan -out=tfplan"
echo "  8. terraform apply tfplan"
echo ""
echo "  See README.md for full details."
echo ""
