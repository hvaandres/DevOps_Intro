#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# setup-test-env.sh
#
# Creates the test prerequisites for the Private Link Network module:
#   1. Backend storage account for Terraform state
#   2. Hub resource group + VNet
#   3. (Optional) Spoke resource group + VNet
#
# Usage:
#   chmod +x scripts/setup-test-env.sh
#   ./scripts/setup-test-env.sh
#
# After running, copy the output values into terraform.tfvars.
###############################################################################

LOCATION="eastus2"
ENVIRONMENT="dev"
SUFFIX=$(openssl rand -hex 3)  # random suffix for globally unique names

# --- Backend Storage ---
TF_STATE_RG="rg-terraform-state-${ENVIRONMENT}"
TF_STATE_SA="stterraformstate${SUFFIX}"
TF_STATE_CONTAINER="tfstate-private-dns"

# --- Hub ---
HUB_RG="rg-hub-networking-${ENVIRONMENT}"
HUB_VNET="vnet-hub-${ENVIRONMENT}"
HUB_VNET_CIDR="10.0.0.0/16"

# --- Spoke (optional — comment out if not needed) ---
SPOKE_RG="rg-spoke-${ENVIRONMENT}"
SPOKE_VNET="vnet-spoke-${ENVIRONMENT}"
SPOKE_VNET_CIDR="10.1.0.0/16"

echo "=============================================="
echo " Setting up test environment in ${LOCATION}"
echo "=============================================="

# Get current subscription
SUB_ID=$(az account show --query id -o tsv)
echo "Subscription: ${SUB_ID}"

###############################################################################
# 1. Backend Storage Account
###############################################################################
echo ""
echo ">>> Creating Terraform backend storage..."

az group create --name "${TF_STATE_RG}" --location "${LOCATION}" --output none
az storage account create \
  --name "${TF_STATE_SA}" \
  --resource-group "${TF_STATE_RG}" \
  --location "${LOCATION}" \
  --sku Standard_LRS \
  --min-tls-version TLS1_2 \
  --output none

az storage container create \
  --name "${TF_STATE_CONTAINER}" \
  --account-name "${TF_STATE_SA}" \
  --output none

echo "    Storage account: ${TF_STATE_SA}"
echo "    Container:       ${TF_STATE_CONTAINER}"

###############################################################################
# 2. Hub VNet
###############################################################################
echo ""
echo ">>> Creating Hub VNet..."

az group create --name "${HUB_RG}" --location "${LOCATION}" --output none
az network vnet create \
  --name "${HUB_VNET}" \
  --resource-group "${HUB_RG}" \
  --location "${LOCATION}" \
  --address-prefixes "${HUB_VNET_CIDR}" \
  --output none

HUB_VNET_ID=$(az network vnet show \
  --name "${HUB_VNET}" \
  --resource-group "${HUB_RG}" \
  --query id -o tsv)

echo "    VNet name: ${HUB_VNET}"
echo "    VNet ID:   ${HUB_VNET_ID}"

###############################################################################
# 3. Spoke VNet (optional)
###############################################################################
echo ""
echo ">>> Creating Spoke VNet..."

az group create --name "${SPOKE_RG}" --location "${LOCATION}" --output none
az network vnet create \
  --name "${SPOKE_VNET}" \
  --resource-group "${SPOKE_RG}" \
  --location "${LOCATION}" \
  --address-prefixes "${SPOKE_VNET_CIDR}" \
  --output none

SPOKE_VNET_ID=$(az network vnet show \
  --name "${SPOKE_VNET}" \
  --resource-group "${SPOKE_RG}" \
  --query id -o tsv)

echo "    VNet name: ${SPOKE_VNET}"
echo "    VNet ID:   ${SPOKE_VNET_ID}"

###############################################################################
# Output — copy these into terraform.tfvars
###############################################################################
echo ""
echo "=============================================="
echo " DONE — Copy these into terraform.tfvars"
echo "=============================================="
echo ""
cat <<EOF
# --- terraform init backend config ---
# terraform init \\
#   -backend-config="resource_group_name=${TF_STATE_RG}" \\
#   -backend-config="storage_account_name=${TF_STATE_SA}" \\
#   -backend-config="container_name=${TF_STATE_CONTAINER}" \\
#   -backend-config="key=privatelink-network.tfstate"

# --- terraform.tfvars ---
hub_subscription_id     = "${SUB_ID}"
hub_vnet_id             = "${HUB_VNET_ID}"
hub_vnet_name           = "${HUB_VNET}"
hub_resource_group_name = "${HUB_RG}"

# Uncomment to test peering:
# spokes = {
#   spoke-dev = {
#     vnet_id             = "${SPOKE_VNET_ID}"
#     vnet_name           = "${SPOKE_VNET}"
#     resource_group_name = "${SPOKE_RG}"
#   }
# }
EOF
