#!/usr/bin/env bash
# =============================================================================
# Bootstrap Terraform Remote Backend
# Creates an Azure Storage Account + container for Terraform state.
# Run this ONCE before the first `terraform init`.
# =============================================================================
set -euo pipefail

# Configuration — adjust these values
RESOURCE_GROUP="rg-terraform-state"
LOCATION="eastus2"
STORAGE_ACCOUNT="sttfstateapiplatform"
CONTAINER_NAME="tfstate"

echo "==> Creating resource group: $RESOURCE_GROUP"
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

echo "==> Creating storage account: $STORAGE_ACCOUNT"
az storage account create \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku "Standard_LRS" \
  --kind "StorageV2" \
  --min-tls-version "TLS1_2" \
  --allow-blob-public-access false \
  --output none

echo "==> Creating blob container: $CONTAINER_NAME"
az storage container create \
  --name "$CONTAINER_NAME" \
  --account-name "$STORAGE_ACCOUNT" \
  --auth-mode login \
  --output none

echo "==> Enabling versioning for state recovery"
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-versioning true \
  --output none

echo "==> Enabling soft delete (14 days) for state protection"
az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-delete-retention true \
  --delete-retention-days 14 \
  --output none

echo ""
echo "✅ Terraform backend ready!"
echo "   Resource Group:   $RESOURCE_GROUP"
echo "   Storage Account:  $STORAGE_ACCOUNT"
echo "   Container:        $CONTAINER_NAME"
echo ""
echo "Update terraform/backend.tf with these values if different."
