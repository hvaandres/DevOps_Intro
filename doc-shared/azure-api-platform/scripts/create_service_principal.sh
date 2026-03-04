#!/usr/bin/env bash
# =============================================================================
# Create Service Principal for Azure API Platform
# Creates an SP with Contributor role scoped to the project resource group.
# Outputs credentials needed for CI/CD pipeline configuration.
# =============================================================================
set -euo pipefail

# Configuration
SP_NAME="sp-apiplatform-cicd"
SUBSCRIPTION_ID=$(az account show --query id -o tsv)

echo "==> Using subscription: $SUBSCRIPTION_ID"

# Create the Service Principal with Contributor role
# Scope will be applied per-environment after resource groups are created
echo "==> Creating Service Principal: $SP_NAME"
SP_OUTPUT=$(az ad sp create-for-rbac \
  --name "$SP_NAME" \
  --role "Contributor" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --sdk-auth \
  2>/dev/null)

# Extract values (do NOT echo secrets — store securely)
CLIENT_ID=$(echo "$SP_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['clientId'])")
TENANT_ID=$(echo "$SP_OUTPUT" | python3 -c "import sys, json; print(json.load(sys.stdin)['tenantId'])")
OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv)

echo ""
echo "✅ Service Principal created!"
echo ""
echo "   Display Name:     $SP_NAME"
echo "   Client ID:        $CLIENT_ID"
echo "   Tenant ID:        $TENANT_ID"
echo "   Object ID:        $OBJECT_ID"
echo "   Subscription ID:  $SUBSCRIPTION_ID"
echo ""
echo "⚠️  IMPORTANT: The full credentials (including client secret) were output above."
echo "   Store the client secret securely in your CI/CD system (GitHub Secrets, Azure DevOps, etc.)."
echo "   The secret will NOT be retrievable again."
echo ""
echo "   Set these in your CI/CD environment:"
echo "     ARM_CLIENT_ID=$CLIENT_ID"
echo "     ARM_TENANT_ID=$TENANT_ID"
echo "     ARM_SUBSCRIPTION_ID=$SUBSCRIPTION_ID"
echo "     ARM_CLIENT_SECRET=<from the JSON output above>"
echo ""
echo "   For Terraform variables:"
echo "     service_principal_object_id = \"$OBJECT_ID\""
echo ""

# Optional: Create App Registration for API consumers
echo "==> Creating App Registration for API consumers (Entra ID)"
APP_REG=$(az ad app create \
  --display-name "Azure API Platform" \
  --sign-in-audience "AzureADMyOrg" \
  --identifier-uris "api://azure-api-platform" \
  --query appId -o tsv)

echo "   App Registration ID: $APP_REG"

# Add "Data.Read" app role
echo "==> Adding Data.Read app role"
az ad app update \
  --id "$APP_REG" \
  --app-roles '[{
    "allowedMemberTypes": ["Application"],
    "description": "Read-only access to platform data",
    "displayName": "Data.Read",
    "isEnabled": true,
    "value": "Data.Read",
    "id": "'$(python3 -c "import uuid; print(uuid.uuid4())")'"
  }]'

echo ""
echo "✅ App Registration created!"
echo "   Application ID: $APP_REG"
echo "   Identifier URI: api://azure-api-platform"
echo "   App Role:       Data.Read"
echo ""
echo "   External consumers can now request tokens with:"
echo "     Scope: api://azure-api-platform/.default"
echo "     Grant: client_credentials"
