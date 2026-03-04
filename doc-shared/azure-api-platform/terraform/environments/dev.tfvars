# =============================================================================
# Dev Environment Configuration
# =============================================================================

environment    = "dev"
location       = "eastus2"
project_name   = "apiplatform"

# Azure credentials — override via environment variables or CI/CD secrets
# subscription_id = ""
# tenant_id       = ""

# Networking
vnet_address_space              = ["10.0.0.0/16"]
subnet_functions_prefix         = "10.0.1.0/24"
subnet_apim_prefix              = "10.0.2.0/24"
subnet_private_endpoints_prefix = "10.0.3.0/24"

# APIM — Developer SKU for dev (cheaper, no SLA)
apim_sku_name      = "Developer_1"
apim_publisher_name  = "API Platform Team"
apim_publisher_email = "api-platform-dev@example.com"

# Function App — smaller SKU for dev
function_app_sku = {
  tier = "ElasticPremium"
  size = "EP1"
}
function_python_version = "3.11"

# Tags
tags = {
  cost_center = "engineering"
  owner       = "platform-team"
}
