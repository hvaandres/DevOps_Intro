# =============================================================================
# Stage Environment Configuration
# =============================================================================

environment    = "stage"
location       = "eastus2"
project_name   = "apiplatform"

# Networking
vnet_address_space              = ["10.1.0.0/16"]
subnet_functions_prefix         = "10.1.1.0/24"
subnet_apim_prefix              = "10.1.2.0/24"
subnet_private_endpoints_prefix = "10.1.3.0/24"

# APIM — Developer SKU for staging (upgrade to Premium for VNet injection in prod)
apim_sku_name        = "Developer_1"
apim_publisher_name  = "API Platform Team"
apim_publisher_email = "api-platform-stage@example.com"

# Function App
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
