# =============================================================================
# Production Environment Configuration
# =============================================================================

environment    = "prod"
location       = "eastus2"
project_name   = "apiplatform"

# Networking — separate address space from dev/stage
vnet_address_space              = ["10.2.0.0/16"]
subnet_functions_prefix         = "10.2.1.0/24"
subnet_apim_prefix              = "10.2.2.0/24"
subnet_private_endpoints_prefix = "10.2.3.0/24"

# APIM — Premium SKU for production (VNet injection, SLA, multi-region)
apim_sku_name        = "Premium_1"
apim_publisher_name  = "API Platform Team"
apim_publisher_email = "api-platform-prod@example.com"

# Function App — larger SKU for production workloads
function_app_sku = {
  tier = "ElasticPremium"
  size = "EP2"
}
function_python_version = "3.11"

# Tags
tags = {
  cost_center  = "engineering"
  owner        = "platform-team"
  compliance   = "soc2"
  data_class   = "confidential"
}
