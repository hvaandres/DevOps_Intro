# =============================================================================
# Root Module — Azure API Platform
# =============================================================================

# -----------------------------------------------------------------------------
# Resource Group
# -----------------------------------------------------------------------------
module "resource_group" {
  source = "./modules/resource_group"

  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.common_tags
}

# -----------------------------------------------------------------------------
# Monitoring (deploy early — other modules reference the workspace)
# -----------------------------------------------------------------------------
module "monitoring" {
  source = "./modules/monitoring"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  name_prefix         = local.name_prefix
  tags                = local.common_tags
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
module "networking" {
  source = "./modules/networking"

  resource_group_name             = module.resource_group.name
  location                        = module.resource_group.location
  name_prefix                     = local.name_prefix
  vnet_address_space              = var.vnet_address_space
  subnet_functions_prefix         = var.subnet_functions_prefix
  subnet_apim_prefix              = var.subnet_apim_prefix
  subnet_private_endpoints_prefix = var.subnet_private_endpoints_prefix
  tags                            = local.common_tags
}

# -----------------------------------------------------------------------------
# Storage (Blob / Data Lake)
# -----------------------------------------------------------------------------
module "storage" {
  source = "./modules/storage"

  resource_group_name  = module.resource_group.name
  location             = module.resource_group.location
  name_prefix          = var.project_name
  environment          = var.environment
  subnet_id            = module.networking.private_endpoints_subnet_id
  vnet_id              = module.networking.vnet_id
  log_analytics_id     = module.monitoring.log_analytics_workspace_id
  tags                 = local.common_tags
}

# -----------------------------------------------------------------------------
# Function App
# -----------------------------------------------------------------------------
module "function_app" {
  source = "./modules/function_app"

  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  name_prefix                = local.name_prefix
  sku_tier                   = var.function_app_sku.tier
  sku_size                   = var.function_app_sku.size
  python_version             = var.function_python_version
  subnet_id                  = module.networking.functions_subnet_id
  storage_account_name       = module.storage.storage_account_name
  storage_account_access_key = module.storage.storage_account_primary_access_key
  application_insights_key   = module.monitoring.application_insights_instrumentation_key
  application_insights_connection_string = module.monitoring.application_insights_connection_string
  tags                       = local.common_tags
}

# -----------------------------------------------------------------------------
# API Management
# -----------------------------------------------------------------------------
module "apim" {
  source = "./modules/apim"

  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  name_prefix         = local.name_prefix
  sku_name            = var.apim_sku_name
  publisher_name      = var.apim_publisher_name
  publisher_email     = var.apim_publisher_email
  subnet_id           = module.networking.apim_subnet_id
  function_app_url    = module.function_app.default_hostname
  function_app_key    = module.function_app.default_function_key
  log_analytics_id    = module.monitoring.log_analytics_workspace_id
  tenant_id           = var.tenant_id
  tags                = local.common_tags
}

# -----------------------------------------------------------------------------
# Identity & RBAC
# -----------------------------------------------------------------------------
module "identity" {
  source = "./modules/identity"

  resource_group_id           = module.resource_group.id
  function_app_identity_id    = module.function_app.identity_principal_id
  storage_account_id          = module.storage.storage_account_id
  service_principal_object_id = var.service_principal_object_id
}
