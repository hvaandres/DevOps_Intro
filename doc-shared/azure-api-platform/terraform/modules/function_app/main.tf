# =============================================================================
# App Service Plan (Elastic Premium for VNet integration)
# =============================================================================
resource "azurerm_service_plan" "this" {
  name                = "asp-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = "Linux"
  sku_name            = var.sku_size

  tags = var.tags
}

# =============================================================================
# Function App (Python v2 programming model)
# =============================================================================
resource "azurerm_linux_function_app" "this" {
  name                       = "func-${var.name_prefix}"
  resource_group_name        = var.resource_group_name
  location                   = var.location
  service_plan_id            = azurerm_service_plan.this.id
  storage_account_name       = var.storage_account_name
  storage_account_access_key = var.storage_account_access_key

  # VNet integration
  virtual_network_subnet_id = var.subnet_id

  # Restrict public access — APIM routes traffic over VNet
  public_network_access_enabled = false

  # Enable system-assigned managed identity
  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on                              = true
    ftps_state                             = "Disabled"
    http2_enabled                          = true
    minimum_tls_version                    = "1.2"
    vnet_route_all_enabled                 = true
    application_insights_key               = var.application_insights_key
    application_insights_connection_string = var.application_insights_connection_string

    application_stack {
      python_version = var.python_version
    }

    # Increase response buffering for large data transfers
    cors {
      allowed_origins = ["https://*.azure-api.net"]
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME"       = "python"
    "AzureWebJobsFeatureFlags"       = "EnableWorkerIndexing"
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    # Data source connection strings injected via Key Vault references or env vars
  }

  tags = var.tags
}
