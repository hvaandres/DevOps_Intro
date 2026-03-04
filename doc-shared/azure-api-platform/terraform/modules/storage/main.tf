# =============================================================================
# Storage Account (Blob + Data Lake Gen2)
# =============================================================================
resource "azurerm_storage_account" "this" {
  name                     = "st${var.name_prefix}${var.environment}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = var.replication_type
  account_kind             = "StorageV2"
  is_hns_enabled           = var.enable_data_lake # Data Lake Gen2
  min_tls_version          = "TLS1_2"

  # Deny public access — only via private endpoint
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled = true
  }

  tags = var.tags
}

# =============================================================================
# Data container
# =============================================================================
resource "azurerm_storage_container" "data" {
  name                  = "data"
  storage_account_name  = azurerm_storage_account.this.name
  container_access_type = "private"
}

# =============================================================================
# Private Endpoint for Blob
# =============================================================================
resource "azurerm_private_endpoint" "blob" {
  name                = "pe-blob-${var.name_prefix}-${var.environment}"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-blob"
    private_connection_resource_id = azurerm_storage_account.this.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }
}

# =============================================================================
# Private DNS Zone for Blob
# =============================================================================
resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "link-blob-${var.name_prefix}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false
}

# =============================================================================
# Diagnostic Settings
# =============================================================================
resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "diag-storage-${var.name_prefix}"
  target_resource_id         = "${azurerm_storage_account.this.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  metric {
    category = "Transaction"
    enabled  = true
  }
}
