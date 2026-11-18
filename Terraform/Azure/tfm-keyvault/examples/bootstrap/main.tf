resource "azurerm_resource_group" "state" {
  name     = var.state_resource_group_name
  location = var.location
}

resource "azurerm_resource_group" "workload" {
  name     = var.workload_resource_group_name
  location = var.location
}

resource "azurerm_storage_account" "state" {
  name                            = var.storage_account_name
  resource_group_name             = azurerm_resource_group.state.name
  location                        = azurerm_resource_group.state.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["None"]
    ip_rules       = var.allowed_ipv4_cidrs
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container" "state" {
  name                  = "tfstate"
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "state" {
  scope                = azurerm_storage_container.state.id
  principal_id         = var.deployment_principal_id
  principal_type       = "ServicePrincipal"
  role_definition_name = "Storage Blob Data Contributor"
}

resource "azurerm_role_assignment" "workload" {
  for_each = toset(["Contributor", "Role Based Access Control Administrator"])

  scope                = azurerm_resource_group.workload.id
  principal_id         = var.deployment_principal_id
  principal_type       = "ServicePrincipal"
  role_definition_name = each.value
}
