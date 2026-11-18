data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "existing" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

resource "azurerm_resource_group" "this" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags

  lifecycle {
    precondition {
      condition     = var.location != null
      error_message = "location is required when create_resource_group is true."
    }
  }
}

locals {
  resource_group_name = var.create_resource_group ? azurerm_resource_group.this[0].name : data.azurerm_resource_group.existing[0].name
  location            = coalesce(var.location, var.create_resource_group ? azurerm_resource_group.this[0].location : data.azurerm_resource_group.existing[0].location)
  tenant_id           = coalesce(var.tenant_id, data.azurerm_client_config.current.tenant_id)
}

resource "azurerm_key_vault" "this" {
  name                          = var.name
  resource_group_name           = local.resource_group_name
  location                      = local.location
  tenant_id                     = local.tenant_id
  sku_name                      = var.sku_name
  rbac_authorization_enabled    = true
  purge_protection_enabled      = var.purge_protection_enabled
  soft_delete_retention_days    = var.soft_delete_retention_days
  public_network_access_enabled = var.public_network_access_enabled
  tags                          = var.tags

  network_acls {
    bypass                     = var.network_acls.bypass
    default_action             = var.network_acls.default_action
    ip_rules                   = var.network_acls.ip_rules
    virtual_network_subnet_ids = var.network_acls.virtual_network_subnet_ids
  }

  lifecycle {
    precondition {
      condition     = var.sku_name == "premium" || alltrue([for key in values(var.keys) : !endswith(key.key_type, "-HSM")])
      error_message = "HSM-backed keys require sku_name = premium."
    }
    precondition {
      condition     = alltrue([for name in keys(var.secrets) : contains(keys(var.secret_values), name)])
      error_message = "secret_values must contain a value for every logical key in secrets."
    }
  }
}
