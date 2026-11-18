resource "azurerm_resource_group" "network" {
  name     = "${var.resource_group_name}-network"
  location = var.location
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-keyvault"
  location            = azurerm_resource_group.network.location
  resource_group_name = azurerm_resource_group.network.name
  address_space       = [var.vnet_address_space]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.network.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.private_endpoint_subnet_prefix]
}

resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.network.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  name                  = "keyvault-vnet-link"
  resource_group_name   = azurerm_resource_group.network.name
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.this.id
  registration_enabled  = false
}

resource "azurerm_user_assigned_identity" "application" {
  name                = "id-keyvault-application"
  location            = var.location
  resource_group_name = azurerm_resource_group.network.name
}

module "keyvault" {
  source = "../.."

  name                  = var.vault_name
  resource_group_name   = var.resource_group_name
  create_resource_group = true
  location              = var.location

  # Needed before Terraform can create keys/secrets. Azure role propagation may
  # still require a retry; dependencies do not guarantee immediate authorization.
  deployment_principal_roles = var.create_objects ? {
    keys    = "Key Vault Crypto Officer"
    secrets = "Key Vault Secrets Officer"
  } : {}

  private_endpoints = {
    application = {
      name                 = "pe-${var.vault_name}"
      subnet_id            = azurerm_subnet.private_endpoints.id
      private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
    }
  }

  keys = var.create_objects ? {
    encryption = {
      name            = "application-encryption"
      key_type        = "RSA"
      key_size        = 3072
      key_opts        = ["wrapKey", "unwrapKey"]
      expiration_date = var.key_expiration_date
      rotation_policy = {
        expire_after         = "P90D"
        notify_before_expiry = "P29D"
        automatic = {
          time_before_expiry = "P30D"
        }
      }
      role_assignments = {
        application = {
          principal_id         = azurerm_user_assigned_identity.application.principal_id
          principal_type       = "ServicePrincipal"
          role_definition_name = "Key Vault Crypto Service Encryption User"
        }
      }
    }
  } : {}

  secrets = var.create_objects ? {
    database_password = {
      name            = "database-password"
      content_type    = "text/plain"
      expiration_date = var.secret_expiration_date
      role_assignments = {
        application = {
          principal_id   = azurerm_user_assigned_identity.application.principal_id
          principal_type = "ServicePrincipal"
          # Key Vault Secrets User, expressed as a fully qualified role ID.
          role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
        }
      }
    }
  } : {}
  secret_values = var.create_objects ? { database_password = var.database_password } : {}

  tags = {
    environment = "production"
    managed_by  = "terraform"
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]
}
