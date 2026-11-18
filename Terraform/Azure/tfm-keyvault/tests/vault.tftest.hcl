mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "11111111-1111-1111-1111-111111111111"
      object_id       = "22222222-2222-2222-2222-222222222222"
      subscription_id = "33333333-3333-3333-3333-333333333333"
    }
  }
  mock_data "azurerm_resource_group" {
    defaults = {
      location = "westeurope"
    }
  }
  mock_resource "azurerm_key_vault" {
    defaults = {
      id        = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-module-test"
      vault_uri = "https://kv-module-test.vault.azure.net/"
    }
  }
}

variables {
  name                = "kv-module-test"
  resource_group_name = "rg-test"
}

run "secure_defaults" {
  command = plan

  assert {
    condition     = azurerm_key_vault.this.rbac_authorization_enabled && azurerm_key_vault.this.purge_protection_enabled && azurerm_key_vault.this.soft_delete_retention_days == 90
    error_message = "RBAC, purge protection, and 90-day retention must be default."
  }
  assert {
    condition     = !azurerm_key_vault.this.public_network_access_enabled && azurerm_key_vault.this.network_acls[0].default_action == "Deny" && azurerm_key_vault.this.network_acls[0].bypass == "None"
    error_message = "Networking must default to private/deny with no bypass."
  }
  assert {
    condition     = length(module.key) == 0 && length(module.secret) == 0 && length(azurerm_private_endpoint.this) == 0 && length(azurerm_role_assignment.deployment) == 0
    error_message = "Optional objects, endpoints, and deployment grants must be absent by default."
  }
  assert {
    condition     = azurerm_key_vault.this.location == "westeurope" && azurerm_key_vault.this.tenant_id == "11111111-1111-1111-1111-111111111111"
    error_message = "Resolve location from the existing group and tenant from the caller."
  }
}

run "create_group_and_roles" {
  command = plan
  variables {
    create_resource_group = true
    location              = "northeurope"
    deployment_principal_roles = {
      secrets = "Key Vault Secrets Officer"
    }
    role_assignments = {
      reader = {
        principal_id         = "44444444-4444-4444-4444-444444444444"
        role_definition_name = "Key Vault Reader"
      }
      secret_reader = {
        principal_id       = "55555555-5555-5555-5555-555555555555"
        role_definition_id = "/subscriptions/33333333-3333-3333-3333-333333333333/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
      }
    }
  }
  assert {
    condition     = length(azurerm_resource_group.this) == 1 && length(data.azurerm_resource_group.existing) == 0 && azurerm_key_vault.this.location == "northeurope"
    error_message = "Create a resource group instead of looking one up."
  }
  assert {
    condition     = azurerm_role_assignment.deployment["secrets"].principal_id == "22222222-2222-2222-2222-222222222222" && length(azurerm_role_assignment.vault) == 2
    error_message = "Resolve the deployment identity and support role names and IDs."
  }
}

run "private_endpoint_configuration" {
  command = plan
  variables {
    private_endpoints = {
      application = {
        name                 = "pe-keyvault"
        subnet_id            = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/endpoints"
        private_dns_zone_ids = ["/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-network/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"]
      }
      external_dns = {
        name      = "pe-external-dns"
        subnet_id = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/endpoints"
      }
    }
  }
  assert {
    condition     = azurerm_private_endpoint.this["application"].name == "pe-keyvault" && length(azurerm_private_endpoint.this["application"].private_dns_zone_group) == 1
    error_message = "Configure each named private endpoint and DNS group."
  }
  assert {
    condition     = azurerm_private_endpoint.this["application"].private_service_connection[0].subresource_names[0] == "vault" && length(azurerm_private_endpoint.this["external_dns"].private_dns_zone_group) == 0
    error_message = "Use the vault subresource and support externally managed DNS."
  }
}

run "compose_keys_and_secrets" {
  command = apply
  variables {
    keys = {
      encryption = { name = "app-encryption" }
    }
    secrets = {
      password = { name = "app-password", content_type = "text/plain" }
    }
    # Deliberately public test fixture, not a credential.
    secret_values = { password = "mock-test-fixture" }
  }
  assert {
    condition     = length(output.keys) == 1 && length(output.secrets) == 1
    error_message = "Compose both object submodules using stable metadata keys."
  }
  assert {
    condition     = toset(keys(output.secrets["password"])) == toset(["id", "versionless_id", "resource_versionless_id", "version"])
    error_message = "Secret outputs must contain references only, never values."
  }
}

run "reject_invalid_name" {
  command = plan
  variables {
    name = "kv--invalid"
  }
  expect_failures = [var.name]
}

run "reject_invalid_retention" {
  command = plan
  variables {
    soft_delete_retention_days = 6
  }
  expect_failures = [var.soft_delete_retention_days]
}

run "reject_ambiguous_role" {
  command = plan
  variables {
    role_assignments = {
      invalid = {
        principal_id         = "44444444-4444-4444-4444-444444444444"
        role_definition_name = "Key Vault Reader"
        role_definition_id   = "/subscriptions/33333333-3333-3333-3333-333333333333/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
      }
    }
  }
  expect_failures = [var.role_assignments]
}

run "reject_hsm_on_standard_vault" {
  command = plan
  variables {
    keys = {
      encryption = { name = "hsm-key", key_type = "RSA-HSM" }
    }
  }
  expect_failures = [azurerm_key_vault.this]
}

run "reject_missing_group_location" {
  command = plan
  variables {
    create_resource_group = true
  }
  expect_failures = [azurerm_resource_group.this]
}

run "reject_duplicate_key_names" {
  command = plan
  variables {
    keys = {
      first  = { name = "same-key" }
      second = { name = "SAME-KEY" }
    }
  }
  expect_failures = [var.keys]
}

run "reject_duplicate_secret_names" {
  command = plan
  variables {
    secrets = {
      first  = { name = "same-secret" }
      second = { name = "SAME-SECRET" }
    }
    secret_values = { first = "mock-first", second = "mock-second" }
  }
  expect_failures = [var.secrets]
}

run "reject_missing_secret_value" {
  command = plan
  variables {
    secrets = {
      password = { name = "app-password" }
    }
  }
  override_module {
    target = module.secret["password"]
    outputs = {
      id                      = "mock-id"
      versionless_id          = "mock-uri"
      resource_versionless_id = "mock-arm-id"
      version                 = "mock-version"
    }
  }
  expect_failures = [azurerm_key_vault.this]
}
