mock_provider "azurerm" {}

variables {
  vault_name          = "kv-complete-test"
  resource_group_name = "rg-complete-test"
  create_objects      = false
}

run "network_only_first_stage" {
  command = plan
  assert {
    condition     = length(module.keyvault.keys) == 0 && length(module.keyvault.secrets) == 0
    error_message = "The first stage must not create data-plane objects before runner connectivity."
  }
  assert {
    condition     = azurerm_private_dns_zone.keyvault.name == "privatelink.vaultcore.azure.net" && !azurerm_private_dns_zone_virtual_network_link.this.registration_enabled
    error_message = "Use the correct Key Vault private zone and a non-registering VNet link."
  }
}

run "objects_require_password" {
  command = plan
  variables {
    create_objects         = true
    key_expiration_date    = "2035-01-01T00:00:00Z"
    secret_expiration_date = "2035-01-01T00:00:00Z"
  }
  expect_failures = [var.database_password]
}

run "complete_object_configuration" {
  command = plan
  variables {
    create_objects         = true
    database_password      = "public-mock-fixture"
    key_expiration_date    = "2035-01-01T00:00:00Z"
    secret_expiration_date = "2035-01-01T00:00:00Z"
  }
  assert {
    condition     = length(module.keyvault.keys) == 1 && length(module.keyvault.secrets) == 1
    error_message = "The complete scenario must configure both keys and secrets."
  }
}
