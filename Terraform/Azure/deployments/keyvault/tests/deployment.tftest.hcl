mock_provider "azurerm" {
  mock_data "azurerm_resource_group" {
    defaults = {
      location = "westeurope"
    }
  }
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id = "11111111-1111-1111-1111-111111111111"
    }
  }
}

variables {
  vault_name          = "kv-deployment-test"
  resource_group_name = "rg-deployment-test"
}

run "private_vault_without_objects" {
  command = plan

  assert {
    condition     = length(module.keyvault.keys) == 0 && length(module.keyvault.secrets) == 0
    error_message = "The pipeline root must not create secret values or keys implicitly."
  }
}
