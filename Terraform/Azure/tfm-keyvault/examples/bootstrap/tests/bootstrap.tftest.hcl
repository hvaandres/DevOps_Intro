mock_provider "azurerm" {}

variables {
  storage_account_name         = "stmockkeyvaultstate"
  state_resource_group_name    = "rg-state"
  workload_resource_group_name = "rg-workload"
  deployment_principal_id      = "44444444-4444-4444-4444-444444444444"
  allowed_ipv4_cidrs           = ["203.0.113.10"]
}

run "state_storage_security" {
  command = plan
  assert {
    condition     = azurerm_storage_container.state.name == "tfstate" && azurerm_storage_container.state.container_access_type == "private"
    error_message = "Use the required tfstate container with private blob access."
  }
  assert {
    condition     = !azurerm_storage_account.state.shared_access_key_enabled && !azurerm_storage_account.state.allow_nested_items_to_be_public && azurerm_storage_account.state.min_tls_version == "TLS1_2"
    error_message = "Disable shared keys/public blobs and enforce TLS 1.2."
  }
  assert {
    condition     = azurerm_storage_account.state.blob_properties[0].versioning_enabled && azurerm_storage_account.state.blob_properties[0].delete_retention_policy[0].days == 30
    error_message = "State recovery requires versioning and soft deletion."
  }
  assert {
    condition     = azurerm_storage_account.state.network_rules[0].default_action == "Deny" && azurerm_role_assignment.state.role_definition_name == "Storage Blob Data Contributor"
    error_message = "Restrict networking and grant the deployment identity blob data permissions."
  }
}

run "reject_empty_allowlist" {
  command = plan
  variables {
    allowed_ipv4_cidrs = []
  }
  expect_failures = [var.allowed_ipv4_cidrs]
}
