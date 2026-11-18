mock_provider "azurerm" {
  mock_resource "azurerm_key_vault_secret" {
    defaults = {
      resource_versionless_id = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-test/secrets/test-secret"
    }
  }
}

variables {
  key_vault_id = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-test"
  secret       = { name = "test-secret" }
  # Public fixture only.
  value = "mock-test-fixture"
}

run "metadata_and_role_definition_id" {
  command = apply
  variables {
    secret = {
      name            = "test-secret"
      content_type    = "text/plain"
      not_before_date = "2034-01-01T00:00:00Z"
      expiration_date = "2035-01-01T00:00:00Z"
      role_assignments = {
        application = {
          principal_id       = "44444444-4444-4444-4444-444444444444"
          role_definition_id = "/subscriptions/33333333-3333-3333-333333333333/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
        }
      }
    }
  }
  assert {
    condition     = azurerm_key_vault_secret.this.content_type == "text/plain" && azurerm_key_vault_secret.this.expiration_date == "2035-01-01T00:00:00Z"
    error_message = "Preserve configured secret metadata."
  }
  assert {
    condition     = azurerm_role_assignment.this["application"].scope == output.resource_versionless_id && startswith(output.resource_versionless_id, "/subscriptions/")
    error_message = "Scope secret roles to the versionless ARM ID."
  }
}

run "reject_empty_value" {
  command = plan
  variables {
    value = ""
  }
  expect_failures = [var.value]
}

run "reject_invalid_name" {
  command = plan
  variables {
    secret = { name = "invalid/name" }
  }
  expect_failures = [var.secret]
}

run "reject_reversed_dates" {
  command = plan
  variables {
    secret = {
      name            = "test-secret"
      not_before_date = "2035-01-01T00:00:00Z"
      expiration_date = "2034-01-01T00:00:00Z"
    }
  }
  expect_failures = [var.secret]
}

run "reject_ambiguous_secret_role" {
  command = plan
  variables {
    secret = {
      name = "test-secret"
      role_assignments = {
        invalid = {
          principal_id         = "44444444-4444-4444-4444-444444444444"
          role_definition_name = "Key Vault Secrets User"
          role_definition_id   = "/subscriptions/33333333-3333-3333-3333-333333333333/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
        }
      }
    }
  }
  expect_failures = [var.secret]
}
