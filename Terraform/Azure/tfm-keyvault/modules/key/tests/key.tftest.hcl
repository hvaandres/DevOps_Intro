mock_provider "azurerm" {
  mock_resource "azurerm_key_vault_key" {
    defaults = {
      resource_versionless_id = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-test/keys/test-key"
    }
  }
}

variables {
  key_vault_id = "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-test/providers/Microsoft.KeyVault/vaults/kv-test"
  key          = { name = "test-key" }
}

run "rsa_defaults" {
  command = plan
  assert {
    condition     = azurerm_key_vault_key.this.key_type == "RSA" && azurerm_key_vault_key.this.key_size == 2048 && length(azurerm_key_vault_key.this.rotation_policy) == 0
    error_message = "RSA defaults should work without a rotation policy."
  }
}

run "ec_configuration" {
  command = plan
  variables {
    key = { name = "ec-signing", key_type = "EC", curve = "P-384", key_opts = ["sign", "verify"] }
  }
  assert {
    condition     = azurerm_key_vault_key.this.curve == "P-384" && azurerm_key_vault_key.this.key_size == null
    error_message = "EC keys must use the configured curve, not an RSA size."
  }
}

run "rotation_and_arm_rbac_scope" {
  command = apply
  variables {
    tags = { environment = "test", owner = "platform" }
    key = {
      name            = "test-key"
      expiration_date = "2035-02-01T00:00:00Z"
      tags            = { owner = "application" }
      rotation_policy = {
        expire_after         = "P90D"
        notify_before_expiry = "P29D"
        automatic = {
          time_before_expiry = "P30D"
        }
      }
      role_assignments = {
        application = {
          principal_id         = "44444444-4444-4444-4444-444444444444"
          role_definition_name = "Key Vault Crypto User"
        }
      }
    }
  }
  assert {
    condition     = azurerm_key_vault_key.this.rotation_policy[0].automatic[0].time_before_expiry == "P30D" && azurerm_key_vault_key.this.tags["owner"] == "application"
    error_message = "Preserve rotation timing and object tag overrides."
  }
  assert {
    condition     = azurerm_role_assignment.this["application"].scope == output.resource_versionless_id && startswith(azurerm_role_assignment.this["application"].scope, "/subscriptions/")
    error_message = "Key RBAC scope must be the versionless ARM ID, not an HTTPS URI."
  }
}

run "reject_weak_rsa" {
  command = plan
  variables {
    key = { name = "test-key", key_size = 1024 }
  }
  expect_failures = [var.key]
}

run "reject_ambiguous_rotation" {
  command = plan
  variables {
    key = {
      name            = "test-key"
      expiration_date = "2035-02-01T00:00:00Z"
      rotation_policy = {
        automatic = { time_after_creation = "P60D", time_before_expiry = "P30D" }
      }
    }
  }
  expect_failures = [var.key]
}

run "reject_rotation_without_expiration" {
  command = plan
  variables {
    key = {
      name = "test-key"
      rotation_policy = {
        automatic = { time_before_expiry = "P30D" }
      }
    }
  }
  expect_failures = [var.key]
}

run "reject_invalid_key_role" {
  command = plan
  variables {
    key = {
      name = "test-key"
      role_assignments = {
        invalid = { principal_id = "44444444-4444-4444-4444-444444444444" }
      }
    }
  }
  expect_failures = [var.key]
}
