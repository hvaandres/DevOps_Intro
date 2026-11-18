resource "azurerm_key_vault_key" "this" {
  name            = var.key.name
  key_vault_id    = var.key_vault_id
  key_type        = var.key.key_type
  key_size        = startswith(var.key.key_type, "RSA") ? var.key.key_size : null
  curve           = startswith(var.key.key_type, "EC") ? var.key.curve : null
  key_opts        = var.key.key_opts
  expiration_date = var.key.expiration_date
  not_before_date = var.key.not_before_date
  tags            = merge(var.tags, var.key.tags)

  dynamic "rotation_policy" {
    for_each = var.key.rotation_policy == null ? [] : [var.key.rotation_policy]
    content {
      expire_after         = rotation_policy.value.expire_after
      notify_before_expiry = rotation_policy.value.notify_before_expiry

      dynamic "automatic" {
        for_each = rotation_policy.value.automatic == null ? [] : [rotation_policy.value.automatic]
        content {
          time_after_creation = automatic.value.time_after_creation
          time_before_expiry  = automatic.value.time_before_expiry
        }
      }
    }
  }
}

resource "azurerm_role_assignment" "this" {
  for_each = var.key.role_assignments

  scope                            = azurerm_key_vault_key.this.resource_versionless_id
  principal_id                     = each.value.principal_id
  role_definition_name             = lookup(each.value, "role_definition_name", null)
  role_definition_id               = lookup(each.value, "role_definition_id", null)
  principal_type                   = each.value.principal_type
  skip_service_principal_aad_check = each.value.skip_service_principal_aad_check
}
