resource "azurerm_key_vault_secret" "this" {
  name            = var.secret.name
  value           = var.value
  key_vault_id    = var.key_vault_id
  content_type    = var.secret.content_type
  expiration_date = var.secret.expiration_date
  not_before_date = var.secret.not_before_date
  tags            = merge(var.tags, var.secret.tags)
}

resource "azurerm_role_assignment" "this" {
  for_each = var.secret.role_assignments

  scope                            = azurerm_key_vault_secret.this.resource_versionless_id
  principal_id                     = each.value.principal_id
  role_definition_name             = lookup(each.value, "role_definition_name", null)
  role_definition_id               = lookup(each.value, "role_definition_id", null)
  principal_type                   = each.value.principal_type
  skip_service_principal_aad_check = each.value.skip_service_principal_aad_check
}
