# This module uses Azure RBAC exclusively, not legacy Key Vault access policies.
resource "azurerm_role_assignment" "vault" {
  for_each = var.role_assignments

  scope                            = azurerm_key_vault.this.id
  principal_id                     = each.value.principal_id
  role_definition_name             = lookup(each.value, "role_definition_name", null)
  role_definition_id               = lookup(each.value, "role_definition_id", null)
  principal_type                   = each.value.principal_type
  skip_service_principal_aad_check = each.value.skip_service_principal_aad_check
}

# Explicit opt-in only. These roles allow the deployment identity to manage
# objects; assignments on the objects themselves cannot authorize their creation.
resource "azurerm_role_assignment" "deployment" {
  for_each = var.deployment_principal_roles

  scope                = azurerm_key_vault.this.id
  principal_id         = coalesce(var.deployment_principal_id, data.azurerm_client_config.current.object_id)
  role_definition_name = each.value
  principal_type       = "ServicePrincipal"
}
