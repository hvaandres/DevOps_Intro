module "secret" {
  source   = "./modules/secret"
  for_each = var.secrets

  key_vault_id = azurerm_key_vault.this.id
  secret       = each.value
  value        = lookup(var.secret_values, each.key, null)
  tags         = var.tags

  depends_on = [
    azurerm_role_assignment.deployment,
    azurerm_role_assignment.vault,
    azurerm_private_endpoint.this,
  ]
}
