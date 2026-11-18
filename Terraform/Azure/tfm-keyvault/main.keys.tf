module "key" {
  source   = "./modules/key"
  for_each = var.keys

  key_vault_id = azurerm_key_vault.this.id
  key          = each.value
  tags         = var.tags

  depends_on = [
    azurerm_role_assignment.deployment,
    azurerm_role_assignment.vault,
    azurerm_private_endpoint.this,
  ]
}
