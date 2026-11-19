# Keep locks downstream of resources and RBAC so an authorized destroy removes
# locks first. Normal deployment identities must not have locks/delete rights.
resource "azurerm_management_lock" "vault" {
  count = var.deletion_protection_enabled ? 1 : 0

  name       = "terraform-keyvault-delete-protection"
  scope      = azurerm_key_vault.this.id
  lock_level = "CanNotDelete"
  notes      = "Remove only through the approved Key Vault tear down workflow."

  depends_on = [
    azurerm_role_assignment.vault,
    azurerm_role_assignment.deployment,
    module.key,
    module.secret,
  ]
}

resource "azurerm_management_lock" "private_endpoint" {
  for_each = var.deletion_protection_enabled ? var.private_endpoints : {}

  name       = "terraform-keyvault-delete-protection"
  scope      = azurerm_private_endpoint.this[each.key].id
  lock_level = "CanNotDelete"
  notes      = "Remove only through the approved Key Vault tear down workflow."
}
