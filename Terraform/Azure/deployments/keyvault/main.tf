module "keyvault" {
  source = "../../tfm-keyvault"

  name                       = var.vault_name
  resource_group_name        = var.resource_group_name
  location                   = "westus2"
  sku_name                   = var.sku_name
  purge_protection_enabled   = var.purge_protection_enabled
  soft_delete_retention_days = var.soft_delete_retention_days
  private_endpoints          = var.private_endpoints
  role_assignments           = var.role_assignments
  tags                       = var.tags
}
