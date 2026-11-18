module "keyvault" {
  source = "../../tfm-keyvault"

  name                = var.vault_name
  resource_group_name = var.resource_group_name
  sku_name            = var.sku_name
  private_endpoints   = var.private_endpoints
  role_assignments    = var.role_assignments
  tags                = var.tags
}
