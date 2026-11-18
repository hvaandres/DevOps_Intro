module "keyvault" {
  source = "../.."

  name                          = var.vault_name
  resource_group_name           = var.resource_group_name
  public_network_access_enabled = true
  network_acls = {
    ip_rules = var.allowed_ipv4_cidrs
  }
  role_assignments = {
    application_secrets = {
      principal_id         = var.application_principal_id
      principal_type       = "ServicePrincipal"
      role_definition_name = "Key Vault Secrets User"
    }
  }
  tags = {
    environment = "development"
    managed_by  = "terraform"
  }
}
