output "vault_id" {
  description = "Vault ARM ID."
  value       = module.keyvault.id
}

output "vault_uri" {
  description = "Vault data-plane endpoint; resolves privately from the linked VNet."
  value       = module.keyvault.vault_uri
}

output "application_identity_client_id" {
  description = "Client ID applications use to select their managed identity."
  value       = azurerm_user_assigned_identity.application.client_id
}

output "vnet_id" {
  description = "VNet to connect to the Terraform runner through peering, VPN, or a VNet-hosted runner."
  value       = azurerm_virtual_network.this.id
}

output "keys" {
  description = "Key references, including versionless IDs."
  value       = module.keyvault.keys
}

output "secrets" {
  description = "Secret references only, never values."
  value       = module.keyvault.secrets
}
