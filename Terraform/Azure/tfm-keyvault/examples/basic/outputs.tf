output "vault_id" {
  description = "Vault ARM ID."
  value       = module.keyvault.id
}

output "vault_uri" {
  description = "Vault data-plane endpoint."
  value       = module.keyvault.vault_uri
}
