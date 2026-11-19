output "vault_id" {
  description = "Vault ARM resource ID."
  value       = module.keyvault.id
}

output "vault_location" {
  description = "Fixed Azure region for pipeline-created vaults."
  value       = module.keyvault.location
}

output "vault_uri" {
  description = "Vault endpoint; reachability requires private networking and DNS."
  value       = module.keyvault.vault_uri
}
