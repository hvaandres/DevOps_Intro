output "id" {
  description = "Versioned data-plane secret URI."
  value       = azurerm_key_vault_secret.this.id
}

output "versionless_id" {
  description = "Versionless data-plane secret URI."
  value       = azurerm_key_vault_secret.this.versionless_id
}

output "resource_versionless_id" {
  description = "Versionless ARM resource ID used for RBAC scopes."
  value       = azurerm_key_vault_secret.this.resource_versionless_id
}

output "version" {
  description = "Current secret version."
  value       = azurerm_key_vault_secret.this.version
}

output "role_assignment_ids" {
  description = "Secret-scoped role assignment IDs."
  value       = { for name, role in azurerm_role_assignment.this : name => role.id }
}
