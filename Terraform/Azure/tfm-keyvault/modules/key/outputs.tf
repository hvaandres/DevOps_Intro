output "id" {
  description = "Versioned data-plane key URI."
  value       = azurerm_key_vault_key.this.id
}

output "versionless_id" {
  description = "Versionless data-plane key URI."
  value       = azurerm_key_vault_key.this.versionless_id
}

output "resource_versionless_id" {
  description = "Versionless ARM resource ID used for RBAC scopes."
  value       = azurerm_key_vault_key.this.resource_versionless_id
}

output "version" {
  description = "Current key version."
  value       = azurerm_key_vault_key.this.version
}

output "role_assignment_ids" {
  description = "Key-scoped role assignment IDs."
  value       = { for name, role in azurerm_role_assignment.this : name => role.id }
}
