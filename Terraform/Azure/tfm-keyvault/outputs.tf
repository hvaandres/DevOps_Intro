output "id" {
  description = "Key Vault ARM resource ID."
  value       = azurerm_key_vault.this.id
}

output "name" {
  description = "Key Vault name."
  value       = azurerm_key_vault.this.name
}

output "location" {
  description = "Azure region of the Key Vault."
  value       = azurerm_key_vault.this.location
}

output "vault_uri" {
  description = "Key Vault data-plane URI."
  value       = azurerm_key_vault.this.vault_uri
}

output "resource_group_name" {
  description = "Resolved resource group name."
  value       = local.resource_group_name
}

output "keys" {
  description = "Key IDs and versions keyed by logical name, including versionless URI and ARM IDs."
  value = {
    for name, key in module.key : name => {
      id                      = key.id
      versionless_id          = key.versionless_id
      resource_versionless_id = key.resource_versionless_id
      version                 = key.version
    }
  }
}

output "secrets" {
  description = "Secret IDs and versions only; never secret values."
  value = {
    for name, secret in module.secret : name => {
      id                      = secret.id
      versionless_id          = secret.versionless_id
      resource_versionless_id = secret.resource_versionless_id
      version                 = secret.version
    }
  }
}

output "private_endpoint_ids" {
  description = "Private endpoint ARM IDs keyed by logical name."
  value       = { for name, endpoint in azurerm_private_endpoint.this : name => endpoint.id }
}

output "role_assignment_ids" {
  description = "Vault-level and deployment role assignment IDs."
  value = {
    vault      = { for name, role in azurerm_role_assignment.vault : name => role.id }
    deployment = { for name, role in azurerm_role_assignment.deployment : name => role.id }
  }
}
