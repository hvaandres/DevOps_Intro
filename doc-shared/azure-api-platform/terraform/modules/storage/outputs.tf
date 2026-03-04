output "storage_account_id" {
  description = "Storage account resource ID."
  value       = azurerm_storage_account.this.id
}

output "storage_account_name" {
  description = "Storage account name."
  value       = azurerm_storage_account.this.name
}

output "storage_account_primary_access_key" {
  description = "Storage account primary access key."
  value       = azurerm_storage_account.this.primary_access_key
  sensitive   = true
}

output "primary_blob_endpoint" {
  description = "Primary blob endpoint."
  value       = azurerm_storage_account.this.primary_blob_endpoint
}
