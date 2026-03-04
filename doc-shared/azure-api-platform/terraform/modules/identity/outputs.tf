output "func_storage_role_assignment_id" {
  description = "Role assignment ID for Function App → Storage Blob Data Reader."
  value       = azurerm_role_assignment.func_storage_blob_reader.id
}

output "func_rg_role_assignment_id" {
  description = "Role assignment ID for Function App → Resource Group Reader."
  value       = azurerm_role_assignment.func_rg_reader.id
}
