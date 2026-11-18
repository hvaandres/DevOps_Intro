output "storage_account_name" {
  description = "Use as storage_account_name in example backend.hcl files."
  value       = azurerm_storage_account.state.name
}

output "container_name" {
  description = "State container."
  value       = azurerm_storage_container.state.name
}

output "workload_resource_group_name" {
  description = "Existing resource group for examples/basic."
  value       = azurerm_resource_group.workload.name
}
