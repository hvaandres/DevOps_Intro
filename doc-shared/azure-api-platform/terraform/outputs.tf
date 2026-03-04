output "resource_group_name" {
  description = "Name of the resource group."
  value       = module.resource_group.name
}

output "apim_gateway_url" {
  description = "APIM gateway URL for API consumers."
  value       = module.apim.gateway_url
}

output "function_app_name" {
  description = "Name of the deployed Function App."
  value       = module.function_app.name
}

output "function_app_url" {
  description = "Default hostname of the Function App."
  value       = module.function_app.default_hostname
}

output "storage_account_name" {
  description = "Name of the storage account."
  value       = module.storage.storage_account_name
}

output "log_analytics_workspace_id" {
  description = "Log Analytics Workspace ID."
  value       = module.monitoring.log_analytics_workspace_id
}

output "vnet_id" {
  description = "VNet resource ID."
  value       = module.networking.vnet_id
}
