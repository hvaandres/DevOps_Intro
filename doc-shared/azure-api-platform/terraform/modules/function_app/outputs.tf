output "name" {
  description = "Function App name."
  value       = azurerm_linux_function_app.this.name
}

output "id" {
  description = "Function App resource ID."
  value       = azurerm_linux_function_app.this.id
}

output "default_hostname" {
  description = "Default hostname of the Function App."
  value       = azurerm_linux_function_app.this.default_hostname
}

output "identity_principal_id" {
  description = "Principal ID of the system-assigned managed identity."
  value       = azurerm_linux_function_app.this.identity[0].principal_id
}

output "default_function_key" {
  description = "Default function host key."
  value       = data.azurerm_function_app_host_keys.this.default_function_key
  sensitive   = true
}

# Data source to retrieve function host keys after deployment
data "azurerm_function_app_host_keys" "this" {
  name                = azurerm_linux_function_app.this.name
  resource_group_name = var.resource_group_name
}
