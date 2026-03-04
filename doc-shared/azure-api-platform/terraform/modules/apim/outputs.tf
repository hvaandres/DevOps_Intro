output "id" {
  description = "APIM resource ID."
  value       = azurerm_api_management.this.id
}

output "name" {
  description = "APIM instance name."
  value       = azurerm_api_management.this.name
}

output "gateway_url" {
  description = "APIM gateway URL."
  value       = azurerm_api_management.this.gateway_url
}

output "management_api_url" {
  description = "APIM management API URL."
  value       = azurerm_api_management.this.management_api_url
}

output "identity_principal_id" {
  description = "Principal ID of APIM system-assigned identity."
  value       = azurerm_api_management.this.identity[0].principal_id
}
