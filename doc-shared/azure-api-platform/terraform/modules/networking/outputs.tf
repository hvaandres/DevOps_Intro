output "vnet_id" {
  description = "VNet resource ID."
  value       = azurerm_virtual_network.this.id
}

output "vnet_name" {
  description = "VNet name."
  value       = azurerm_virtual_network.this.name
}

output "functions_subnet_id" {
  description = "Functions subnet ID."
  value       = azurerm_subnet.functions.id
}

output "apim_subnet_id" {
  description = "APIM subnet ID."
  value       = azurerm_subnet.apim.id
}

output "private_endpoints_subnet_id" {
  description = "Private endpoints subnet ID."
  value       = azurerm_subnet.private_endpoints.id
}
