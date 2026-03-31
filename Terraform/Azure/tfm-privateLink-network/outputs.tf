###############################################################################
# Outputs
###############################################################################

# --- Private DNS Zones ---

output "private_dns_zone_ids" {
  description = "Map of logical name to Private DNS Zone resource IDs."
  value       = module.private_dns.zone_ids
}

output "private_dns_zone_names" {
  description = "Map of logical name to Private DNS Zone FQDNs."
  value       = module.private_dns.zone_names
}

# --- Resource Groups ---

output "private_dns_resource_group_name" {
  description = "Name of the resource group containing Private DNS Zones."
  value       = azurerm_resource_group.private_dns.name
}

output "private_dns_resource_group_id" {
  description = "ID of the resource group containing Private DNS Zones."
  value       = azurerm_resource_group.private_dns.id
}

# --- VNet Peerings ---

output "vnet_peering_ids" {
  description = "Map of spoke name to the hub-to-spoke peering ID."
  value = {
    for key, peering in module.vnet_peering : key => peering.hub_to_spoke_peering_id
  }
}

# --- DNS Records (empty maps when no records are managed here) ---

output "dns_a_record_ids" {
  description = "Map of record key to the DNS A record IDs. Empty when records are managed externally."
  value       = module.private_dns_records.a_record_ids
}

output "dns_a_record_fqdns" {
  description = "Map of record key to the DNS A record FQDNs. Empty when records are managed externally."
  value       = module.private_dns_records.a_record_fqdns
}
