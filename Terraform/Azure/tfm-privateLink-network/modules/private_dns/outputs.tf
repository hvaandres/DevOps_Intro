output "zone_ids" {
  description = "Map of logical name to Private DNS Zone resource IDs."
  value = {
    for key, zone in azurerm_private_dns_zone.this : key => zone.id
  }
}

output "zone_names" {
  description = "Map of logical name to Private DNS Zone FQDNs."
  value = {
    for key, zone in azurerm_private_dns_zone.this : key => zone.name
  }
}

output "hub_vnet_link_ids" {
  description = "Map of zone key to hub VNet link IDs."
  value = {
    for key, link in azurerm_private_dns_zone_virtual_network_link.hub : key => link.id
  }
}

output "spoke_vnet_link_ids" {
  description = "Map of zone-spoke composite key to spoke VNet link IDs."
  value = {
    for key, link in azurerm_private_dns_zone_virtual_network_link.spoke : key => link.id
  }
}

output "zone_max_record_sets" {
  description = "Map of zone key to the maximum number of record sets allowed."
  value = {
    for key, zone in azurerm_private_dns_zone.this : key => zone.max_number_of_record_sets
  }
}

output "zone_max_vnet_links" {
  description = "Map of zone key to the maximum number of VNet links allowed."
  value = {
    for key, zone in azurerm_private_dns_zone.this : key => zone.max_number_of_virtual_network_links
  }
}
