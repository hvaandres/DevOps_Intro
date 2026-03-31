output "a_record_ids" {
  description = "Map of record key to the DNS A record resource IDs."
  value = {
    for key, record in azurerm_private_dns_a_record.this : key => record.id
  }
}

output "a_record_fqdns" {
  description = "Map of record key to the DNS A record FQDNs."
  value = {
    for key, record in azurerm_private_dns_a_record.this : key => record.fqdn
  }
}
