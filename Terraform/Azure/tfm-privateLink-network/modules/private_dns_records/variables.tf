variable "resource_group_name" {
  description = "Resource group containing the hub-owned Private DNS Zones."
  type        = string
}

variable "dns_a_records" {
  description = <<-EOT
    Map of DNS A records to create for Private Endpoints.
    Key = unique identifier for the record.
  EOT
  type = map(object({
    zone_name = string # FQDN of the Private DNS Zone (e.g. "privatelink.blob.core.windows.net")
    name      = string # Record name (e.g. "mystorageaccount")
    ttl       = optional(number, 300)
    records   = list(string) # Private IP addresses
  }))
  default = {}
}

variable "tags" {
  description = "Tags to apply to all records."
  type        = map(string)
  default     = {}
}
