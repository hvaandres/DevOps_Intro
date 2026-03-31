###############################################################################
# Common Variables
###############################################################################

variable "location" {
  description = "Azure region for all resources."
  type        = string
}

variable "environment" {
  description = "Environment name (e.g. dev, staging, prod)."
  type        = string
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}

###############################################################################
# Hub References
###############################################################################

variable "hub_subscription_id" {
  description = "Subscription ID where the hub resources reside."
  type        = string
}

variable "hub_vnet_id" {
  description = "Resource ID of the hub virtual network."
  type        = string
}

variable "hub_vnet_name" {
  description = "Name of the hub virtual network."
  type        = string
}

variable "hub_resource_group_name" {
  description = "Resource group name of the hub virtual network."
  type        = string
}

###############################################################################
# Private DNS Zones
###############################################################################

variable "private_dns_zones" {
  description = <<-EOT
    Map of Private DNS Zone names to create in the hub.
    Key   = logical name (used as Terraform map key)
    Value = the DNS zone FQDN (e.g. "privatelink.blob.core.windows.net")

    Add new entries as new services / partitions are onboarded.
  EOT
  type        = map(string)

  # Example:
  # private_dns_zones = {
  #   blob      = "privatelink.blob.core.windows.net"
  #   sql       = "privatelink.database.windows.net"
  #   keyvault  = "privatelink.vaultcore.azure.net"
  #   webapp    = "privatelink.azurewebsites.net"
  #   staticapp = "privatelink.azurestaticapps.net"
  # }
}

###############################################################################
# Spokes
###############################################################################

variable "spokes" {
  description = <<-EOT
    Map of spoke networks to peer with the hub and link to Private DNS.
    Key = logical spoke name.
  EOT
  type = map(object({
    vnet_id               = string
    vnet_name             = string
    resource_group_name   = string
    subscription_id       = optional(string, "")
    registration_enabled  = optional(bool, false)
    allow_gateway_transit = optional(bool, false)
    use_remote_gateways   = optional(bool, false)
  }))
  default = {}
}

###############################################################################
# Private DNS A Records (for Private Endpoints)
#
# OPTIONAL — Leave empty (default) when records are managed manually or by
# each spoke's own Terraform. The private_dns and vnet_peering modules work
# independently of whether any records are defined here.
###############################################################################

variable "dns_a_records" {
  description = <<-EOT
    (Optional) Map of Private DNS A records to create for Private Endpoints.
    Leave empty if records are managed outside this configuration.
    Key = unique record identifier.
  EOT
  type = map(object({
    zone_name = string # Must match a value in private_dns_zones
    name      = string # Record name (e.g. "mystorageaccount")
    ttl       = optional(number, 300)
    records   = list(string) # List of IP addresses
  }))
  default = {}
}

###############################################################################
# Alerting
###############################################################################

variable "alert_action_group_id" {
  description = "Azure Monitor Action Group ID to send DNS capacity alerts to. Leave empty to skip alert creation."
  type        = string
  default     = ""
}

variable "alert_thresholds" {
  description = "Thresholds for Azure Monitor metric alerts on Private DNS Zones."
  type = object({
    record_set_capacity_pct = optional(number, 80)
    vnet_link_capacity_pct  = optional(number, 80)
    record_set_count        = optional(number, 20000)
  })
  default = {}
}

###############################################################################
# Safety
###############################################################################

variable "enable_resource_locks" {
  description = "Enable CanNotDelete management locks on Private DNS Zones."
  type        = bool
  default     = true
}
