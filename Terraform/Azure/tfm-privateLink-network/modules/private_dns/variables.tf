variable "resource_group_name" {
  description = "Resource group where the Private DNS Zones will be created."
  type        = string
}

variable "location" {
  description = "Azure region (used only for alert resources)."
  type        = string
}

variable "private_dns_zones" {
  description = "Map of logical name => DNS zone FQDN to create."
  type        = map(string)
}

variable "hub_vnet_id" {
  description = "Resource ID of the hub virtual network to link to all DNS zones."
  type        = string
}

variable "spoke_vnet_links" {
  description = "Map of spoke key => { vnet_id, registration_enabled } to link to all DNS zones."
  type = map(object({
    vnet_id              = string
    registration_enabled = optional(bool, false)
  }))
  default = {}
}

variable "enable_resource_locks" {
  description = "Whether to apply CanNotDelete locks on DNS zones."
  type        = bool
  default     = true
}

variable "alert_action_group_id" {
  description = "Action group ID for metric alerts. Empty string disables alerts."
  type        = string
  default     = ""
}

variable "alert_record_set_capacity_pct" {
  description = "Percentage threshold for RecordSetCapacityUtilization alert."
  type        = number
  default     = 80
}

variable "alert_vnet_link_capacity_pct" {
  description = "Percentage threshold for VirtualNetworkLinkCapacityUtilization alert."
  type        = number
  default     = 80
}

variable "alert_record_set_count" {
  description = "Absolute threshold for RecordSetCount alert."
  type        = number
  default     = 20000
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
