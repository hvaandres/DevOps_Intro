variable "vault_name" {
  description = "Globally unique name of the private-only vault."
  type        = string
  nullable    = false
}

variable "resource_group_name" {
  description = "Existing workload resource group; provision separately."
  type        = string
  nullable    = false
}

variable "sku_name" {
  description = "Vault SKU; premium is required for future HSM-backed keys."
  type        = string
  default     = "standard"
}

variable "purge_protection_enabled" {
  description = "Enable purge protection; Azure does not allow disabling it once enabled."
  type        = bool
  default     = true
  nullable    = false
}

variable "soft_delete_retention_days" {
  description = "Immutable soft-delete retention in whole days, from 7 to 90."
  type        = number
  default     = 90
  nullable    = false
  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90 && floor(var.soft_delete_retention_days) == var.soft_delete_retention_days
    error_message = "soft_delete_retention_days must be an integer from 7 to 90."
  }
}

variable "private_endpoints" {
  description = "Existing endpoint subnets and hub-owned private DNS zones. Runner connectivity is configured separately."
  type = map(object({
    name                 = string
    subnet_id            = string
    resource_group_name  = optional(string)
    location             = optional(string)
    private_dns_zone_ids = optional(list(string), [])
    tags                 = optional(map(string), {})
  }))
  default = {}
}

variable "role_assignments" {
  description = "Explicit application object IDs and vault-level roles. Never inferred from the planning identity."
  type = map(object({
    principal_id                     = string
    role_definition_name             = optional(string)
    role_definition_id               = optional(string)
    principal_type                   = optional(string, "ServicePrincipal")
    skip_service_principal_aad_check = optional(bool, false)
  }))
  default = {}
}

variable "tags" {
  description = "Non-sensitive resource tags."
  type        = map(string)
  default     = {}
}
