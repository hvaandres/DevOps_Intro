variable "name" {
  description = "Globally unique Key Vault name: 3-24 alphanumeric/hyphen characters, beginning with a letter, ending with an alphanumeric, without consecutive hyphens."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$", var.name)) && !strcontains(var.name, "--")
    error_message = "Provide a valid 3-24 character Key Vault name."
  }
}

variable "resource_group_name" {
  description = "Name of an existing resource group, or the resource group to create."
  type        = string
  nullable    = false
}

variable "create_resource_group" {
  description = "Create the resource group instead of looking it up."
  type        = bool
  default     = false
  nullable    = false
}

variable "location" {
  description = "Azure region; defaults to the existing resource group's location. Required for a new resource group."
  type        = string
  default     = null
}

variable "tenant_id" {
  description = "Tenant ID; defaults to the authenticated provider tenant."
  type        = string
  default     = null
}

variable "sku_name" {
  description = "Vault SKU. HSM-backed keys require premium."
  type        = string
  default     = "standard"
  nullable    = false
  validation {
    condition     = contains(["standard", "premium"], var.sku_name)
    error_message = "sku_name must be standard or premium."
  }
}

variable "deletion_protection_enabled" {
  description = "Create CanNotDelete locks on the vault and managed private endpoints. Lock removal requires separately privileged authorization."
  type        = bool
  default     = true
  nullable    = false
}

variable "purge_protection_enabled" {
  description = "Enable purge protection. Once enabled, Azure does not allow disabling it."
  type        = bool
  default     = true
  nullable    = false
}

variable "soft_delete_retention_days" {
  description = "Immutable soft-delete retention in whole days, between 7 and 90."
  type        = number
  default     = 90
  nullable    = false
  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90 && floor(var.soft_delete_retention_days) == var.soft_delete_retention_days
    error_message = "soft_delete_retention_days must be an integer between 7 and 90."
  }
}

variable "public_network_access_enabled" {
  description = "Allow public-endpoint access subject to network_acls; disabled by default."
  type        = bool
  default     = false
  nullable    = false
}

variable "network_acls" {
  description = "Vault firewall. Denies all by default, with no trusted-service bypass."
  type = object({
    bypass                     = optional(string, "None")
    default_action             = optional(string, "Deny")
    ip_rules                   = optional(set(string), [])
    virtual_network_subnet_ids = optional(set(string), [])
  })
  default  = {}
  nullable = false
  validation {
    condition     = contains(["None", "AzureServices"], var.network_acls.bypass) && contains(["Allow", "Deny"], var.network_acls.default_action)
    error_message = "Use bypass None or AzureServices and default_action Allow or Deny."
  }
}

variable "role_assignments" {
  description = "Vault-scoped RBAC assignments keyed by stable logical names. Specify exactly one role name or fully qualified role definition ID."
  type = map(object({
    principal_id                     = string
    role_definition_name             = optional(string)
    role_definition_id               = optional(string)
    principal_type                   = optional(string)
    skip_service_principal_aad_check = optional(bool, false)
  }))
  default  = {}
  nullable = false
  validation {
    condition     = alltrue([for role in values(var.role_assignments) : (role.role_definition_name != null) != (role.role_definition_id != null)])
    error_message = "Each role assignment must specify exactly one of role_definition_name or role_definition_id."
  }
}

variable "deployment_principal_id" {
  description = "Service principal object ID for optional deployment roles; defaults to the authenticated principal object ID."
  type        = string
  default     = null
}

variable "deployment_principal_roles" {
  description = "Explicit vault data-plane roles for the deployment service principal. Keys are stable assignment identifiers; values are role names. Avoid duplicating role_assignments."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "keys" {
  description = "Keys indexed by stable logical names; per-key roles are scoped to the versionless ARM key resource."
  type = map(object({
    name            = string
    key_type        = optional(string, "RSA")
    key_size        = optional(number, 2048)
    curve           = optional(string, "P-256")
    key_opts        = optional(set(string), ["wrapKey", "unwrapKey"])
    expiration_date = optional(string)
    not_before_date = optional(string)
    tags            = optional(map(string), {})
    rotation_policy = optional(object({
      expire_after         = optional(string)
      notify_before_expiry = optional(string)
      automatic = optional(object({
        time_after_creation = optional(string)
        time_before_expiry  = optional(string)
      }))
    }))
    role_assignments = optional(map(object({
      principal_id                     = string
      role_definition_name             = optional(string)
      role_definition_id               = optional(string)
      principal_type                   = optional(string)
      skip_service_principal_aad_check = optional(bool, false)
    })), {})
  }))
  default  = {}
  nullable = false
  validation {
    condition     = length(distinct([for key in values(var.keys) : lower(key.name)])) == length(var.keys)
    error_message = "Keys must have unique Azure names, ignoring case."
  }
}

variable "secrets" {
  description = "Non-sensitive secret metadata, keyed by stable logical names. Pass values separately through secret_values."
  type = map(object({
    name            = string
    content_type    = optional(string)
    expiration_date = optional(string)
    not_before_date = optional(string)
    tags            = optional(map(string), {})
    role_assignments = optional(map(object({
      principal_id                     = string
      role_definition_name             = optional(string)
      role_definition_id               = optional(string)
      principal_type                   = optional(string)
      skip_service_principal_aad_check = optional(bool, false)
    })), {})
  }))
  default  = {}
  nullable = false
  validation {
    condition     = length(distinct([for secret in values(var.secrets) : lower(secret.name)])) == length(var.secrets)
    error_message = "Secrets must have unique Azure names, ignoring case."
  }
}

variable "secret_values" {
  description = "Sensitive secret values keyed identically to secrets. Values are persisted in Terraform state; protect backend access."
  type        = map(string)
  default     = {}
  sensitive   = true
  nullable    = false
}

variable "private_endpoints" {
  description = "Private endpoints and optional existing private DNS zone IDs. Caller manages DNS zones, VNet links, and runner connectivity."
  type = map(object({
    name                 = string
    subnet_id            = string
    resource_group_name  = optional(string)
    location             = optional(string)
    private_dns_zone_ids = optional(list(string), [])
    tags                 = optional(map(string), {})
  }))
  default  = {}
  nullable = false
}

variable "tags" {
  description = "Common resource tags, merged with per-object tags."
  type        = map(string)
  default     = {}
  nullable    = false
}
