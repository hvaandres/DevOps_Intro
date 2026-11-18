variable "key_vault_id" {
  description = "ARM ID of an existing RBAC-enabled vault. Caller needs vault-level secret management permissions and network access."
  type        = string
  nullable    = false
}

variable "value" {
  description = "Secret value. Sensitive in CLI output, but persisted in Terraform state."
  type        = string
  sensitive   = true
  nullable    = false
  validation {
    condition     = length(var.value) > 0
    error_message = "The secret value must not be empty."
  }
}

variable "secret" {
  description = "Non-sensitive secret metadata and optional secret-scoped RBAC."
  type = object({
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
  })
  nullable = false
  validation {
    condition     = can(regex("^[A-Za-z0-9-]{1,127}$", var.secret.name))
    error_message = "Secret names must contain 1-127 alphanumeric or hyphen characters."
  }
  validation {
    condition     = alltrue([for date in [var.secret.expiration_date, var.secret.not_before_date] : date == null ? true : can(formatdate("YYYY-MM-DD", date))])
    error_message = "Secret validity dates must be RFC 3339 timestamps."
  }
  validation {
    condition     = var.secret.expiration_date == null || var.secret.not_before_date == null ? true : try(timecmp(var.secret.expiration_date, var.secret.not_before_date) > 0, false)
    error_message = "expiration_date must be later than not_before_date."
  }
  validation {
    condition     = alltrue([for role in values(var.secret.role_assignments) : (role.role_definition_name != null) != (role.role_definition_id != null)])
    error_message = "Each secret role assignment must specify exactly one role name or role definition ID."
  }
}

variable "tags" {
  description = "Common tags; secret-specific tags take precedence."
  type        = map(string)
  default     = {}
  nullable    = false
}
