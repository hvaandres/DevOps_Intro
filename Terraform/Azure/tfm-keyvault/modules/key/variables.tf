variable "key_vault_id" {
  description = "ARM ID of an existing RBAC-enabled vault. The caller must already have data-plane permissions and network access."
  type        = string
  nullable    = false
}

variable "key" {
  description = "Key configuration and optional key-scoped RBAC. HSM types require a premium vault."
  type = object({
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
  })
  nullable = false
  validation {
    condition     = can(regex("^[A-Za-z0-9-]{1,127}$", var.key.name))
    error_message = "Key names must contain 1-127 alphanumeric or hyphen characters."
  }
  validation {
    condition     = contains(["RSA", "RSA-HSM", "EC", "EC-HSM"], var.key.key_type)
    error_message = "key_type must be RSA, RSA-HSM, EC, or EC-HSM."
  }
  validation {
    condition     = !startswith(var.key.key_type, "RSA") || contains([2048, 3072, 4096], var.key.key_size)
    error_message = "RSA key_size must be 2048, 3072, or 4096 bits."
  }
  validation {
    condition     = !startswith(var.key.key_type, "EC") || contains(["P-256", "P-256K", "P-384", "P-521"], var.key.curve)
    error_message = "Provide a supported elliptic curve for EC keys."
  }
  validation {
    condition     = length(var.key.key_opts) > 0 && alltrue([for op in var.key.key_opts : contains(["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"], op)])
    error_message = "key_opts must include supported JSON web key operations."
  }
  validation {
    condition = var.key.rotation_policy == null ? true : (
      var.key.rotation_policy.automatic == null ? true :
      (var.key.rotation_policy.automatic.time_after_creation != null) != (var.key.rotation_policy.automatic.time_before_expiry != null)
    )
    error_message = "Automatic rotation requires exactly one of time_after_creation or time_before_expiry."
  }
  validation {
    condition = var.key.rotation_policy == null ? true : (
      var.key.rotation_policy.automatic == null ? true :
      var.key.rotation_policy.automatic.time_before_expiry == null ? true :
      var.key.expiration_date != null
    )
    error_message = "Rotation before expiry requires an initial expiration_date on the key."
  }
  validation {
    condition     = alltrue([for date in [var.key.expiration_date, var.key.not_before_date] : date == null ? true : can(formatdate("YYYY-MM-DD", date))])
    error_message = "Key validity dates must be RFC 3339 timestamps."
  }
  validation {
    condition     = var.key.expiration_date == null || var.key.not_before_date == null ? true : try(timecmp(var.key.expiration_date, var.key.not_before_date) > 0, false)
    error_message = "expiration_date must be later than not_before_date."
  }
  validation {
    condition     = alltrue([for role in values(var.key.role_assignments) : (role.role_definition_name != null) != (role.role_definition_id != null)])
    error_message = "Each key role assignment must specify exactly one role name or role definition ID."
  }
}

variable "tags" {
  description = "Common tags; key-specific tags take precedence."
  type        = map(string)
  default     = {}
  nullable    = false
}
