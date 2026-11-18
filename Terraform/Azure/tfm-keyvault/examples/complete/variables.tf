variable "vault_name" {
  description = "Globally unique vault name."
  type        = string
}

variable "resource_group_name" {
  description = "New vault resource group name; network resources use a separate -network group."
  type        = string
}

variable "location" {
  description = "Azure deployment region."
  type        = string
  default     = "westeurope"
}

variable "vnet_address_space" {
  description = "Non-overlapping VNet range; adapt for peering or VPN connectivity."
  type        = string
  default     = "10.42.0.0/16"
}

variable "private_endpoint_subnet_prefix" {
  description = "Private endpoint subnet within vnet_address_space."
  type        = string
  default     = "10.42.1.0/24"
}

variable "create_objects" {
  description = "False for an initial network-only deployment before connecting the runner; true to create keys and secrets."
  type        = bool
  default     = true
}

variable "database_password" {
  description = "Supply from a secret store through TF_VAR_database_password, not a committed tfvars file. Required when create_objects is true."
  type        = string
  sensitive   = true
  default     = null
  validation {
    condition     = !var.create_objects ? true : try(length(var.database_password) > 0, false)
    error_message = "Supply database_password when create_objects is true."
  }
}

variable "key_expiration_date" {
  description = "Initial future UTC expiration, typically 90 days after initial deployment. Required for before-expiry rotation when create_objects is true."
  type        = string
  default     = null
  validation {
    condition     = !var.create_objects ? true : var.key_expiration_date != null
    error_message = "Supply key_expiration_date when create_objects is true."
  }
}

variable "secret_expiration_date" {
  description = "Future UTC secret expiration; expiration does not automatically rotate its value."
  type        = string
  default     = null
  validation {
    condition     = !var.create_objects ? true : var.secret_expiration_date != null
    error_message = "Supply secret_expiration_date when create_objects is true."
  }
}
