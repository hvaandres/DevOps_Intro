variable "vault_name" {
  description = "Globally unique vault name."
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group name."
  type        = string
}

variable "application_principal_id" {
  description = "Application service principal or managed identity object ID, not its client ID."
  type        = string
}

variable "allowed_ipv4_cidrs" {
  description = "Explicit public IPv4 CIDRs allowed through the vault firewall. Empty denies all."
  type        = set(string)
  default     = []
}
