variable "storage_account_name" {
  description = "Globally unique state storage account name: 3-24 lowercase letters and digits."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Use 3-24 lowercase letters and digits for storage_account_name."
  }
}

variable "state_resource_group_name" {
  description = "New resource group for Terraform state."
  type        = string
}

variable "workload_resource_group_name" {
  description = "New workload group. Matches the basic example's existing resource_group_name."
  type        = string
}

variable "location" {
  description = "Azure region for state and workload resource groups."
  type        = string
  default     = "westeurope"
}

variable "deployment_principal_id" {
  description = "Existing deployment service principal object ID, not its application/client ID."
  type        = string
}

variable "allowed_ipv4_cidrs" {
  description = "Public IPv4 ranges for bootstrap and deployment runners. Azure Storage requires plain IPv4 addresses instead of /32 or /31 CIDRs."
  type        = set(string)
  validation {
    condition     = length(var.allowed_ipv4_cidrs) > 0
    error_message = "Explicitly allow at least one runner IPv4 address or range."
  }
}
