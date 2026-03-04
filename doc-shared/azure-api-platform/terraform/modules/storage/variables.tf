variable "resource_group_name" {
  description = "Name of the resource group."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "name_prefix" {
  description = "Naming prefix (alphanumeric only for storage accounts)."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "replication_type" {
  description = "Storage replication type."
  type        = string
  default     = "GRS"
}

variable "enable_data_lake" {
  description = "Enable hierarchical namespace (Data Lake Gen2)."
  type        = bool
  default     = true
}

variable "subnet_id" {
  description = "Subnet ID for private endpoint."
  type        = string
}

variable "vnet_id" {
  description = "VNet ID for DNS zone link."
  type        = string
}

variable "log_analytics_id" {
  description = "Log Analytics Workspace ID for diagnostics."
  type        = string
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
