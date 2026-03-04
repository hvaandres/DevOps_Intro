variable "resource_group_name" {
  description = "Name of the resource group."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "name_prefix" {
  description = "Naming prefix for resources."
  type        = string
}

variable "sku_name" {
  description = "APIM SKU name (e.g. Developer_1, Premium_1)."
  type        = string
  default     = "Developer_1"
}

variable "publisher_name" {
  description = "Publisher name for APIM."
  type        = string
}

variable "publisher_email" {
  description = "Publisher email for APIM."
  type        = string
}

variable "vnet_type" {
  description = "VNet integration type: None, External, or Internal."
  type        = string
  default     = "External"
}

variable "subnet_id" {
  description = "Subnet ID for APIM VNet injection."
  type        = string
  default     = ""
}

variable "function_app_url" {
  description = "Default hostname of the backend Function App."
  type        = string
}

variable "function_app_key" {
  description = "Default host key for the Function App."
  type        = string
  sensitive   = true
}

variable "log_analytics_id" {
  description = "Log Analytics Workspace ID for diagnostics."
  type        = string
}

variable "tenant_id" {
  description = "Entra ID tenant ID for JWT validation."
  type        = string
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
