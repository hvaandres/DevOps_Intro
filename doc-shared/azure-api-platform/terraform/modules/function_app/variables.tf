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

variable "sku_tier" {
  description = "App Service Plan SKU tier."
  type        = string
  default     = "ElasticPremium"
}

variable "sku_size" {
  description = "App Service Plan SKU size."
  type        = string
  default     = "EP1"
}

variable "python_version" {
  description = "Python version for the Function App."
  type        = string
  default     = "3.11"
}

variable "subnet_id" {
  description = "Subnet ID for VNet integration."
  type        = string
}

variable "storage_account_name" {
  description = "Storage account name for Function App."
  type        = string
}

variable "storage_account_access_key" {
  description = "Storage account access key."
  type        = string
  sensitive   = true
}

variable "application_insights_key" {
  description = "Application Insights instrumentation key."
  type        = string
  sensitive   = true
}

variable "application_insights_connection_string" {
  description = "Application Insights connection string."
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
