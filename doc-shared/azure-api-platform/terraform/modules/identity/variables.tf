variable "resource_group_id" {
  description = "Resource group ID for role assignments."
  type        = string
}

variable "function_app_identity_id" {
  description = "Principal ID of the Function App managed identity."
  type        = string
}

variable "storage_account_id" {
  description = "Storage account resource ID."
  type        = string
}

variable "cosmos_account_id" {
  description = "Cosmos DB account resource ID (empty string to skip)."
  type        = string
  default     = ""
}

variable "sql_server_id" {
  description = "SQL Server resource ID (empty string to skip)."
  type        = string
  default     = ""
}

variable "service_principal_object_id" {
  description = "Object ID of the CI/CD Service Principal (empty string to skip)."
  type        = string
  default     = ""
}
