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

variable "retention_days" {
  description = "Log retention in days."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
