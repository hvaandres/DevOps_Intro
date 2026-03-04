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

variable "vnet_address_space" {
  description = "VNet address space."
  type        = list(string)
}

variable "subnet_functions_prefix" {
  description = "CIDR for Functions subnet."
  type        = string
}

variable "subnet_apim_prefix" {
  description = "CIDR for APIM subnet."
  type        = string
}

variable "subnet_private_endpoints_prefix" {
  description = "CIDR for private endpoints subnet."
  type        = string
}

variable "tags" {
  description = "Tags to apply."
  type        = map(string)
  default     = {}
}
