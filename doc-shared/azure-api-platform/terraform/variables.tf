# -----------------------------------------------------------------------------
# General
# -----------------------------------------------------------------------------
variable "project_name" {
  description = "Project name used as a prefix for all resources."
  type        = string
  default     = "apiplatform"
}

variable "environment" {
  description = "Environment name (dev, stage, prod)."
  type        = string
  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "Environment must be one of: dev, stage, prod."
  }
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "eastus2"
}

variable "subscription_id" {
  description = "Azure subscription ID."
  type        = string
  sensitive   = true
}

variable "tenant_id" {
  description = "Azure AD / Entra ID tenant ID."
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
variable "vnet_address_space" {
  description = "Address space for the VNet."
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_functions_prefix" {
  description = "CIDR prefix for the Functions subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "subnet_apim_prefix" {
  description = "CIDR prefix for the APIM subnet."
  type        = string
  default     = "10.0.2.0/24"
}

variable "subnet_private_endpoints_prefix" {
  description = "CIDR prefix for the private endpoints subnet."
  type        = string
  default     = "10.0.3.0/24"
}

# -----------------------------------------------------------------------------
# APIM
# -----------------------------------------------------------------------------
variable "apim_sku_name" {
  description = "APIM SKU (Developer_1, Premium_1, etc.)."
  type        = string
  default     = "Developer_1"
}

variable "apim_publisher_name" {
  description = "APIM publisher name."
  type        = string
  default     = "API Platform Team"
}

variable "apim_publisher_email" {
  description = "APIM publisher email."
  type        = string
}

# -----------------------------------------------------------------------------
# Function App
# -----------------------------------------------------------------------------
variable "function_app_sku" {
  description = "App Service Plan SKU tier and size for the Function App."
  type = object({
    tier = string
    size = string
  })
  default = {
    tier = "ElasticPremium"
    size = "EP1"
  }
}

variable "function_python_version" {
  description = "Python version for the Function App."
  type        = string
  default     = "3.11"
}

# -----------------------------------------------------------------------------
# Identity
# -----------------------------------------------------------------------------
variable "service_principal_object_id" {
  description = "Object ID of the Service Principal used for CI/CD."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Tags
# -----------------------------------------------------------------------------
variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}
