###############################################################################
# Hub Side
###############################################################################

variable "hub_vnet_name" {
  description = "Name of the hub virtual network."
  type        = string
}

variable "hub_vnet_id" {
  description = "Resource ID of the hub virtual network."
  type        = string
}

variable "hub_resource_group_name" {
  description = "Resource group of the hub virtual network."
  type        = string
}

###############################################################################
# Spoke Side
###############################################################################

variable "spoke_name" {
  description = "Logical name of the spoke (used in peering resource names)."
  type        = string
}

variable "spoke_vnet_name" {
  description = "Name of the spoke virtual network."
  type        = string
}

variable "spoke_vnet_id" {
  description = "Resource ID of the spoke virtual network."
  type        = string
}

variable "spoke_resource_group_name" {
  description = "Resource group of the spoke virtual network."
  type        = string
}

###############################################################################
# Peering Options
###############################################################################

variable "allow_gateway_transit" {
  description = "Allow gateway transit on the hub-to-spoke peering. Enable if hub has a VPN/ER gateway."
  type        = bool
  default     = false
}

variable "use_remote_gateways" {
  description = "Use remote gateways on the spoke-to-hub peering. Requires allow_gateway_transit on hub side."
  type        = bool
  default     = false
}
