###############################################################################
# VNet Peering — Bidirectional Hub <-> Spoke
###############################################################################

# Hub -> Spoke
resource "azurerm_virtual_network_peering" "hub_to_spoke" {
  name                      = "peer-hub-to-${var.spoke_name}"
  resource_group_name       = var.hub_resource_group_name
  virtual_network_name      = var.hub_vnet_name
  remote_virtual_network_id = var.spoke_vnet_id

  allow_forwarded_traffic = true
  allow_gateway_transit   = var.allow_gateway_transit
}

# Spoke -> Hub
resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  name                      = "peer-${var.spoke_name}-to-hub"
  resource_group_name       = var.spoke_resource_group_name
  virtual_network_name      = var.spoke_vnet_name
  remote_virtual_network_id = var.hub_vnet_id

  allow_forwarded_traffic = true
  use_remote_gateways     = var.use_remote_gateways
}
