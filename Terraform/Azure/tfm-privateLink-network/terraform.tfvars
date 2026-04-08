###############################################################################
# Common
###############################################################################

location    = "eastus2"
environment = "dev"

tags = {
  Environment = "dev"
  ManagedBy   = "terraform"
  Project     = "privatelink-network"
}

###############################################################################
# Hub References — Replace with your actual values
###############################################################################

hub_subscription_id     = "00000000-0000-0000-0000-000000000000"
hub_vnet_id             = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-hub-networking/providers/Microsoft.Network/virtualNetworks/vnet-hub"
hub_vnet_name           = "vnet-hub"
hub_resource_group_name = "rg-hub-networking"

###############################################################################
# Private DNS Zones — Add or remove zones as services are onboarded
###############################################################################

private_dns_zones = {
  ah-app1 = "privatelink.ahapp1.com"
  ah-app2 = "privatelink.ahapp2.com"
  ah-app3 = "privatelink.ahapp3.com"
  ah-app4 = "privatelink.ahapp4.com"
  ah-app5 = "privatelink.ahapp5.com"
}

###############################################################################
# Spokes — Add spoke entries as they are onboarded
###############################################################################

# spokes = {
#   spoke-dev = {
#     vnet_id             = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-spoke-dev/providers/Microsoft.Network/virtualNetworks/vnet-spoke-dev"
#     vnet_name           = "vnet-spoke-dev"
#     resource_group_name = "rg-spoke-dev"
#   }
# }

###############################################################################
# DNS A Records — Optional, leave empty when records are managed externally
###############################################################################

# dns_a_records = {}

###############################################################################
# Safety & Alerting
###############################################################################

enable_resource_locks = false # Set to true for production

# alert_action_group_id = "/subscriptions/.../resourceGroups/.../providers/Microsoft.Insights/actionGroups/ag-platform-alerts"

# alert_thresholds = {
#   record_set_capacity_pct = 80
#   vnet_link_capacity_pct  = 80
#   record_set_count        = 20000
# }
