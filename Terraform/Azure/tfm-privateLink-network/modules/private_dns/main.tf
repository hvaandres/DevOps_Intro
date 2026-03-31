###############################################################################
# Private DNS Zones (Hub-Owned)
#
# These zones are shared resources owned by the hub. Their state lives in the
# hub's Terraform backend, so destroying a spoke can never destroy a DNS zone.
###############################################################################

resource "azurerm_private_dns_zone" "this" {
  for_each = var.private_dns_zones

  name                = each.value
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

###############################################################################
# Virtual Network Links — Hub VNet
###############################################################################

resource "azurerm_private_dns_zone_virtual_network_link" "hub" {
  for_each = var.private_dns_zones

  name                  = "link-hub-${each.key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = var.hub_vnet_id
  registration_enabled  = false

  tags = var.tags
}

###############################################################################
# Virtual Network Links — Spoke VNets
#
# Creates a link for every (zone × spoke) combination.
# flatten + for_each pattern keeps the resource addresses stable.
###############################################################################

locals {
  zone_spoke_links = flatten([
    for zone_key, zone_fqdn in var.private_dns_zones : [
      for spoke_key, spoke in var.spoke_vnet_links : {
        key                  = "${zone_key}-${spoke_key}"
        zone_key             = zone_key
        spoke_key            = spoke_key
        vnet_id              = spoke.vnet_id
        registration_enabled = spoke.registration_enabled
      }
    ]
  ])

  zone_spoke_links_map = {
    for item in local.zone_spoke_links : item.key => item
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "spoke" {
  for_each = local.zone_spoke_links_map

  name                  = "link-${each.value.spoke_key}-${each.value.zone_key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.value.zone_key].name
  virtual_network_id    = each.value.vnet_id
  registration_enabled  = each.value.registration_enabled

  tags = var.tags
}

###############################################################################
# Management Locks — Prevent accidental deletion of DNS Zones
###############################################################################

resource "azurerm_management_lock" "dns_zone" {
  for_each = var.enable_resource_locks ? var.private_dns_zones : {}

  name       = "lock-${each.key}-do-not-delete"
  scope      = azurerm_private_dns_zone.this[each.key].id
  lock_level = "CanNotDelete"
  notes      = "Managed by Terraform. This Private DNS Zone is a shared hub resource — do not delete."
}

###############################################################################
# Azure Monitor Metric Alerts
#
# Alerts fire when DNS zone capacity metrics cross configured thresholds.
# Alerts are only created when an action group ID is provided.
###############################################################################

locals {
  alerts_enabled = var.alert_action_group_id != ""
}

resource "azurerm_monitor_metric_alert" "record_set_capacity" {
  for_each = local.alerts_enabled ? var.private_dns_zones : {}

  name                = "alert-dns-recordset-capacity-${each.key}"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_private_dns_zone.this[each.key].id]
  description         = "Record Set capacity utilization for ${each.value} exceeds ${var.alert_record_set_capacity_pct}%."
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Network/privateDnsZones"
    metric_name      = "RecordSetCapacityUtilization"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.alert_record_set_capacity_pct
  }

  action {
    action_group_id = var.alert_action_group_id
  }

  tags = var.tags
}

resource "azurerm_monitor_metric_alert" "vnet_link_capacity" {
  for_each = local.alerts_enabled ? var.private_dns_zones : {}

  name                = "alert-dns-vnetlink-capacity-${each.key}"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_private_dns_zone.this[each.key].id]
  description         = "VNet Link capacity utilization for ${each.value} exceeds ${var.alert_vnet_link_capacity_pct}%."
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Network/privateDnsZones"
    metric_name      = "VirtualNetworkLinkCapacityUtilization"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.alert_vnet_link_capacity_pct
  }

  action {
    action_group_id = var.alert_action_group_id
  }

  tags = var.tags
}

resource "azurerm_monitor_metric_alert" "record_set_count" {
  for_each = local.alerts_enabled ? var.private_dns_zones : {}

  name                = "alert-dns-recordset-count-${each.key}"
  resource_group_name = var.resource_group_name
  scopes              = [azurerm_private_dns_zone.this[each.key].id]
  description         = "Record Set count for ${each.value} exceeds ${var.alert_record_set_count}."
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Network/privateDnsZones"
    metric_name      = "RecordSetCount"
    aggregation      = "Maximum"
    operator         = "GreaterThan"
    threshold        = var.alert_record_set_count
  }

  action {
    action_group_id = var.alert_action_group_id
  }

  tags = var.tags
}
