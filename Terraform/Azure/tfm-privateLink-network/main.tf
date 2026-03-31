###############################################################################
# Terraform Configuration
###############################################################################

terraform {
  required_version = ">= 1.9, < 2.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    # Configured via backend config file or CLI flags:
    #   resource_group_name  = "rg-terraform-state"
    #   storage_account_name = "stterraformstate"
    #   container_name       = "tfstate-private-dns"
    #   key                  = "privatelink-network.tfstate"
  }
}

###############################################################################
# Provider Configuration
###############################################################################

provider "azurerm" {
  features {}

  subscription_id = var.hub_subscription_id
}

# Alias provider for spoke subscriptions (when spokes live in different subs)
provider "azurerm" {
  alias = "spoke"
  features {}
}

###############################################################################
# Module: Private DNS Zones (Hub-Owned)
###############################################################################

module "private_dns" {
  source = "./modules/private_dns"

  resource_group_name = azurerm_resource_group.private_dns.name
  location            = var.location

  private_dns_zones = var.private_dns_zones
  hub_vnet_id       = var.hub_vnet_id

  spoke_vnet_links = {
    for key, spoke in var.spokes : key => {
      vnet_id              = spoke.vnet_id
      registration_enabled = lookup(spoke, "registration_enabled", false)
    }
  }

  enable_resource_locks = var.enable_resource_locks

  # Alerting
  alert_action_group_id         = var.alert_action_group_id
  alert_record_set_capacity_pct = var.alert_thresholds.record_set_capacity_pct
  alert_vnet_link_capacity_pct  = var.alert_thresholds.vnet_link_capacity_pct
  alert_record_set_count        = var.alert_thresholds.record_set_count

  tags = var.tags
}

###############################################################################
# Module: VNet Peerings (Hub <-> Spoke)
###############################################################################

module "vnet_peering" {
  source   = "./modules/vnet_peering"
  for_each = var.spokes

  # Hub side
  hub_vnet_name           = var.hub_vnet_name
  hub_vnet_id             = var.hub_vnet_id
  hub_resource_group_name = var.hub_resource_group_name

  # Spoke side
  spoke_name                = each.key
  spoke_vnet_name           = each.value.vnet_name
  spoke_vnet_id             = each.value.vnet_id
  spoke_resource_group_name = each.value.resource_group_name

  # Peering options
  allow_gateway_transit = lookup(each.value, "allow_gateway_transit", false)
  use_remote_gateways   = lookup(each.value, "use_remote_gateways", false)
}

###############################################################################
# Module: Private DNS Records (Private Endpoint A Records)
#
# OPTIONAL — This module is a no-op when dns_a_records is empty (the default).
# In many projects records are managed manually or by the spoke's own Terraform
# rather than centrally here. The Private DNS zones and VNet peerings work
# independently of whether any records are created.
###############################################################################

module "private_dns_records" {
  source = "./modules/private_dns_records"

  resource_group_name = azurerm_resource_group.private_dns.name
  dns_a_records       = var.dns_a_records
  tags                = var.tags
}

###############################################################################
# Import Blocks (for existing resources)
# Uncomment and adjust as needed when importing pre-existing resources.
###############################################################################

# import {
#   to = module.private_dns.azurerm_private_dns_zone.this["privatelink.blob.core.windows.net"]
#   id = "/subscriptions/SUBSCRIPTION_ID/resourceGroups/RG_NAME/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
# }
