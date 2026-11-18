provider "azurerm" {
  resource_provider_registrations = "none"
  features {}

  subscription_id = var.hub_subscription_id
}

# Retained for compatibility; cross-subscription peering is not wired.
provider "azurerm" {
  alias                           = "spoke"
  resource_provider_registrations = "none"
  features {}
}
