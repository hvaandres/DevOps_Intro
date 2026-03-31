###############################################################################
# Resource Groups
###############################################################################

resource "azurerm_resource_group" "private_dns" {
  name     = "rg-private-dns-${var.environment}"
  location = var.location
  tags     = var.tags
}
