###############################################################################
# Private DNS A Records
#
# Creates DNS A records in hub-owned Private DNS Zones for Private Endpoints.
# The zones themselves are managed by the private_dns module — this module
# only creates records within those zones.
###############################################################################

resource "azurerm_private_dns_a_record" "this" {
  for_each = var.dns_a_records

  name                = each.value.name
  zone_name           = each.value.zone_name
  resource_group_name = var.resource_group_name
  ttl                 = each.value.ttl
  records             = each.value.records

  tags = var.tags
}
