resource "azurerm_private_endpoint" "this" {
  for_each = var.private_endpoints

  name                = each.value.name
  resource_group_name = coalesce(each.value.resource_group_name, local.resource_group_name)
  location            = coalesce(each.value.location, local.location)
  subnet_id           = each.value.subnet_id
  tags                = merge(var.tags, each.value.tags)

  private_service_connection {
    name                           = "${each.value.name}-connection"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  dynamic "private_dns_zone_group" {
    for_each = length(each.value.private_dns_zone_ids) == 0 ? [] : [each.value.private_dns_zone_ids]
    content {
      name                 = "keyvault"
      private_dns_zone_ids = private_dns_zone_group.value
    }
  }
}
