# =============================================================================
# VNet
# =============================================================================
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  address_space       = var.vnet_address_space
  tags                = var.tags
}

# =============================================================================
# Subnets
# =============================================================================

# Functions subnet — delegated to Microsoft.Web/serverFarms for VNet integration
resource "azurerm_subnet" "functions" {
  name                 = "snet-functions-${var.name_prefix}"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.subnet_functions_prefix]

  delegation {
    name = "function-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# APIM subnet
resource "azurerm_subnet" "apim" {
  name                 = "snet-apim-${var.name_prefix}"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.subnet_apim_prefix]
}

# Private endpoints subnet
resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-pe-${var.name_prefix}"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.subnet_private_endpoints_prefix]

  private_endpoint_network_policies_enabled = true
}

# =============================================================================
# Network Security Groups
# =============================================================================

resource "azurerm_network_security_group" "functions" {
  name                = "nsg-functions-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_network_security_group" "apim" {
  name                = "nsg-apim-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  # Allow inbound HTTPS for APIM gateway
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "VirtualNetwork"
  }

  # Allow APIM management endpoint
  security_rule {
    name                       = "AllowAPIMManagement"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3443"
    source_address_prefix      = "ApiManagement"
    destination_address_prefix = "VirtualNetwork"
  }

  # Allow Azure Load Balancer
  security_rule {
    name                       = "AllowAzureLoadBalancer"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "6390"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "VirtualNetwork"
  }
}

resource "azurerm_network_security_group" "private_endpoints" {
  name                = "nsg-pe-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# =============================================================================
# NSG Associations
# =============================================================================

resource "azurerm_subnet_network_security_group_association" "functions" {
  subnet_id                 = azurerm_subnet.functions.id
  network_security_group_id = azurerm_network_security_group.functions.id
}

resource "azurerm_subnet_network_security_group_association" "apim" {
  subnet_id                 = azurerm_subnet.apim.id
  network_security_group_id = azurerm_network_security_group.apim.id
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  subnet_id                 = azurerm_subnet.private_endpoints.id
  network_security_group_id = azurerm_network_security_group.private_endpoints.id
}
