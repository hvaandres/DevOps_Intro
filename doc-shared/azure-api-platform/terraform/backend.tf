terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "sttfstateapiplatform"
    container_name       = "tfstate"
    key                  = "azure-api-platform.tfstate"
  }
}
