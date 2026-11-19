# No workload resources or module calls: the selected state is the inventory.
# Provider aliases must be added through review, never generated from user input.
terraform {
  required_version = ">= 1.9, < 2.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.71"
    }
  }

  backend "azurerm" {
    use_azuread_auth = true
  }
}

provider "azurerm" {
  resource_provider_registrations = "none"

  features {
    api_management {
      purge_soft_delete_on_destroy = false
    }
    app_configuration {
      purge_soft_delete_on_destroy = false
    }
    cognitive_account {
      purge_soft_delete_on_destroy = false
    }
    log_analytics_workspace {
      permanently_delete_on_destroy = false
    }
    machine_learning {
      purge_soft_deleted_workspace_on_destroy = false
    }
    recovery_service {
      purge_protected_items_from_vault_on_destroy = false
    }
    template_deployment {
      delete_nested_items_during_deletion = false
    }
    virtual_machine {
      delete_os_disk_on_deletion = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true
    }
    key_vault {
      purge_soft_delete_on_destroy          = false
      purge_soft_deleted_keys_on_destroy    = false
      purge_soft_deleted_secrets_on_destroy = false
    }
  }
}
