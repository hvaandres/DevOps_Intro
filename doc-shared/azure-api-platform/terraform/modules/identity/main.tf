# =============================================================================
# RBAC Role Assignments — Least Privilege
# =============================================================================

# --- Function App Managed Identity → Storage Blob Data Reader ---
resource "azurerm_role_assignment" "func_storage_blob_reader" {
  scope                = var.storage_account_id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = var.function_app_identity_id
}

# --- Function App Managed Identity → Reader on Resource Group ---
resource "azurerm_role_assignment" "func_rg_reader" {
  scope                = var.resource_group_id
  role_definition_name = "Reader"
  principal_id         = var.function_app_identity_id
}

# --- Function App Managed Identity → Cosmos DB Account Reader (if Cosmos is used) ---
resource "azurerm_role_assignment" "func_cosmos_reader" {
  count = var.cosmos_account_id != "" ? 1 : 0

  scope                = var.cosmos_account_id
  role_definition_name = "Cosmos DB Account Reader Role"
  principal_id         = var.function_app_identity_id
}

# --- Function App Managed Identity → SQL DB Reader (if SQL is used) ---
resource "azurerm_role_assignment" "func_sql_reader" {
  count = var.sql_server_id != "" ? 1 : 0

  scope                = var.sql_server_id
  role_definition_name = "SQL DB Contributor" # Minimum for read; use custom role for stricter
  principal_id         = var.function_app_identity_id
}

# =============================================================================
# Service Principal Role Assignments (CI/CD)
# =============================================================================
resource "azurerm_role_assignment" "sp_contributor" {
  count = var.service_principal_object_id != "" ? 1 : 0

  scope                = var.resource_group_id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_object_id
}
