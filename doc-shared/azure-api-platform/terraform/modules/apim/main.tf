# =============================================================================
# API Management Instance
# =============================================================================
resource "azurerm_api_management" "this" {
  name                = "apim-${var.name_prefix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  publisher_name      = var.publisher_name
  publisher_email     = var.publisher_email
  sku_name            = var.sku_name

  # VNet integration (External mode: gateway is public, management is private)
  virtual_network_type = var.vnet_type

  dynamic "virtual_network_configuration" {
    for_each = var.subnet_id != "" ? [1] : []
    content {
      subnet_id = var.subnet_id
    }
  }

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# =============================================================================
# API Definition — Data Platform API
# =============================================================================
resource "azurerm_api_management_api" "data_platform" {
  name                  = "data-platform-api"
  resource_group_name   = var.resource_group_name
  api_management_name   = azurerm_api_management.this.name
  revision              = "1"
  display_name          = "Data Platform API"
  path                  = "data"
  protocols             = ["https"]
  subscription_required = true

  service_url = "https://${var.function_app_url}/api"
}

# =============================================================================
# API Operations (read-only)
# =============================================================================
resource "azurerm_api_management_api_operation" "health" {
  operation_id        = "health-check"
  api_name            = azurerm_api_management_api.data_platform.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
  display_name        = "Health Check"
  method              = "GET"
  url_template        = "/health"
}

resource "azurerm_api_management_api_operation" "list_blobs" {
  operation_id        = "list-blobs"
  api_name            = azurerm_api_management_api.data_platform.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
  display_name        = "List Blob Data"
  method              = "GET"
  url_template        = "/blob-data"
}

resource "azurerm_api_management_api_operation" "get_blob" {
  operation_id        = "get-blob"
  api_name            = azurerm_api_management_api.data_platform.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
  display_name        = "Get Blob Data"
  method              = "GET"
  url_template        = "/blob-data/{container}/{blob}"

  template_parameter {
    name     = "container"
    required = true
    type     = "string"
  }

  template_parameter {
    name     = "blob"
    required = true
    type     = "string"
  }
}

resource "azurerm_api_management_api_operation" "query_sql" {
  operation_id        = "query-sql"
  api_name            = azurerm_api_management_api.data_platform.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
  display_name        = "Query SQL Data"
  method              = "GET"
  url_template        = "/sql-data"
}

resource "azurerm_api_management_api_operation" "query_cosmos" {
  operation_id        = "query-cosmos"
  api_name            = azurerm_api_management_api.data_platform.name
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
  display_name        = "Query Cosmos Data"
  method              = "GET"
  url_template        = "/cosmos-data"
}

# =============================================================================
# Product — External Consumers (read-only)
# =============================================================================
resource "azurerm_api_management_product" "external" {
  product_id            = "external-readonly"
  api_management_name   = azurerm_api_management.this.name
  resource_group_name   = var.resource_group_name
  display_name          = "External Read-Only Access"
  description           = "Product for external consumers with read-only data access."
  subscription_required = true
  subscriptions_limit   = 10
  approval_required     = true
  published             = true
}

resource "azurerm_api_management_product_api" "external" {
  api_name            = azurerm_api_management_api.data_platform.name
  product_id          = azurerm_api_management_product.external.product_id
  api_management_name = azurerm_api_management.this.name
  resource_group_name = var.resource_group_name
}

# =============================================================================
# Global Policy (read-only enforcement + JWT validation + rate limiting)
# =============================================================================
resource "azurerm_api_management_policy" "global" {
  api_management_id = azurerm_api_management.this.id

  xml_content = <<-XML
    <policies>
      <inbound>
        <!-- Enforce read-only: reject all non-GET/HEAD methods -->
        <choose>
          <when condition="@(context.Request.Method != "GET" && context.Request.Method != "HEAD")">
            <return-response>
              <set-status code="405" reason="Method Not Allowed" />
              <set-body>{"error": "Only GET and HEAD methods are permitted."}</set-body>
            </return-response>
          </when>
        </choose>

        <!-- JWT Validation (Entra ID) -->
        <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-scheme="Bearer">
          <openid-config url="https://login.microsoftonline.com/${var.tenant_id}/v2.0/.well-known/openid-configuration" />
          <audiences>
            <audience>api://${azurerm_api_management.this.name}</audience>
          </audiences>
          <issuers>
            <issuer>https://sts.windows.net/${var.tenant_id}/</issuer>
          </issuers>
        </validate-jwt>

        <!-- Rate limiting: 100 calls per minute per subscription -->
        <rate-limit-by-key calls="100" renewal-period="60"
          counter-key="@(context.Subscription?.Key ?? context.Request.IpAddress)" />

        <!-- Forward Function App host key -->
        <set-header name="x-functions-key" exists-action="override">
          <value>{{function-app-key}}</value>
        </set-header>

        <base />
      </inbound>
      <backend>
        <base />
      </backend>
      <outbound>
        <!-- Remove internal headers -->
        <set-header name="X-Powered-By" exists-action="delete" />
        <set-header name="X-AspNet-Version" exists-action="delete" />
        <base />
      </outbound>
      <on-error>
        <base />
      </on-error>
    </policies>
  XML
}

# =============================================================================
# Named Value for Function App Key
# =============================================================================
resource "azurerm_api_management_named_value" "function_key" {
  name                = "function-app-key"
  resource_group_name = var.resource_group_name
  api_management_name = azurerm_api_management.this.name
  display_name        = "function-app-key"
  value               = var.function_app_key
  secret              = true
}

# =============================================================================
# Diagnostic Settings
# =============================================================================
resource "azurerm_monitor_diagnostic_setting" "apim" {
  name                       = "diag-apim-${var.name_prefix}"
  target_resource_id         = azurerm_api_management.this.id
  log_analytics_workspace_id = var.log_analytics_id

  enabled_log {
    category = "GatewayLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
