# Key Vault secret submodule
Create a secret in an existing RBAC-enabled vault and assign secret-scoped roles. The caller configures AzureRM and supplies existing data-plane permissions, role-assignment permissions when needed, and network access.

```hcl
module "database_secret" {
  source       = "../../modules/secret"
  key_vault_id = var.key_vault_id
  value        = var.database_password
  secret = {
    name            = "database-password"
    content_type    = "text/plain"
    expiration_date = var.secret_expiration_date
    role_assignments = {
      application = {
        principal_id         = var.application_principal_id
        principal_type       = "ServicePrincipal"
        role_definition_name = "Key Vault Secrets User"
      }
    }
  }
}
```

Inputs: required `key_vault_id`, sensitive non-empty `value`, and non-sensitive `secret` metadata; optional common `tags`. Metadata supports name, content type, expiration/not-before dates, tags, and role assignments. Role assignments require exactly one role name or fully qualified definition ID.

The caller's password variable must also be sensitive. **The value is stored in Terraform state and plan artifacts** despite display redaction. Do not commit values or expose them in outputs. Restrict access to state and its historical versions.

Expiration does not rotate values. The deployment identity needs vault-scoped Secrets Officer (or equivalent) to create/manage secrets. Application access can be narrowed to this secret; RBAC uses its versionless ARM ID. An object-only application should fetch the known secret by name rather than list the entire vault.

Outputs: `id` (versioned URI), `versionless_id` (URI), `resource_versionless_id` (ARM ID), `version`, and `role_assignment_ids`. No secret-value output is provided.

<!-- BEGIN_TF_DOCS -->
## Requirements

The following requirements are needed by this module:

- <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) (>= 1.9, < 2.0)

- <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) (~> 4.71)

## Providers

The following providers are used by this module:

- <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) (4.81.0)

## Modules

No modules.

## Resources

The following resources are used by this module:

- [azurerm_key_vault_secret.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret) (resource)
- [azurerm_role_assignment.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)

## Required Inputs

The following input variables are required:

### <a name="input_key_vault_id"></a> [key\_vault\_id](#input\_key\_vault\_id)

Description: ARM ID of an existing RBAC-enabled vault. Caller needs vault-level secret management permissions and network access.

Type: `string`

### <a name="input_secret"></a> [secret](#input\_secret)

Description: Non-sensitive secret metadata and optional secret-scoped RBAC.

Type:

```hcl
object({
    name            = string
    content_type    = optional(string)
    expiration_date = optional(string)
    not_before_date = optional(string)
    tags            = optional(map(string), {})
    role_assignments = optional(map(object({
      principal_id                     = string
      role_definition_name             = optional(string)
      role_definition_id               = optional(string)
      principal_type                   = optional(string)
      skip_service_principal_aad_check = optional(bool, false)
    })), {})
  })
```

### <a name="input_value"></a> [value](#input\_value)

Description: Secret value. Sensitive in CLI output, but persisted in Terraform state.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_tags"></a> [tags](#input\_tags)

Description: Common tags; secret-specific tags take precedence.

Type: `map(string)`

Default: `{}`

## Outputs

The following outputs are exported:

### <a name="output_id"></a> [id](#output\_id)

Description: Versioned data-plane secret URI.

### <a name="output_resource_versionless_id"></a> [resource\_versionless\_id](#output\_resource\_versionless\_id)

Description: Versionless ARM resource ID used for RBAC scopes.

### <a name="output_role_assignment_ids"></a> [role\_assignment\_ids](#output\_role\_assignment\_ids)

Description: Secret-scoped role assignment IDs.

### <a name="output_version"></a> [version](#output\_version)

Description: Current secret version.

### <a name="output_versionless_id"></a> [versionless\_id](#output\_versionless\_id)

Description: Versionless data-plane secret URI.
<!-- END_TF_DOCS -->
