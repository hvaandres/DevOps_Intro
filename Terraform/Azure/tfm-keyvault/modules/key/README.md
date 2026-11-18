# Key Vault key submodule
Create a key in an existing RBAC-enabled vault, optionally configure rotation, and assign key-scoped roles. The caller configures AzureRM and must already have vault data-plane permissions, role-assignment permissions when needed, and network access.

```hcl
module "encryption_key" {
  source       = "../../modules/key"
  key_vault_id = var.key_vault_id
  key = {
    name            = "application-encryption"
    key_type        = "RSA"
    key_size        = 3072
    key_opts        = ["wrapKey", "unwrapKey"]
    expiration_date = var.key_expiration_date
    rotation_policy = {
      expire_after         = "P90D"
      notify_before_expiry = "P29D"
      automatic = {
        time_before_expiry = "P30D"
      }
    }
    role_assignments = {
      application = {
        principal_id         = var.application_principal_id
        principal_type       = "ServicePrincipal"
        role_definition_name = "Key Vault Crypto Service Encryption User"
      }
    }
  }
}
```

Inputs: required `key_vault_id` and typed `key` object; optional common `tags`. `key` supports `name`, `key_type`, `key_size`, `curve`, `key_opts`, validity dates, tags, rotation policy, and RBAC assignments. See `variables.tf` for defaults and validations.

RSA uses 2048/3072/4096 bits; EC uses a supported curve and omits RSA size. HSM variants require a premium vault. An automatic rotation policy accepts exactly one timing mode. Before-expiry rotation requires an initial future expiration date; `expire_after` sets lifetime for rotated versions. Durations must satisfy Azure's ISO 8601 and timing constraints.

Role assignments accept either a name or a fully qualified definition ID and use the versionless ARM resource ID, not a data-plane URI. Object-scoped roles do not authorize Terraform to create the key; grant the deployment identity vault-scoped Crypto Officer (or equivalent) beforehand.

Outputs: `id` (versioned URI), `versionless_id` (URI), `resource_versionless_id` (ARM ID), `version`, and `role_assignment_ids`. Use a compatible versionless reference for consumers that support rotation.

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

- [azurerm_key_vault_key.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key) (resource)
- [azurerm_role_assignment.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)

## Required Inputs

The following input variables are required:

### <a name="input_key"></a> [key](#input\_key)

Description: Key configuration and optional key-scoped RBAC. HSM types require a premium vault.

Type:

```hcl
object({
    name            = string
    key_type        = optional(string, "RSA")
    key_size        = optional(number, 2048)
    curve           = optional(string, "P-256")
    key_opts        = optional(set(string), ["wrapKey", "unwrapKey"])
    expiration_date = optional(string)
    not_before_date = optional(string)
    tags            = optional(map(string), {})
    rotation_policy = optional(object({
      expire_after         = optional(string)
      notify_before_expiry = optional(string)
      automatic = optional(object({
        time_after_creation = optional(string)
        time_before_expiry  = optional(string)
      }))
    }))
    role_assignments = optional(map(object({
      principal_id                     = string
      role_definition_name             = optional(string)
      role_definition_id               = optional(string)
      principal_type                   = optional(string)
      skip_service_principal_aad_check = optional(bool, false)
    })), {})
  })
```

### <a name="input_key_vault_id"></a> [key\_vault\_id](#input\_key\_vault\_id)

Description: ARM ID of an existing RBAC-enabled vault. The caller must already have data-plane permissions and network access.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_tags"></a> [tags](#input\_tags)

Description: Common tags; key-specific tags take precedence.

Type: `map(string)`

Default: `{}`

## Outputs

The following outputs are exported:

### <a name="output_id"></a> [id](#output\_id)

Description: Versioned data-plane key URI.

### <a name="output_resource_versionless_id"></a> [resource\_versionless\_id](#output\_resource\_versionless\_id)

Description: Versionless ARM resource ID used for RBAC scopes.

### <a name="output_role_assignment_ids"></a> [role\_assignment\_ids](#output\_role\_assignment\_ids)

Description: Key-scoped role assignment IDs.

### <a name="output_version"></a> [version](#output\_version)

Description: Current key version.

### <a name="output_versionless_id"></a> [versionless\_id](#output\_versionless\_id)

Description: Versionless data-plane key URI.
<!-- END_TF_DOCS -->
