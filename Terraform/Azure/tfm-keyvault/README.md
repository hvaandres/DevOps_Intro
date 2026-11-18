# Azure Key Vault Terraform module
Reusable Azure Key Vault provisioning with Azure RBAC, optional private endpoints, and independently reusable key and secret submodules.

## Requirements
- Terraform >= 1.9, < 2.0 and AzureRM >= 4.71, < 5.0.
- An existing Azure subscription and deployment service principal.
- Appropriate management-plane roles, data-plane roles, and network access as described below.

The module declares provider requirements only. Configure providers, credentials, and state backends in your calling root configuration, not inside this module.

## Structure
- `main.tf`: vault, dynamic resource-group creation/lookup, and tenant/location resolution.
- `main.access_policies.tf`: RBAC assignments only; no legacy access policies.
- `main.keys.tf`, `main.secrets.tf`: optional child modules using stable map keys.
- `main.private-endpoint.tf`: optional private endpoints and DNS zone groups.
- `modules/key`, `modules/secret`: independently usable object modules.
- `examples/basic`: existing resource group, firewall, and vault-level application access.
- `examples/complete`: private networking, managed identity, rotating key, and application secret.
- `examples/bootstrap`: separate remote-state storage and service-principal role setup.

## Usage
From another root configuration, adjust `source` to this directory:

```hcl
provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy         = false
      purge_soft_deleted_keys_on_destroy   = false
      purge_soft_deleted_secrets_on_destroy = false
    }
  }
}

module "keyvault" {
  source = "../../Azure/tfm-keyvault"

  name                = "kv-yourapp-prod-unique"
  resource_group_name = "rg-yourapp-prod"

  private_endpoints = {
    application = {
      name                 = "pe-yourapp-keyvault"
      subnet_id            = var.private_endpoint_subnet_id
      private_dns_zone_ids = [var.keyvault_private_dns_zone_id]
    }
  }

  deployment_principal_roles = {
    secrets = "Key Vault Secrets Officer"
  }

  secrets = {
    database = {
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
  secret_values = { database = var.database_password }
}
```

Define the caller's password variable as `sensitive = true`. Every secret metadata map key must have a corresponding value key. Metadata is deliberately separate from sensitive values so it can safely drive `for_each`. Do not put secrets in resource names, tags, or role-assignment map keys.

To create a resource group, set `create_resource_group = true` and provide `location`. Otherwise, the module looks up the existing group and uses its location unless overridden. Omit `tenant_id` to use the provider tenant.

## Authorization and service-principal setup
Use the service principal's **object ID** (`principal_id`) for RBAC, not its application/client ID. Managed identities are also `ServicePrincipal` principals. No Microsoft Graph lookup or AzureAD provider is needed.

The deployment identity needs distinct permissions:
- **Contributor** at the workload resource-group scope for vault and related resource management. Contributor does not grant RBAC assignment or Key Vault secret/key access.
- **Role Based Access Control Administrator** at the workload scope for the RBAC assignments this module creates. This is privileged authorization management; use approved role-assignment conditions or narrower custom permissions where practical. Changing an existing vault's permission model can require unrestricted authorization permissions.
- **Key Vault Crypto Officer** at vault scope when Terraform creates/manages keys.
- **Key Vault Secrets Officer** at vault scope when Terraform creates/manages secrets.
- **Storage Blob Data Contributor** on the `tfstate` container for backend state read/write and lease locking.
- Appropriate access to existing endpoint subnets and DNS zones, including subnet join and private DNS zone join/write operations. Cross-resource-group or cross-subscription networks require assignments at those scopes too.

New resource groups require resource-group creation rights at subscription scope, since resource-group-scoped Contributor cannot create its own scope. The complete example creates two groups; grant appropriate subscription-level rights or adapt it to pre-provisioned groups. The bootstrap example's workload grants are sufficient for the basic example, not automatically for complete.

Have a subscription administrator pre-register `Microsoft.KeyVault`, `Microsoft.Network`, `Microsoft.ManagedIdentity`, and `Microsoft.Storage` as required by the selected example. The basic and complete providers set `resource_provider_registrations = "none"` so a resource-group-scoped service principal does not attempt subscription-wide automatic registration.

`deployment_principal_roles` is opt-in and defaults to empty. It assigns roles to the authenticated service principal unless `deployment_principal_id` is provided. The caller must already be authorized to create those assignments; the module cannot bootstrap its own management-plane privileges. If roles are already inherited, leave this map empty. Do not declare the same principal/role/scope twice in deployment and regular assignments.

For application identities, prefer the narrow roles in the examples, not `Key Vault Administrator`. Object roles use **versionless ARM IDs** (`/subscriptions/.../vaults/.../keys/...` or `/secrets/...`), never `https://...vault.azure.net` data-plane URIs. Role assignments accept exactly one of `role_definition_name` or a fully qualified `role_definition_id`.

RBAC changes are eventually consistent. Dependencies enforce ordering, not immediate authorization. Allow propagation and retry after a newly assigned role produces a 403. Persistent 403s may instead indicate incorrect identity, scope, or firewall configuration. Applications using object-only roles should request the known object name, not list the entire vault.

## Authentication and state
Use standard AzureRM environment variables:
- `ARM_SUBSCRIPTION_ID`: deployment subscription.
- `ARM_TENANT_ID`: service-principal tenant.
- `ARM_CLIENT_ID`: application/client ID.
- `ARM_CLIENT_SECRET`: retrieve securely from a secret manager, or use a certificate.

Prefer federated OIDC in CI: set `ARM_USE_OIDC=true` and configure the CI platform's token and federated identity; do not set `ARM_CLIENT_SECRET` for OIDC. Backend and provider authenticate independently, even when using the same environment variables.

Do not put client secrets, access keys, SAS tokens, or OIDC tokens into HCL, backend files, CLI arguments, or Git. The examples enable `use_azuread_auth = true` for state, eliminating storage access-key lookup. Reader on the storage account is only additionally needed if backend endpoint lookup is enabled.

Use an existing state account or deploy `examples/bootstrap` with a separately privileged identity first. Each consuming example declares the `tfstate` container and its own blob key. Copy `backend.hcl.example` to `backend.hcl` and replace the account name, then:

```sh
terraform init -backend-config=backend.hcl
terraform plan -out=deployment.tfplan
# Review the saved plan before applying it.
terraform apply deployment.tfplan
```

These are manual deployment instructions; local validation does not deploy Azure resources. Always use a distinct backend key for each independent deployment/environment. Backend settings cannot reference normal Terraform variables.

## Security and lifecycle
- RBAC is always enabled. The file named `main.access_policies.tf` intentionally contains no legacy access policies.
- Public network access is disabled and firewall default action is `Deny` with bypass `None`. Without a private endpoint or explicitly enabled/allowlisted public access, the vault remains inaccessible to data-plane operations. Do not use unrestricted public access for convenience.
- For private endpoints, the caller supplies an existing `privatelink.vaultcore.azure.net` DNS zone, VNet links, and runner connectivity. An endpoint alone does not connect your laptop/CI runner to the VNet. The complete example demonstrates DNS setup and a network-only bootstrap stage.
- Purge protection defaults to true and cannot be disabled after enabling it. Soft-delete retention defaults to 90 days, accepts 7-90 days, and cannot be changed after creation. Soft-delete is always enabled by Azure. Purge protection blocks permanent deletion during retention, not ordinary soft-delete.
- Configure provider purge-on-destroy flags to false as shown. Deleted names may remain reserved through retention. Destroying keys/secrets still requires data-plane permissions and network access; keep the runner connected until destruction completes.
- Ordinary Terraform-managed secret values **are stored in raw state and saved plans** even when marked sensitive. Sensitive only redacts normal display. Protect state, backups, plan artifacts, logs, and blob versions; anyone who can read state can potentially read those secrets. Versioning and soft deletion retain older secret values too. No output intentionally exposes values.
- Azure Key Vault supports certificate storage, but this module does not issue/import certificates. Key rotation is supported; secret expiration does not rotate the secret.
- Before-expiry key rotation requires an initial `expiration_date`. Set a meaningful future date, typically 90 days from initial deployment, and a compatible ISO 8601 rotation policy. `expire_after` applies to newly rotated key versions. Use versionless IDs for consumers that support automatic rotation. Do not dynamically change the initial expiration on every plan.
- HSM-backed keys require `sku_name = "premium"`; the standalone key module relies on the caller to select a compatible vault.

## Input/output reference
Required root inputs are `name` and `resource_group_name`. Main optional inputs:
- `create_resource_group`, `location`, `tenant_id`, `sku_name`.
- `purge_protection_enabled`, `soft_delete_retention_days`.
- `public_network_access_enabled`, `network_acls`.
- `role_assignments`, `deployment_principal_id`, `deployment_principal_roles`.
- `keys`, `secrets`, sensitive `secret_values`, `private_endpoints`, and `tags`.

`variables.tf` contains the full typed schema and defaults. Outputs include `id`, `name`, `vault_uri`, `resource_group_name`, object reference maps (`keys`, `secrets`), `private_endpoint_ids`, and vault `role_assignment_ids`.

## Validation and documentation
Run from this module directory:

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
terraform -chdir=modules/key init -backend=false
terraform -chdir=modules/key test
terraform -chdir=modules/secret init -backend=false
terraform -chdir=modules/secret test
```

Mock-provider tests need no Azure credentials and do not contact Azure. They verify configuration, not live RBAC propagation, Azure policy, networking reachability, or service behavior. Initialize/validate the three example directories with `-backend=false` separately. Tests in the complete and bootstrap examples also use mock providers.

With terraform-docs >= 0.19 installed, regenerate all six references from this module directory:

```sh
for directory in . modules/key modules/secret examples/basic examples/complete examples/bootstrap; do
  terraform-docs --config .terraform-docs.yml "$directory"
done
```

`.terraform-docs.yml` injects the generated references without replacing the existing guides. To regenerate only this module's reference, run `terraform-docs .`.

<!-- BEGIN_TF_DOCS -->
## Requirements

The following requirements are needed by this module:

- <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) (>= 1.9, < 2.0)

- <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) (~> 4.71)

## Providers

The following providers are used by this module:

- <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) (4.81.0)

## Modules

The following Modules are called:

### <a name="module_key"></a> [key](#module\_key)

Source: ./modules/key

Version:

### <a name="module_secret"></a> [secret](#module\_secret)

Source: ./modules/secret

Version:

## Resources

The following resources are used by this module:

- [azurerm_key_vault.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault) (resource)
- [azurerm_private_endpoint.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) (resource)
- [azurerm_resource_group.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) (resource)
- [azurerm_role_assignment.deployment](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)
- [azurerm_role_assignment.vault](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)
- [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) (data source)
- [azurerm_resource_group.existing](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/resource_group) (data source)

## Required Inputs

The following input variables are required:

### <a name="input_name"></a> [name](#input\_name)

Description: Globally unique Key Vault name: 3-24 alphanumeric/hyphen characters, beginning with a letter, ending with an alphanumeric, without consecutive hyphens.

Type: `string`

### <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name)

Description: Name of an existing resource group, or the resource group to create.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_create_resource_group"></a> [create\_resource\_group](#input\_create\_resource\_group)

Description: Create the resource group instead of looking it up.

Type: `bool`

Default: `false`

### <a name="input_deployment_principal_id"></a> [deployment\_principal\_id](#input\_deployment\_principal\_id)

Description: Service principal object ID for optional deployment roles; defaults to the authenticated principal object ID.

Type: `string`

Default: `null`

### <a name="input_deployment_principal_roles"></a> [deployment\_principal\_roles](#input\_deployment\_principal\_roles)

Description: Explicit vault data-plane roles for the deployment service principal. Keys are stable assignment identifiers; values are role names. Avoid duplicating role\_assignments.

Type: `map(string)`

Default: `{}`

### <a name="input_keys"></a> [keys](#input\_keys)

Description: Keys indexed by stable logical names; per-key roles are scoped to the versionless ARM key resource.

Type:

```hcl
map(object({
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
  }))
```

Default: `{}`

### <a name="input_location"></a> [location](#input\_location)

Description: Azure region; defaults to the existing resource group's location. Required for a new resource group.

Type: `string`

Default: `null`

### <a name="input_network_acls"></a> [network\_acls](#input\_network\_acls)

Description: Vault firewall. Denies all by default, with no trusted-service bypass.

Type:

```hcl
object({
    bypass                     = optional(string, "None")
    default_action             = optional(string, "Deny")
    ip_rules                   = optional(set(string), [])
    virtual_network_subnet_ids = optional(set(string), [])
  })
```

Default: `{}`

### <a name="input_private_endpoints"></a> [private\_endpoints](#input\_private\_endpoints)

Description: Private endpoints and optional existing private DNS zone IDs. Caller manages DNS zones, VNet links, and runner connectivity.

Type:

```hcl
map(object({
    name                 = string
    subnet_id            = string
    resource_group_name  = optional(string)
    location             = optional(string)
    private_dns_zone_ids = optional(list(string), [])
    tags                 = optional(map(string), {})
  }))
```

Default: `{}`

### <a name="input_public_network_access_enabled"></a> [public\_network\_access\_enabled](#input\_public\_network\_access\_enabled)

Description: Allow public-endpoint access subject to network\_acls; disabled by default.

Type: `bool`

Default: `false`

### <a name="input_purge_protection_enabled"></a> [purge\_protection\_enabled](#input\_purge\_protection\_enabled)

Description: Enable purge protection. Once enabled, Azure does not allow disabling it.

Type: `bool`

Default: `true`

### <a name="input_role_assignments"></a> [role\_assignments](#input\_role\_assignments)

Description: Vault-scoped RBAC assignments keyed by stable logical names. Specify exactly one role name or fully qualified role definition ID.

Type:

```hcl
map(object({
    principal_id                     = string
    role_definition_name             = optional(string)
    role_definition_id               = optional(string)
    principal_type                   = optional(string)
    skip_service_principal_aad_check = optional(bool, false)
  }))
```

Default: `{}`

### <a name="input_secret_values"></a> [secret\_values](#input\_secret\_values)

Description: Sensitive secret values keyed identically to secrets. Values are persisted in Terraform state; protect backend access.

Type: `map(string)`

Default: `{}`

### <a name="input_secrets"></a> [secrets](#input\_secrets)

Description: Non-sensitive secret metadata, keyed by stable logical names. Pass values separately through secret\_values.

Type:

```hcl
map(object({
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
  }))
```

Default: `{}`

### <a name="input_sku_name"></a> [sku\_name](#input\_sku\_name)

Description: Vault SKU. HSM-backed keys require premium.

Type: `string`

Default: `"standard"`

### <a name="input_soft_delete_retention_days"></a> [soft\_delete\_retention\_days](#input\_soft\_delete\_retention\_days)

Description: Immutable soft-delete retention in whole days, between 7 and 90.

Type: `number`

Default: `90`

### <a name="input_tags"></a> [tags](#input\_tags)

Description: Common resource tags, merged with per-object tags.

Type: `map(string)`

Default: `{}`

### <a name="input_tenant_id"></a> [tenant\_id](#input\_tenant\_id)

Description: Tenant ID; defaults to the authenticated provider tenant.

Type: `string`

Default: `null`

## Outputs

The following outputs are exported:

### <a name="output_id"></a> [id](#output\_id)

Description: Key Vault ARM resource ID.

### <a name="output_keys"></a> [keys](#output\_keys)

Description: Key IDs and versions keyed by logical name, including versionless URI and ARM IDs.

### <a name="output_name"></a> [name](#output\_name)

Description: Key Vault name.

### <a name="output_private_endpoint_ids"></a> [private\_endpoint\_ids](#output\_private\_endpoint\_ids)

Description: Private endpoint ARM IDs keyed by logical name.

### <a name="output_resource_group_name"></a> [resource\_group\_name](#output\_resource\_group\_name)

Description: Resolved resource group name.

### <a name="output_role_assignment_ids"></a> [role\_assignment\_ids](#output\_role\_assignment\_ids)

Description: Vault-level and deployment role assignment IDs.

### <a name="output_secrets"></a> [secrets](#output\_secrets)

Description: Secret IDs and versions only; never secret values.

### <a name="output_vault_uri"></a> [vault\_uri](#output\_vault\_uri)

Description: Key Vault data-plane URI.
<!-- END_TF_DOCS -->
