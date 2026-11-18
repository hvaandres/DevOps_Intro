# Complete: private application vault with rotation
This example creates two resource groups, a VNet/subnet, a private endpoint, private DNS zone and VNet link, a managed identity, and optionally an RSA encryption key and database password secret. Public vault access remains disabled.

The key rotates 30 days before expiry, newly rotated versions expire after 90 days, and notification is configured 29 days before expiry. The application gets key-scoped Crypto Service Encryption User (role name) and secret-scoped Secrets User (fully qualified role ID).

## Prerequisites
- Existing remote-state storage (`tfstate` container) reachable by the runner.
- A deployment service principal with rights to create resource groups at subscription scope, Contributor permissions for all created resources, and authorization-management permissions at the vault scope or an ancestor. The bootstrap example's single workload-group assignments alone are not sufficient here.
- A runner connected to the example's VNet, or an initial network-only deployment followed by connectivity setup. Peering, VPN, runner hosts, custom DNS forwarding, and CI federation are deliberately not provisioned here.
- Non-overlapping VNet/subnet ranges suitable for your network.

## Two-stage first deployment
1. Copy `terraform.tfvars.example` and `backend.hcl.example` to local files without `.example`; fill in names. Keep `create_objects = false`.
2. Initialize with `terraform init -backend-config=backend.hcl`, plan, review, and apply. This creates networking, the managed identity, and an empty vault without data-plane calls for keys/secrets.
3. Connect your runner using VPN/peering or place it inside the VNet. Confirm the vault hostname resolves to the private endpoint and HTTPS/443 is reachable. Peering alone does not automatically provide private DNS resolution from a different VNet; configure links or forwarding for that runner network.
4. Change `create_objects = true`. Supply stable future UTC `key_expiration_date` and `secret_expiration_date`; typically use an initial key expiration 90 days from deployment. Retrieve the real database password securely from your secret store into `TF_VAR_database_password`, without displaying it or putting it in CLI arguments or source files.
5. Review a fresh plan and apply it from the connected runner. Newly created data-plane roles can take time to propagate; if Azure returns an authorization 403, verify the identity/scope and retry after propagation.

With a preconnected runner and correct DNS you can deploy in one stage with `create_objects = true`.

The state blob is `keyvault/complete.tfstate` in `tfstate`. Saved plans and state contain the secret; restrict and retain them accordingly. The example provides only a secret's storage, not a database or its password configuration.

Keep `create_objects = true` for steady state. Switching it to false after deployment **destroys** the managed key/secret and removes deployment data roles; this is a bootstrap switch, not a pause/resume feature. Destroy objects while the runner still has private connectivity. Purge protection retains soft-deleted objects and vault names for the configured retention.

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

### <a name="module_keyvault"></a> [keyvault](#module\_keyvault)

Source: ../..

Version:

## Resources

The following resources are used by this module:

- [azurerm_private_dns_zone.keyvault](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone) (resource)
- [azurerm_private_dns_zone_virtual_network_link.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link) (resource)
- [azurerm_resource_group.network](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) (resource)
- [azurerm_subnet.private_endpoints](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) (resource)
- [azurerm_user_assigned_identity.application](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/user_assigned_identity) (resource)
- [azurerm_virtual_network.this](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) (resource)
- [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) (data source)

## Required Inputs

The following input variables are required:

### <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name)

Description: New vault resource group name; network resources use a separate -network group.

Type: `string`

### <a name="input_vault_name"></a> [vault\_name](#input\_vault\_name)

Description: Globally unique vault name.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_create_objects"></a> [create\_objects](#input\_create\_objects)

Description: False for an initial network-only deployment before connecting the runner; true to create keys and secrets.

Type: `bool`

Default: `true`

### <a name="input_database_password"></a> [database\_password](#input\_database\_password)

Description: Supply from a secret store through TF\_VAR\_database\_password, not a committed tfvars file. Required when create\_objects is true.

Type: `string`

Default: `null`

### <a name="input_key_expiration_date"></a> [key\_expiration\_date](#input\_key\_expiration\_date)

Description: Initial future UTC expiration, typically 90 days after initial deployment. Required for before-expiry rotation when create\_objects is true.

Type: `string`

Default: `null`

### <a name="input_location"></a> [location](#input\_location)

Description: Azure deployment region.

Type: `string`

Default: `"westeurope"`

### <a name="input_private_endpoint_subnet_prefix"></a> [private\_endpoint\_subnet\_prefix](#input\_private\_endpoint\_subnet\_prefix)

Description: Private endpoint subnet within vnet\_address\_space.

Type: `string`

Default: `"10.42.1.0/24"`

### <a name="input_secret_expiration_date"></a> [secret\_expiration\_date](#input\_secret\_expiration\_date)

Description: Future UTC secret expiration; expiration does not automatically rotate its value.

Type: `string`

Default: `null`

### <a name="input_vnet_address_space"></a> [vnet\_address\_space](#input\_vnet\_address\_space)

Description: Non-overlapping VNet range; adapt for peering or VPN connectivity.

Type: `string`

Default: `"10.42.0.0/16"`

## Outputs

The following outputs are exported:

### <a name="output_application_identity_client_id"></a> [application\_identity\_client\_id](#output\_application\_identity\_client\_id)

Description: Client ID applications use to select their managed identity.

### <a name="output_keys"></a> [keys](#output\_keys)

Description: Key references, including versionless IDs.

### <a name="output_secrets"></a> [secrets](#output\_secrets)

Description: Secret references only, never values.

### <a name="output_vault_id"></a> [vault\_id](#output\_vault\_id)

Description: Vault ARM ID.

### <a name="output_vault_uri"></a> [vault\_uri](#output\_vault\_uri)

Description: Vault data-plane endpoint; resolves privately from the linked VNet.

### <a name="output_vnet_id"></a> [vnet\_id](#output\_vnet\_id)

Description: VNet to connect to the Terraform runner through peering, VPN, or a VNet-hosted runner.
<!-- END_TF_DOCS -->