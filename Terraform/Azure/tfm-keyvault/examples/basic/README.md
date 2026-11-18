# Basic: application vault in an existing resource group
This example provisions a vault and gives an existing application identity the Key Vault Secrets User role. It does not create secrets, keys, or a resource group. Retention is 90 days, purge protection is enabled, and the public endpoint is firewall restricted.

1. Use existing state storage or separately deploy `../bootstrap`.
2. Authenticate the deployment service principal using the environment variables in the root README.
3. Copy `terraform.tfvars.example` to `terraform.tfvars`, replace the vault/group/principal values, and explicitly allow application/runner public IPv4 ranges if data-plane access is needed. Empty ranges deny all.
4. Copy `backend.hcl.example` to `backend.hcl` and set the real state account name.
5. Initialize, review a plan, and apply only after review:

```sh
terraform init -backend-config=backend.hcl
terraform plan -out=deployment.tfplan
terraform apply deployment.tfplan
```

The state container is `tfstate`, key `keyvault/basic.tfstate`. Use a unique key for another independent deployment. The deployment identity needs workload Contributor, authorization-management permissions for assignments, and container-scoped Storage Blob Data Contributor. Vault data-plane roles are not required here because no secret/key resources are managed.

Application identity is an object ID, not client ID. Role grants do not bypass the firewall. For private-only access, use the complete example instead.

<!-- BEGIN_TF_DOCS -->
## Requirements

The following requirements are needed by this module:

- <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) (>= 1.9, < 2.0)

- <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) (~> 4.71)

## Providers

No providers.

## Modules

The following Modules are called:

### <a name="module_keyvault"></a> [keyvault](#module\_keyvault)

Source: ../..

Version:

## Resources

No resources.

## Required Inputs

The following input variables are required:

### <a name="input_application_principal_id"></a> [application\_principal\_id](#input\_application\_principal\_id)

Description: Application service principal or managed identity object ID, not its client ID.

Type: `string`

### <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name)

Description: Existing resource group name.

Type: `string`

### <a name="input_vault_name"></a> [vault\_name](#input\_vault\_name)

Description: Globally unique vault name.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_allowed_ipv4_cidrs"></a> [allowed\_ipv4\_cidrs](#input\_allowed\_ipv4\_cidrs)

Description: Explicit public IPv4 CIDRs allowed through the vault firewall. Empty denies all.

Type: `set(string)`

Default: `[]`

## Outputs

The following outputs are exported:

### <a name="output_vault_id"></a> [vault\_id](#output\_vault\_id)

Description: Vault ARM ID.

### <a name="output_vault_uri"></a> [vault\_uri](#output\_vault\_uri)

Description: Vault data-plane endpoint.
<!-- END_TF_DOCS -->