# Bootstrap: remote state and deployment roles
Run once with a separately privileged bootstrap identity. This is not a child module of the vault deployment and does not create a service principal or client secret.

Creates:
- A state resource group and GRS storage account with TLS 1.2 minimum, shared-key authentication disabled, and public blob access disabled.
- Blob versioning and 30-day blob/container soft deletion.
- A default-deny storage firewall with explicitly supplied public runner IP ranges.
- The private-access `tfstate` container.
- Storage Blob Data Contributor for an existing deployment principal at container scope.
- A separate workload resource group and Contributor plus Role Based Access Control Administrator grants for that principal at that group's scope.

The storage account has Terraform `prevent_destroy`. This guards normal Terraform destruction, not manual deletion or removal of the resource from configuration. Do not casually remove it.

## Run
The bootstrap identity needs subscription-level resource creation and role-assignment permissions. Because shared keys are disabled and the provider uses Entra authentication for storage, it also needs Storage Blob Data Contributor on the state account or an ancestor before storage data-plane operations. Management-plane Owner alone does not grant blob data access. Pre-grant the role at the state resource-group/subscription scope as appropriate for your bootstrap process.

Use a runner outside the storage account's Azure region for IP-based firewall rules; same-region Azure service traffic is not reliably controlled by public-IP rules. Production private runners should adapt this example to a private endpoint/service endpoint and private DNS. Include both bootstrap and future deployment runner addresses in the allowlist. IP allowlists do not grant identity permissions.

Copy `terraform.tfvars.example` to `terraform.tfvars` and replace every placeholder, especially the globally unique account name, real public runner addresses, and service-principal **object ID**.

```sh
terraform init
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
```

Review the plan before applying. This example deliberately starts with **local state**, since a configuration cannot initialize a backend that does not exist yet. Protect that file and its backups; never commit them. After setup, use the output account name in the consuming examples' `backend.hcl` files.

Optionally add an AzureRM backend block to this bootstrap root after creation, using `container_name = "tfstate"`, `key = "bootstrap.tfstate"`, `use_azuread_auth = true`, and the created account name. Run `terraform init -migrate-state` with an identity authorized to read/write that container; verify successful migration and follow your organization's local-state cleanup procedure. Do not share the workload example's state key.

The workload group is precreated for `../basic`. This example does not grant subscription-wide deployment rights or network permissions elsewhere; `../complete` needs additional grants because it creates groups. Role assignments are eventually consistent; allow propagation before initializing workloads.

Versioning/soft deletion retains old state containing any historical secrets. Treat the account and backups as sensitive. Configure additional organizational requirements such as diagnostics, private-only networking, CMK, locks, and recovery policies before production use.

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

- [azurerm_resource_group.state](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) (resource)
- [azurerm_resource_group.workload](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) (resource)
- [azurerm_role_assignment.state](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)
- [azurerm_role_assignment.workload](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_assignment) (resource)
- [azurerm_storage_account.state](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account) (resource)
- [azurerm_storage_container.state](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) (resource)

## Required Inputs

The following input variables are required:

### <a name="input_allowed_ipv4_cidrs"></a> [allowed\_ipv4\_cidrs](#input\_allowed\_ipv4\_cidrs)

Description: Public IPv4 ranges for bootstrap and deployment runners. Azure Storage requires plain IPv4 addresses instead of /32 or /31 CIDRs.

Type: `set(string)`

### <a name="input_deployment_principal_id"></a> [deployment\_principal\_id](#input\_deployment\_principal\_id)

Description: Existing deployment service principal object ID, not its application/client ID.

Type: `string`

### <a name="input_state_resource_group_name"></a> [state\_resource\_group\_name](#input\_state\_resource\_group\_name)

Description: New resource group for Terraform state.

Type: `string`

### <a name="input_storage_account_name"></a> [storage\_account\_name](#input\_storage\_account\_name)

Description: Globally unique state storage account name: 3-24 lowercase letters and digits.

Type: `string`

### <a name="input_workload_resource_group_name"></a> [workload\_resource\_group\_name](#input\_workload\_resource\_group\_name)

Description: New workload group. Matches the basic example's existing resource\_group\_name.

Type: `string`

## Optional Inputs

The following input variables are optional (have default values):

### <a name="input_location"></a> [location](#input\_location)

Description: Azure region for state and workload resource groups.

Type: `string`

Default: `"westeurope"`

## Outputs

The following outputs are exported:

### <a name="output_container_name"></a> [container\_name](#output\_container\_name)

Description: State container.

### <a name="output_storage_account_name"></a> [storage\_account\_name](#output\_storage\_account\_name)

Description: Use as storage\_account\_name in example backend.hcl files.

### <a name="output_workload_resource_group_name"></a> [workload\_resource\_group\_name](#output\_workload\_resource\_group\_name)

Description: Existing resource group for examples/basic.
<!-- END_TF_DOCS -->