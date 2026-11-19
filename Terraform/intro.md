# Terraform Azure setup — Make command reference

`Terraform/` contains shared tooling and separate deployable roots. Run Terraform
inside a deployment, not in this directory. Private Link provider configuration is
in `Azure/tfm-privateLink-network/providers.tf`; Key Vault deployment provider
configuration is in `Azure/deployments/keyvault/providers.tf`.

## Guide navigation

- [Requirements and installation](#requirements)
- [All available commands](#available-commands)
- [First-time sequence](#recommended-first-time-sequence)
- [Help](#help)
- [Login and subscription selection](#azure-login-and-azure-subscription)
- [Subscription permissions](#azure-permissions)
- [Resource group creation](#resource-group-create)
- [Backend creation](#backend-create)
- [Backend smoke test](#backend-test)
- [Offline tests](#test)
- [Configuration variables](#configuration-variables)
- [Noninteractive execution](#noninteractive-execution)
- [Next steps for each deployment](#next-steps-for-each-deployment)
- [Request a Key Vault from CI/CD](#request-a-key-vault-from-cicd)
- [Troubleshooting and cleanup](#troubleshooting-and-cleanup)

## Requirements

- Azure CLI (`az`), Bash, Make, and Python 3.9+.
- Terraform >= 1.9 and < 2.0 for deployment (use the version pinned by CI when possible).
- An Azure subscription and permission to create resource groups/storage accounts.
- Existing Owner, User Access Administrator, or Role Based Access Control
  Administrator privileges at the required scope to assign roles. PIM roles must
  already be activated; assignment conditions or deny policies may still restrict
  grants. These commands cannot give an unauthorized caller more access.

On macOS, if Homebrew is already installed:

```bash
brew install azure-cli python
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

Bash is included with macOS. Apple's command-line developer tools provide Make;
if it is missing, install those tools with `xcode-select --install`.
Verify your tools:

```bash
az version
python3 --version
terraform version
make --version
bash --version
```

The helper is invoked through Bash by Make; no `chmod` step is needed.

## Available commands

Run these directly from the repository root, without `-C`. The root `Makefile`
includes `Terraform/Makefile`, so the same targets also work when you are inside
`Terraform/`. Other project directories have independent Makefiles.

- `make` or `make help`: print commands and defaults.
- `make azure-login`: authenticate, list subscriptions, and select one.
- `make azure-subscription`: select a subscription without logging in again.
- `make azure-permissions`: confirm and grant subscription-wide roles.
- `make resource-group-create`: confirm and create/reuse a resource group only.
- `make backend-create`: confirm and create/reuse test backend resources.
- `make backend-test`: check the backend with a temporary blob.
- `make test`: run offline tests with a mocked Azure CLI.

There are no `plan`, `apply`, or `destroy` targets in this shared Makefile.
Creating a backend does not deploy either Terraform stack.

## Recommended first-time sequence

```bash
make azure-login

# Replace these values before running subsequent commands.
export SUBSCRIPTION_ID="<subscription UUID>"
export STORAGE_ACCOUNT="<globally unique 3-24 lowercase letters/digits>"

make azure-permissions
# Optional: backend-create also creates/reuses this group.
make resource-group-create
make backend-create
make backend-test
```

The permissions and creation commands require confirmation. If an administrator
already assigned the needed roles, skip `azure-permissions`. Azure resource
creation can incur charges.

## help

```bash
make help
```

Lists targets and configuration defaults without contacting Azure. This is also
the default target when running `make` with no command.

## azure-login and azure-subscription

```bash
make azure-login
make azure-subscription
# Or select directly:
make azure-subscription SUBSCRIPTION_ID="<subscription UUID or name>"
```

`azure-login` opens the Azure CLI authentication flow, then lists enabled
subscriptions and prompts for a subscription UUID or name.
`azure-subscription` skips authentication and only lists/selects subscriptions.
Both update the Azure CLI default and show the selected account.

For safety, every resource/permission/backend command still requires an explicit
`SUBSCRIPTION_ID` and passes the resolved UUID to each Azure resource operation.
A Make recipe cannot export variables back into your terminal, which is why the
first-time sequence exports the variable in your own shell.

## azure-permissions

```bash
make azure-permissions
```

Displays the signed-in user's Entra object ID and requests confirmation by typing
the target subscription UUID. Assigns these roles at subscription scope, skipping
matching assignments at that scope or inherited from ancestors:

- **Contributor**: resource management.
- **Owner**: resource management and role assignments. This already includes
  Contributor capabilities; both are assigned to match the requested setup.
- **Storage Blob Data Contributor**: Azure AD blob read/write/delete and state
  lease access; Contributor/Owner alone do not provide this data-plane access.
- **Key Vault Administrator**: RBAC vault data-plane management, including
  keys, secrets, and certificates. Owner handles vault resources and role
  assignments. No additional purge role is assigned automatically.

These are intentionally broad development/admin grants, **not production or CI
defaults**. Prefer resource-group-level Contributor, container-level Storage Blob
Data Contributor, and vault-scoped task-specific Key Vault roles for workloads.
The existing Key Vault module uses RBAC, not legacy access policies. RBAC does not
bypass firewalls, private endpoints, or purge protection.

Role changes are not automatically revoked if a later assignment fails; inspect
partial results before retrying. Group-derived effective permissions are not
exhaustively evaluated. Existing role-assignment authority is required: the command
does not bootstrap its own permissions.

To target another identity, use its **Entra object ID**, not an application/client
ID:

```bash
make azure-permissions \
  PRINCIPAL_ID="<Entra object UUID>" PRINCIPAL_TYPE=ServicePrincipal
# PRINCIPAL_TYPE can also be User or Group.
```

## resource-group-create

Create a resource group without creating storage or assigning roles:

```bash
make resource-group-create \
  SUBSCRIPTION_ID="<subscription UUID>" \
  RESOURCE_GROUP=rg-my-test LOCATION=eastus2
```

This resolves and displays the target subscription, group, and location; asks you
to type the subscription UUID for confirmation; then runs `az group create`.
You must already be logged in and have resource-group creation permission, such
as Contributor at subscription scope. `STORAGE_ACCOUNT` and Blob/Key Vault roles
are not required.

Defaults are `RESOURCE_GROUP=rg-terraform-state-test` and `LOCATION=eastus2`.
Reusing an existing group does not delete its contents; an existing group's
location cannot be changed by rerunning this command. If you want the backend in
that group, pass the same `RESOURCE_GROUP` to `backend-create` and `backend-test`.
No backend configuration or Terraform deployment inputs are written by this target.

## backend-create

First ensure the **identity currently running Azure CLI** has management access and
Storage Blob Data Contributor. Assigning roles to another principal does not grant
the caller access.

```bash
make backend-create
```

After subscription confirmation, creates/reuses:

- Resource group `rg-terraform-state-test` in `eastus2`.
- Your named StorageV2 account using Standard_LRS, HTTPS/TLS 1.2+, no public blob
  access, and **shared-key access disabled**.
- Private container `tfstate`, using `--auth-mode login`, not account keys or SAS.
- Blob versioning and seven-day blob/container soft delete.

Use a dedicated test account: reusing an existing account enforces these settings
and may affect clients relying on shared keys. Firewalls and organizational
policies may require additional connectivity/setup. RBAC-sensitive operations
retry up to six times, ten seconds apart; propagation may take longer.

Successful creation writes ignored `Terraform/backend.hcl` with backend
coordinates and `use_azuread_auth = true`. Identical configuration can be reused;
a differing existing file is never overwritten. No credentials are written.
To customize:

```bash
make backend-create \
  RESOURCE_GROUP=rg-state-sandbox LOCATION=westus2 \
  CONTAINER_NAME=tfstate STATE_KEY=privatelink-network.tfstate
```

The default state key is `test/terraform.tfstate`. Use a different `STATE_KEY` and
`BACKEND_CONFIG` for each independent deployment; never initialize unrelated
stacks against the same key. The default file is ignored by Git. If you choose
another filename, keep it outside Git or add an appropriate ignore rule.

Backend creation never initializes Terraform, migrates state, or creates
networking/Key Vault resources. For a **new, uninitialized** Private Link stack,
after reviewing the generated configuration:

```bash
terraform -chdir=Terraform/Azure/tfm-privateLink-network init \
  -backend-config=../../backend.hcl
```

Do not use this to switch an existing deployment's backend without a separately
reviewed state migration. Backend initialization also does not set deployment
input variables such as `hub_subscription_id`. The deployment providers disable
automatic resource-provider registration; an administrator must register required
namespaces such as Microsoft.Storage, Microsoft.Network, and Microsoft.KeyVault
as applicable.

## backend-test

Use the same subscription, account, group, and container used for creation:

```bash
make backend-test
# If you customized resource names during creation:
make backend-test RESOURCE_GROUP=rg-state-sandbox CONTAINER_NAME=tfstate
```

Checks resource availability, uploads a unique `_bootstrap-tests/<UUID>.txt`,
downloads and compares its contents, then deletes it. Failure paths also attempt
cleanup and report cleanup failures. It never reads, overwrites, or deletes a state
blob. Versioning/soft delete may retain the deleted test blob until retention
expires. The test changes only that temporary blob and does not require the
creation confirmation. It does not read values from `backend.hcl`; supply the
same variables each time.

This is an access smoke test, not a Terraform deployment test: it does not run
`terraform plan`, validate deployment inputs, or exercise Terraform's state-lock
protocol. A passing result proves the tested identity could reach the configured
backend and perform those blob operations at that time.

## test

```bash
make test
```

Runs offline Python unittest regression tests using a temporary mocked Azure CLI.
Does not log in, assign roles, or contact Azure. Requires Python 3.9+ but does not
require a real Azure CLI installation. For an additional Bash syntax check:

```bash
bash -n Terraform/scripts/azure-bootstrap.sh
```

To also run the existing pipeline regression suite:

```bash
python3 -m unittest discover -s .github/scripts/tests -v
```

## Configuration variables

Pass variables as `make ... NAME=value` or export them in your shell.
Command-line values override environment values.

- `SUBSCRIPTION_ID`: required for resource/permission/backend commands; UUID or name.
  Login/selection commands prompt if absent.
- `STORAGE_ACCOUNT`: required for backend commands; globally unique account name,
  3–24 lowercase letters/digits.
- `RESOURCE_GROUP`: default `rg-terraform-state-test`.
- `LOCATION`: default `eastus2`; used by `resource-group-create` and `backend-create`.
- `CONTAINER_NAME`: default `tfstate`; lowercase letters/digits/hyphens, 3–63
  characters, no consecutive hyphens.
- `STATE_KEY`: default `test/terraform.tfstate`; written to generated backend
  configuration, not used as the smoke-test blob name.
- `BACKEND_CONFIG`: default `Terraform/backend.hcl`, anchored to the shared
  Terraform Makefile directory, unchanged whichever entry point you use.
  Custom relative paths are relative to your current working directory: the
  repository root when using root-level `make`, or `Terraform/` when running
  Make there. Used by `backend-create`.
- `PRINCIPAL_ID`: defaults to the signed-in user's Entra object ID. Required when
  `PRINCIPAL_TYPE` is Group or ServicePrincipal.
- `PRINCIPAL_TYPE`: User (default), Group, or ServicePrincipal.
- `CONFIRM_SUBSCRIPTION`: optional exact resolved subscription UUID, only for
  deliberate noninteractive confirmation of role grants/group/backend creation.

Do not run cloud-changing targets concurrently with `make -j`; perform login,
permissions, creation, and testing sequentially.

The Makefile does not automatically load `.env`, `terraform.tfvars`, or
`backend.hcl`. Export values or pass them explicitly. Shell quotes protect spaces
in values such as subscription names:

```bash
make azure-subscription SUBSCRIPTION_ID="Development Subscription"
```

## Noninteractive execution

Use this only after reviewing the resolved subscription and the intended roles
or resource changes. `CONFIRM_SUBSCRIPTION` must contain the exact subscription
UUID, even when `SUBSCRIPTION_ID` was supplied as a subscription name.

```bash
export SUBSCRIPTION_ID="<subscription UUID>"
export STORAGE_ACCOUNT="<globally unique storage account name>"

# Existing Azure CLI authentication is required; these commands do not log in.
make azure-permissions CONFIRM_SUBSCRIPTION="$SUBSCRIPTION_ID"
make resource-group-create CONFIRM_SUBSCRIPTION="$SUBSCRIPTION_ID"
make backend-create CONFIRM_SUBSCRIPTION="$SUBSCRIPTION_ID"
make backend-test
```

For a service principal or managed identity session, pass `PRINCIPAL_ID` and
`PRINCIPAL_TYPE=ServicePrincipal` to the permissions command. The ID must be the
service principal's Entra object ID. This helper does not create identities or
configure CI federation; use the deployment-specific OIDC guidance below for CI.

All targets return a nonzero exit status on failure. Successful changes made
before a failure remain in Azure. Fix the cause, review any partial resources or
assignments, and rerun with the same configuration. A different existing backend
configuration is rejected before resource creation.

## Next steps for each deployment

- [Private Link networking](Azure/tfm-privateLink-network/README.md): configure
  hub/spoke inputs and resource-provider registrations, then initialize, review
  the plan, and deploy from `Azure/tfm-privateLink-network/`.
- [Key Vault](Azure/tfm-keyvault/README.md): read the module examples and CI/OIDC
  setup. The deployable wrapper lives in `Azure/deployments/keyvault/`.

For example, to generate a separate backend file for a **new** Key Vault stack
using the same test account/container but a different state key:

```bash
make backend-create \
  STATE_KEY=keyvault/deployment.tfstate \
  BACKEND_CONFIG=Terraform/Azure/deployments/keyvault/backend.hcl

terraform -chdir=Terraform/Azure/deployments/keyvault init \
  -backend-config=backend.hcl
```

This path is also ignored by the repository's `backend.hcl` rule.
The example runs from the repository root; when inside `Terraform/`, use
`BACKEND_CONFIG=Azure/deployments/keyvault/backend.hcl` instead.
The backend commands do not write deployment input files or run `plan`/`apply`.
Review each deployment's required inputs and follow its own guide; do not use
`init` to silently redirect an existing stack to a new state file.

## Request a Key Vault from CI/CD

Use **Actions → CI and CD — Key Vault → Run workflow**, on `main`, to enter
the vault name, existing resource group, and vault configuration. Choose
`cyber-dev`, `cyber-tst`, or `cyber-prd` (default). The pipeline verifies that the
group belongs to that selected subscription and fixes the vault region to
`westus2`; it does not create the group or change your local Azure CLI selection.

Leave **dry_run enabled** for a real Terraform plan without apply. To proceed,
submit the same values with dry-run disabled and have **hvaandres** approve the
fresh plan in **Review deployments**. Each requested vault gets its own state key.
All mutating pipelines require hvaandres approval; read-only CI runs automatically.

Actions shows separate steps for `terraform fmt -check`, `terraform init`,
`terraform validate`, `terraform test` (offline CI), `terraform plan`, approval,
and `terraform apply` (only after approval and with dry-run disabled). There is no
standalone `terraform check` command. Azure CLI is used only for read-only
subscription/group preflight, never to create the vault.

An administrator must first configure the Cyber UUID/identity/backend variables,
OIDC trust, trusted runner, and protected approval environments. A run initiated
by hvaandres cannot self-approve; another operator must initiate a mutating run.
See the [full form, dry-run, and approval setup guide](Azure/tfm-keyvault/README.md#request-a-cyber-key-vault-from-the-actions-form).

## Troubleshooting and cleanup

- **AuthorizationFailed on role assignment:** ask an authorized subscription
  administrator to assign the roles, or activate an eligible PIM role.
- **Blob authorization error:** verify Storage Blob Data Contributor for the
  executing identity, allow propagation time, and rerun. Contributor alone is
  insufficient for Azure AD blob operations.
- **Networking error:** ensure your terminal can reach the account/vault endpoint.
  RBAC does not override firewalls or private-endpoint requirements.
- **Storage account name unavailable:** choose a different globally unique name.
- **Resource provider not registered:** ask an authorized administrator to register
  the namespace reported by Azure, then retry. Terraform's deployment providers
  intentionally do not register namespaces automatically.
- **Cannot resolve the signed-in user:** for a non-user Azure CLI session, pass
  `PRINCIPAL_ID` and `PRINCIPAL_TYPE=ServicePrincipal`; for a user, check tenant
  selection and Microsoft Graph access.
- **Backend config differs:** review it and use a new `BACKEND_CONFIG`; the command
  will not overwrite an existing configuration or migrate state.
- **Temporary blob cleanup failed:** the failure output identifies the blob to
  inspect/remove. Never remove a state blob as part of test cleanup.

No resource-group/account deletion target is provided. Review test resources in
Azure before removing them, and never delete a backend holding active state.