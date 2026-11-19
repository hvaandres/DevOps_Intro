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
For local development, authenticate with Azure CLI using an authorized identity or your organization's approved service-principal mechanism. CI uses federated OIDC: `ARM_USE_OIDC=true` with GitHub's token endpoint and federated app credentials. Do not configure `ARM_CLIENT_SECRET` for these workflows. Backend and provider authenticate independently, even when using the same environment variables.

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

## GitHub Actions CI/CD and Blob state setup
### Request a Cyber Key Vault from the Actions form
Open **Actions → CI and CD — Key Vault → Run workflow** and choose `main`.
The form includes these non-secret fields:

- `subscription`: `cyber-dev`, `cyber-tst`, or **`cyber-prd` (default)**. Production
  is selected initially, so confirm the selection carefully.
- `vault_name`: required globally unique vault name, 3–24 letters/digits/hyphens,
  starting with a letter, ending with a letter/digit, without consecutive hyphens.
  The request normalizes it to lowercase for consistent state keys.
- `resource_group_name`: required name of an **existing** group in the selected
  Cyber subscription, not a resource ID. No group is created by this pipeline.
- `sku_name`: `standard` (default) or `premium`.
- `purge_protection_enabled`: true by default. Once enabled it cannot be disabled.
- `soft_delete_retention_days`: whole number from 7 to 90, default 90.
  Azure does not permit changing retention after creation.
- `private_endpoints_json`: object keyed by endpoint logical name, default `{}`.
  See the example below.
- `role_assignments_json`: object keyed by assignment logical name, default `{}`.
- `tags_json`: string-to-string object, default `{}`.
- `dry_run`: **true by default**. Plans only; no Terraform apply.

The vault's region is fixed in the deployment wrapper to **`westus2`**, not
inferred from the resource group's metadata region. This is an Azure region, not
an availability-zone number. RBAC remains enabled, public access is disabled,
and the firewall remains deny-by-default. Tenant/identity/backend information is
resolved from trusted repository variables, never entered into the form.
The request does not create keys, secret values, certificates, or service
principals. Empty endpoint settings leave a private-only vault unreachable until
private connectivity is configured. Endpoint location, if supplied, must match
the endpoint subnet's region; it does not change the vault region.

The pipeline runs offline checks, validates form fields on a hosted runner,
authenticates the planning identity using OIDC, verifies the configured
subscription **UUID and Azure display name**, and looks up the group using that
explicit subscription UUID. Missing/inaccessible groups, unknown subscriptions,
misconfigured UUID/name mappings, and a group outside the selected subscription
fail before backend initialization or planning. A group in `cyber-dev` must be
requested with `cyber-dev` selected; the pipeline never silently switches to a
different subscription. Subscription display names must be exactly `cyber-dev`,
`cyber-tst`, and `cyber-prd` (case-insensitive). Access is rechecked after approval.

#### Dry run, then deploy
1. Submit the form with `dry_run=true`. Inspect the Terraform summary for **create**,
   **update**, or **no vault changes**, and inspect failures/logs if planning fails.
   This is a real Azure-backed Terraform plan, not a guarantee that a later apply
   will succeed under Azure naming, quota, policy, RBAC, or network conditions.
2. To proceed, submit the **same inputs again** with `dry_run=false`. This creates
   a fresh plan against current state and pauses at the protected apply job.
3. **hvaandres** reviews the new plan and chooses **Review deployments → Approve
   and deploy**. Only that reviewed saved plan is applied.

Alternatively, start with dry-run disabled to plan, pause, and approve within one
run. A completed dry-run does not have an apply button; it must never authorize
applying an old plan in another run. No-change plans skip approval/apply. A dry run
still needs the backend, OIDC, scoped permissions, network access, enable flag, and
correct approval-environment configuration. It can read state/acquire Blob leases
but does not apply managed-resource changes.

The Actions UI exposes each Terraform phase as a separate step: formatting check
(`terraform fmt -check`), initialization (`terraform init`), configuration checks
(`terraform validate`), offline mocked tests (`terraform test`), saved live plan
(`terraform plan`), approval, and finally `terraform apply` of that saved plan.
Terraform has no standalone `terraform check` command. Azure CLI preflight only
reads subscription/group metadata; Terraform manages all deployed resources.

Each requested vault uses
`keyvault/<subscription-choice>/<lowercase-vault-name>.tfstate`. Different vault
requests therefore do not replace the legacy deployment or each other. Repeating
the same name/subscription targets the same managed vault: supply its complete
desired endpoint/role/tag configuration, not just incremental additions.
Do not move existing resources into this workflow without a reviewed state
migration/import. The request path rejects plans that delete or replace a vault;
moving its resource group or changing immutable settings requires separate review.

#### Cyber repository variables
Set **repository-level Actions variables** for each prefix:

- `cyber-dev` → `CYBER_DEV_KEYVAULT`
- `cyber-tst` → `CYBER_TST_KEYVAULT`
- `cyber-prd` → `CYBER_PRD_KEYVAULT`

For each prefix configure:

- `<PREFIX>_SUBSCRIPTION_ID`: the corresponding real Cyber subscription UUID.
- `<PREFIX>_TENANT_ID`: Entra tenant UUID.
- `<PREFIX>_PLAN_CLIENT_ID` and `<PREFIX>_APPLY_CLIENT_ID`: OIDC app/client UUIDs.
- `<PREFIX>_BACKEND_ACCOUNT` and `<PREFIX>_BACKEND_CONTAINER`: pre-existing state
  account/container names.
- `<PREFIX>_RUNNER_LABELS`: optional runner-label JSON array, default
  `["self-hosted","linux","azure-terraform"]`. Cyber runners also need Azure CLI.
- `<PREFIX>_DEPLOY_ENABLED`: literal `true` after setup, including for dry runs.

For example, the production UUID variable is
`CYBER_PRD_KEYVAULT_SUBSCRIPTION_ID`. These mappings are intentionally not guessed
from subscription names. No Cyber UUIDs are committed. The Cyber form does **not**
use `KEYVAULT_TFVARS_JSON` or a `<PREFIX>_TFVARS_JSON`; form inputs are authoritative.
Do not override shared identity/subscription settings at environment scope.
Reader on the target subscription/group must let the planning identity verify
membership; apply needs workload Contributor plus the narrowly scoped rights
required by the requested RBAC/endpoints. Both identities need state-container
Storage Blob Data Contributor. Neither command grants itself permissions.

Use the OIDC setup below, with the repository's `main` subject for planning and
the corresponding protected-environment subject for applying, for example
`repo:hvaandres/DevOps_Intro:environment:keyvault-cyber-prd-apply` when using legacy
GitHub subject formatting. Check actual repository OIDC subject configuration.

#### JSON field examples
`private_endpoints_json`:
```json
{
  "application": {
    "name": "pe-kv-application",
    "subnet_id": "/subscriptions/<subscription UUID>/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-app/subnets/private-endpoints",
    "resource_group_name": "rg-network",
    "location": "westus2",
    "private_dns_zone_ids": [
      "/subscriptions/<DNS subscription UUID>/resourceGroups/rg-dns/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
    ],
    "tags": {"managed_by": "terraform"}
  }
}
```
Replace every placeholder with a real UUID/reference. The pipeline does not
provision the subnet, DNS zone, VNet links, or runner connectivity.
`role_assignments_json`:
```json
{
  "application_reader": {
    "principal_id": "<Entra service principal object UUID>",
    "principal_type": "ServicePrincipal",
    "role_definition_name": "Key Vault Secrets User"
  }
}
```
Each assignment specifies exactly one `role_definition_name` or fully qualified
`role_definition_id`. Optional `skip_service_principal_aad_check` defaults false.
Use object IDs, not app/client IDs. `tags_json`, for example:
```json
{"environment":"prd","owner":"platform","managed_by":"terraform"}
```
Do not place credentials or secret values in any form field.

### Required approval gateway for all mutating workflows
All repository-changing resource requests and Azure deployments have multiple
stages and must be approved by **hvaandres**. Read-only CI checks remain automatic.
Create these GitHub repository environments **before enabling the workflows**:

- `keyvault-cyber-dev-plan`, `keyvault-cyber-tst-plan`,
  `keyvault-cyber-prd-plan`: current Cyber plan/apply environments. The current
  configuration routes both jobs to the same per-subscription environment.
- `keyvault-cyber-dev-apply`, `keyvault-cyber-tst-apply`,
  `keyvault-cyber-prd-apply`: also supported if separate apply environments are configured.
- `keyvault-apply`: legacy post-merge single-vault deployment approval.
- `privatelink-apply`: network deployment approval.
- `resource-request-approval`: approval before the Private Link request workflow
  creates a branch/PR; merging that PR is not an Azure deployment approval.

For **each** environment, configure required reviewers as **only the user
`hvaandres`** (not a team or a list of alternates), disable **Prevent self-review**,
restrict deployment to exactly one branch rule `main` (no tags), and disable
administrator bypass where supported. Merely naming an environment in YAML does
not configure these rules. The workflows check the protection settings and the
actual approving user's identity through GitHub's API; missing/wrong settings,
another approver, rejection, or absent approval fail closed.

**Solo-maintainer mode:** hvaandres may initiate a request and explicitly approve
that same run. Approval is not automatic: the gate still checks for an actual
approved review by hvaandres for the selected environment. Missing reviews,
rejections, or approvals by other users are rejected when approval is enabled.

To enable this in GitHub, open **Repository → Settings → Environments**, select
the environment used by the run (for example `keyvault-cyber-prd-plan`), keep only
`hvaandres` under **Required reviewers**, uncheck **Prevent self-review**, and
save the protection rules. Repeat for any other environments you use. Keep the
`main`-only branch policy and other protections unchanged. The local script cannot
change GitHub settings without authenticated repository administration access.

Use `require_approval=true` to retain explicit approval while working alone;
`false` is the existing temporary script-check bypass, not self-approval mode.
The bypass does not remove GitHub's configured required-reviewer gate.
Read-only dry runs can still be initiated by hvaandres. Start a **new workflow
run** after failures, expiration, or changes; do not reuse the Re-run jobs button.
Review history does not identify attempts, so mutating jobs reject later run
attempts rather than potentially accepting an old approval.
Protect `main` and require review of workflow/approval-helper changes. GitHub
administrators still control repository settings and must not bypass these
protections. If your GitHub plan does not support required environment reviewers,
leave mutation/deployment disabled.

### Existing stack CI/CD
The repository workflows cover both Key Vault and Private Link Network:
- `ci-keyvault.yml` and `ci-privatelink-network.yml`: credential-free PR checks and, when enabled, deployment after a push/merge to `main`.
- `terraform-checks.yml`: formatting, backend-disabled validation, and mock tests. PR code never runs on the private deployment runner and receives no Azure token.
- `terraform-deploy.yml`: OIDC plan against remote Blob state, review summary, required environment approval, then apply of that exact saved plan. Manual runs from `main` default to `dry_run=true`, which skips apply entirely.
- `add-resource-privatelink.yml`: offline validation, hvaandres approval, and then resource-request PR generation; it never accesses Azure or state.

Deployments are **disabled by default**. Leave `KEYVAULT_DEPLOY_ENABLED` and `PRIVATELINK_DEPLOY_ENABLED` unset or `false` while doing local dry runs. Local checks use `init -backend=false` and mock providers; they do not establish that live federation, RBAC, or connectivity works.

### 1. Provision the storage account and Blob container separately
Use existing Azure Blob Storage or provision it with an administrator before enabling CD. This pipeline does not create its own backend. Set a **storage account name** and **container name**, not a Blob URL, connection string, SAS token, or account key.

Both stacks can share an account/container because they use different blob keys:
- Legacy post-merge Key Vault: `keyvault/deployment.tfstate`.
- Manual Cyber Key Vault requests: `keyvault/<subscription-choice>/<vault-name>.tfstate`.
- Private Link: `privatelink-network.tfstate` (preserves the existing workflow's key).

The backend uses Entra data-plane authorization (`ARM_USE_AZUREAD=true`) and OIDC. Grant **Storage Blob Data Contributor** on the selected container to both planning and apply service principals, including blob-lease locking rights. Normal initialization does not need account-key lookup or storage-account Reader; Reader is additionally required if you explicitly enable management-plane endpoint discovery.

Enable versioning, blob/container soft delete, encryption, restricted access, and appropriate retention on the state account. Do not put a read-only immutability policy on the active state blob, because Terraform must update and lease it. Restrict the storage firewall/private endpoint to trusted runners. OIDC does not provide network access.

**State is a snapshot of managed infrastructure, not a change log.** Saved plans describe proposed changes; blob versions provide historical state snapshots. No changes are persisted to the state blob during these local dry-run checks.

If these resources already have state under another blob key/account, stop and perform a reviewed state migration/import first. Do not enable a second root against empty state for existing resources. Never copy Key Vault example state into this new deployment root without reconciling its resource addresses and inputs.

### 2. Configure federated service principals
Use separate plan and apply app registrations/service principals per stack by default. Federation is configured on the **Entra app registration**; Azure RBAC targets the corresponding **service principal object ID**. Workflow configuration uses its **application/client ID**, not object ID.

Configure federated credentials with:
- Issuer: `https://token.actions.githubusercontent.com`.
- Audience: `api://AzureADTokenExchange`.
- Plan trust: this repository's `main` branch token subject.
- Apply trust: this repository's `keyvault-apply` or `privatelink-apply` environment token subject.

For repositories using the legacy subject format, subjects are:
- Plan: `repo:hvaandres/DevOps_Intro:ref:refs/heads/main`.
- Key Vault apply: `repo:hvaandres/DevOps_Intro:environment:keyvault-apply`.
- Private Link apply: `repo:hvaandres/DevOps_Intro:environment:privatelink-apply`.

**Verify the repository's actual OIDC subject configuration before creating trust.** New/transferred/renamed repositories may use immutable owner/repository IDs, and customized subjects can differ. Do not print or persist bearer tokens to discover claims. Use the repository OIDC configuration and GitHub's current subject-format documentation. Do not trust all branches, PR subjects, or arbitrary repositories.

Terraform requests short-lived tokens directly using job-scoped `id-token: write`; no stored client secret, access key, SAS, or token file is required. Cyber requests additionally use `azure/login` with the same OIDC identity for Azure CLI subscription/group preflight; Terraform still authenticates independently with OIDC. If your environment must use one service principal, set both client-ID variables to that ID and add both federated credentials, but understand that the planning job then has the same Azure privileges as apply.

Planning needs workload Reader and enough scoped read/data-plane access to refresh managed resources, plus state-container permissions. Applying needs workload Contributor and any required subnet/private-DNS permissions. Role assignments require narrowly scoped Role Based Access Control Administrator or an equivalent approved custom role; Contributor alone cannot create role assignments or management locks. Pre-register the required Azure resource providers because the roots disable automatic registration. Do not grant Owner by default.

The new Key Vault deployment root uses an **existing resource group**, private/deny defaults, optional private endpoints, and explicit application role assignments. It intentionally exposes no key/secret-value inputs. Vault data-plane roles are not needed by this root until it is extended to manage such objects; that extension also requires private runner connectivity and sensitive-input handling. Existing mock/example tests still cover the module's key/secret features.

### 3. Configure protected deployment environments
Create `keyvault-apply` and `privatelink-apply` in the repository settings before enabling deployment:
1. Set the sole required reviewer to **hvaandres**, with **Prevent self-review** disabled to allow solo-maintainer approval.
2. Select **Selected branches and tags**, with exactly one **branch** rule named `main` and no tag rules.
3. Disable administrator bypass where supported.
4. Protect `main` and require CI/review for changes to Terraform and `.github/`.

When approval is enabled, the plan job checks the sole hvaandres reviewer and branch rules via the GitHub API and fails if they are absent. The script permits self-approval, but GitHub must also have Prevent self-review disabled for the requester to approve. Apply checks the actual approving user's identity again before Azure access. Administrator bypass must be disabled manually; the read API does not reliably expose that setting. YAML environment names alone do not enforce review. Reviewers are only available for public repositories on GitHub Free/Pro/Team; a private repository needs a plan supporting that protection. If unavailable, leave deployment disabled rather than removing the gate.

### 4. Set repository Actions variables
For each prefix `KEYVAULT` and `PRIVATELINK`, configure these **repository-level non-secret variables** (do not override shared settings at environment scope):
- `<PREFIX>_PLAN_CLIENT_ID`: planning app/client UUID.
- `<PREFIX>_APPLY_CLIENT_ID`: privileged apply app/client UUID.
- `<PREFIX>_TENANT_ID`: tenant UUID.
- `<PREFIX>_SUBSCRIPTION_ID`: workload subscription UUID.
- `<PREFIX>_BACKEND_ACCOUNT`: state storage account name.
- `<PREFIX>_BACKEND_CONTAINER`: existing Blob container name.
- `<PREFIX>_TFVARS_JSON`: non-secret deployment inputs as a JSON object.
- `<PREFIX>_RUNNER_LABELS`: optional JSON array, default `["self-hosted","linux","azure-terraform"]`.
- `<PREFIX>_DEPLOY_ENABLED`: set to the literal `true` **only after** federation, RBAC, state, environments, inputs, and runner setup are complete.

Example `KEYVAULT_TFVARS_JSON` (replace names and add actual subnet/DNS references under `private_endpoints` if required):
```json
{
  "vault_name": "kv-yourapp-dev-unique",
  "resource_group_name": "rg-yourapp-dev",
  "tags": {"environment": "dev", "managed_by": "terraform"}
}
```
An empty endpoint map creates an inaccessible private-only vault until you configure connectivity; it never enables public access. Optional inputs are `sku_name`, `purge_protection_enabled`, `soft_delete_retention_days`, `private_endpoints`, `role_assignments`, and `tags`; see `../deployments/keyvault/variables.tf`. The pipeline rejects unknown top-level inputs to avoid accidental secrets/configuration injection. The wrapper now fixes location to westus2 for all deployments. If a legacy state contains a vault in another region, stop and review the resulting replacement/migration requirements before enabling CD; this change does not migrate resources.

For Private Link, provide real `hub_subscription_id`, `hub_vnet_id`, `hub_vnet_name`, and `hub_resource_group_name`. Optional settings are `location`, `environment`, `tags`, `enable_resource_locks`, `alert_action_group_id`, and `alert_thresholds`. Deployment JSON overrides the placeholder hub values in committed `terraform.tfvars`. Keep zone/spoke/record maps in that committed file so resource-request PRs remain authoritative. Only same-subscription spoke peerings are supported by the current provider wiring.

Use a dedicated, preferably ephemeral, **trusted Linux deployment runner** with Python/tool-download capability, outbound access to GitHub OIDC/Entra/Azure APIs, access to the Blob endpoint, and private DNS/routing to any managed private service. Tag it `azure-terraform`, restrict its runner group to trusted workflows, and give the host no ambient privileged Azure credentials. Never run PR code there. Hosted runners can be configured using `["ubuntu-latest"]` only where all required endpoints are reachable without weakening firewall policy.

### 5. Enable and operate deployment
After configuration, enable each stack independently. A merge/push to `main` affecting that stack (or shared `.github` files) runs CI, then plans. No-change plans skip approval/apply. Review the resource-action summary, code diff, and trusted workflow logs before approving the environment job.

For a cloud-backed dry run, manually run the stack workflow on `main` with **dry_run enabled** (the default). This still requires deployment configuration, federation, state-container RBAC, protected-environment setup, and network access, but skips the apply job regardless of changes. It can read state and acquire Blob leases; it is not an offline check. For a real manual deployment, explicitly disable dry_run and then approve the protected apply job. Post-merge deployments always retain their approval gate.

Plan/apply use Terraform 1.16.0, committed provider locks, one backend, one commit, and one run/attempt. Apply checks artifact digest, file hashes, provenance, provider lock, and whether `main` has advanced. Runs serialize per stack without cancelling an active apply; Terraform also uses Blob leases. GitHub concurrency can replace older pending runs, and superseded commits are rejected; it is not a deployment queue guaranteeing every commit is applied. Independently triggered stacks are not automatically dependency-ordered: provision shared DNS/subnets first before adding Key Vault endpoint references.

Plan artifacts retain for **one day**, contain raw state/plan data, and must be treated as sensitive even though review summaries omit all attribute values. Restrict repository/artifact/log access. OIDC eliminates authentication secrets, not secrets stored in Terraform state. Do not put secrets in tags, resource names, outputs, repository variables, tfvars, or provider diagnostics.

If approval is delayed beyond artifact retention, state changes externally, or a run fails, start a **new full workflow run** on current `main` to create/review a fresh plan. Do not rerun only apply: run-attempt binding intentionally rejects a previous attempt's plan. Never bypass this by regenerating a plan inside the apply job.

Resource-request PRs use `GITHUB_TOKEN`, so GitHub does not automatically run ordinary PR workflows for those bot-created PRs. Reopen the PR as a user or configure an approved GitHub App installation token with narrowly scoped contents/PR permissions if automatic PR checks are needed. No Azure credential is needed for resource requests.

References: [Azure OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure), [Azure Blob backend](https://developer.hashicorp.com/terraform/language/backend/azurerm), [environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

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

### <a name="output_location"></a> [location](#output\_location)

Description: Azure region of the Key Vault.

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
