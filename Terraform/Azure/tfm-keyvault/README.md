# Azure Key Vault Terraform module
Provision an RBAC-enabled Azure Key Vault with optional private endpoints, keys, secrets, and scoped role assignments.

## What is configured
- **Defaults:** Standard SKU, public access disabled, firewall `Deny`, trusted-service bypass `None`, purge protection enabled, and 90-day soft-delete retention.
- **Reusable module:** accepts `name` and `resource_group_name`; looks up the existing group and inherits its location unless overridden. Set `create_resource_group = true` and `location` to create a group.
- **Actions deployment:** uses [the deployment wrapper](../deployments/keyvault/main.tf), accepts `vault_name`, requires an existing group, and fixes the vault region to **`westus2`**. It does not create keys, secrets, certificates, identities, subnets, or DNS zones.
- **Versions:** Terraform `>= 1.9, < 2.0`; AzureRM `~> 4.71` (module lock: `4.81.0`). Actions uses Terraform `1.16.0`.

These are checked-in settings, not confirmation that live Azure resources or GitHub protection rules have been configured.

## Reuse the module
Configure authentication, provider behavior, and the backend in your calling root. Adjust the local source path:

```hcl
provider "azurerm" {
  resource_provider_registrations = "none"
  features {
    key_vault {
      purge_soft_delete_on_destroy          = false
      purge_soft_deleted_keys_on_destroy    = false
      purge_soft_deleted_secrets_on_destroy = false
    }
  }
}

module "keyvault" {
  source = "../../Azure/tfm-keyvault"

  name                = "kv-yourapp-dev-unique"
  resource_group_name = "rg-yourapp-dev"
  tags                = { environment = "dev", managed_by = "terraform" }

  private_endpoints = {
    application = {
      name                 = "pe-yourapp-keyvault"
      subnet_id            = var.private_endpoint_subnet_id
      private_dns_zone_ids = [var.keyvault_private_dns_zone_id]
    }
  }
}
```

The caller must declare the two referenced variables and supply existing subnet/DNS zone ARM IDs. The module does not configure DNS VNet links or connect the runner to the private network. Omitting endpoints leaves a private-only vault without data-plane connectivity.

### Inputs and outputs
[variables.tf](variables.tf) is the complete typed input reference; [outputs.tf](outputs.tf) defines all outputs.

| Input group | Inputs / behavior |
| --- | --- |
| Required | `name`, `resource_group_name` |
| Placement | `create_resource_group=false`, `location=null`, `tenant_id=null` (provider tenant) |
| Protection | `sku_name="standard"`, `purge_protection_enabled=true`, `soft_delete_retention_days=90` (whole days, 7–90) |
| Network | `public_network_access_enabled=false`, `network_acls`, `private_endpoints` |
| Authorization | `role_assignments`, optional `deployment_principal_id` and `deployment_principal_roles` |
| Objects | `keys`, `secrets` metadata, sensitive `secret_values`; all default empty |
| Tags | `tags`, merged with per-object tags; object-specific values take precedence |

Outputs: `id`, `name`, `location`, `vault_uri`, `resource_group_name`, `keys`, `secrets`, `private_endpoint_ids`, and `role_assignment_ids`. Object maps expose IDs/versions, not secret values; `resource_versionless_id` is the ARM ID used for object-scoped RBAC.

## Request a vault with GitHub Actions
Open **Actions → CI and CD — Key Vault → Run workflow**, using `main`.

| Form field | Requirement / default |
| --- | --- |
| `subscription` | `cyber-dev`, `cyber-tst`, or **`cyber-prd` (default)** |
| `vault_name` | Globally unique, 3–24 letters/digits/hyphens; starts with a letter, ends alphanumeric, no consecutive hyphens; normalized to lowercase |
| `resource_group_name` | Existing group name in the selected subscription, not an ARM ID |
| `sku_name` | `standard` (default) or `premium` |
| `purge_protection_enabled` | `true`; cannot be disabled once enabled |
| `soft_delete_retention_days` | `90`; whole number 7–90, immutable after creation |
| `private_endpoints_json` | Endpoint map; default `{}` leaves the vault without private connectivity |
| `role_assignments_json`, `tags_json` | Non-secret objects, default `{}` |
| `dry_run` | **`true`**: Azure-backed plan only, no apply |
| `require_approval` | **`false` currently**: explicitly select `true` for the helper's named-review checks |

The pipeline validates inputs, verifies the subscription UUID **and actual Azure display name** against the selected Cyber name, and checks resource-group membership before backend initialization. It rechecks before apply; there is no fallback subscription.

Start with a dry run and review the summary/logs. To deploy, submit the same resource inputs in a **new run**, disable dry run, and enable approval checks. Only that run's saved plan is applied; no-change plans skip apply. A completed dry run cannot later be approved into an apply.

**Approval caveats in the current code:**
- Cyber plan and apply both use `keyvault-cyber-<dev|tst|prd>-plan`. Protection can therefore gate planning itself; the helper's same-environment review check does **not guarantee a distinct post-plan approval**. Separate apply gating requires changing [environment routing](../../../.github/scripts/terraform-pipeline.py), variables, and OIDC trust, not just creating an `*-apply` environment.
- Manual Key Vault runs default approval checks off; post-merge Key Vault runs also pass `false`. GitHub's own environment rules still apply independently. Do not assume every Key Vault apply has a helper-enforced named approval.
- With checks enabled, the helper requires only **hvaandres**, a `main`-only branch policy, and an actual approval. Disable **Prevent self-review** for solo maintenance and administrator bypass where supported. Start a new run rather than reusing an earlier attempt's approval.

### GitHub variables and OIDC
Create `keyvault-cyber-dev-plan`, `keyvault-cyber-tst-plan`, and/or `keyvault-cyber-prd-plan` under **Settings → Environments**. Configure these **unprefixed, non-secret variables** in each selected environment:
- `SUBSCRIPTION_ID`, `TENANT_ID`: actual Azure subscription and tenant UUIDs.
- `PLAN_CLIENT_ID`, `APPLY_CLIENT_ID`: federated application/client UUIDs, not principal object IDs.
- `BACKEND_ACCOUNT`, `BACKEND_CONTAINER`: pre-existing storage account/container names, not URLs or access keys.
- `DEPLOY_ENABLED=true`: required even for Cyber dry runs.
- `RUNNER_LABELS`: optional JSON array; current default is `["ubuntu-latest"]`. Use trusted self-hosted runners when private endpoints require them. Cyber preflight needs Azure CLI.

Both identities need OIDC federation for the **actual job environment**. Legacy subject example: `repo:hvaandres/DevOps_Intro:environment:keyvault-cyber-prd-plan`; issuer `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`. Verify the repository's actual subject format before configuring trust. The workflows use `ARM_USE_OIDC=true`, `ARM_USE_AZUREAD=true`, and `ARM_USE_CLI=false`; do not configure client secrets, access keys, or SAS tokens.

For **post-merge Key Vault**, the outer workflow checks repository `DEPLOY_ENABLED=true`; jobs use `keyvault-plan` and `keyvault-apply`. Configure the same unprefixed variables for their respective jobs, plus non-secret `TFVARS_JSON` for planning. `KEYVAULT_*` variables are not read by the current workflow. Cyber dispatch uses form inputs instead of `TFVARS_JSON`.

Related Private Link workflows share the deployment helper but still use `PRIVATELINK_DEPLOY_ENABLED` as their outer enable flag; their job variables are also unprefixed. They select `privatelink-plan` / `privatelink-apply`, and retain approval checks by default. The resource-request workflow uses `resource-request-approval` and opens a PR; it does not deploy Azure resources.

Workflow sources: [Key Vault caller](../../../.github/workflows/ci-keyvault.yml), [checks](../../../.github/workflows/terraform-checks.yml), [shared deployment](../../../.github/workflows/terraform-deploy.yml), and [approval helper](../../../.github/scripts/approval-gate.cjs).

## Permissions, state, and networking
- **Plan identity:** workload Reader plus any read/data-plane permissions needed to refresh the resources it manages. **Apply identity:** workload Contributor; RBAC creation additionally needs scoped **Role Based Access Control Administrator** or an approved equivalent. Contributor alone cannot assign roles.
- **Both identities:** **Storage Blob Data Contributor** on the state container, including lease locking. Use principal **object IDs** for RBAC, client IDs for authentication. Creating new resource groups needs subscription-level creation rights.
- **Optional keys/secrets:** the Terraform identity needs **Key Vault Crypto Officer** / **Key Vault Secrets Officer**, respectively, and reachable vault networking. `deployment_principal_roles` is opt-in, cannot bootstrap management privileges, and may require an RBAC propagation wait/retry.
- **Private endpoints:** provide existing subnets and optionally `privatelink.vaultcore.azure.net` zone IDs, subnet/DNS join permissions, DNS links/forwarding, and runner routing/HTTPS access. Endpoint location overrides must match the subnet region. OIDC does not provide network connectivity.
- **Resource providers:** pre-register the providers used by the deployment (`Microsoft.KeyVault`, `Microsoft.Network`, and, for relevant examples, `Microsoft.ManagedIdentity` / `Microsoft.Storage`); configured roots disable automatic registration.

Provision state storage separately using an existing account or the bootstrap example. Use Entra authorization, versioning, soft delete, restricted network access, and separate blob keys:
- Cyber requests: `keyvault/<subscription-choice>/<lowercase-vault-name>.tfstate`.
- Legacy Key Vault: `keyvault/deployment.tfstate`.
- Basic / complete examples: `keyvault/basic.tfstate` / `keyvault/complete.tfstate`, container `tfstate`.
- Related Private Link stack: `privatelink-network.tfstate`.

Repeated Cyber requests for the same subscription/name target the same state: supply the **complete desired** endpoints, roles, and tags. The request path rejects vault deletion/replacement. Existing resources under other state need a reviewed migration/import first. Plan artifacts expire after **one day**; apply verifies same-run provenance, integrity, provider lock, and that `main` has not advanced. Runs serialize per stack, with Blob leases for state locking.

## Examples and lifecycle safety
- [Basic](examples/basic/README.md): existing group, explicitly enabled IP-allowlisted public access, application Secrets User role; no keys/secrets created.
- [Complete](examples/complete/README.md): two groups, VNet/subnet, private DNS/link, endpoint, managed identity, optional rotating RSA key and secret. First use `create_objects=false`, connect the runner, then enable objects. Turning it off later **destroys managed objects**.
- [Bootstrap](examples/bootstrap/README.md): creates state/workload groups, protected state storage, `tfstate` container, and deployment-principal RBAC. Initially uses local state and a separately privileged identity; it does not create OIDC identities/trust.

For basic/complete, copy their `terraform.tfvars.example` and `backend.hcl.example` to local files, fill in values, then initialize with `terraform init -backend-config=backend.hcl`. Review a saved plan before applying. The reusable module itself declares no backend.

**Protect state and plans:** normal Terraform secret values remain in both even when marked sensitive. Pass values securely, match each `secrets` metadata key in `secret_values`, and never place credentials in Git, tags, names, or workflow inputs. Secret expiration does not rotate values. Before-expiry key rotation needs a stable future initial expiration; HSM keys need Premium. Purge protection is irreversible, retention is immutable, and deleted names can remain reserved. Keep data-plane permissions and connectivity until object destruction finishes.

## Local validation
From this module directory, run the same configuration coverage as Key Vault CI without accessing Azure state:

```sh
terraform fmt -check -recursive
terraform -chdir=../deployments/keyvault fmt -check -recursive
for directory in . modules/key modules/secret examples/basic examples/complete examples/bootstrap ../deployments/keyvault; do
  terraform -chdir="$directory" init -backend=false -input=false -lockfile=readonly || break
  terraform -chdir="$directory" validate -no-color || break
  if [ -d "$directory/tests" ]; then
    terraform -chdir="$directory" test -no-color || break
  fi
done
python3 -m unittest discover -s ../../../.github/scripts/tests -v
node --test ../../../.github/scripts/tests/approval-gate.test.cjs
```

Initialization may download providers/modules; mocked tests do not need Azure credentials or deploy resources. They do not verify live federation, RBAC propagation, policy, or network reachability. CI currently initializes with `-upgrade`; local commands above preserve committed locks. Pipeline regression tests use Python 3 and Node.js (CI: Python 3.12 / Node 22).

This README intentionally links to the typed schemas instead of embedding a long generated reference. Optional `terraform-docs .` (>= 0.19) injects a full reference using [.terraform-docs.yml](.terraform-docs.yml); it will lengthen this guide.
