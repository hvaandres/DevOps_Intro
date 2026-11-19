# Private Link Network — Terraform Module

Centrally manages Azure **Private DNS Zones**, **VNet Peerings**, and **Private Endpoint DNS records** in a Hub-Spoke model.

## Why this exists

When teams deploy Azure services with Private Endpoints (Storage, SQL, Key Vault, etc.), each service needs a Private DNS Zone (e.g. `privatelink.blob.core.windows.net`) so that name resolution works over the private network.

**The problem:** If each spoke team creates their own DNS zone in their own Terraform state, destroying a spoke (`terraform destroy`) also destroys the shared DNS zone — breaking name resolution for every other team.

**The solution:** This module keeps all Private DNS Zones in the **Hub's Terraform state**. The hub owns the zones; spokes only peer with the hub and get DNS resolution automatically. Zones can never be accidentally destroyed by a spoke teardown.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     HUB (this module)                    │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Private DNS Zones (hub-owned, locked)              │ │
│  │  • privatelink.blob.core.windows.net                │ │
│  │  • privatelink.database.windows.net                 │ │
│  │  • privatelink.vaultcore.azure.net                  │ │
│  │  • ... (add more via tfvars)                        │ │
│  └──────────────┬──────────────────────┬───────────────┘ │
│                 │  VNet Links          │  VNet Links      │
│  ┌──────────────┴──┐          ┌────────┴──────────┐      │
│  │  Hub VNet        │          │  Spoke VNet(s)    │      │
│  │  (auto-linked)   │◄─peering─►│  (auto-linked)    │      │
│  └─────────────────┘          └───────────────────┘      │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Azure Monitor Alerts                               │ │
│  │  • RecordSetCapacityUtilization > 80%               │ │
│  │  • VNetLinkCapacityUtilization > 80%                │ │
│  │  • RecordSetCount > 20,000                          │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Management Locks (CanNotDelete) on every zone      │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## Project structure

```
tfm-privateLink-network/
├── main.tf                  # Terraform requirements, backend, module calls
├── providers.tf             # Default and spoke AzureRM providers
├── variables.tf             # All input variables
├── outputs.tf               # Zone IDs, peering IDs, record FQDNs
├── resource_groups.tf       # Hub resource group for DNS zones
├── terraform.tfvars         # ← THE ONLY FILE TEAMS EDIT
├── renovate.json            # Automated dependency updates
├── .gitignore               # Excludes .terraform/, plans, state
├── scripts/
│   ├── setup-test-env.sh    # Creates test hub/spoke/backend in Azure
│   ├── teardown-test-env.sh # Destroys test resources
│   └── update-tfvars.py     # Adds entries to tfvars (used by CI)
└── modules/
    ├── private_dns/          # DNS zones, VNet links, locks, alerts
    ├── vnet_peering/         # Bidirectional hub ↔ spoke peerings
    └── private_dns_records/  # A records for private endpoints
```

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Terraform | >= 1.9 | `brew install terraform` |
| Azure CLI | latest | `brew install azure-cli` |
| Python 3 | >= 3.9 | Pre-installed on macOS |

You also need:
- An Azure subscription with permissions to create DNS zones, VNets, and peerings
- A **hub VNet** already provisioned (or use the test setup script)
- A **Storage Account** for the Terraform backend

## Quick start (first-time setup)
For shared Make commands covering login, subscription selection, subscription
permissions, and a standalone resource group/storage/tfstate backend test, see
[Terraform setup](../../intro.md). From the repository root, run
`make help`. That backend setup does not create hub/spoke VNets;
the networking setup below is separate.

### 1. Login to Azure

```bash
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

### 2. Create test infrastructure (if you don't have a hub yet)

```bash
chmod +x scripts/setup-test-env.sh
./scripts/setup-test-env.sh
```

This creates a backend storage account, a hub VNet, and a spoke VNet. Copy the output into `terraform.tfvars`.

### 3. Edit `terraform.tfvars`

Replace the placeholder values with your real Azure resource IDs:

```hcl
hub_subscription_id     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
hub_vnet_id             = "/subscriptions/.../virtualNetworks/vnet-hub"
hub_vnet_name           = "vnet-hub"
hub_resource_group_name = "rg-hub-networking"
```

### 4. Initialize and deploy

```bash
terraform init \
  -backend-config="resource_group_name=rg-terraform-state-dev" \
  -backend-config="storage_account_name=<YOUR_STORAGE_ACCOUNT>" \
  -backend-config="container_name=tfstate-private-dns" \
  -backend-config="key=privatelink-network.tfstate"

terraform plan -out=tfplan
terraform apply tfplan
```

---

## How to request new resources

There are **two ways** to add resources: via the GitHub Actions UI (recommended for teams) or by editing `terraform.tfvars` directly.

### Option A: GitHub Actions workflow (recommended)

Go to **Actions → "Add Resource — Private Link Network" → Run workflow**.

You'll see three independent toggles:

| Toggle | What it does |
|--------|-------------|
| **Add a Private DNS Zone?** | Creates a new `privatelink.*` DNS zone in the hub |
| **Add DNS A Record(s)?** | Creates one or more A records for private endpoints |
| **Add a Spoke VNet Peering?** | Peers a new spoke VNet with the hub |

Pick any combination — they're independent. You can add just a zone, just records, or all three at once.

#### Example: Add a new DNS zone

1. Enable **"Add a Private DNS Zone?"**
2. Fill in:
   - **Logical key:** `cosmosdb`
   - **Zone suffix:** `documents.azure.com` (the workflow prepends `privatelink.` automatically)
3. Leave the other toggles disabled
4. Click **Run workflow**

The workflow will:
- Modify `terraform.tfvars`
- Run backend-disabled initialization and Terraform validation without Azure credentials
- Pause for **hvaandres** approval in the protected `resource-request-approval`
  environment; its sole required reviewer must be the user `hvaandres`, with
  **Prevent self-review** disabled to allow solo maintenance, and a `main`-only branch rule
- Rebuild/revalidate the same request and open a **Pull Request** after approval
- Leave cloud planning and deployment to the post-merge approval-gated pipeline

#### Example: Add multiple DNS records

1. Enable **"Add Private DNS A records?"**
2. Paste a JSON array in the records field:

```json
[
  {
    "key": "stor_account1",
    "zone": "privatelink.blob.core.windows.net",
    "name": "mystorageaccount",
    "ips": "10.0.1.5"
  },
  {
    "key": "sql_mydb",
    "zone": "privatelink.database.windows.net",
    "name": "mydbserver",
    "ips": "10.0.2.10",
    "ttl": 600
  }
]
```

Each record needs: `key` (unique ID), `zone` (must start with `privatelink.`), `name` (record name), `ips` (comma-separated). `ttl` is optional (defaults to 300).

#### Example: Add a new spoke

1. Enable **"Add a spoke VNet peering?"**
2. Fill in:
   - **Logical name:** `spoke-analytics`
   - **VNet resource ID:** `/subscriptions/.../virtualNetworks/vnet-analytics`
   - **VNet name:** `vnet-analytics`
   - **Resource group:** `rg-analytics`
3. Click **Run workflow**

#### Example: Add everything at once

Enable all three toggles and fill in the fields. All selected changes must pass validation before a PR is opened; invalid input fails the request without modifying infrastructure.

### Option B: Edit `terraform.tfvars` directly

For teams comfortable with Terraform, edit the file and open a PR:

**Add a DNS zone** — add a line to `private_dns_zones`:

```hcl
private_dns_zones = {
  blob      = "privatelink.blob.core.windows.net"
  cosmosdb  = "privatelink.documents.azure.com"   # ← new
}
```

**Add a spoke** — add a block to `spokes`:

```hcl
spokes = {
  spoke-analytics = {
    vnet_id             = "/subscriptions/.../virtualNetworks/vnet-analytics"
    vnet_name           = "vnet-analytics"
    resource_group_name = "rg-analytics"
  }
}
```

**Add DNS records** — add entries to `dns_a_records`:

```hcl
dns_a_records = {
  stor_account1 = {
    zone_name = "privatelink.blob.core.windows.net"
    name      = "mystorageaccount"
    records   = ["10.0.1.5"]
  }
}
```

Then:

```bash
terraform plan -out=tfplan   # Review what will change
terraform apply tfplan        # Apply when satisfied
```

---

## CI/CD pipeline

Every push to `main` or PR targeting `main` that touches module/shared workflow files triggers **CI and CD — Private Link Network**:

1. **Format check** — fails if `terraform fmt` finds issues
2. **Validate** — catches syntax and type errors
3. **After merge, when enabled:** OIDC-authenticated plan using the Azure Blob backend
4. **Review:** resource-action summary and saved plan, followed by required `azure-apply` environment approval by **hvaandres**
5. **Apply:** applies the exact saved plan from the same commit/run; no-change plans skip apply

PR checks never access Azure or state. Deployment is disabled until `PRIVATELINK_DEPLOY_ENABLED=true` and required setup is complete. Formatting errors fail CI rather than becoming warnings. Plan/apply use separate OIDC identities by default; there is no client secret.

Manual runs default to **dry_run=true**: plan against Blob state, but never enter apply. Disable dry_run explicitly to request a manual deployment, which still requires environment approval. Local offline dry runs use a disabled backend instead and need no Azure access.

Read-only CI steps run automatically. Mutating paths verify the sole required
reviewer is `hvaandres` and verify the actual approval history before proceeding.
See the [shared approval configuration](../tfm-keyvault/README.md#required-approval-gateway-for-all-mutating-workflows).
With **Prevent self-review** disabled in GitHub, hvaandres can initiate and
explicitly approve their own request. A bot-created PR is a request artifact,
not permission to deploy.

---

## What happens when you add a new zone?

When you add `cosmosdb = "privatelink.documents.azure.com"` to the zones map, Terraform automatically creates:

1. The `azurerm_private_dns_zone` resource
2. A **hub VNet link** (so the hub can resolve the zone)
3. A **spoke VNet link** for every spoke in the `spokes` map
4. A **CanNotDelete lock** (if `enable_resource_locks = true`)
5. **3 Azure Monitor alerts** (record set capacity, VNet link capacity, record set count) — if an action group is configured

No code changes needed. Just a one-line tfvars edit.

---

## Scaling & limits

| Azure limit | Default | Alert threshold |
|-------------|---------|-----------------|
| Record sets per zone | 25,000 | 80% (configurable) |
| VNet links per zone | 1,000 | 80% (configurable) |
| VNet links with auto-registration | 100 | — |

As your service grows (more clients, more partitions), record counts will only increase. The built-in alerts warn you before hitting Azure limits so you can plan sharding or cleanup.

---

## Cleanup (test environments)

```bash
terraform destroy                      # Remove Terraform-managed resources
chmod +x scripts/teardown-test-env.sh
./scripts/teardown-test-env.sh         # Remove test hub, spoke, and backend
```

---

## GitHub OIDC and Blob backend configuration

Follow the complete [CI/CD setup guide](../tfm-keyvault/README.md#github-actions-cicd-and-blob-state-setup) for federation, role scopes, reviewers, runner connectivity, and artifact safety.

Set repository Actions variables with prefix `PRIVATELINK`: `PLAN_CLIENT_ID`, `APPLY_CLIENT_ID`, `SUBSCRIPTION_ID`, `TENANT_ID`, `BACKEND_ACCOUNT`, `BACKEND_CONTAINER`, `TFVARS_JSON`, optionally `RUNNER_LABELS`, and finally `DEPLOY_ENABLED=true`. For example, the account variable is `PRIVATELINK_BACKEND_ACCOUNT`. Old `ARM_CLIENT_SECRET` and `TF_BACKEND_*` secrets are not used by these workflows.

The backend is an existing storage account's Blob container, with state blob key **`privatelink-network.tfstate`** and Blob lease locking. Key Vault can share the container using its different key `keyvault/deployment.tfstate`. Both identities need Storage Blob Data Contributor on the state container; no storage keys/SAS are used. Provision storage separately and enable versioning/soft delete; do not migrate an existing state implicitly.

Example `PRIVATELINK_TFVARS_JSON` (replace the subscription and hub references):
```json
{
  "hub_subscription_id": "11111111-2222-3333-4444-555555555555",
  "hub_vnet_id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-hub-networking/providers/Microsoft.Network/virtualNetworks/vnet-hub",
  "hub_vnet_name": "vnet-hub",
  "hub_resource_group_name": "rg-hub-networking",
  "enable_resource_locks": true
}
```
The subscription must match `PRIVATELINK_SUBSCRIPTION_ID`. JSON overrides committed placeholder hub references; keep `private_dns_zones`, `spokes`, and `dns_a_records` in `terraform.tfvars` for PR review. This root currently supports only same-subscription hub/spoke peerings: its child peering module does not wire per-spoke subscription providers. Validation rejects cross-subscription references instead of deploying into the wrong scope.

Resource providers must be registered separately. Grant workload Contributor plus narrowly scoped network/DNS rights for apply; management locks additionally need approved authorization-management permissions. Provisioning the DNS resource group requires resource-group creation permissions at subscription scope. An administrator can instead pre-create/import that resource group to keep the deployment scope narrower.

To perform a dry run without cloud access, leave deployment disabled and run formatting, `terraform init -backend=false`, and `terraform validate`. This verifies configuration only, not actual resource changes. A live cloud plan needs OIDC, existing Blob state, RBAC, and runner connectivity, but still makes no Terraform-managed resource changes until approval/apply.
