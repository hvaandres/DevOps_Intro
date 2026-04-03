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
├── main.tf                  # Provider, backend, module calls
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

1. Set **"Add a Private DNS Zone?"** to `yes`
2. Fill in:
   - **Logical key:** `cosmosdb`
   - **Zone suffix:** `documents.azure.com` (the workflow prepends `privatelink.` automatically)
3. Leave the other toggles as `no`
4. Click **Run workflow**

The workflow will:
- Modify `terraform.tfvars`
- Run `terraform plan` to validate
- Open a **Pull Request** if the plan succeeds
- Show a summary of what's ephemeral vs. applied

#### Example: Add multiple DNS records

1. Set **"Add DNS A Record(s)?"** to `yes`
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

1. Set **"Add a Spoke VNet Peering?"** to `yes`
2. Fill in:
   - **Logical name:** `spoke-analytics`
   - **VNet resource ID:** `/subscriptions/.../virtualNetworks/vnet-analytics`
   - **VNet name:** `vnet-analytics`
   - **Resource group:** `rg-analytics`
3. Click **Run workflow**

#### Example: Add everything at once

Set all three toggles to `yes` and fill in all the fields. The workflow handles each section independently — if one fails validation, the others still run.

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

## CI pipeline

Every push or PR that touches module files triggers the **CI — Private Link Network** workflow:

1. **Format check** — fails if `terraform fmt` finds issues
2. **Validate** — catches syntax and type errors
3. **Plan** — shows exactly what would be created, changed, or destroyed
4. **Report** — posts a plan summary as a PR comment and job summary

The plan report clearly marks everything as **ephemeral** — nothing is applied until someone runs `terraform apply`.

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

## GitHub Secrets required

Configure these in **Settings → Secrets and variables → Actions**:

| Secret | Description |
|--------|-------------|
| `ARM_CLIENT_ID` | Service principal app ID |
| `ARM_CLIENT_SECRET` | Service principal secret |
| `ARM_SUBSCRIPTION_ID` | Azure subscription ID |
| `ARM_TENANT_ID` | Azure AD tenant ID |
| `TF_BACKEND_RG` | Backend storage resource group |
| `TF_BACKEND_SA` | Backend storage account name |
| `TF_BACKEND_CONTAINER` | Backend blob container name |
