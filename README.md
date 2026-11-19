# DevOps_Intro

The primary objective of this project is to enhance people's familiarity with DevOps tools by utilizing real-life scenarios. To achieve this goal, each project will comprise a blog post and a video that will offer valuable insights into the daily routines of DevOps Engineers. Additionally, this will be an open-source project, enabling individuals to contribute their ideas and insights to this initiative.

## Project Structure
Each project will be structured as follows:
- A blog post that will be published on [Medium](https://medium.com/@ithvaandres)
- A video that will be published on [YouTube](https://www.youtube.com/channel/hvaandres)
- A GitHub repository that will contain the code and the [documentation](https://ithvaandres.github.io/DevOps_Intro)

## Project List
- [x] Tools
    - [x] Git
    - [x] GitHub
    - [x] Markdown
    - [x] Docker
    - [x] Kubernetes
        - [x] Helm
        - [x] Kustomize
        - [x] Minikube
        - [x] Kind
        - [x] K9S
    - [x] Github Actions
        - [x] CI
        - [x] CD
        - [x] Secrets
    - [x] Terraform
    - [x] AWS
    - [x] Azure
    - [x] GCP
    - [x] Prometheus
    - [x] Grafana
    - [x] ELK
    - [x] Istio
    - [x] Argo
    - [x] Python
    - [x] Bash

## Terraform Azure setup

See the [Terraform Make command reference](Terraform/intro.md) for Azure login,
subscription selection, permissions, and creating/testing a Terraform state
backend. All targets run from the repository root without `-C`:

```bash
make help
make azure-login
make azure-subscription
make resource-group-create SUBSCRIPTION_ID="<subscription UUID>" RESOURCE_GROUP=rg-my-test LOCATION=eastus2
```

The same entry point provides `make azure-permissions`, `make backend-create`,
`make backend-test`, and `make test`. See the guide for required variables and
confirmation details. Resource group creation needs no storage account.

Deployment-specific documentation:
- [Private Link networking](Terraform/Azure/tfm-privateLink-network/README.md)
- [Key Vault](Terraform/Azure/tfm-keyvault/README.md)

To request a Key Vault in CI/CD, use **Actions → CI and CD — Key Vault → Run
workflow**. Select `cybersecurity-stg`, `cybersecurity-tst`, or `cybersecurity-prd` (default), supply the
vault and existing resource-group names, and leave **dry_run** enabled to preview.
Vaults deploy only to `westus2`; explicitly enable approval checks for the current
creation workflow. See its [request form and approval caveats](Terraform/Azure/tfm-keyvault/README.md#request-a-vault-with-github-actions).

## Azure-wide GitHub environments
Use the **`azure-` prefix**, not a service name. `<subscription>` is exactly
`cybersecurity-stg`, `cybersecurity-tst`, or `cybersecurity-prd`.

| Operation | GitHub environment |
| --- | --- |
| Cyber creation request | `azure-<subscription>-plan` |
| Existing non-Cyber deployment: plan / apply | `azure-plan` / `azure-apply` |
| Manual teardown: plan / destroy | `azure-<subscription>-teardown-plan` / `azure-<subscription>-teardown` |

Production examples: `azure-cybersecurity-prd-plan`,
`azure-cybersecurity-prd-teardown-plan`, and `azure-cybersecurity-prd-teardown`.
Current Cyber creation routing uses the **same `*-plan` environment for plan and
apply**; the name does not imply a separate post-plan approval. Teardown uses two
distinct environments and requires explicit approval before destruction.

### Migrate existing environments
Changing repository files does **not** migrate live GitHub environments or Entra trust.

1. **Pause deployment while migrating.** Leave the applicable `DEPLOY_ENABLED`,
   `PRIVATELINK_DEPLOY_ENABLED`, and `TEARDOWN_ENABLED` flags unset/false. Under
   **Settings → Environments**, create the replacements:
   - `key-vault-cyber-prd-plan` (or `keyvault-cybersecurity-prd-plan`) → `azure-cybersecurity-prd-plan`.
   - Other Cyber creation environments → `azure-<subscription>-plan`.
   - `keyvault-plan` / `privatelink-plan` → shared `azure-plan`;
     `keyvault-apply` / `privatelink-apply` → shared `azure-apply`.
   - `terraform-<subscription>-teardown-plan` / `terraform-<subscription>-teardown`
     → the corresponding `azure-` names.
2. **Copy and review variables.** Preserve the correct subscription, tenant, client
   IDs, and backend settings; do not blindly merge identities from old environments.
   In shared `azure-plan`, move non-secret workload inputs to
   `KEYVAULT_TFVARS_JSON` and `PRIVATELINK_TFVARS_JSON`, not one `TFVARS_JSON`.
   Identity/backend variables remain unprefixed. Cyber requests still use form
   inputs; teardown uses `TEARDOWN_ALLOWED_STATE_KEYS` and its separate client ID.
3. **Recreate protection rules.** Protected apply/teardown environments require
   **hvaandres** as the sole reviewer and exactly one `main` branch rule. Disable
   administrator bypass where supported; allow self-review for solo maintenance.
   Preserve creation protections and keep teardown identities separate.
4. **Update Entra federated credentials for each job's new environment.** For legacy
   GitHub subjects, production creation uses
   `repo:hvaandres/DevOps_Intro:environment:azure-cybersecurity-prd-plan`;
   destruction uses
   `repo:hvaandres/DevOps_Intro:environment:azure-cybersecurity-prd-teardown`.
   Configure the planning identity for its own plan environment too. Issuer remains
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`.
   Verify the repository's actual subject format; customized/immutable subjects differ.
5. **Verify before retiring old names.** Enable only the configured workflow, start
   a **new manual dry run on `main`**, and check subscription, backend, OIDC, and
   approval configuration. Teardown must not apply in dry-run mode. Retire old
   environments/federated trust only after the replacement path is verified;
   approvals from old environments or previous runs do not transfer.

Environment renaming does not require renaming Azure resources, state containers,
or blob keys. Keep the existing backend locations; do not initialize a new empty
state as part of this migration. See [teardown setup](#one-time-administrator-setup)
for its required variables and permissions.

## Manual state-driven tear down
**Actions → tear down → Run workflow** is the only trigger: there are no push,
pull-request, scheduled, or automatic teardown runs. Use `main` and supply:
- `subscription`: only `cybersecurity-stg`, `cybersecurity-tst`, or **`cybersecurity-prd` (default)**.
- `resource_group_name`: boundary for **all managed resources in the selected state**.
- `state_key`: exact existing blob key, e.g. `applications/dev/compute.tfstate`.
- `dry_run`: defaults **true**; reports drift and proposed destruction without applying.
- `confirmation`: for actual destruction, type the exact state key and disable dry run.

Storage account is fixed to **`kvstate12790`**; container defaults to `tfstate`.
The [isolated teardown root](Terraform/Azure/deployments/teardown/providers.tf) has
no workload modules or variables: Terraform uses state inventory and stored
dependencies, whether the workload is VMs, networking, Key Vault, or other supported
AzureRM resources. Only the selected state is destroyed, never the state blob/backend.
A resource group **is deleted if it is tracked in that state**; the provider blocks
group deletion when resources remain. Service-level cascading deletion can still
affect children, so review parent-resource deletions and external consumers carefully.

### One-time administrator setup
For each subscription, create separate `azure-cybersecurity-<stg|tst|prd>-teardown-plan`
and `azure-cybersecurity-<stg|tst|prd>-teardown` GitHub environments. Protect the latter
with **hvaandres as sole required reviewer**, exactly one `main` branch rule, no
administrator bypass, and self-review allowed if operating solo. Teardown has no
approval-bypass input; even dry runs verify that protection exists.

Set these non-secret variables in **both** environments:
- `SUBSCRIPTION_ID`, `TENANT_ID`: real UUIDs; Azure display name must match the selected subscription.
- `PLAN_CLIENT_ID`, `TEARDOWN_CLIENT_ID`: **distinct** OIDC app/client UUIDs.
- `BACKEND_RESOURCE_GROUP_NAME`: actual group containing `kvstate12790`.
- `BACKEND_SUBSCRIPTION_ID`: optional backend subscription UUID; defaults to the workload subscription.
- `BACKEND_CONTAINER`: optional, defaults `tfstate`.
- `TEARDOWN_ALLOWED_STATE_KEYS`: explicit JSON list, e.g. `["applications/dev/compute.tfstate"]`; no wildcard authorization.
- `TEARDOWN_ENABLED=true`: only after access and protection are ready; unset disables execution.

Optionally set repository `TEARDOWN_RUNNER_LABELS` to a trusted runner-label JSON
array (default `["ubuntu-latest"]`). Runners need Azure CLI and access to state,
Azure APIs, and any private data planes. Federate each app only to its own actual
job environment; legacy execution subject example:
`repo:hvaandres/DevOps_Intro:environment:azure-cybersecurity-stg-teardown`.
Verify the repository's real OIDC subject format first; use no client secrets or storage keys.

Both identities need scoped state-container **Storage Blob Data Contributor**,
Reader on the backend account, workload read/data-plane access for refresh, and
subscription-level `Microsoft.Authorization/locks/read` for inherited-lock checks.
Only the protected teardown identity gets scoped resource deletion, required
data-plane deletion, role-assignment deletion, and managed-lock deletion rights.
Normal deployment identities must not be able to remove protection locks.
Existing Key Vault deployments gain locks only after a reviewed normal apply.

### Drift and execution rules
Dry runs report refresh-only drift without writing refreshed state. Actual
destruction **fails on drift**: investigate and reconcile in the owning deployment,
then start a new teardown run. After approval, state lineage/serial/content,
subscription/group, locks, artifact hashes, and live drift are checked again.
A verification plan must match the approved deletion actions and attributes;
only the **original saved destroy plan** is applied, never that verification plan.
This is the reviewable equivalent of `terraform destroy`.

Unsupported providers/aliases, unknown identity formats, cross-group/subscription
state, missing/empty state, or untracked/inherited locks fail closed. Current
provider support is default-root AzureRM, ARM IDs, and explicitly validated Key Vault
key/secret URIs; it is not an arbitrary-provider runner. Add other provider
configurations/ownership adapters through review. The backend account and its
containing group are always protected. Purge and common implicit-delete options
are disabled; some retained disks or soft-deleted objects may need separate lifecycle handling.
Configuration-only `prevent_destroy`, provisioners, and workload-specific provider
options are not loaded by this isolated root; the state allowlist, locks, scoped
identity, and mandatory review are the authorization boundary.

Plans are sensitive and retained for **one day** on real runs; dry runs upload no
plan artifact. Start a fresh run after failure, expiry, drift, or changes to `main`;
reruns and stale plans are rejected. Repository Azure deployment/teardown runs
serialize and use Blob leases, but external changes between the final check and
deletion remain possible. A partial destroy can occur if Azure rejects an operation;
inspect the updated state and use a fresh run, not manual state deletion.

## Contribution
If you would like to contribute to this project, please follow the steps below:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Create a pull request
5. If you are using a different tool, please create a new folder:
    5.1 Create a new folder with the name of the tool
    5.2 Create a new file called `readMe.md` and add the following content:
    ```
    #### Intro
    #### Prerequisites
    #### Installation
    #### Usage
    ```
    5.3 Add as much information about your project as possible to make it easier for other people to understand and use it.


## License
This project is licensed under the MIT License - see the [LICENSE](https://ithvaandres.github.io/DevOps_Intro/LICENSE.txt) file for details.

## Acknowledgments
- Every Developer that contribute to this project by sharing their knowledge and experience with the community will be mentioned in the blog post and the video.

## Contact
If you have any questions, please feel free to contact me at hello@aharo.dev.

## Disclaimer
This project is not affiliated with any of the companies mentioned above. The content of this project is solely for educational purposes.

## Author
- [Andres Haro](https://www.aharo.dev)

## Social Media
- [LinkedIn](https://www.linkedin.com/in/ithvaandres/)
- [Twitter](https://twitter.com/madebyux)
- [Instagram](https://www.instagram.com/hvaandres)
- [Podcast](https://open.spotify.com/show/1ImqedW8QKl5XI1HJUDQJR)
- [Medium](https://medium.com/@ithvaandres)

## Donate
If you would like to support this project, please consider donating to the following platforms:
- [Patreon](https://www.patreon.com/ithvaandres)
