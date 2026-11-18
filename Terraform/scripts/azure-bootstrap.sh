#!/usr/bin/env bash
set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
require() { command -v "$1" >/dev/null || die "$1 is required."; }
uuid() { [[ "$1" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; }

require az
command_name="${1:-}"

select_subscription() {
  az account list --refresh --query "[?state=='Enabled'].{Name:name,Subscription:id,Tenant:tenantId}" --output table
  if [[ -z "${SUBSCRIPTION_ID:-}" ]]; then
    read -r -p 'Subscription ID or name: ' SUBSCRIPTION_ID || die 'Subscription selection cancelled.'
  fi
  [[ -n "$SUBSCRIPTION_ID" ]] || die 'Subscription must not be empty.'
  az account set --subscription "$SUBSCRIPTION_ID"
  az account show --query '{Name:name,Subscription:id,Tenant:tenantId}' --output table
  printf 'For subsequent commands, pass SUBSCRIPTION_ID=<subscription UUID> to make.\n'
}

case "$command_name" in
  azure-login) az login --output none; select_subscription; exit ;;
  azure-subscription) select_subscription; exit ;;
  azure-permissions|backend-create|backend-test) ;;
  *) die "Unknown command: $command_name" ;;
esac

[[ -n "${SUBSCRIPTION_ID:-}" ]] || die 'Set SUBSCRIPTION_ID explicitly (UUID or subscription name).'
subscription=$(az account show --subscription "$SUBSCRIPTION_ID" --query id --output tsv)
uuid "$subscription" || die 'Azure did not return a valid subscription UUID.'
scope="/subscriptions/$subscription"
printf 'Target subscription: %s\n' "$subscription"

confirm() {
  local answer="${CONFIRM_SUBSCRIPTION:-}"
  printf '%s\n' "$1"
  if [[ -z "$answer" ]]; then
    read -r -p "Type subscription UUID $subscription to confirm: " answer || die 'Confirmation cancelled.'
  fi
  [[ "$answer" == "$subscription" ]] || die 'Confirmation does not match the target subscription.'
}

if [[ "$command_name" == azure-permissions ]]; then
  principal_type="${PRINCIPAL_TYPE:-User}"
  case "$principal_type" in User|Group|ServicePrincipal) ;; *) die 'Invalid PRINCIPAL_TYPE.' ;; esac
  principal="${PRINCIPAL_ID:-}"
  if [[ -z "$principal" ]]; then
    [[ "$principal_type" == User ]] || die 'PRINCIPAL_ID is required for a group or service principal.'
    principal=$(az ad signed-in-user show --query id --output tsv)
  fi
  uuid "$principal" || die 'PRINCIPAL_ID must be an Entra object UUID, not an application/client ID.'
  roles=("Contributor" "Owner" "Storage Blob Data Contributor" "Key Vault Administrator")
  role_ids=(
    b24988ac-6180-42a0-ab88-20f7382dd24c
    8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    ba92f5b4-2d11-453d-a403-e96b0029c9fe
    00482a5a-887f-4fb3-b363-3b7fe8e74483
  )
  printf 'Principal: %s (%s)\nScope: %s\n' "$principal" "$principal_type" "$scope"
  printf 'Role: %s\n' "${roles[@]}"
  confirm 'These are broad subscription-wide admin grants. Owner includes Contributor. Existing role-assignment authority is required.'
  for i in "${!roles[@]}"; do
    count=$(az role assignment list --assignee-object-id "$principal" --scope "$scope" \
      --include-inherited --fill-principal-name false --subscription "$subscription" \
      --query "length([?ends_with(roleDefinitionId, '/${role_ids[$i]}')])" --output tsv)
    [[ "$count" =~ ^[0-9]+$ ]] || die 'Could not inspect existing role assignments.'
    if [[ "$count" -gt 0 ]]; then
      printf 'Already assigned: %s\n' "${roles[$i]}"
    else
      az role assignment create --assignee-object-id "$principal" \
        --assignee-principal-type "$principal_type" --role "${role_ids[$i]}" \
        --scope "$scope" --subscription "$subscription" --output none
      printf 'Assigned: %s\n' "${roles[$i]}"
    fi
  done
  printf 'RBAC propagation can take several minutes. Key Vault network restrictions still apply.\n'
  exit
fi

require python3
resource_group="${RESOURCE_GROUP:-rg-terraform-state-test}"
location="${LOCATION:-eastus2}"
account="${STORAGE_ACCOUNT:-}"
container="${CONTAINER_NAME:-tfstate}"
[[ "$account" =~ ^[a-z0-9]{3,24}$ ]] || die 'STORAGE_ACCOUNT must contain 3-24 lowercase letters/digits.'
[[ "$container" =~ ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$ && "$container" != *--* ]] || die 'Invalid container name.'
[[ -n "$resource_group" && "$resource_group" != -* ]] || die 'Invalid resource group name.'
printf 'Resource group: %s\nStorage account: %s\nContainer: %s\n' "$resource_group" "$account" "$container"

retry() {
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if "$@"; then return 0; fi
    if [[ "$attempt" -lt 6 ]]; then
      printf 'Operation failed; retrying in 10 seconds (%s/6). Check RBAC and network access.\n' "$attempt" >&2
      sleep 10
    fi
  done
  die 'Operation failed after six attempts; verify Storage Blob Data Contributor and network access.'
}

if [[ "$command_name" == backend-create ]]; then
  backend_config="${BACKEND_CONFIG:-$(dirname "$0")/../backend.hcl}"
  state_key="${STATE_KEY:-test/terraform.tfstate}"
  [[ -n "$state_key" ]] || die 'STATE_KEY must not be empty.'
  backend_config_file() {
    python3 - "$1" "$backend_config" "$resource_group" "$account" "$container" "$state_key" "$subscription" <<'PY'
import json
import pathlib
import sys

mode, filename, *values = sys.argv[1:]
keys = ("resource_group_name", "storage_account_name", "container_name", "key", "subscription_id")
text = "".join(
    f"{key} = {json.dumps(value).replace('${', '$${').replace('%{', '%%{')}\n"
    for key, value in zip(keys, values)
) + "use_azuread_auth = true\n"
path = pathlib.Path(filename)
if path.exists():
    if path.read_text(encoding="utf-8") != text:
        sys.exit(f"Backend config differs: {path}. Choose another BACKEND_CONFIG; existing files are never overwritten.")
elif not path.parent.is_dir():
    sys.exit(f"Backend config directory does not exist: {path.parent}")
elif mode == "write":
    with path.open("x", encoding="utf-8") as stream:
        stream.write(text)
PY
  }
  backend_config_file check
  confirm 'Create/reuse test resources and enforce secure storage settings. Existing accounts must belong to this resource group. Azure charges may apply.'
  az group create --name "$resource_group" --location "$location" --subscription "$subscription" --output none
  az storage account create --name "$account" --resource-group "$resource_group" \
    --location "$location" --kind StorageV2 --sku Standard_LRS \
    --https-only true --min-tls-version TLS1_2 --allow-blob-public-access false \
    --allow-shared-key-access false --subscription "$subscription" --output none
  az storage account blob-service-properties update --account-name "$account" \
    --resource-group "$resource_group" --enable-versioning true \
    --enable-delete-retention true --delete-retention-days 7 \
    --enable-container-delete-retention true --container-delete-retention-days 7 \
    --subscription "$subscription" --output none
  retry az storage container create --name "$container" --account-name "$account" \
    --auth-mode login --public-access off --subscription "$subscription" --output none
  backend_config_file write
  printf 'Backend configuration written to %s. No Terraform initialization or state migration was performed.\n' "$backend_config"
  exit
fi

# Verify management-plane resources and data-plane access without touching state.
az group show --name "$resource_group" --subscription "$subscription" --output none
az storage account show --name "$account" --resource-group "$resource_group" --subscription "$subscription" --output none
retry az storage container show --name "$container" --account-name "$account" \
  --auth-mode login --subscription "$subscription" --output none
work_dir=$(mktemp -d)
blob_name="_bootstrap-tests/$(python3 -c 'import uuid; print(uuid.uuid4())').txt"
uploaded=false
cleanup() {
  local result=$?
  trap - EXIT
  if [[ "$uploaded" == true ]]; then
    if ! az storage blob delete --account-name "$account" --container-name "$container" \
      --name "$blob_name" --auth-mode login --subscription "$subscription" --output none; then
      printf 'Could not clean up temporary blob: %s\n' "$blob_name" >&2
      result=1
    fi
  fi
  rm -f "$work_dir/input.txt" "$work_dir/output.txt"
  rmdir "$work_dir"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Terraform backend smoke test\n' > "$work_dir/input.txt"
# Mark before upload so cleanup is attempted even if Azure accepts a request but the CLI fails.
uploaded=true
retry az storage blob upload --account-name "$account" --container-name "$container" \
  --name "$blob_name" --file "$work_dir/input.txt" --overwrite false \
  --auth-mode login --subscription "$subscription" --output none
az storage blob download --account-name "$account" --container-name "$container" \
  --name "$blob_name" --file "$work_dir/output.txt" \
  --auth-mode login --subscription "$subscription" --output none
cmp "$work_dir/input.txt" "$work_dir/output.txt" || die 'Downloaded blob content did not match.'
printf 'Backend read/write test passed; removing temporary blob %s.\n' "$blob_name"
