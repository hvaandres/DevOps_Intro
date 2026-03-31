#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# teardown-test-env.sh
#
# Removes all test infrastructure created by setup-test-env.sh.
# Run `terraform destroy` FIRST before running this script.
#
# Usage:
#   chmod +x scripts/teardown-test-env.sh
#   ./scripts/teardown-test-env.sh
###############################################################################

ENVIRONMENT="dev"

echo ">>> Destroying test resource groups..."

for RG in "rg-private-dns-${ENVIRONMENT}" "rg-hub-networking-${ENVIRONMENT}" "rg-spoke-${ENVIRONMENT}" "rg-terraform-state-${ENVIRONMENT}"; do
  if az group exists --name "${RG}" | grep -q true; then
    echo "    Deleting ${RG}..."
    az group delete --name "${RG}" --yes --no-wait
  else
    echo "    ${RG} does not exist, skipping."
  fi
done

echo ""
echo ">>> Deletion initiated (--no-wait). Resource groups are being removed in the background."
echo "    Check status: az group list --query \"[?starts_with(name,'rg-')].{Name:name,State:properties.provisioningState}\" -o table"
