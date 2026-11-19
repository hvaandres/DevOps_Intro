#!/usr/bin/env python3
"""Non-secret deployment configuration and saved-plan integrity checks."""

import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


ROOTS = {
    "KEYVAULT": "Terraform/Azure/deployments/keyvault",
    "PRIVATELINK": "Terraform/Azure/tfm-privateLink-network",
}


class SubscriptionMismatchError(ValueError):
    """Safe subscription metadata that can be shown in workflow diagnostics."""


STATE_KEYS = {
    "KEYVAULT": "keyvault/deployment.tfstate",
    "PRIVATELINK": "privatelink-network.tfstate",
}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
CYBER_ENVIRONMENTS = {
    "cyber-dev": "keyvault-cyber-dev",
    "cyber-tst": "keyvault-cyber-tst",
    "cyber-prd": "keyvault-cyber-prd",
}


def object_json(value):
    document = json.loads(value)
    if not isinstance(document, dict):
        raise ValueError("Expected a JSON object")
    return document


def valid_uuid(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value.lower() and value != ZERO_UUID


def group_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", value) or value.endswith("."):
        raise ValueError("Invalid resource group name")
    return value


def string_tags(value):
    if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise ValueError("Tags must map strings to strings")


def request_values():
    """Only the dedicated Cyber dispatch path may supply request inputs."""
    subscription = os.environ.get("CYBER_SUBSCRIPTION", "")
    raw = os.environ.get("KEYVAULT_REQUEST_JSON", "")
    if not subscription and not raw:
        return None
    if require("STACK") != "KEYVAULT" or subscription not in CYBER_ENVIRONMENTS:
        raise ValueError("Unknown Cyber subscription or unsupported request stack")
    document = object_json(raw)
    allowed = {
        "subscription", "vault_name", "resource_group_name", "sku_name",
        "purge_protection_enabled", "soft_delete_retention_days",
        "private_endpoints_json", "role_assignments_json", "tags_json", "dry_run",
        "require_approval",
    }
    if set(document) - allowed or document.get("subscription") != subscription:
        raise ValueError("Unsupported request fields or mismatched subscription")
    name = document.get("vault_name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]", name) or "--" in name:
        raise ValueError("Invalid Key Vault name")
    group = group_name(document.get("resource_group_name"))
    sku = document.get("sku_name", "standard")
    purge = document.get("purge_protection_enabled", True)
    retention_value = document.get("soft_delete_retention_days", 90)
    if isinstance(retention_value, bool):
        raise ValueError("Retention must be a whole number from 7 to 90")
    if isinstance(retention_value, int):
        retention = retention_value
    elif isinstance(retention_value, float) and retention_value.is_integer():
        retention = int(retention_value)
    elif isinstance(retention_value, str) and re.fullmatch(r"[0-9]+", retention_value):
        retention = int(retention_value)
    else:
        raise ValueError("Retention must be a whole number from 7 to 90")
    dry_run = document.get("dry_run", True)
    require_approval = document.get("require_approval", True)
    if sku not in ("standard", "premium") or type(purge) is not bool or type(dry_run) is not bool:
        raise ValueError("Invalid SKU or boolean request fields")
    if type(require_approval) is not bool:
        raise ValueError("require_approval must be a boolean")
    if not 7 <= retention <= 90:
        raise ValueError("Retention must be a whole number from 7 to 90")
    if os.environ.get("DRY_RUN", "true") != ("true" if dry_run else "false"):
        raise ValueError("Dispatch dry-run setting does not match deployment mode")
    if os.environ.get("REQUIRE_APPROVAL", "true") != ("true" if require_approval else "false"):
        raise ValueError("Dispatch approval setting does not match deployment mode")
    endpoints = object_json(document.get("private_endpoints_json", "{}"))
    assignments = object_json(document.get("role_assignments_json", "{}"))
    tags = object_json(document.get("tags_json", "{}"))
    string_tags(tags)
    resource_id = r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/"
    for endpoint in endpoints.values():
        fields = {"name", "subnet_id", "resource_group_name", "location", "private_dns_zone_ids", "tags"}
        if not isinstance(endpoint, dict) or set(endpoint) - fields:
            raise ValueError("Invalid private endpoint fields")
        if not isinstance(endpoint.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", endpoint["name"]):
            raise ValueError("Invalid private endpoint name")
        if not isinstance(endpoint.get("subnet_id"), str) or not re.fullmatch(
            resource_id + r"Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+", endpoint["subnet_id"], re.I,
        ):
            raise ValueError("Private endpoint requires a subnet ARM ID")
        if "resource_group_name" in endpoint:
            group_name(endpoint["resource_group_name"])
        if "location" in endpoint and (
            not isinstance(endpoint["location"], str) or not re.fullmatch(r"[a-z0-9]+", endpoint["location"])
        ):
            raise ValueError("Invalid private endpoint region")
        zones = endpoint.get("private_dns_zone_ids", [])
        if not isinstance(zones, list) or any(
            not isinstance(zone, str) or not re.fullmatch(
                resource_id + r"Microsoft.Network/privateDnsZones/privatelink\.vaultcore\.azure\.net", zone, re.I,
            ) for zone in zones
        ):
            raise ValueError("Invalid private Key Vault DNS zone ID")
        string_tags(endpoint.get("tags", {}))
    for role in assignments.values():
        fields = {"principal_id", "role_definition_name", "role_definition_id", "principal_type", "skip_service_principal_aad_check"}
        if not isinstance(role, dict) or set(role) - fields or not valid_uuid(role.get("principal_id")):
            raise ValueError("Invalid role assignment fields or principal object ID")
        role_name, role_id = role.get("role_definition_name"), role.get("role_definition_id")
        if bool(role_name) == bool(role_id):
            raise ValueError("Specify exactly one role definition name or ID")
        if role_name and (not isinstance(role_name, str) or not re.fullmatch(r"[A-Za-z0-9 ()_-]{1,128}", role_name)):
            raise ValueError("Invalid role definition name")
        if role_id and (not isinstance(role_id, str) or not re.fullmatch(
            r"/subscriptions/[0-9a-fA-F-]{36}/providers/Microsoft.Authorization/roleDefinitions/[0-9a-fA-F-]{36}", role_id, re.I,
        )):
            raise ValueError("Invalid role definition ARM ID")
        if role.get("principal_type", "ServicePrincipal") not in ("User", "Group", "ServicePrincipal"):
            raise ValueError("Invalid role principal type")
        if type(role.get("skip_service_principal_aad_check", False)) is not bool:
            raise ValueError("Invalid service principal check option")
    return {
        "vault_name": name.lower(), "resource_group_name": group, "sku_name": sku,
        "purge_protection_enabled": purge, "soft_delete_retention_days": int(retention),
        "private_endpoints": endpoints, "role_assignments": assignments, "tags": tags,
    }


def configure():
    stack, _ = context()
    values = request_values()
    subscription = os.environ.get("CYBER_SUBSCRIPTION", "")
    if values is not None:
        base_environment = CYBER_ENVIRONMENTS[subscription]
        plan_environment = f"{base_environment}-plan"
        apply_environment = plan_environment
    else:
        plan_environment = "keyvault-plan" if stack == "KEYVAULT" else "privatelink-plan"
        apply_environment = "keyvault-apply" if stack == "KEYVAULT" else "privatelink-apply"
    with Path(require("GITHUB_OUTPUT")).open("a") as stream:
        stream.write(
            f"plan_environment={plan_environment}\n"
            f"apply_environment={apply_environment}\n"
        )


def azure_preflight():
    identity()
    context()
    values = request_values()
    if values is None:
        raise ValueError("Azure request preflight requires a Cyber Key Vault request")
    subscription_id = require("ARM_SUBSCRIPTION_ID")

    def azure_json(arguments):
        result = subprocess.run(
            ["az", *arguments, "--subscription", subscription_id, "--output", "json", "--only-show-errors"],
            check=True, text=True, capture_output=True, timeout=120,
        )
        return object_json(result.stdout)

    account = azure_json(["account", "show"])
    selected_subscription = require("CYBER_SUBSCRIPTION")
    actual_id = account.get("id")
    if not isinstance(actual_id, str) or actual_id.lower() != subscription_id.lower():
        raise SubscriptionMismatchError(
            f"Deployment blocked: Azure subscription ID does not match environment SUBSCRIPTION_ID "
            f"for workflow_dispatch choice {selected_subscription}."
        )
    actual_name = account.get("name")
    if not isinstance(actual_name, str) or actual_name.casefold() != selected_subscription.casefold():
        displayed_name = json.dumps(actual_name) if isinstance(actual_name, str) else "<missing>"
        raise SubscriptionMismatchError(
            f"Deployment blocked: workflow_dispatch selected {selected_subscription}, but configured "
            f"subscription {subscription_id} is named {displayed_name} in Azure. Set the selected GitHub "
            f"environment's SUBSCRIPTION_ID to the intended {selected_subscription} subscription. "
            "No fallback subscription will be used."
        )
    group = azure_json(["group", "show", "--name", values["resource_group_name"]])
    expected = f"/subscriptions/{subscription_id}/resourceGroups/{values['resource_group_name']}"
    if group.get("id", "").lower() != expected.lower() or group.get("name", "").lower() != values["resource_group_name"].lower():
        raise ValueError("Resource group does not belong to the selected Cyber subscription")
    print(
        f"Verified workflow_dispatch subscription {selected_subscription} ({subscription_id}) "
        f"and resource group {values['resource_group_name']}. Vault region: westus2."
    )


def require(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Missing required setting: {name}")
    return value


def identity():
    for name in ("ARM_CLIENT_ID", "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID"):
        value = require(name)
        if str(uuid.UUID(value)) != value.lower() or value == ZERO_UUID:
            raise ValueError(f"{name} must be a real UUID")
    for name in ("ARM_CLIENT_SECRET", "ARM_ACCESS_KEY", "ARM_SAS_TOKEN"):
        if os.environ.get(name):
            raise ValueError(f"Remove {name}; this workflow only supports OIDC")


def context():
    stack = require("STACK")
    if stack not in ROOTS or require("TF_ROOT") != ROOTS[stack]:
        raise ValueError("Unknown stack or unexpected Terraform root")
    if require("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Deployment is restricted to main")
    return stack, Path(ROOTS[stack])


def prepare():
    identity()
    stack, root = context()
    account = require("BACKEND_ACCOUNT")
    container = require("BACKEND_CONTAINER")
    if not re.fullmatch(r"[a-z0-9]{3,24}", account):
        raise ValueError("Invalid backend account name")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])", container) or "--" in container:
        raise ValueError("Invalid backend container name")
    requested = request_values()
    if requested is not None and os.environ.get("DEPLOY_ENABLED") != "true":
        raise ValueError("Deployment is not enabled for this Cyber subscription")
    values = requested if requested is not None else json.loads(require("TFVARS_JSON"))
    if not isinstance(values, dict):
        raise ValueError("TFVARS_JSON must be a non-secret JSON object")
    if stack == "KEYVAULT":
        allowed = {
            "vault_name", "resource_group_name", "sku_name", "private_endpoints", "role_assignments", "tags",
            "purge_protection_enabled", "soft_delete_retention_days",
        }
        required = {"vault_name", "resource_group_name"}
    else:
        allowed = {
            "hub_subscription_id", "hub_vnet_id", "hub_vnet_name", "hub_resource_group_name",
            "location", "environment", "tags", "enable_resource_locks", "alert_action_group_id",
            "alert_thresholds",
        }
        required = {"hub_subscription_id", "hub_vnet_id", "hub_vnet_name", "hub_resource_group_name"}
    if set(values) - allowed or any(not values.get(key) for key in required):
        raise ValueError("TFVARS_JSON contains unsupported inputs or is missing required inputs")
    serialized = json.dumps(values)
    if ZERO_UUID in serialized or re.search(r"<[^>]*>|YOUR_|REPLACE_ME", serialized, re.I):
        raise ValueError("Replace all placeholder deployment values")
    if stack == "PRIVATELINK" and values["hub_subscription_id"].lower() != require("ARM_SUBSCRIPTION_ID").lower():
        raise ValueError("Private Link hub subscription must match ARM_SUBSCRIPTION_ID")
    # Plan and apply must use only committed providers/configuration, not persistent-runner leftovers.
    if (root / ".terraform").exists():
        raise ValueError("Runner checkout must be clean: .terraform already exists")
    pipeline = root / ".pipeline"
    pipeline.mkdir(exist_ok=False)
    state_key = STATE_KEYS[stack] if requested is None else (
        f"keyvault/{require('CYBER_SUBSCRIPTION')}/{values['vault_name']}.tfstate"
    )
    backend = {"storage_account_name": account, "container_name": container, "key": state_key}
    (pipeline / "backend.hcl").write_text("".join(f"{key} = {json.dumps(value)}\n" for key, value in backend.items()))
    (pipeline / "inputs.tfvars.json").write_text(serialized + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance():
    values = {name: require(name) for name in (
        "STACK", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "TF_VERSION",
    )}
    requested = request_values()
    if requested is not None:
        values["CYBER_SUBSCRIPTION"] = require("CYBER_SUBSCRIPTION")
        values["KEYVAULT_REQUEST_SHA256"] = hashlib.sha256(
            json.dumps(requested, sort_keys=True).encode()
        ).hexdigest()
    return values


def manifest():
    _, root = context()
    pipeline = root / ".pipeline"
    lock = root / ".terraform.lock.hcl"
    document = {
        "provenance": provenance(),
        "files": {name: digest(pipeline / name) for name in ("backend.hcl", "inputs.tfvars.json", "deployment.tfplan")},
        "lock_sha256": digest(lock),
    }
    (pipeline / "manifest.json").write_text(json.dumps(document, indent=2) + "\n")


def verify():
    identity()
    _, root = context()
    # The workflow checks GitHub's artifact digest; the manifest binds files to this run.
    if not re.fullmatch(r"[0-9a-f]{64}", require("EXPECTED_ARTIFACT_DIGEST")):
        raise ValueError("Missing uploaded artifact digest")
    pipeline = root / ".pipeline"
    document = json.loads((pipeline / "manifest.json").read_text())
    if document["provenance"] != provenance():
        raise ValueError("Plan provenance does not match this workflow run")
    if set(document["files"]) != {"backend.hcl", "inputs.tfvars.json", "deployment.tfplan"}:
        raise ValueError("Unexpected plan artifact contents")
    for name, expected in document["files"].items():
        if digest(pipeline / name) != expected:
            raise ValueError("Plan artifact integrity check failed")
    if digest(root / ".terraform.lock.hcl") != document["lock_sha256"]:
        raise ValueError("Provider lock differs from the reviewed plan")
    if (root / ".terraform").exists():
        raise ValueError("Runner checkout must be clean: .terraform already exists")


def summarize():
    plan = json.load(sys.stdin)
    requested = request_values()
    if require("STACK") == "KEYVAULT" and any(
        item.get("mode", "managed") == "managed" and (
            "delete" in item["change"]["actions"]
            or (
                item.get("type") == "azurerm_management_lock"
                and item["change"].get("after", {}).get("lock_level") != "CanNotDelete"
            )
        )
        for item in plan.get("resource_changes", [])
    ):
        raise ValueError("Key Vault deletion/replacement or lock weakening requires the approved tear down workflow")
    changes = [item for item in plan.get("resource_changes", []) if item["change"]["actions"] != ["no-op"]]
    lines = [
        f"## Terraform plan: {html.escape(require('STACK'))}",
        f"Commit: `{require('GITHUB_SHA')}`",
        f"Resources with actions: {len(changes)}",
        "Attribute values and outputs are deliberately omitted. Review code and trusted runner logs before approval.",
    ]
    if requested is not None:
        vault_changes = [item for item in changes if item.get("type") == "azurerm_key_vault"]
        status = "create" if any("create" in item["change"]["actions"] for item in vault_changes) else (
            "update" if vault_changes else "no vault changes"
        )
        lines.extend([
            f"Requested vault: `{requested['vault_name']}`; region: `westus2`.",
            f"Target: `{require('CYBER_SUBSCRIPTION')}` / `{require('ARM_SUBSCRIPTION_ID')}`.",
            f"Resource group: `{html.escape(requested['resource_group_name'])}`.",
            f"Vault plan result: **{status}**.",
        ])
    for item in changes[:250]:
        address = html.escape(item["address"]).replace("`", "&#96;")
        actions = ", ".join(item["change"]["actions"])
        lines.append(f"- {address}: {actions}")
    if len(changes) > 250:
        lines.append("Additional resource actions omitted; inspect the trusted run.")
    if not changes:
        lines.append("No resource actions. Terraform may still have state or output changes.")
    if os.environ.get("DRY_RUN") == "true":
        lines.append("DRY RUN: apply is disabled for this workflow run. No managed infrastructure changes will be applied.")
    else:
        lines.append("Nothing has been applied. Changes require protected-environment approval.")
    with Path(require("GITHUB_STEP_SUMMARY")).open("a") as stream:
        stream.write("\n\n".join(lines) + "\n")


def main():
    commands = {
        "configure": configure, "azure-preflight": azure_preflight,
        "prepare": prepare, "manifest": manifest, "verify": verify, "summarize": summarize,
    }
    try:
        commands[sys.argv[1]]()
    except (ValueError, KeyError, IndexError, OSError, TypeError, subprocess.SubprocessError) as error:
        # Configuration errors must never dump settings, plan JSON, or environment contents.
        hint = {
            "configure": "Check the Cyber subscription choice, vault/group names, and typed JSON request fields.",
            "azure-preflight": "Verify the selected Cyber subscription UUID/display name, existing resource-group membership, Azure access, and connectivity.",
            "summarize": "The plan could not be reviewed; Key Vault deletions/replacements require the approved tear down workflow.",
        }.get(sys.argv[1] if len(sys.argv) > 1 else "", "Check required settings, enable flags, and artifact provenance.")
        detail = str(error) if isinstance(error, SubscriptionMismatchError) else hint
        print(f"::error::Pipeline check failed ({type(error).__name__}). {detail}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
