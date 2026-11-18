#!/usr/bin/env python3
"""Non-secret deployment configuration and saved-plan integrity checks."""

import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys
import uuid


ROOTS = {
    "KEYVAULT": "Terraform/Azure/deployments/keyvault",
    "PRIVATELINK": "Terraform/Azure/tfm-privateLink-network",
}
STATE_KEYS = {
    "KEYVAULT": "keyvault/deployment.tfstate",
    "PRIVATELINK": "privatelink-network.tfstate",
}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


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
    values = json.loads(require("TFVARS_JSON"))
    if not isinstance(values, dict):
        raise ValueError("TFVARS_JSON must be a non-secret JSON object")
    if stack == "KEYVAULT":
        allowed = {"vault_name", "resource_group_name", "sku_name", "private_endpoints", "role_assignments", "tags"}
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
    backend = {"storage_account_name": account, "container_name": container, "key": STATE_KEYS[stack]}
    (pipeline / "backend.hcl").write_text("".join(f"{key} = {json.dumps(value)}\n" for key, value in backend.items()))
    (pipeline / "inputs.tfvars.json").write_text(serialized + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance():
    return {name: require(name) for name in (
        "STACK", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "TF_VERSION",
    )}


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
    changes = [item for item in plan.get("resource_changes", []) if item["change"]["actions"] != ["no-op"]]
    lines = [
        f"## Terraform plan: {html.escape(require('STACK'))}",
        f"Commit: `{require('GITHUB_SHA')}`",
        f"Resources with actions: {len(changes)}",
        "Attribute values and outputs are deliberately omitted. Review code and trusted runner logs before approval.",
    ]
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
    commands = {"prepare": prepare, "manifest": manifest, "verify": verify, "summarize": summarize}
    try:
        commands[sys.argv[1]]()
    except (ValueError, KeyError, IndexError, OSError) as error:
        # Configuration errors must never dump settings, plan JSON, or environment contents.
        print(f"::error::Pipeline check failed ({type(error).__name__}). Check required settings and artifact provenance.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
