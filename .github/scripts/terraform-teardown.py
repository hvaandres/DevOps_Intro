#!/usr/bin/env python3
"""State-driven Azure teardown with scope, approval, artifact, and drift checks."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
from urllib.parse import urlsplit


ROOT = Path("Terraform/Azure/deployments/teardown")
ACCOUNT = "kvstate12790"
SUBSCRIPTIONS = {"cybersecurity-prd", "cybersecurity-stg", "cybersecurity-tst"}
PROVIDER = 'provider["registry.terraform.io/hashicorp/azurerm"]'
FILES = {"backend.hcl", "backend-target.json", "target.json", "drift.json", "destroy.tfplan"}
PIPELINE = ROOT / ".pipeline"


class SafetyError(ValueError):
    """Only fixed, non-sensitive diagnostics may be displayed."""


def require(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise SafetyError(f"Missing required setting: {name}")
    return value


def real_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value.lower() and uuid.UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def request():
    document = json.loads(require("TEARDOWN_REQUEST_JSON"))
    if not isinstance(document, dict) or set(document) != {
        "subscription", "resource_group_name", "vault_name", "dry_run", "confirmation",
    }:
        raise SafetyError("Unexpected teardown fields.")
    if document["subscription"] not in SUBSCRIPTIONS:
        raise SafetyError("Choose cybersecurity-prd, cybersecurity-stg, or cybersecurity-tst.")
    vault = document["vault_name"]
    if (
        not isinstance(vault, str)
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]", vault)
        or "--" in vault
    ):
        raise SafetyError("Invalid Key Vault name.")
    key = f"keyvault/{document['subscription']}/{vault.lower()}.tfstate"
    group = document["resource_group_name"]
    if not isinstance(group, str) or not re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", group) or group.endswith("."):
        raise SafetyError("Invalid resource group name.")
    if type(document["dry_run"]) is not bool or not isinstance(document["confirmation"], str):
        raise SafetyError("Invalid dry-run or confirmation value.")
    if not document["dry_run"] and document["confirmation"].lower() != vault.lower():
        raise SafetyError("Actual destruction requires confirmation equal to the exact vault name.")
    document["state_key"] = key
    return document


def context():
    if require("GITHUB_REF") != "refs/heads/main" or require("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise SafetyError("Teardown requires a new manual workflow run on main.")
    if require("GITHUB_RUN_ATTEMPT") != "1":
        raise SafetyError("Start a new workflow run; reruns cannot reuse destruction approval.")
    expected = f"{require('GITHUB_REPOSITORY')}/.github/workflows/tear-down.yml@refs/heads/main"
    if require("GITHUB_WORKFLOW_REF") != expected:
        raise SafetyError("Unexpected teardown workflow.")
    return request()


def settings():
    selected = context()
    if require("TEARDOWN_ENABLED") != "true":
        raise SafetyError("Teardown is not enabled in this job environment.")
    allowed = json.loads(require("TEARDOWN_ALLOWED_STATE_KEYS"))
    if not isinstance(allowed, list) or not all(isinstance(key, str) for key in allowed) or selected["state_key"] not in allowed:
        raise SafetyError("State key is not explicitly authorized in this subscription environment.")
    for name in ("ARM_CLIENT_ID", "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "PLAN_CLIENT_ID", "TEARDOWN_CLIENT_ID"):
        if not real_uuid(require(name)):
            raise SafetyError(f"{name} must be a nonzero UUID.")
    if require("PLAN_CLIENT_ID").lower() == require("TEARDOWN_CLIENT_ID").lower():
        raise SafetyError("Use distinct planning and teardown identities.")
    phase = require("TEARDOWN_PHASE")
    expected = require("PLAN_CLIENT_ID" if phase == "plan" else "TEARDOWN_CLIENT_ID")
    if phase not in {"plan", "destroy"} or require("ARM_CLIENT_ID").lower() != expected.lower():
        raise SafetyError("Unexpected identity for teardown phase.")
    if phase == "destroy" and selected["dry_run"]:
        raise SafetyError("A dry run cannot execute destruction.")
    for name in ("ARM_CLIENT_SECRET", "ARM_ACCESS_KEY", "ARM_SAS_TOKEN"):
        if os.environ.get(name):
            raise SafetyError("Remove legacy credentials; teardown only supports OIDC.")
    if any(os.environ.get(name) != "true" for name in ("ARM_USE_OIDC", "ARM_USE_AZUREAD")) or os.environ.get("ARM_USE_CLI") != "false":
        raise SafetyError("Enable OIDC and Entra Blob authentication; disable Terraform CLI authentication.")
    container = os.environ.get("BACKEND_CONTAINER", "") or "tfstate"
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", container) or "--" in container:
        raise SafetyError("Invalid state container.")
    backend_group = require("BACKEND_RESOURCE_GROUP_NAME")
    backend_subscription = os.environ.get("BACKEND_SUBSCRIPTION_ID") or require("ARM_SUBSCRIPTION_ID")
    if not real_uuid(backend_subscription) or not re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", backend_group) or backend_group.endswith("."):
        raise SafetyError("Invalid backend subscription or resource group.")
    return selected, {
        "storage_account_name": ACCOUNT, "container_name": container,
        "key": selected["state_key"], "resource_group_name": backend_group, "subscription_id": backend_subscription,
    }


def execute(arguments, label, accepted=(0,)):
    # Capture stdout/stderr: Terraform state, plan JSON, and provider errors can
    # contain sensitive attributes. Never include CalledProcessError output.
    result = subprocess.run(arguments, text=True, capture_output=True, timeout=1200)
    if result.returncode not in accepted:
        raise SafetyError(f"{label} failed. Check scoped RBAC, OIDC, backend access, policy, locks, and runner networking.")
    return result


def azure(arguments, label, subscription=None):
    return json.loads(execute(
        ["az", *arguments, "--subscription", subscription or require("ARM_SUBSCRIPTION_ID"), "--output", "json", "--only-show-errors"],
        label,
    ).stdout)


def terraform(arguments, label, accepted=(0,)):
    return execute(["terraform", f"-chdir={ROOT}", *arguments], label, accepted)


def configure():
    selected = context()
    base = f"terraform-{selected['subscription']}"
    with Path(require("GITHUB_OUTPUT")).open("a") as stream:
        stream.write(f"plan_environment={base}-teardown-plan\ndestroy_environment={base}-teardown\n")


def prepare():
    settings()
    if (ROOT / ".terraform").exists() or PIPELINE.exists():
        raise SafetyError("Use a clean checkout without Terraform or pipeline leftovers.")
    _, backend = settings()
    PIPELINE.mkdir(mode=0o700)
    (PIPELINE / "backend.hcl").write_text("".join(f"{key} = {json.dumps(value)}\n" for key, value in backend.items()))


def group_id():
    return f"/subscriptions/{require('ARM_SUBSCRIPTION_ID')}/resourceGroups/{context()['resource_group_name']}"


def backend_id():
    _, backend = settings()
    return f"/subscriptions/{backend['subscription_id']}/resourceGroups/{backend['resource_group_name']}/providers/Microsoft.Storage/storageAccounts/{ACCOUNT}"


def preflight():
    selected, backend = settings()
    account = azure(["account", "show"], "Azure identity/subscription lookup")
    if (
        str(account.get("id", "")).lower() != require("ARM_SUBSCRIPTION_ID").lower()
        or str(account.get("tenantId", "")).lower() != require("ARM_TENANT_ID").lower()
        or str(account.get("name", "")).casefold() != selected["subscription"].casefold()
    ):
        raise SafetyError("Subscription UUID, tenant, or Azure display name does not match the selected Cyber subscription.")
    group = azure(["group", "show", "--name", selected["resource_group_name"]], "Resource group lookup")
    if str(group.get("id", "")).lower() != group_id().lower():
        raise SafetyError("Resource group is outside the selected subscription.")
    storage = azure([
        "storage", "account", "show", "--ids", backend_id(),
    ], "Backend account ownership lookup", backend["subscription_id"])
    if str(storage.get("id", "")).lower() != backend_id().lower():
        raise SafetyError("Backend account ownership does not match trusted configuration.")
    target_path = PIPELINE / "backend-target.json"
    storage_target = {"id": backend_id()}
    if require("TEARDOWN_PHASE") == "destroy":
        if json.loads(target_path.read_text()) != storage_target:
            raise SafetyError("Backend ownership changed after approval.")
    else:
        target_path.write_text(json.dumps(storage_target) + "\n")
    exists = azure([
        "storage", "blob", "exists", "--auth-mode", "login", "--account-name", ACCOUNT,
        "--container-name", backend["container_name"], "--name", backend["key"],
    ], "State blob existence check")
    if exists.get("exists") is not True:
        raise SafetyError("Selected state blob does not exist; teardown will not create or search for another state.")
    print("Verified subscription name/UUID, tenant, group, backend ownership, and existing state blob.")


def address(resource, instance):
    prefix = resource.get("module", "")
    result = f"{prefix}.{resource['type']}.{resource['name']}" if prefix else f"{resource['type']}.{resource['name']}"
    if "index_key" in instance:
        result += f"[{json.dumps(instance['index_key'], ensure_ascii=True)}]"
    return result


def scoped_arm_id(arm_id):
    if not isinstance(arm_id, str) or any(char in arm_id for char in ("?", "#", "|", "\\", "%")):
        raise SafetyError("Resource has an unsupported ARM identity.")
    if any(part in {".", ".."} for part in arm_id.split("/")):
        raise SafetyError("Resource identity contains traversal.")
    boundary = group_id().lower()
    if arm_id.lower() != boundary and not arm_id.lower().startswith(boundary + "/providers/"):
        raise SafetyError("State includes resources outside the selected subscription/resource group.")
    if arm_id.lower().startswith(backend_id().lower()):
        raise SafetyError("The state storage account and its children must never be destroyed.")
    backend_group = backend_id().lower().split("/providers/", 1)[0]
    if arm_id.lower() == backend_group:
        raise SafetyError("A resource group containing state storage must never be destroyed.")
    return arm_id


def resource_identity(kind, values):
    identity = values.get("id")
    if not isinstance(identity, str):
        raise SafetyError("Managed resource has no identity.")
    if identity.startswith("/"):
        scope = scoped_arm_id(identity)
    elif kind in {"azurerm_key_vault_key", "azurerm_key_vault_secret"}:
        # Explicit adapters for data-plane IDs; never infer Azure ownership from
        # an arbitrary HTTPS hostname or another resource's unrelated attributes.
        arm = scoped_arm_id(values.get("resource_versionless_id"))
        object_type = "keys" if kind == "azurerm_key_vault_key" else "secrets"
        match = re.fullmatch(
            r"(.*/providers/Microsoft\.KeyVault/vaults/([^/]+))/" + object_type + r"/([^/]+)", arm, re.I,
        )
        parsed = urlsplit(identity)
        if not match or parsed.scheme != "https" or parsed.query or parsed.fragment:
            raise SafetyError("Unsupported Key Vault object identity.")
        owner, vault, name = match.groups()
        parts = parsed.path.strip("/").split("/")
        if parsed.netloc.lower() != f"{vault}.vault.azure.net".lower() or len(parts) != 3 or parts[:2] != [object_type, name]:
            raise SafetyError("Key Vault object URI does not match its ARM owner.")
        if values.get("key_vault_id", owner).lower() != owner.lower():
            raise SafetyError("Key Vault object has a mismatched owner.")
        scope = owner
    else:
        raise SafetyError("Unsupported non-ARM identity; add a reviewed ownership adapter/provider configuration.")
    if kind == "azurerm_management_lock":
        owner = scoped_arm_id(values.get("scope"))
        expected = f"{owner}/providers/Microsoft.Authorization/locks/{values['name']}"
        if identity.lower() != expected.lower() or values.get("lock_level") not in {"CanNotDelete", "ReadOnly"}:
            raise SafetyError("State lock identity, scope, or level is invalid.")
    if kind == "azurerm_key_vault" and str(values.get("tenant_id", "")).lower() != require("ARM_TENANT_ID").lower():
        raise SafetyError("Vault belongs to a different tenant.")
    return {"id": identity, "scope": scope, "type": kind}


def fingerprint(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect_state(document):
    if document.get("version") != 4 or not real_uuid(document.get("lineage")) or type(document.get("serial")) is not int or document["serial"] < 0:
        raise SafetyError("Unsupported or missing Terraform state metadata.")
    resources, identities = {}, set()
    for resource in document.get("resources", []):
        # Only the reviewed default-root AzureRM provider is configured. Do not
        # fabricate aliases or execute provider code supplied through dispatch.
        if resource.get("provider") != PROVIDER:
            raise SafetyError("State needs an unavailable provider or alias; add its configuration through review.")
        if resource.get("mode") == "data":
            continue
        if resource.get("mode") != "managed" or not resource.get("type", "").startswith("azurerm_"):
            raise SafetyError("Unsupported provider/resource mode.")
        for instance in resource.get("instances", []):
            if instance.get("deposed") or instance.get("status"):
                raise SafetyError("Resolve deposed or tainted instances in the owning deployment first.")
            addr = address(resource, instance)
            record = resource_identity(resource["type"], instance["attributes"])
            if addr in resources or record["id"].lower() in identities:
                raise SafetyError("Duplicate resource addresses or remote identities in state.")
            resources[addr] = record
            identities.add(record["id"].lower())
    if not resources:
        raise SafetyError("State is empty or already destroyed; no managed resources were found.")
    return {
        "lineage": document["lineage"], "serial": document["serial"],
        "state_sha256": fingerprint(document), "resources": resources,
    }


def read_state():
    return json.loads(terraform(["state", "pull"], "Remote state inspection").stdout)


def state():
    settings()
    target = inspect_state(read_state())
    (PIPELINE / "target.json").write_text(json.dumps(target) + "\n")
    print(f"Validated {len(target['resources'])} managed resources from state; no workload configuration is required.")


def check_locks(target):
    allowed = {item["id"].lower() for item in target["resources"].values() if item["type"] == "azurerm_management_lock"}
    scopes = {item["scope"].lower() for item in target["resources"].values() if item["type"] != "azurerm_management_lock"}
    subscription_scope = f"/subscriptions/{require('ARM_SUBSCRIPTION_ID')}"
    # List at subscription level to include parent and child locks explicitly;
    # don't assume a resource-level list includes inherited subscription locks.
    document = azure([
        "rest", "--method", "get", "--url",
        f"https://management.azure.com{subscription_scope}/providers/Microsoft.Authorization/locks?api-version=2016-09-01",
    ], "Inherited/resource lock inspection")
    if document.get("nextLink"):
        raise SafetyError("Lock listing is paginated; review inherited locks separately.")
    if not isinstance(document.get("value"), list):
        raise SafetyError("Invalid Azure lock response.")
    for lock in document["value"]:
        identity = str(lock.get("id", "")).lower()
        parts = identity.rsplit("/providers/microsoft.authorization/locks/", 1)
        if len(parts) != 2 or not parts[0].startswith(subscription_scope.lower()):
            raise SafetyError("Azure returned an unrecognized lock scope.")
        owner = parts[0]
        related = any(owner == scope or scope.startswith(owner + "/") or owner.startswith(scope + "/") for scope in scopes)
        if related and identity not in allowed:
            raise SafetyError("An inherited or unmanaged lock blocks teardown. Ask its owner to review it; it will not be removed.")
    print("Lock preflight passed. Managed locks are removed only by the approved Terraform destroy plan.")


def locks():
    settings()
    check_locks(json.loads((PIPELINE / "target.json").read_text()))


def drift_actions(document):
    if document.get("errored") or document.get("complete") is False or document.get("deferred_changes"):
        raise SafetyError("Plan is incomplete, deferred, or errored.")
    return [
        {"address": item["address"], "actions": item["change"]["actions"]}
        for item in document.get("resource_drift", []) if item["change"]["actions"] != ["no-op"]
    ]


def validate_plan(document, target, dry_run=False):
    drift = drift_actions(document)
    if drift and not dry_run:
        raise SafetyError("Live drift detected. Reconcile it in the owning deployment, then start a new teardown run.")
    seen, deleted = set(), []
    for item in document.get("resource_changes", []):
        if item.get("mode") == "data":
            continue
        addr, change = item["address"], item["change"]
        if addr in seen or addr not in target["resources"]:
            raise SafetyError("Plan contains duplicate or unapproved resource addresses.")
        expected = target["resources"][addr]
        if (
            item.get("mode") != "managed" or item.get("type") != expected["type"]
            or change.get("actions") != ["delete"] or change.get("after") is not None
            or item.get("deposed") or item.get("previous_address") or change.get("importing")
            or resource_identity(item["type"], change.get("before") or {}) != expected
        ):
            raise SafetyError("Only deletion of the exact state-tracked resources inside the approved scope is allowed.")
        seen.add(addr)
        deleted.append(addr)
    missing = set(target["resources"]) - seen
    externally_deleted = {
        item["address"] for item in drift if item["actions"] == ["delete"]
    }
    if missing and (not dry_run or not missing.issubset(externally_deleted)):
        raise SafetyError("Empty/partial destruction or unaccounted state drift detected.")
    if not deleted and not (dry_run and missing and missing.issubset(externally_deleted)):
        raise SafetyError("No state-tracked deletions to execute.")
    return sorted(deleted)


def planned_document(filename="destroy.tfplan"):
    return json.loads(terraform(["show", "-json", f".pipeline/{filename}"], "Saved plan inspection").stdout)


def create_plan(filename, refresh_only=False):
    terraform([
        "plan", "-refresh-only" if refresh_only else "-destroy", "-input=false", "-no-color",
        "-lock-timeout=5m", "-detailed-exitcode", f"-out=.pipeline/{filename}",
    ], "Terraform drift planning" if refresh_only else "Terraform destroy planning", accepted=(0, 2))
    document = planned_document(filename)
    if refresh_only:
        (PIPELINE / filename).unlink()
    return document


def summary(title, records):
    lines = [f"## {title}"]
    for record in records:
        safe_address = re.sub(r'[^A-Za-z0-9_.\[\]"-]', "?", record["address"])
        actions = ", ".join(record["actions"])
        lines.append(f"- `{safe_address}`: {actions}")
    with Path(require("GITHUB_STEP_SUMMARY")).open("a") as stream:
        stream.write("\n".join(lines) + "\n\n")


def drift():
    settings()
    changes = drift_actions(create_plan("drift.tfplan", refresh_only=True))
    (PIPELINE / "drift.json").write_text(json.dumps(changes) + "\n")
    summary("Live drift detected" if changes else "No live drift detected", changes)
    if changes and not context()["dry_run"]:
        raise SafetyError("Live drift blocks destruction. Review and reconcile it in the owning deployment, then run teardown again.")
    print(f"Drift check: {len(changes)} changed resource(s). No state or resources updated.")


def plan():
    selected, backend = settings()
    if require("TEARDOWN_PHASE") != "plan":
        raise SafetyError("Destroy plans must be created by the planning job.")
    target = json.loads((PIPELINE / "target.json").read_text())
    document = create_plan("destroy.tfplan")
    deleted = validate_plan(document, target, selected["dry_run"])
    # Catch a concurrent state update during either planning operation.
    if inspect_state(read_state()) != target:
        raise SafetyError("Remote state changed while planning. Start a new run.")
    summary("State-driven tear down — proposed deletions", [{"address": addr, "actions": ["delete"]} for addr in deleted])
    with Path(require("GITHUB_STEP_SUMMARY")).open("a") as stream:
        stream.write(
            f"Target: `{selected['subscription']}` / `{selected['resource_group_name']}`. "
            f"State: `{ACCOUNT}/{backend['container_name']}/{backend['key']}`.\n\n"
            + ("DRY RUN: no locks removed, state refreshed, or resources deleted.\n" if selected["dry_run"] else
               "Nothing applied. The saved destroy plan requires a separate hvaandres approval.\n")
            + "\nOnly objects tracked in the selected state are proposed for deletion. "
            "State storage is protected. A tracked resource group can be deleted; untracked contents must block it. "
            "Planning cannot prove all delete permissions or eliminate changes after the final check.\n"
        )
    print(f"Destroy plan validated: {len(deleted)} deletions; no changes applied.")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance():
    selected, backend = settings()
    return {
        "operation": "azure-state-destroy", "request": selected, "backend": backend,
        **{name: require(name) for name in (
            "GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "TF_VERSION", "PLAN_CLIENT_ID", "TEARDOWN_CLIENT_ID",
        )},
    }


def seal():
    if require("TEARDOWN_PHASE") != "plan":
        raise SafetyError("Only the planning job may seal a destroy plan.")
    document = {
        "provenance": provenance(), "files": {name: digest(PIPELINE / name) for name in sorted(FILES)},
        "lock_sha256": digest(ROOT / ".terraform.lock.hcl"),
    }
    (PIPELINE / "manifest.json").write_text(json.dumps(document) + "\n")


def verify():
    if require("TEARDOWN_PHASE") != "destroy":
        raise SafetyError("Only the protected destruction job may verify execution artifacts.")
    if not re.fullmatch(r"[0-9a-f]{64}", require("EXPECTED_ARTIFACT_DIGEST")):
        raise SafetyError("Missing uploaded artifact digest.")
    document = json.loads((PIPELINE / "manifest.json").read_text())
    if (
        document["provenance"] != provenance() or set(document["files"]) != FILES
        or {path.name for path in PIPELINE.iterdir()} != FILES | {"manifest.json"}
        or any(path.is_symlink() for path in PIPELINE.iterdir())
        or any(digest(PIPELINE / name) != value for name, value in document["files"].items())
        or digest(ROOT / ".terraform.lock.hcl") != document["lock_sha256"]
        or (ROOT / ".terraform").exists()
    ):
        raise SafetyError("Artifact provenance/integrity, provider lock, or clean-checkout verification failed.")
    _, backend = settings()
    expected = "".join(f"{key} = {json.dumps(value)}\n" for key, value in backend.items())
    if (PIPELINE / "backend.hcl").read_text() != expected:
        raise SafetyError("Artifact backend does not match the selected target.")


def verify_plan():
    settings()
    if require("TEARDOWN_PHASE") != "destroy":
        raise SafetyError("Execution validation requires the protected teardown identity.")
    target = json.loads((PIPELINE / "target.json").read_text())
    if inspect_state(read_state()) != target:
        raise SafetyError("Remote state changed after planning; start a new full workflow run.")
    approved = planned_document()
    validate_plan(approved, target)
    check_locks(target)
    if drift_actions(create_plan("recheck-drift.tfplan", refresh_only=True)):
        raise SafetyError("New live drift after approval. Start a new run; the approved plan will not execute.")
    verification = create_plan("verification.tfplan")
    validate_plan(verification, target)
    def signature(document):
        return fingerprint(sorted(
            [item for item in document.get("resource_changes", []) if item.get("mode") == "managed"],
            key=lambda item: item["address"],
        ))
    if signature(approved) != signature(verification) or inspect_state(read_state()) != target:
        raise SafetyError("Destruction scope, live attributes, or remote state changed after approval. Start a new run.")
    (PIPELINE / "verification.tfplan").unlink()
    print("Approved plan matches current state/live resources. Only the original saved destroy plan may execute.")


def main():
    commands = {
        "configure": configure, "prepare": prepare, "preflight": preflight, "state": state, "locks": locks,
        "drift": drift, "plan": plan, "seal": seal, "verify": verify, "verify-plan": verify_plan,
    }
    try:
        commands[sys.argv[1]]()
    except SafetyError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.SubprocessError):
        print("::error::Teardown validation failed. Check required settings, supported state layout, and artifact integrity; raw state was not logged.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
