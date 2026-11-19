"""Offline teardown tests: all Azure/Terraform interactions are mocked."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_pipeline as shared


teardown = shared.load("teardown", shared.REPO / ".github/scripts/terraform-teardown.py")


class TeardownTests(unittest.TestCase):
    def setUp(self):
        shared.PipelineTests.setUp(self)
        self.root = teardown.ROOT
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / ".terraform.lock.hcl").write_text("public-lock-fixture")
        self.request = {
            "subscription": "cybersecurity-stg", "resource_group_name": "rg-fixture",
            "vault_name": "kv-fixture", "dry_run": True, "confirmation": "",
        }
        self.derived_state_key = "keyvault/cybersecurity-stg/kv-fixture.tfstate"
        os.environ.update(
            GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY="owner/repo",
            GITHUB_WORKFLOW_REF="owner/repo/.github/workflows/tear-down.yml@refs/heads/main",
            TEARDOWN_ENABLED="true", TEARDOWN_PHASE="plan",
            PLAN_CLIENT_ID=os.environ["ARM_CLIENT_ID"],
            TEARDOWN_CLIENT_ID="44444444-4444-4444-4444-444444444444",
            TEARDOWN_ALLOWED_STATE_KEYS=json.dumps([self.derived_state_key]),
            BACKEND_RESOURCE_GROUP_NAME="rg-state",
            ARM_USE_OIDC="true", ARM_USE_AZUREAD="true", ARM_USE_CLI="false",
            GITHUB_OUTPUT=str(Path(self.directory.name) / "outputs"),
        )
        self.update()
        self.document = {
            "version": 4, "lineage": "55555555-5555-5555-5555-555555555555", "serial": 8,
            "resources": [
                self.resource("azurerm_linux_virtual_machine", "compute", self.arm("Microsoft.Compute/virtualMachines/vm-app")),
                self.resource("azurerm_network_interface", "nic", self.arm("Microsoft.Network/networkInterfaces/nic-app"), module="module.network"),
                self.resource("azurerm_virtual_network", "vnet", self.arm("Microsoft.Network/virtualNetworks/vnet-app")),
            ],
        }

    def update(self, **changes):
        self.request.update(changes)
        os.environ["TEARDOWN_REQUEST_JSON"] = json.dumps(self.request)

    def arm(self, suffix):
        return f"{teardown.group_id()}/providers/{suffix}"

    def resource(self, kind, name, arm_id, module="module.application", **attributes):
        return {
            "module": module, "provider": teardown.PROVIDER, "mode": "managed", "type": kind, "name": name,
            "instances": [{"attributes": {"id": arm_id, **attributes}}],
        }

    def destroy_document(self):
        return {
            "complete": True,
            "resource_changes": [
                {
                    "address": teardown.address(resource, instance), "mode": "managed", "type": resource["type"],
                    "change": {"actions": ["delete"], "before": instance["attributes"], "after": None},
                }
                for resource in self.document["resources"] for instance in resource["instances"]
            ],
        }

    def real_run(self):
        self.update(dry_run=False, confirmation=self.request["vault_name"])

    def execution_phase(self):
        self.real_run()
        os.environ["TEARDOWN_PHASE"] = "destroy"
        os.environ["ARM_CLIENT_ID"] = os.environ["TEARDOWN_CLIENT_ID"]

    def prepare_artifact(self):
        self.real_run()
        teardown.prepare()
        (teardown.PIPELINE / "backend-target.json").write_text(json.dumps({"id": teardown.backend_id()}))
        (teardown.PIPELINE / "target.json").write_text(json.dumps(teardown.inspect_state(self.document)))
        (teardown.PIPELINE / "drift.json").write_text("[]")
        (teardown.PIPELINE / "destroy.tfplan").write_bytes(b"public-destroy-plan-fixture")
        teardown.seal()
        self.execution_phase()

    def test_generic_inventory_does_not_need_vault_or_module_configuration(self):
        target = teardown.inspect_state(self.document)
        self.assertEqual(len(target["resources"]), 3)
        self.assertTrue(any("virtual_machine" in address for address in target["resources"]))
        self.assertEqual(teardown.validate_plan(self.destroy_document(), target), sorted(target["resources"]))

    def test_exact_state_key_and_fixed_account(self):
        teardown.prepare()
        backend = (teardown.PIPELINE / "backend.hcl").read_text()
        self.assertIn('storage_account_name = "kvstate12790"', backend)
        self.assertIn(f'key = "{self.derived_state_key}"', backend)

    def test_subscription_choices_and_separate_generic_environments(self):
        for name in ("cybersecurity-stg", "cybersecurity-tst", "cybersecurity-prd"):
            self.update(subscription=name)
            teardown.configure()
            output = Path(os.environ["GITHUB_OUTPUT"]).read_text()
            self.assertIn(f"plan_environment=terraform-{name}-teardown-plan", output)
            self.assertIn(f"destroy_environment=terraform-{name}-teardown\n", output)
        self.update(subscription="other")
        with self.assertRaises(teardown.SafetyError):
            teardown.configure()

    def test_invalid_vault_names_are_rejected(self):
        for vault in ("kv--bad", "../kv-fixture", "kv bad", "1vault", "a" * 25):
            with self.subTest(vault=vault):
                self.update(vault_name=vault)
                with self.assertRaises(teardown.SafetyError):
                    teardown.settings()

    def test_confirmation_and_distinct_identities_are_mandatory(self):
        self.update(dry_run=False)
        with self.assertRaisesRegex(teardown.SafetyError, "confirmation"):
            teardown.settings()
        self.real_run()
        os.environ["TEARDOWN_CLIENT_ID"] = os.environ["PLAN_CLIENT_ID"]
        with self.assertRaisesRegex(teardown.SafetyError, "distinct"):
            teardown.settings()

    def test_non_main_non_dispatch_reruns_and_disabled_environments_rejected(self):
        for field, value in (
            ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_RUN_ATTEMPT", "2"), ("TEARDOWN_ENABLED", "false"),
            ("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/other.yml@refs/heads/main"),
            ("ARM_USE_OIDC", "false"), ("ARM_USE_CLI", "true"),
        ):
            with self.subTest(field=field), patch.dict(os.environ, {field: value}):
                with self.assertRaises(teardown.SafetyError):
                    teardown.settings()

    def test_dry_run_cannot_enter_destruction_phase(self):
        os.environ["TEARDOWN_PHASE"] = "destroy"
        os.environ["ARM_CLIENT_ID"] = os.environ["TEARDOWN_CLIENT_ID"]
        with self.assertRaisesRegex(teardown.SafetyError, "dry run"):
            teardown.settings()

    def test_wrong_subscription_group_provider_or_empty_state_rejected(self):
        for change in ("subscription", "group", "provider", "empty", "tainted"):
            document = copy.deepcopy(self.document)
            resource = document["resources"][0]
            if change == "subscription":
                resource["instances"][0]["attributes"]["id"] = resource["instances"][0]["attributes"]["id"].replace(os.environ["ARM_SUBSCRIPTION_ID"], os.environ["ARM_CLIENT_ID"])
            elif change == "group":
                resource["instances"][0]["attributes"]["id"] = resource["instances"][0]["attributes"]["id"].replace("rg-fixture", "rg-other")
            elif change == "provider":
                resource["provider"] += ".unconfigured_alias"
            elif change == "empty":
                document["resources"] = []
            else:
                resource["instances"][0]["status"] = "tainted"
            with self.subTest(change=change), self.assertRaises(teardown.SafetyError):
                teardown.inspect_state(document)

    def test_backend_account_children_and_containing_group_protected(self):
        os.environ["BACKEND_RESOURCE_GROUP_NAME"] = "rg-fixture"
        for kind, identity in (
            ("azurerm_storage_account", teardown.backend_id()),
            ("azurerm_storage_container", teardown.backend_id() + "/blobServices/default/containers/tfstate"),
            ("azurerm_resource_group", teardown.group_id()),
        ):
            document = {**self.document, "resources": [self.resource(kind, "backend", identity)]}
            with self.subTest(kind=kind), self.assertRaises(teardown.SafetyError):
                teardown.inspect_state(document)

    def test_tracked_workload_resource_group_is_supported(self):
        document = {**self.document, "resources": [self.resource("azurerm_resource_group", "workload", teardown.group_id())]}
        self.assertEqual(len(teardown.inspect_state(document)["resources"]), 1)

    def test_keyvault_data_plane_ownership_is_explicitly_validated(self):
        owner = self.arm("Microsoft.KeyVault/vaults/kv-fixture")
        values = {
            "id": "https://kv-fixture.vault.azure.net/secrets/password/abc123",
            "key_vault_id": owner, "resource_versionless_id": owner + "/secrets/password",
        }
        self.assertEqual(teardown.resource_identity("azurerm_key_vault_secret", values)["scope"], owner)
        values["id"] = values["id"].replace("kv-fixture.vault", "other.vault")
        with self.assertRaises(teardown.SafetyError):
            teardown.resource_identity("azurerm_key_vault_secret", values)

    def test_preflight_scopes_lookups_and_rejects_missing_blob(self):
        teardown.prepare()
        responses = [
            {"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": "cybersecurity-stg", "tenantId": os.environ["ARM_TENANT_ID"]},
            {"id": teardown.group_id()}, {"id": teardown.backend_id()}, {"exists": True},
        ]
        with patch.object(teardown, "azure", side_effect=responses) as execute:
            teardown.preflight()
        self.assertEqual(execute.call_count, 4)
        responses[-1] = {"exists": False}
        with patch.object(teardown, "azure", side_effect=responses), self.assertRaisesRegex(teardown.SafetyError, "does not exist"):
            teardown.preflight()
        responses[0]["name"] = "cybersecurity-prd"
        with patch.object(teardown, "azure", side_effect=responses), self.assertRaisesRegex(teardown.SafetyError, "display name"):
            teardown.preflight()

    def test_unmanaged_and_inherited_locks_are_not_removed(self):
        target = teardown.inspect_state(self.document)
        with patch.object(teardown, "azure", return_value={"value": []}):
            teardown.check_locks(target)
        with patch.object(teardown, "azure", return_value={"value": [{"id": teardown.group_id() + "/providers/Microsoft.Authorization/locks/admin"}]}):
            with self.assertRaisesRegex(teardown.SafetyError, "inherited or unmanaged"):
                teardown.check_locks(target)

    def test_non_destroy_new_resources_and_changed_ids_rejected(self):
        target = teardown.inspect_state(self.document)
        for change in ("update", "replace", "create", "extra", "id"):
            document = self.destroy_document()
            first = document["resource_changes"][0]
            if change in {"update", "create"}:
                first["change"]["actions"] = [change]
            elif change == "replace":
                first["change"]["actions"] = ["delete", "create"]
            elif change == "extra":
                first["address"] = "azurerm_linux_virtual_machine.untracked"
            else:
                first["change"]["before"] = {**first["change"]["before"], "id": self.arm("Microsoft.Compute/virtualMachines/other")}
            with self.subTest(change=change), self.assertRaises(teardown.SafetyError):
                teardown.validate_plan(document, target)

    def test_live_drift_reported_in_dry_run_but_blocks_real_plan(self):
        target = teardown.inspect_state(self.document)
        document = self.destroy_document()
        document["resource_drift"] = [{
            "address": document["resource_changes"][0]["address"], "change": {"actions": ["update"]},
        }]
        self.assertEqual(len(teardown.validate_plan(document, target, dry_run=True)), 3)
        with self.assertRaisesRegex(teardown.SafetyError, "drift"):
            teardown.validate_plan(document, target)

    def test_external_deletion_is_visible_not_silently_accepted(self):
        target = teardown.inspect_state(self.document)
        document = self.destroy_document()
        removed = document["resource_changes"].pop()
        document["resource_drift"] = [{"address": removed["address"], "change": {"actions": ["delete"]}}]
        self.assertEqual(len(teardown.validate_plan(document, target, dry_run=True)), 2)
        with self.assertRaises(teardown.SafetyError):
            teardown.validate_plan(document, target)

    def test_actual_drift_check_fails_without_updating_state(self):
        teardown.prepare()
        self.real_run()
        document = {"resource_drift": [{"address": "azurerm_virtual_network.vnet", "change": {"actions": ["update"]}}]}
        with patch.object(teardown, "create_plan", return_value=document), self.assertRaisesRegex(teardown.SafetyError, "Live drift"):
            teardown.drift()
        self.assertIn("Live drift detected", Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text())

    def test_matching_artifact_and_different_execution_identity_accepted(self):
        self.prepare_artifact()
        teardown.verify()

    def test_modified_artifacts_backend_run_and_state_allowlist_rejected(self):
        self.prepare_artifact()
        for field, value in (
            ("GITHUB_RUN_ID", "999"), ("BACKEND_CONTAINER", "other"),
            ("TEARDOWN_ALLOWED_STATE_KEYS", "[]"), ("ARM_TENANT_ID", os.environ["ARM_SUBSCRIPTION_ID"]),
        ):
            with self.subTest(field=field), patch.dict(os.environ, {field: value}):
                with self.assertRaises(teardown.SafetyError):
                    teardown.verify()
        (teardown.PIPELINE / "destroy.tfplan").write_bytes(b"tampered")
        with self.assertRaises(teardown.SafetyError):
            teardown.verify()

    def test_new_drift_after_approval_blocks_original_plan(self):
        self.prepare_artifact()
        with patch.object(teardown, "read_state", return_value=self.document), patch.object(teardown, "planned_document", return_value=self.destroy_document()), patch.object(teardown, "check_locks"), patch.object(teardown, "create_plan", return_value={
            "resource_drift": [{"address": "azurerm_virtual_network.vnet", "change": {"actions": ["update"]}}],
        }):
            with self.assertRaisesRegex(teardown.SafetyError, "New live drift"):
                teardown.verify_plan()

    def test_remote_state_edit_even_without_serial_change_is_rejected(self):
        self.prepare_artifact()
        document = copy.deepcopy(self.document)
        document["resources"][0]["instances"][0]["attributes"]["tags"] = {"changed": "outside-terraform"}
        with patch.object(teardown, "read_state", return_value=document), self.assertRaisesRegex(teardown.SafetyError, "state changed"):
            teardown.verify_plan()

    def test_verification_plan_does_not_replace_approved_plan(self):
        self.prepare_artifact()
        approved = self.destroy_document()
        (teardown.PIPELINE / "verification.tfplan").write_bytes(b"verification-only")
        with patch.object(teardown, "read_state", return_value=self.document), patch.object(teardown, "planned_document", return_value=approved), patch.object(teardown, "check_locks"), patch.object(teardown, "create_plan", side_effect=[{}, approved]) as execute:
            teardown.verify_plan()
        self.assertEqual(execute.call_args_list[0].args, ("recheck-drift.tfplan",))
        self.assertEqual((teardown.PIPELINE / "destroy.tfplan").read_bytes(), b"public-destroy-plan-fixture")

    def test_changed_live_attributes_even_without_drift_record_block_execution(self):
        self.prepare_artifact()
        approved = self.destroy_document()
        verification = copy.deepcopy(approved)
        verification["resource_changes"][0]["change"]["before"]["tags"] = {"changed": "after-approval"}
        with patch.object(teardown, "read_state", return_value=self.document), patch.object(teardown, "planned_document", return_value=approved), patch.object(teardown, "check_locks"), patch.object(teardown, "create_plan", side_effect=[{}, verification]):
            with self.assertRaisesRegex(teardown.SafetyError, "live attributes"):
                teardown.verify_plan()

    def test_state_values_and_provider_errors_never_logged(self):
        output = io.StringIO()
        with patch.object(teardown.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="PRIVATE-FIXTURE", stderr="PRIVATE-FIXTURE")):
            with patch("sys.argv", ["terraform-teardown.py", "state"]), contextlib.redirect_stderr(output), self.assertRaises(SystemExit):
                teardown.main()
        self.assertNotIn("PRIVATE-FIXTURE", output.getvalue())


class TeardownWorkflowTests(unittest.TestCase):
    def test_workflow_is_manual_generic_and_dry_run_first(self):
        source = (shared.REPO / ".github/workflows/tear-down.yml").read_text()
        self.assertIn("name: tear down", source)
        triggers = source.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", triggers, re.M), ["workflow_dispatch"])
        self.assertIn("options: [cybersecurity-prd, cybersecurity-stg, cybersecurity-tst]", source)
        self.assertIn("vault_name:", source)
        self.assertNotIn("state_key:", source)
        self.assertIn("Terraform/Azure/deployments/teardown", source)
        self.assertNotIn("require_approval:", source)
        self.assertNotIn("${{ inputs.", "\n".join(line for line in source.splitlines() if "run:" in line))
        destroy = source.split("\n  destroy:\n", 1)[1]
        self.assertIn("if: ${{ !inputs.dry_run }}", destroy)
        self.assertLess(destroy.index("verifyTeardownApproval"), destroy.index("uses: azure/login"))
        self.assertLess(destroy.index("verify-plan"), destroy.index(" apply -input=false"))
        self.assertNotIn("terraform destroy", destroy)
        self.assertIn(".pipeline/destroy.tfplan", destroy)
        deploy = (shared.REPO / ".github/workflows/terraform-deploy.yml").read_text()
        self.assertIn("group: terraform-deployment-AZURE", source)
        self.assertIn("group: terraform-deployment-AZURE", deploy)

    def test_provider_only_root_has_no_workload_or_variables(self):
        source = (shared.REPO / teardown.ROOT / "providers.tf").read_text()
        self.assertNotIn('module "', source)
        self.assertNotIn('resource "', source)
        self.assertNotIn("var.", source)
        self.assertIn("prevent_deletion_if_contains_resources = true", source)
        self.assertIn("purge_soft_delete_on_destroy          = false", source)

    def test_normal_keyvault_pipeline_rejects_all_deletions_and_weakened_locks(self):
        for kind, actions, after in (
            ("azurerm_key_vault", ["delete"], None),
            ("azurerm_private_endpoint", ["delete", "create"], {}),
            ("azurerm_role_assignment", ["delete"], None),
            ("azurerm_management_lock", ["update"], {"lock_level": "ReadOnly"}),
        ):
            with self.subTest(kind=kind), patch.dict(os.environ, {"STACK": "KEYVAULT", "CYBER_SUBSCRIPTION": "", "KEYVAULT_REQUEST_JSON": ""}):
                document = {"resource_changes": [{"type": kind, "change": {"actions": actions, "after": after}}]}
                with patch("sys.stdin", io.StringIO(json.dumps(document))), self.assertRaises(ValueError):
                    shared.pipeline.summarize()

    def test_managed_lock_dependencies_keep_lock_removal_first(self):
        source = (shared.REPO / "Terraform/Azure/tfm-keyvault/main.locks.tf").read_text()
        for dependency in ("azurerm_role_assignment.vault", "azurerm_role_assignment.deployment", "module.key", "module.secret"):
            self.assertIn(dependency, source)
        self.assertIn('scope      = azurerm_private_endpoint.this[each.key].id', source)
        wrapper = (shared.REPO / "Terraform/Azure/deployments/keyvault/main.tf").read_text()
        self.assertIn("deletion_protection_enabled = true", wrapper)


if __name__ == "__main__":
    unittest.main()
