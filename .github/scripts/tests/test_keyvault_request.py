"""Offline request/preflight tests; subprocess Azure calls are always mocked."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_pipeline as shared


pipeline = shared.pipeline


class CyberRequestTests(unittest.TestCase):
    def setUp(self):
        shared.PipelineTests.setUp(self)
        self.request = {
            "subscription": "cyber-prd",
            "vault_name": "kv-cyber-request",
            "resource_group_name": "rg-cyber-test",
            "sku_name": "standard",
            "purge_protection_enabled": True,
            "soft_delete_retention_days": 90,
            "private_endpoints_json": "{}",
            "role_assignments_json": "{}",
            "tags_json": "{}",
            "dry_run": True,
        }
        os.environ.update(
            CYBER_SUBSCRIPTION="cyber-prd", DRY_RUN="true", DEPLOY_ENABLED="true",
            GITHUB_OUTPUT=str(Path(self.directory.name) / "output"),
        )
        self.update_request()

    def update_request(self, **changes):
        self.request.update(changes)
        os.environ["KEYVAULT_REQUEST_JSON"] = json.dumps(self.request)

    def azure_results(self):
        subscription = os.environ["ARM_SUBSCRIPTION_ID"]
        name = self.request["resource_group_name"]
        return [
            {"id": subscription, "name": self.request["subscription"]},
            {"id": f"/subscriptions/{subscription}/resourceGroups/{name}", "name": name},
        ]

    def preflight(self, responses=None):
        results = self.azure_results() if responses is None else responses
        with patch.object(pipeline.subprocess, "run", side_effect=[
            SimpleNamespace(stdout=json.dumps(value)) for value in results
        ]) as execute, contextlib.redirect_stdout(io.StringIO()):
            pipeline.azure_preflight()
        return execute

    def saved_plan(self):
        shared.PipelineTests.saved_plan(self)

    def test_defaults_and_normalization(self):
        self.update_request(vault_name="KV-Cyber-Request")
        values = pipeline.request_values()
        self.assertEqual(values["vault_name"], "kv-cyber-request")
        self.assertNotIn("location", values)
        self.assertEqual(values["soft_delete_retention_days"], 90)

    def test_approval_control_is_accepted_in_configuration(self):
        for required in (True, False):
            with self.subTest(require_approval=required):
                os.environ["REQUIRE_APPROVAL"] = "true" if required else "false"
                self.update_request(require_approval=required)
                pipeline.configure()
                self.assertIn(
                    "plan_environment=keyvault-cyber-prd-plan\n",
                    Path(os.environ["GITHUB_OUTPUT"]).read_text(),
                )
                self.assertNotIn("require_approval", pipeline.request_values())

    def test_missing_approval_control_remains_backwards_compatible(self):
        self.assertNotIn("require_approval", self.request)
        self.assertNotIn("require_approval", pipeline.request_values())

    def test_approval_control_rejects_non_boolean_values(self):
        for value in ("true", "false", 1, 0, None, [], {}):
            with self.subTest(value=value):
                self.update_request(require_approval=value)
                with self.assertRaisesRegex(ValueError, "require_approval must be a boolean"):
                    pipeline.request_values()

    def test_approval_control_must_match_reusable_workflow_input(self):
        for required in (True, False):
            with self.subTest(require_approval=required):
                os.environ["REQUIRE_APPROVAL"] = "false" if required else "true"
                self.update_request(require_approval=required)
                with self.assertRaisesRegex(ValueError, "Dispatch approval setting"):
                    pipeline.configure()

    def test_approval_control_is_not_written_to_terraform_inputs(self):
        self.update_request(require_approval=True)
        os.environ["REQUIRE_APPROVAL"] = "true"
        pipeline.prepare()
        values = json.loads((self.root / ".pipeline/inputs.tfvars.json").read_text())
        self.assertNotIn("require_approval", values)
        self.assertNotIn("dry_run", values)

    def test_dispatch_number_input_is_normalized_from_string(self):
        self.update_request(soft_delete_retention_days="90")
        values = pipeline.request_values()
        self.assertEqual(values["soft_delete_retention_days"], 90)

    def test_all_cyber_subscriptions_map_to_fixed_configuration(self):
        for subscription, environment in pipeline.CYBER_ENVIRONMENTS.items():
            with self.subTest(subscription=subscription):
                os.environ["CYBER_SUBSCRIPTION"] = subscription
                self.update_request(subscription=subscription)
                pipeline.configure()
                source = Path(os.environ["GITHUB_OUTPUT"]).read_text()
                self.assertIn(f"plan_environment={environment}-plan\n", source)
                self.assertIn(f"apply_environment={environment}-plan\n", source)

    def test_unknown_and_mismatched_subscriptions_fail(self):
        for subscription in ("other-prd", "cyber-prd\nprefix=KEYVAULT", "cyber-dev"):
            with self.subTest(subscription=subscription):
                os.environ["CYBER_SUBSCRIPTION"] = subscription
                with self.assertRaises(ValueError):
                    pipeline.configure()

    def test_request_cannot_use_private_link_stack(self):
        os.environ["STACK"] = "PRIVATELINK"
        with self.assertRaises(ValueError):
            pipeline.request_values()

    def test_missing_request_and_selector_fail_closed(self):
        os.environ["KEYVAULT_REQUEST_JSON"] = ""
        with self.assertRaises(ValueError):
            pipeline.request_values()
        os.environ["KEYVAULT_REQUEST_JSON"] = json.dumps(self.request)
        os.environ["CYBER_SUBSCRIPTION"] = ""
        with self.assertRaises(ValueError):
            pipeline.request_values()

    def test_invalid_names_and_regions_are_rejected(self):
        for field, value in (
            ("vault_name", "kv--bad"), ("vault_name", "$(touch injected)"),
            ("vault_name", "a" * 25), ("vault_name", "1vault"),
            ("resource_group_name", "/subscriptions/other/resourceGroups/rg"),
            ("resource_group_name", "rg; touch injected"), ("resource_group_name", "rg."),
            ("location", "eastus2"), ("secret_values", {"password": "not-a-secret"}),
        ):
            with self.subTest(field=field):
                original = self.request.copy()
                self.update_request(**{field: value})
                with self.assertRaises(ValueError):
                    pipeline.request_values()
                self.request = original
                self.update_request()

    def test_boolean_sku_and_retention_validation(self):
        for field, value in (
            ("sku_name", "free"), ("purge_protection_enabled", "false"),
            ("dry_run", "false"), ("soft_delete_retention_days", True),
            ("soft_delete_retention_days", 6), ("soft_delete_retention_days", 91),
            ("soft_delete_retention_days", 7.5), ("soft_delete_retention_days", "not-a-number"),
            ("soft_delete_retention_days", "90.5"),
        ):
            with self.subTest(field=field, value=value):
                original = self.request.copy()
                self.update_request(**{field: value})
                with self.assertRaises(ValueError):
                    pipeline.request_values()
                self.request = original
                self.update_request()

    def test_dry_run_mode_must_match_dispatch(self):
        self.update_request(dry_run=False)
        with self.assertRaises(ValueError):
            pipeline.request_values()
        os.environ["DRY_RUN"] = "false"
        self.assertIsNotNone(pipeline.request_values())

    def test_json_fields_require_objects_and_typed_values(self):
        for changes in (
            {"tags_json": "[]"}, {"tags_json": '{"owner": 42}'},
            {"role_assignments_json": '{"app":{"principal_id":"bad"}}'},
            {"private_endpoints_json": '{"endpoint":{"name":"pe","subnet_id":"bad"}}'},
            {"private_endpoints_json": '{"endpoint":{"name":"pe","unexpected":true}}'},
        ):
            original = self.request.copy()
            self.update_request(**changes)
            with self.assertRaises(ValueError):
                pipeline.request_values()
            self.request = original
            self.update_request()

    def test_typed_endpoint_roles_and_tags_are_preserved(self):
        subscription = os.environ["ARM_SUBSCRIPTION_ID"]
        base = f"/subscriptions/{subscription}/resourceGroups/rg-network/providers/Microsoft.Network"
        endpoints = {"app": {
            "name": "pe-vault", "subnet_id": f"{base}/virtualNetworks/vnet/subnets/private",
            "resource_group_name": "rg-network", "location": "westus2",
            "private_dns_zone_ids": [f"{base}/privateDnsZones/privatelink.vaultcore.azure.net"],
            "tags": {"owner": "platform"},
        }}
        roles = {"app": {
            "principal_id": os.environ["ARM_CLIENT_ID"],
            "role_definition_name": "Key Vault Secrets User", "principal_type": "ServicePrincipal",
        }}
        self.update_request(
            private_endpoints_json=json.dumps(endpoints),
            role_assignments_json=json.dumps(roles), tags_json='{"environment":"prd"}',
        )
        values = pipeline.request_values()
        self.assertEqual(values["private_endpoints"], endpoints)
        self.assertEqual(values["role_assignments"], roles)
        self.assertEqual(values["tags"], {"environment": "prd"})

    def test_subscription_and_group_checks_are_explicitly_scoped(self):
        execute = self.preflight()
        self.assertEqual(execute.call_count, 2)
        for call in execute.call_args_list:
            args = call.args[0]
            self.assertEqual(args[args.index("--subscription") + 1], os.environ["ARM_SUBSCRIPTION_ID"])
            self.assertTrue(call.kwargs["check"])
            self.assertNotIn("shell", call.kwargs)

    def test_wrong_account_uuid_fails_before_group_lookup(self):
        replacement = {"id": os.environ["ARM_CLIENT_ID"], "name": "cyber-prd"}
        with self.assertRaises(pipeline.SubscriptionMismatchError):
            self.preflight([replacement])

    def test_wrong_account_name_is_rejected_even_when_uuid_matches(self):
        for actual_name in ("cyber-dev", "cyber-tst", "Azure subscription 1", "cyber-prd-copy", "", None):
            with self.subTest(actual_name=actual_name):
                replacement = {"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": actual_name}
                with self.assertRaisesRegex(pipeline.SubscriptionMismatchError, "workflow_dispatch selected cyber-prd"):
                    self.preflight([replacement])

    def test_every_dispatch_choice_requires_the_actual_subscription_name(self):
        for selected in pipeline.CYBER_ENVIRONMENTS:
            with self.subTest(subscription=selected):
                os.environ["CYBER_SUBSCRIPTION"] = selected
                self.update_request(subscription=selected)
                execute = self.preflight()
                self.assertEqual(execute.call_count, 2)
                wrong = "cyber-tst" if selected != "cyber-tst" else "cyber-prd"
                with self.assertRaises(pipeline.SubscriptionMismatchError):
                    self.preflight([{"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": wrong}])

    def test_subscription_name_matching_is_case_insensitive(self):
        responses = self.azure_results()
        responses[0]["name"] = "CYBER-PRD"
        self.assertEqual(self.preflight(responses).call_count, 2)

    def test_subscription_name_mismatch_stops_before_group_lookup(self):
        account = {"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": "Azure subscription 1"}
        with patch.object(pipeline.subprocess, "run", return_value=SimpleNamespace(
            stdout=json.dumps(account),
        )) as execute:
            with self.assertRaises(pipeline.SubscriptionMismatchError):
                pipeline.azure_preflight()
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(execute.call_args.args[0][1:3], ["account", "show"])

    def test_subscription_mismatch_cannot_be_bypassed_by_disabling_approval(self):
        os.environ["REQUIRE_APPROVAL"] = "false"
        os.environ["DRY_RUN"] = "false"
        self.update_request(require_approval=False, dry_run=False)
        account = {"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": "Azure subscription 1"}
        with self.assertRaises(pipeline.SubscriptionMismatchError):
            self.preflight([account])

    def test_subscription_mismatch_is_actionable_in_workflow_error(self):
        account = {"id": os.environ["ARM_SUBSCRIPTION_ID"], "name": "Azure subscription 1"}
        errors = io.StringIO()
        with patch.object(pipeline.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(account))):
            with patch("sys.argv", ["terraform-pipeline.py", "azure-preflight"]), contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as exited:
                    pipeline.main()
        self.assertEqual(exited.exception.code, 1)
        message = errors.getvalue()
        self.assertIn("workflow_dispatch selected cyber-prd", message)
        self.assertIn("Azure subscription 1", message)
        self.assertIn("SUBSCRIPTION_ID", message)
        self.assertIn("No fallback subscription", message)

    def test_group_from_another_subscription_is_rejected(self):
        responses = self.azure_results()
        responses[1]["id"] = responses[1]["id"].replace(
            os.environ["ARM_SUBSCRIPTION_ID"], os.environ["ARM_CLIENT_ID"],
        )
        with self.assertRaises(ValueError):
            self.preflight(responses)

    def test_missing_or_inaccessible_group_fails(self):
        with patch.object(pipeline.subprocess, "run", side_effect=[
            SimpleNamespace(stdout=json.dumps(self.azure_results()[0])),
            subprocess.CalledProcessError(3, ["az", "group", "show"]),
        ]):
            with self.assertRaises(subprocess.CalledProcessError):
                pipeline.azure_preflight()

    def test_enabled_flag_is_required_even_for_dry_run(self):
        os.environ["DEPLOY_ENABLED"] = "false"
        with self.assertRaises(ValueError):
            pipeline.prepare()
        self.assertFalse((self.root / ".pipeline").exists())

    def test_request_values_replace_legacy_variables_and_isolate_state(self):
        os.environ["TFVARS_JSON"] = "invalid legacy input is ignored"
        pipeline.prepare()
        backend = (self.root / ".pipeline/backend.hcl").read_text()
        self.assertIn('key = "keyvault/cyber-prd/kv-cyber-request.tfstate"', backend)
        values = json.loads((self.root / ".pipeline/inputs.tfvars.json").read_text())
        self.assertEqual(values["resource_group_name"], "rg-cyber-test")
        self.assertNotIn("location", values)

    def test_different_vaults_have_different_provenance(self):
        first = pipeline.provenance()
        self.update_request(vault_name="kv-another-request")
        self.assertNotEqual(first, pipeline.provenance())

    def test_saved_plan_cannot_be_reused_for_different_request(self):
        self.saved_plan()
        self.update_request(resource_group_name="rg-another-cyber-group")
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_unchanged_request_allows_separate_apply_identity(self):
        self.saved_plan()
        os.environ["ARM_CLIENT_ID"] = "44444444-4444-4444-4444-444444444444"
        pipeline.verify()

    def test_summary_reports_create_update_or_no_vault_changes(self):
        for actions, expected in ((["create"], "create"), (["update"], "update"), (["no-op"], "no vault changes")):
            plan = {"resource_changes": [{
                "address": "module.keyvault.azurerm_key_vault.this",
                "type": "azurerm_key_vault", "change": {"actions": actions},
            }]}
            with patch("sys.stdin", io.StringIO(json.dumps(plan))):
                pipeline.summarize()
            summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
            self.assertIn(f"Vault plan result: **{expected}**", summary)
            self.assertIn("westus2", summary)
            self.assertIn("DRY RUN: apply is disabled", summary)

    def test_delete_and_replacement_plans_are_rejected(self):
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            plan = {"resource_changes": [{
                "type": "azurerm_key_vault", "change": {"actions": actions},
            }]}
            with patch("sys.stdin", io.StringIO(json.dumps(plan))):
                with self.assertRaises(ValueError):
                    pipeline.summarize()


class CyberWorkflowTests(unittest.TestCase):
    def test_terraform_commands_are_separate_visible_steps(self):
        checks = (shared.REPO / ".github/workflows/terraform-checks.yml").read_text()
        for label in (
            "Terraform format check", "Terraform init (offline backend)",
            "Terraform validate", "Terraform test",
        ):
            self.assertIn(label, checks)
        deploy = (shared.REPO / ".github/workflows/terraform-deploy.yml").read_text()
        labels = [
            'name: "Terraform check:', 'name: "Terraform init: OIDC',
            'name: "Terraform validate:', 'name: "Terraform plan:',
            "name: Require an actual hvaandres approval", 'name: "Terraform apply:',
        ]
        positions = [deploy.index(label) for label in labels]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("terraform check\n", deploy)
        self.assertNotIn("az keyvault create", deploy)

    def test_dispatch_has_only_cyber_choices_and_safe_defaults(self):
        source = (shared.REPO / ".github/workflows/ci-keyvault.yml").read_text()
        self.assertIn("workflow_dispatch:", source)
        self.assertIn("default: cyber-prd", source)
        self.assertIn("dry_run:", source)
        self.assertIn("require_approval:", source)
        self.assertIn("default: false", source.split("require_approval:\n", 1)[1])
        self.assertIn("default: true", source.split("dry_run:\n", 1)[1])
        self.assertIn("&& toJSON(inputs) || ''", source)
        self.assertNotRegex(source, r"(?m)^\s+run:\s*\$\{\{")
        self.assertNotIn("secrets.", source)

    def test_preflight_precedes_backend_and_is_repeated_after_approval(self):
        source = (shared.REPO / ".github/workflows/terraform-deploy.yml").read_text()
        self.assertEqual(source.count("terraform-pipeline.py azure-preflight"), 2)
        self.assertGreaterEqual(source.count('["ubuntu-latest"]'), 2)
        self.assertNotIn('["self-hosted","linux","azure-terraform"]', source)
        self.assertLess(source.index("terraform-pipeline.py prepare"), source.index("uses: azure/login@v2"))
        self.assertLess(source.index("terraform-pipeline.py azure-preflight"), source.index("init -input=false"))
        apply = source.split("\n  apply:\n", 1)[1]
        self.assertLess(apply.index("terraform-pipeline.py azure-preflight"), apply.index("init -input=false"))
        self.assertLess(apply.index("terraform-pipeline.py azure-preflight"), apply.index("apply -input=false"))
        self.assertIn("needs.plan.outputs.changed == 'true' && !inputs.dry_run", source)
        self.assertIn("name: ${{ needs.configuration.outputs.apply_environment }}", source)
        self.assertIn("terraform-pipeline.py verify", source)
        self.assertIn("vars.PLAN_CLIENT_ID", source)
        self.assertIn("vars.APPLY_CLIENT_ID", source)
        self.assertIn("vars.TENANT_ID", source)
        self.assertIn("vars.SUBSCRIPTION_ID", source)
        self.assertNotIn("CYBER_DEV_KEYVAULT_", source)

    def test_configuration_receives_the_actual_approval_control(self):
        source = (shared.REPO / ".github/workflows/terraform-deploy.yml").read_text()
        global_env = source.split("\nenv:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn(
            "REQUIRE_APPROVAL: ${{ inputs.require_approval && 'true' || 'false' }}",
            global_env,
        )

    def test_network_resource_requests_require_named_approval_before_pr_creation(self):
        source = (shared.REPO / ".github/workflows/add-resource-privatelink.yml").read_text()
        self.assertIn("needs: validate", source)
        self.assertIn("name: resource-request-approval", source)
        self.assertIn("gate.verifyProtection", source)
        self.assertLess(source.index("gate.verifyApproval"), source.index("peter-evans/create-pull-request"))


if __name__ == "__main__":
    unittest.main()
