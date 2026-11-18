import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pipeline = load("pipeline", REPO / ".github/scripts/terraform-pipeline.py")
request = load("request", REPO / ".github/scripts/request-privatelink.py")
editor = load("editor", request.EDITOR)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.directory.name)
        self.addCleanup(os.chdir, self.previous)
        self.root = Path(pipeline.ROOTS["KEYVAULT"])
        self.root.mkdir(parents=True)
        (self.root / ".terraform.lock.hcl").write_text("public-lock-fixture")
        self.env = {
            "STACK": "KEYVAULT",
            "TF_ROOT": str(self.root),
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "TF_VERSION": "1.16.0",
            "ARM_CLIENT_ID": "11111111-1111-1111-1111-111111111111",
            "ARM_TENANT_ID": "22222222-2222-2222-2222-222222222222",
            "ARM_SUBSCRIPTION_ID": "33333333-3333-3333-3333-333333333333",
            "BACKEND_ACCOUNT": "stpublicfixture",
            "BACKEND_CONTAINER": "tfstate",
            "TFVARS_JSON": json.dumps({"vault_name": "kv-public-fixture", "resource_group_name": "rg-fixture"}),
            "GITHUB_STEP_SUMMARY": str(Path(self.directory.name) / "summary"),
            "EXPECTED_ARTIFACT_DIGEST": "b" * 64,
        }
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def saved_plan(self):
        pipeline.prepare()
        (self.root / ".pipeline/deployment.tfplan").write_bytes(b"public-plan-fixture")
        pipeline.manifest()

    def test_blob_backend_uses_separate_key(self):
        pipeline.prepare()
        backend = (self.root / ".pipeline/backend.hcl").read_text()
        self.assertIn('storage_account_name = "stpublicfixture"', backend)
        self.assertIn('container_name = "tfstate"', backend)
        self.assertIn('key = "keyvault/deployment.tfstate"', backend)
        self.assertNotEqual(pipeline.STATE_KEYS["KEYVAULT"], pipeline.STATE_KEYS["PRIVATELINK"])
        self.assertNotIn("client", backend)

    def test_oidc_rejects_legacy_credentials(self):
        os.environ["ARM_CLIENT_SECRET"] = "public-test-fixture-not-a-credential"
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_missing_required_configuration(self):
        del os.environ["BACKEND_CONTAINER"]
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_zero_client_id_rejected(self):
        os.environ["ARM_CLIENT_ID"] = pipeline.ZERO_UUID
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_branch_restriction(self):
        os.environ["GITHUB_REF"] = "refs/pull/1/merge"
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_secret_inputs_not_supported(self):
        os.environ["TFVARS_JSON"] = json.dumps({"secret_values": {"password": "public-test-fixture"}})
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_placeholder_rejected(self):
        os.environ["TFVARS_JSON"] = json.dumps({"vault_name": "YOUR_VAULT", "resource_group_name": "rg"})
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_unclean_runner_rejected(self):
        (self.root / ".terraform").mkdir()
        with self.assertRaises(ValueError):
            pipeline.prepare()

    def test_matching_manifest_accepted_with_different_apply_identity(self):
        self.saved_plan()
        os.environ["ARM_CLIENT_ID"] = "44444444-4444-4444-4444-444444444444"
        pipeline.verify()

    def test_modified_plan_rejected(self):
        self.saved_plan()
        (self.root / ".pipeline/deployment.tfplan").write_bytes(b"modified")
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_modified_backend_rejected(self):
        self.saved_plan()
        (self.root / ".pipeline/backend.hcl").write_text("modified")
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_cross_run_rejected(self):
        self.saved_plan()
        os.environ["GITHUB_RUN_ID"] = "456"
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_changed_provider_lock_rejected(self):
        self.saved_plan()
        (self.root / ".terraform.lock.hcl").write_text("modified")
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_cross_attempt_rejected(self):
        self.saved_plan()
        os.environ["GITHUB_RUN_ATTEMPT"] = "2"
        with self.assertRaises(ValueError):
            pipeline.verify()

    def test_summary_omits_resource_values(self):
        plan = {
            "resource_changes": [{
                "address": "azurerm_key_vault.fixture",
                "change": {"actions": ["create"], "after": {"value": "PUBLIC-SENSITIVE-FIXTURE"}},
            }],
            "output_changes": {"value": {"after": "PUBLIC-SENSITIVE-FIXTURE"}},
        }
        with patch("sys.stdin", io.StringIO(json.dumps(plan))):
            pipeline.summarize()
        summary = Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text()
        self.assertIn("azurerm_key_vault.fixture", summary)
        self.assertNotIn("PUBLIC-SENSITIVE-FIXTURE", summary)

    def test_dry_run_summary_explicitly_disables_apply(self):
        os.environ["DRY_RUN"] = "true"
        with patch("sys.stdin", io.StringIO('{"resource_changes": []}')):
            pipeline.summarize()
        self.assertIn("DRY RUN: apply is disabled", Path(os.environ["GITHUB_STEP_SUMMARY"]).read_text())


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.content = (request.EDITOR.parent.parent / "terraform.tfvars").read_text()

    def test_no_selection_rejected(self):
        with self.assertRaises(ValueError):
            request.update({}, editor, self.content)

    def test_zone_injection_rejected(self):
        with self.assertRaises(ValueError):
            request.update({"add_dns_zone": True, "zone_key": "$(touch injected)", "zone_suffix": "blob.core.windows.net"}, editor, self.content)

    def test_hcl_expression_rejected(self):
        with self.assertRaises(ValueError):
            request.update({"add_dns_zone": True, "zone_key": "fixture", "zone_suffix": '${file("sensitive")}'}, editor, self.content)

    def test_invalid_address_rejected(self):
        with self.assertRaises(ValueError):
            request.update({
                "add_dns_records": True,
                "dns_records_json": json.dumps([{"key": "fixture", "zone": "privatelink.blob.core.windows.net", "name": "fixture", "ips": "not-an-ip"}]),
            }, editor, self.content)

    def test_multiple_records_and_spokes_remain_valid_hcl(self):
        values = {
            "add_dns_zone": True,
            "zone_key": "test_storage",
            "zone_suffix": "blob.core.windows.net",
            "add_dns_records": True,
            "dns_records_json": json.dumps([
                {"key": "fixture1", "zone": "privatelink.blob.core.windows.net", "name": "one", "ips": "10.0.0.1"},
                {"key": "fixture2", "zone": "privatelink.blob.core.windows.net", "name": "two", "ips": "10.0.0.2"},
            ]),
            "add_spoke": True,
            "spoke_key": "fixture_spoke",
            "spoke_vnet_id": "/subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-fixture/providers/Microsoft.Network/virtualNetworks/vnet-fixture",
            "spoke_vnet_name": "vnet-fixture",
            "spoke_rg": "rg-fixture",
        }
        with contextlib.redirect_stdout(io.StringIO()):
            result = request.update(values, editor, self.content)
            result = editor.add_spoke(result, "second_spoke", values["spoke_vnet_id"], "vnet-fixture", "rg-fixture")
            self.assertEqual(result, editor.add_spoke(result, "second_spoke", values["spoke_vnet_id"], "vnet-fixture", "rg-fixture"))
        self.assertEqual(result.count("fixture2 = {"), 1)
        self.assertIn("second_spoke", result)
        # fmt parses HCL without Azure credentials, providers, or backend access.
        completed = subprocess.run(["terraform", "fmt", "-"], input=result, text=True, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)


class WorkflowTests(unittest.TestCase):
    def test_ci_does_not_get_oidc_or_self_hosted_runners(self):
        source = (REPO / ".github/workflows/terraform-checks.yml").read_text()
        self.assertNotIn("id-token: write", source)
        self.assertNotIn("self-hosted", source)
        self.assertIn("init -backend=false", source)

    def test_deploy_requires_approval_and_saved_plan(self):
        source = (REPO / ".github/workflows/terraform-deploy.yml").read_text()
        self.assertIn("required_reviewers", source)
        self.assertIn("prevent_self_review", source)
        self.assertIn("needs: plan", source)
        self.assertIn("cancel-in-progress: false", source)
        self.assertIn("needs.plan.outputs.changed == 'true' && !inputs.dry_run", source)
        self.assertIn("apply -input=false -no-color -lock-timeout=5m .pipeline/deployment.tfplan", source)
        self.assertIn("ARM_USE_OIDC:", source)
        self.assertIn("ARM_USE_AZUREAD:", source)
        self.assertNotIn("secrets.ARM_CLIENT_SECRET", source)


if __name__ == "__main__":
    unittest.main()
