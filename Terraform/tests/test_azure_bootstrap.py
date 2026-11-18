"""Offline integration tests: the real az CLI must never be called."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"
PRINCIPAL = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
MOCK_AZ = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["AZ_LOG"], "a") as stream:
    stream.write(json.dumps(args) + "\n")
def option(name):
    return args[args.index(name) + 1]
prefix = " ".join(args[:3])
if os.environ.get("FAIL_PREFIX") and prefix.startswith(os.environ["FAIL_PREFIX"]):
    sys.exit(1)
if args[:2] == ["account", "show"] and "--subscription" in args:
    print("11111111-2222-3333-4444-555555555555")
elif args[:3] == ["ad", "signed-in-user", "show"]:
    print("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
elif prefix == "role assignment list":
    print(os.environ.get("ROLE_COUNT", "0"))
elif prefix == "storage container create" and os.environ.get("RETRY_ONCE"):
    marker = Path(os.environ["AZ_LOG"] + ".retry")
    if not marker.exists():
        marker.touch()
        sys.exit(1)
elif prefix == "storage blob download":
    content = "wrong\n" if os.environ.get("CORRUPT") else "Terraform backend smoke test\n"
    Path(option("--file")).write_text(content)
"""


class AzureBootstrapTests(unittest.TestCase):
    make_directory = ROOT.parent

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.log = self.directory / "az.jsonl"
        self.config = self.directory / "backend.hcl"
        for name, content in (("az", MOCK_AZ), ("sleep", "#!/bin/sh\nexit 0\n")):
            executable = self.directory / name
            executable.write_text(content)
            executable.chmod(0o755)
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in {
                "SUBSCRIPTION_ID", "PRINCIPAL_ID", "PRINCIPAL_TYPE", "CONFIRM_SUBSCRIPTION",
                "RESOURCE_GROUP", "LOCATION", "CONTAINER_NAME", "STORAGE_ACCOUNT",
                "STATE_KEY", "BACKEND_CONFIG", "MAKEFLAGS", "MFLAGS", "MAKELEVEL",
            }
        }
        self.env.update(
            PATH=f"{self.directory}{os.pathsep}{os.environ['PATH']}",
            AZ_LOG=str(self.log),
            SUBSCRIPTION_ID=SUBSCRIPTION,
            CONFIRM_SUBSCRIPTION=SUBSCRIPTION,
            STORAGE_ACCOUNT="sttfstatetest123",
            BACKEND_CONFIG=str(self.config),
        )

    def run_target(self, target, success=True, stdin="", make_variables=(), **overrides):
        env = self.env | overrides
        result = subprocess.run(
            ["make", "--no-print-directory", target, *make_variables],
            cwd=self.make_directory,
            env=env, input=stdin, text=True, capture_output=True, timeout=15,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def calls(self, prefix=()):
        rows = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [row for row in rows if row[:len(prefix)] == list(prefix)]

    def assert_scoped(self):
        for call in self.calls():
            if call[0] in {"storage", "group", "role"}:
                self.assertIn("--subscription", call)
                self.assertEqual(call[call.index("--subscription") + 1], SUBSCRIPTION)
            if call[:2] in (["storage", "container"], ["storage", "blob"]):
                self.assertEqual(call[call.index("--auth-mode") + 1], "login")

    def test_help_does_not_call_azure(self):
        self.run_target("help")
        self.assertEqual(self.calls(), [])

    def test_login_and_subscription_prompt(self):
        self.run_target("azure-login", SUBSCRIPTION_ID="", stdin=SUBSCRIPTION + "\n")
        self.assertEqual(self.calls()[0][:1], ["login"])
        self.assertEqual(self.calls(("account", "set"))[0][-1], SUBSCRIPTION)

    def test_failed_login_does_not_select_subscription(self):
        self.run_target("azure-login", success=False, FAIL_PREFIX="login")
        self.assertEqual(self.calls(("account",)), [])

    def test_subscription_name_can_be_selected_without_login(self):
        self.run_target("azure-subscription", SUBSCRIPTION_ID="My Dev Subscription")
        self.assertEqual(self.calls(("account", "set"))[0][-1], "My Dev Subscription")
        self.assertEqual(self.calls(("login",)), [])

    def test_subscription_selection_cancelled(self):
        self.run_target("azure-subscription", success=False, SUBSCRIPTION_ID="")
        self.assertEqual(self.calls(("account", "set")), [])

    def test_mutations_require_explicit_subscription(self):
        for target in ("azure-permissions", "resource-group-create", "backend-create", "backend-test"):
            self.run_target(target, success=False, SUBSCRIPTION_ID="")
        self.assertEqual(self.calls(), [])

    def test_resource_group_create_needs_no_storage(self):
        self.run_target("resource-group-create", STORAGE_ACCOUNT="", RESOURCE_GROUP="rg-only", LOCATION="westus2")
        call = self.calls(("group", "create"))[0]
        self.assertEqual(call[call.index("--name") + 1], "rg-only")
        self.assertEqual(call[call.index("--location") + 1], "westus2")
        self.assertEqual(self.calls(("storage",)), [])
        self.assertEqual(self.calls(("role",)), [])
        self.assertFalse(self.config.exists())
        self.assert_scoped()

    def test_resource_group_confirmation_precedes_creation(self):
        self.run_target("resource-group-create", success=False, CONFIRM_SUBSCRIPTION="wrong")
        self.assertEqual(self.calls(("group",)), [])

    def test_resource_group_rejects_invalid_name(self):
        self.run_target("resource-group-create", success=False, RESOURCE_GROUP="-invalid")
        self.assertEqual(self.calls(("group",)), [])

    def test_command_line_variables_override_environment(self):
        self.run_target(
            "resource-group-create", RESOURCE_GROUP="rg-environment",
            make_variables=("RESOURCE_GROUP=rg-command-line", "LOCATION=westus2"),
        )
        call = self.calls(("group", "create"))[0]
        self.assertEqual(call[call.index("--name") + 1], "rg-command-line")
        self.assertEqual(call[call.index("--location") + 1], "westus2")

    def test_permissions_grant_all_four_roles(self):
        self.run_target("azure-permissions")
        calls = self.calls(("role", "assignment", "create"))
        self.assertEqual(len(calls), 4)
        self.assertEqual(len({call[call.index("--role") + 1] for call in calls}), 4)
        for call in calls:
            self.assertEqual(call[call.index("--scope") + 1], f"/subscriptions/{SUBSCRIPTION}")
            self.assertEqual(call[call.index("--assignee-object-id") + 1], PRINCIPAL)
        self.assert_scoped()

    def test_existing_roles_are_skipped(self):
        self.run_target("azure-permissions", ROLE_COUNT="1")
        self.assertEqual(self.calls(("role", "assignment", "create")), [])

    def test_service_principal_override_avoids_graph(self):
        self.run_target("azure-permissions", PRINCIPAL_ID=PRINCIPAL, PRINCIPAL_TYPE="ServicePrincipal")
        self.assertEqual(self.calls(("ad",)), [])
        for call in self.calls(("role", "assignment", "create")):
            self.assertEqual(call[call.index("--assignee-principal-type") + 1], "ServicePrincipal")

    def test_service_principal_requires_id(self):
        self.run_target("azure-permissions", success=False, PRINCIPAL_TYPE="ServicePrincipal")
        self.assertEqual(self.calls(("role",)), [])

    def test_permission_confirmation_rejects_wrong_subscription(self):
        self.run_target("azure-permissions", success=False, CONFIRM_SUBSCRIPTION="wrong")
        self.assertEqual(self.calls(("role",)), [])

    def test_permission_confirmation_accepts_typed_uuid(self):
        self.run_target("azure-permissions", CONFIRM_SUBSCRIPTION="", stdin=SUBSCRIPTION + "\n")
        self.assertEqual(len(self.calls(("role", "assignment", "create"))), 4)

    def test_role_failure_stops_further_grants(self):
        self.run_target("azure-permissions", success=False, FAIL_PREFIX="role assignment create")
        self.assertEqual(len(self.calls(("role", "assignment", "create"))), 1)

    def test_backend_creation_and_identical_rerun(self):
        self.run_target("backend-create")
        content = self.config.read_text()
        self.assertIn('use_azuread_auth = true', content)
        self.assertIn('container_name = "tfstate"', content)
        self.assertIn(f'subscription_id = "{SUBSCRIPTION}"', content)
        create = self.calls(("storage", "account", "create"))[0]
        for flag in ("--allow-shared-key-access", "--allow-blob-public-access"):
            self.assertEqual(create[create.index(flag) + 1], "false")
        self.run_target("backend-create")
        self.assertEqual(self.config.read_text(), content)
        self.assert_scoped()

    def test_backend_config_is_not_overwritten(self):
        self.config.write_text("existing backend\n")
        self.run_target("backend-create", success=False)
        self.assertEqual(self.config.read_text(), "existing backend\n")
        self.assertEqual(self.calls(("group",)), [])

    def test_backend_input_validation(self):
        for overrides in (
            {"STORAGE_ACCOUNT": ""},
            {"STORAGE_ACCOUNT": "Invalid_Name"},
            {"CONTAINER_NAME": "bad--container"},
            {"CONTAINER_NAME": "UPPER"},
            {"RESOURCE_GROUP": "-invalid"},
        ):
            self.run_target("backend-create", success=False, **overrides)
        self.assertEqual(self.calls(("group",)), [])

    def test_backend_confirmation_precedes_creation(self):
        self.run_target("backend-create", success=False, CONFIRM_SUBSCRIPTION="wrong")
        self.assertEqual(self.calls(("group",)), [])

    def test_failed_container_creation_retries_without_config(self):
        self.run_target("backend-create", success=False, FAIL_PREFIX="storage container create")
        self.assertEqual(len(self.calls(("storage", "container", "create"))), 6)
        self.assertFalse(self.config.exists())

    def test_transient_failure_is_retried(self):
        self.run_target("backend-create", RETRY_ONCE="1")
        self.assertEqual(len(self.calls(("storage", "container", "create"))), 2)
        self.assertTrue(self.config.exists())

    def test_backend_overrides_and_hcl_interpolation_escaping(self):
        self.run_target(
            "backend-create", RESOURCE_GROUP="rg-custom", LOCATION="westus2",
            CONTAINER_NAME="custom-state", STATE_KEY='test/${not-an-expression}/%{literal}.tfstate',
        )
        self.assertIn('resource_group_name = "rg-custom"', self.config.read_text())
        self.assertIn('$${not-an-expression}', self.config.read_text())
        self.assertIn('%%{literal}', self.config.read_text())

    def test_backend_smoke_test_isolated_blob_and_cleanup(self):
        self.run_target("backend-test")
        blobs = self.calls(("storage", "blob"))
        self.assertEqual([call[2] for call in blobs], ["upload", "download", "delete"])
        names = {call[call.index("--name") + 1] for call in blobs}
        self.assertEqual(len(names), 1)
        self.assertTrue(next(iter(names)).startswith("_bootstrap-tests/"))
        self.assertTrue(next(iter(names)).endswith(".txt"))
        upload = blobs[0]
        self.assertEqual(upload[upload.index("--overwrite") + 1], "false")
        self.assert_scoped()
        self.assertFalse(self.config.exists())

    def test_download_failure_cleans_up(self):
        self.run_target("backend-test", success=False, FAIL_PREFIX="storage blob download")
        self.assertEqual(len(self.calls(("storage", "blob", "delete"))), 1)

    def test_content_mismatch_cleans_up(self):
        self.run_target("backend-test", success=False, CORRUPT="1")
        self.assertEqual(len(self.calls(("storage", "blob", "delete"))), 1)

    def test_cleanup_failure_is_reported(self):
        result = self.run_target("backend-test", success=False, FAIL_PREFIX="storage blob delete")
        self.assertIn("Could not clean up temporary blob", result.stderr)


class TerraformDirectoryTests(AzureBootstrapTests):
    """Run the same checks inside Terraform/ to preserve existing usage."""

    make_directory = ROOT


if __name__ == "__main__":
    unittest.main()
