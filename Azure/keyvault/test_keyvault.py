"""Offline tests: all Azure clients are mocked; no real credentials are read."""

import argparse
import io
import json
import os
import stat
import tempfile
import unittest
import warnings
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

import keyvault_common as kv

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION = "33333333-3333-3333-3333-333333333333"
VALUE = "synthetic-test-value\nsecond line\n\n"
IDS = ["--tenant-id", TENANT, "--client-id", CLIENT]


class KeyVaultTests(unittest.TestCase):
    def setUp(self):
        # Ensure tests never consume a real credential or contact Azure.
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.credential_patch = patch.object(kv, "ClientSecretCredential")
        self.credential_class = self.credential_patch.start()
        self.addCleanup(self.credential_patch.stop)
        self.prompt_patch = patch.object(
            kv.getpass, "getpass", return_value="fake-client-secret"
        )
        self.prompt = self.prompt_patch.start()
        self.addCleanup(self.prompt_patch.stop)
        self.secret_patch = patch.object(kv, "SecretClient")
        self.secret_class = self.secret_patch.start()
        self.addCleanup(self.secret_patch.stop)
        self.client = self.secret_class.return_value.__enter__.return_value
        self.client.get_secret.return_value = SimpleNamespace(value=VALUE)
        self.client.list_properties_of_secrets.return_value = []
        self.subscription_patch = patch.object(kv, "SubscriptionClient")
        self.subscription_class = self.subscription_patch.start()
        self.addCleanup(self.subscription_patch.stop)
        self.subscriptions = (
            self.subscription_class.return_value.__enter__.return_value.subscriptions
        )
        self.subscription = SimpleNamespace(
            display_name="Development",
            subscription_id=SUBSCRIPTION,
            state="Enabled",
        )
        self.subscriptions.get.return_value = self.subscription
        self.subscriptions.list.return_value = [self.subscription]
        self.manager_patch = patch.object(kv, "KeyVaultManagementClient")
        self.manager_class = self.manager_patch.start()
        self.addCleanup(self.manager_patch.stop)
        self.manager = self.manager_class.return_value.__enter__.return_value
        self.manager.vaults.get.return_value = SimpleNamespace(
            properties=SimpleNamespace(vault_uri="https://demo-vault.vault.azure.net/")
        )

    def invoke(self, action, extra=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = kv.main(action, IDS + list(extra))
        return result, stdout.getvalue(), stderr.getvalue()

    def test_login_only_requests_token_without_outputting_it(self):
        credential = self.credential_class.return_value.__enter__.return_value
        credential.get_token.return_value = SimpleNamespace(token=VALUE)
        result, output, error = self.invoke("login")
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output)["authenticated"])
        self.assertNotIn(VALUE, output + error)
        credential.get_token.assert_called_once_with(kv.ARM_SCOPE)
        self.subscriptions.list.assert_not_called()

    def test_hidden_prompt_uses_explicit_service_principal(self):
        self.invoke("login")
        self.prompt.assert_called_once()
        self.credential_class.assert_called_once_with(
            tenant_id=TENANT,
            client_id=CLIENT,
            client_secret="fake-client-secret",
            logging_enable=False,
        )

    def test_environment_credential_does_not_prompt_and_is_removed_in_process(self):
        os.environ["AZURE_CLIENT_SECRET"] = "fake-injected-secret"
        self.invoke("login")
        self.prompt.assert_not_called()
        self.assertNotIn("AZURE_CLIENT_SECRET", os.environ)

    def test_empty_credential_is_rejected(self):
        os.environ["AZURE_CLIENT_SECRET"] = ""
        result, _, error = self.invoke("login")
        self.assertEqual(result, 1)
        self.assertIn("must not be empty", error)
        self.credential_class.assert_not_called()

    def test_prompt_fails_closed_if_echo_cannot_be_disabled(self):
        def unsafe_prompt(*_):
            warnings.warn("No echo control", kv.getpass.GetPassWarning)
            return "should-not-be-used"

        self.prompt.side_effect = unsafe_prompt
        result, _, error = self.invoke("login")
        self.assertEqual(result, 1)
        self.assertIn("No hidden terminal", error)
        self.credential_class.assert_not_called()

    def test_authentication_error_does_not_leak_response(self):
        credential = self.credential_class.return_value.__enter__.return_value
        credential.get_token.side_effect = ClientAuthenticationError(message=VALUE)
        result, output, error = self.invoke("login")
        self.assertEqual(result, 1)
        self.assertNotIn(VALUE, output + error)
        self.assertIn("Authentication failed", error)

    def test_subscription_uuid_uses_direct_lookup(self):
        result = kv.resolve_subscription(MagicMock(), SUBSCRIPTION)
        self.assertEqual(result.subscription_id, SUBSCRIPTION)
        self.subscriptions.get.assert_called_once_with(SUBSCRIPTION)
        self.subscriptions.list.assert_not_called()

    def test_subscription_name_is_resolved(self):
        self.assertEqual(
            kv.resolve_subscription(MagicMock(), "Development").subscription_id,
            SUBSCRIPTION,
        )

    def test_duplicate_subscription_names_are_rejected(self):
        self.subscriptions.list.return_value = [self.subscription, self.subscription]
        with self.assertRaisesRegex(kv.SafeError, "ambiguous"):
            kv.resolve_subscription(MagicMock(), "Development")

    def test_missing_subscription_name_is_rejected(self):
        with self.assertRaisesRegex(kv.SafeError, "No accessible"):
            kv.resolve_subscription(MagicMock(), "Missing")

    def test_disabled_subscription_is_rejected(self):
        self.subscription.state = "Disabled"
        with self.assertRaisesRegex(kv.SafeError, "not enabled"):
            kv.resolve_subscription(MagicMock(), SUBSCRIPTION)

    def test_vault_listing_uses_selected_subscription(self):
        self.manager.vaults.list_by_subscription.return_value = [
            SimpleNamespace(name="demo-vault", location="eastus")
        ]
        result, output, _ = self.invoke("vaults", ["--subscription", "Development"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)[0]["name"], "demo-vault")
        self.manager_class.assert_called_once_with(
            unittest.mock.ANY, SUBSCRIPTION, logging_enable=False
        )

    def test_empty_vault_check_does_not_get_secret_values(self):
        result, output, _ = self.invoke("check", ["--vault", "demo-vault"])
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output)["can_list_secrets"])
        self.client.list_properties_of_secrets.assert_called_once()
        self.client.get_secret.assert_not_called()
        self.subscription_class.assert_not_called()

    def test_secret_listing_excludes_values_and_tags(self):
        self.client.list_properties_of_secrets.return_value = [
            SimpleNamespace(
                name="api-token",
                enabled=True,
                expires_on=None,
                value=VALUE,
                tags={"x": VALUE},
            )
        ]
        result, output, _ = self.invoke("secrets", ["--vault", "demo-vault"])
        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(output),
            [{"name": "api-token", "enabled": True, "expires_on": None}],
        )
        self.client.get_secret.assert_not_called()

    def test_default_retrieval_hides_value(self):
        result, output, error = self.invoke(
            "get", ["--vault", "demo-vault", "--secret", "api-token"]
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["value"], "[hidden]")
        self.assertNotIn(VALUE, output + error)
        self.client.get_secret.assert_called_once_with("api-token", version=None)

    def test_pipe_preserves_exact_value(self):
        result, output, error = self.invoke(
            "get", ["--vault", "demo-vault", "--secret", "api-token", "--stdout"]
        )
        self.assertEqual(result, 0)
        self.assertEqual(output, VALUE)
        self.assertEqual(error, "")

    def test_terminal_stdout_is_rejected_before_authentication(self):
        with (
            patch.object(kv.sys.stdout, "isatty", return_value=True),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            kv.main(
                "get",
                IDS + ["--vault", "demo-vault", "--secret", "api-token", "--stdout"],
            )
        self.assertEqual(caught.exception.code, 2)
        self.credential_class.assert_not_called()

    def test_file_preserves_value_and_restricts_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            kv.write_secret_file(path, VALUE)
            self.assertEqual(path.read_bytes(), VALUE.encode("utf-8"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("existing")
            with self.assertRaises(FileExistsError):
                kv.write_secret_file(path, VALUE)
            self.assertEqual(path.read_text(), "existing")

    def test_dangling_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            target = Path(directory) / "target"
            path.symlink_to(target)
            with self.assertRaises(OSError):
                kv.write_secret_file(path, VALUE)
            self.assertFalse(target.exists())
            self.assertTrue(path.is_symlink())

    def test_get_to_file_never_emits_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            result, output, error = self.invoke(
                "get",
                [
                    "--vault",
                    "demo-vault",
                    "--secret",
                    "api-token",
                    "--output-file",
                    str(path),
                ],
            )
            self.assertEqual(result, 0)
            self.assertEqual(path.read_text(), VALUE)
            self.assertEqual(output, "")
            self.assertNotIn(VALUE, error)

    def test_forbidden_check_is_not_reported_as_connected(self):
        error = HttpResponseError(message=VALUE)
        error.status_code = 403
        self.client.list_properties_of_secrets.side_effect = error
        result, output, message = self.invoke("check", ["--vault", "demo-vault"])
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("Access denied", message)
        self.assertNotIn(VALUE, message)

    def test_subscription_membership_verification(self):
        result, _, _ = self.invoke(
            "check",
            [
                "--vault",
                "demo-vault",
                "--subscription",
                SUBSCRIPTION,
                "--resource-group",
                "demo-rg",
            ],
        )
        self.assertEqual(result, 0)
        self.manager.vaults.get.assert_called_once_with("demo-rg", "demo-vault")

    def test_membership_failure_never_falls_back_to_direct_access(self):
        self.manager.vaults.get.side_effect = HttpResponseError(message=VALUE)
        result, _, error = self.invoke(
            "get",
            [
                "--vault",
                "demo-vault",
                "--secret",
                "api-token",
                "--subscription",
                SUBSCRIPTION,
                "--resource-group",
                "demo-rg",
            ],
        )
        self.assertEqual(result, 1)
        self.secret_class.assert_not_called()
        self.assertNotIn(VALUE, error)

    def test_mismatched_endpoint_is_rejected(self):
        self.manager.vaults.get.return_value.properties.vault_uri = (
            "https://untrusted.example/"
        )
        with ExitStack() as stack, self.assertRaises(kv.SafeError):
            kv.secret_client(
                stack,
                MagicMock(),
                SimpleNamespace(
                    subscription=SUBSCRIPTION, resource_group="rg", vault="demo-vault"
                ),
            )
        self.secret_class.assert_not_called()

    def test_bad_names_are_rejected(self):
        for name in ["https://example.com", "../vault", "ab", "a--b", "-bad", "a" * 25]:
            with self.subTest(name=name), self.assertRaises(argparse.ArgumentTypeError):
                kv.vault_name(name)
        for name in ["../secret", "secret/value", "a" * 128, ""]:
            with self.subTest(name=name), self.assertRaises(argparse.ArgumentTypeError):
                kv.secret_name(name)

    def test_subscription_requires_resource_group_for_data_plane(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            kv.main(
                "check", IDS + ["--vault", "demo-vault", "--subscription", SUBSCRIPTION]
            )
        self.credential_class.assert_not_called()

    def test_unexpected_errors_are_sanitized(self):
        self.client.get_secret.side_effect = RuntimeError(VALUE)
        result, output, error = self.invoke(
            "get", ["--vault", "demo-vault", "--secret", "api-token"]
        )
        self.assertEqual(result, 1)
        self.assertNotIn(VALUE, output + error)


if __name__ == "__main__":
    unittest.main()
