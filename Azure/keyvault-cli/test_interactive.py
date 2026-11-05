"""Offline CLI coverage. All Azure clients/credentials are replaced with mocks."""

import io
import json
import os
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import keyvault_cli as cli

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION = "33333333-3333-3333-3333-333333333333"
IDS = ["--tenant-id", TENANT, "--client-id", CLIENT]
VALUE = "synthetic-value\nsecond line\n\n"


class InteractiveTests(unittest.TestCase):
    def setUp(self):
        self.enter_patch(patch.dict(os.environ, {}, clear=True))
        self.credential_class = self.enter_patch(
            patch.object(cli.kv, "ClientSecretCredential")
        )
        self.credential = self.credential_class.return_value.__enter__.return_value
        self.credential.get_token.return_value = SimpleNamespace(
            token="fake-access-token"
        )
        self.prompt = self.enter_patch(
            patch.object(
                cli.kv.getpass, "getpass", return_value="synthetic-client-secret"
            )
        )
        self.sub_class = self.enter_patch(patch.object(cli.kv, "SubscriptionClient"))
        self.sub_client = self.sub_class.return_value.__enter__.return_value
        self.subscription = SimpleNamespace(
            display_name="Development", subscription_id=SUBSCRIPTION, state="Enabled"
        )
        self.sub_client.subscriptions.list.return_value = [self.subscription]
        self.sub_client.subscriptions.get.return_value = self.subscription
        self.manager_class = self.enter_patch(
            patch.object(cli.kv, "KeyVaultManagementClient")
        )
        self.manager = self.manager_class.return_value.__enter__.return_value
        self.vault = SimpleNamespace(
            name="demo-vault",
            location="eastus",
            id=f"/subscriptions/{SUBSCRIPTION}/resourceGroups/demo-rg/providers/"
            "Microsoft.KeyVault/vaults/demo-vault",
            properties=SimpleNamespace(vault_uri="https://demo-vault.vault.azure.net/"),
        )
        self.manager.vaults.list_by_subscription.return_value = [self.vault]
        self.manager.vaults.get.return_value = self.vault
        self.secret_class = self.enter_patch(patch.object(cli.kv, "SecretClient"))
        self.secret_client = self.secret_class.return_value.__enter__.return_value
        self.secret_properties = SimpleNamespace(name="api-token", enabled=True)
        self.secret_client.list_properties_of_secrets.return_value = [
            self.secret_properties
        ]
        self.secret_client.get_secret.return_value = SimpleNamespace(value=VALUE)

    def enter_patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def invoke(self, answers, extra=(), ids=True, stdout_tty=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            patch.object(sys.stdin, "isatty", return_value=True),
            patch.object(stdout, "isatty", return_value=stdout_tty),
            patch("builtins.input", side_effect=answers),
        ):
            result = cli.main((IDS if ids else []) + list(extra))
        return result, stdout.getvalue(), stderr.getvalue()

    def test_full_numbered_flow_authenticates_once_and_hides_values(self):
        result, output, messages = self.invoke(["1", "1", "1", ""])
        self.assertEqual(result, 0)
        self.assertEqual(output, "")
        self.assertIn("Retrieval succeeded. Value hidden", messages)
        self.assertNotIn(VALUE, messages)
        self.assertNotIn("fake-access-token", messages)
        self.assertNotIn("synthetic-client-secret", messages)
        self.credential_class.assert_called_once()
        self.prompt.assert_called_once()
        self.credential.get_token.assert_called_once_with(cli.kv.ARM_SCOPE)
        self.manager.vaults.get.assert_called_once_with("demo-rg", "demo-vault")
        self.secret_client.get_secret.assert_called_once_with("api-token")
        self.secret_class.assert_called_once_with(
            vault_url="https://demo-vault.vault.azure.net",
            credential=self.credential,
            logging_enable=False,
        )
        self.credential.__exit__.assert_not_called()
        self.credential_class.return_value.__exit__.assert_called_once()
        self.secret_class.return_value.__exit__.assert_called_once()

    def test_exact_name_selections(self):
        result, _, _ = self.invoke(["Development", "demo-vault", "api-token", "1"])
        self.assertEqual(result, 0)

    def test_prompts_for_missing_identifiers_and_retries_bad_uuid(self):
        result, _, messages = self.invoke(
            ["bad-uuid", TENANT, CLIENT, "1", "1", "1", ""], ids=False
        )
        self.assertEqual(result, 0)
        self.assertIn("Enter a valid UUID", messages)
        self.credential_class.assert_called_once_with(
            tenant_id=TENANT,
            client_id=CLIENT,
            client_secret="synthetic-client-secret",
            logging_enable=False,
        )

    def test_duplicate_subscription_names_require_number_or_id(self):
        other = SimpleNamespace(
            display_name="Development",
            subscription_id="44444444-4444-4444-4444-444444444444",
            state="Enabled",
        )
        self.sub_client.subscriptions.list.return_value = [self.subscription, other]
        result, _, messages = self.invoke(["Development", SUBSCRIPTION, "1", "1", ""])
        self.assertEqual(result, 0)
        self.assertIn("ambiguous", messages)
        self.assertIn(other.subscription_id, messages)

    def test_bad_menu_choices_retry(self):
        result, _, messages = self.invoke(
            ["0", "500", "missing", "1", "1", "1", "bad", ""]
        )
        self.assertEqual(result, 0)
        self.assertIn("No matching selection", messages)
        self.assertIn("Choose 1, 2, or 3", messages)

    def test_empty_subscription_vault_or_secret_lists_fail_without_retrieval(self):
        for stage, answers in [
            ("subscriptions", []),
            ("vaults", ["1"]),
            ("secrets", ["1", "1"]),
        ]:
            with self.subTest(stage=stage):
                self.sub_client.subscriptions.list.return_value = (
                    [] if stage == "subscriptions" else [self.subscription]
                )
                self.manager.vaults.list_by_subscription.return_value = (
                    [] if stage == "vaults" else [self.vault]
                )
                self.secret_client.list_properties_of_secrets.return_value = []
                result, output, messages = self.invoke(answers)
                self.assertEqual(result, 1)
                self.assertEqual(output, "")
                self.assertIn(f"No accessible {stage}", messages)
        self.secret_client.get_secret.assert_not_called()

    def test_disabled_subscriptions_are_excluded(self):
        self.subscription.state = "Disabled"
        result, _, messages = self.invoke([])
        self.assertEqual(result, 1)
        self.assertIn("No accessible subscriptions", messages)

    def test_disabled_secret_is_not_retrieved(self):
        self.secret_properties.enabled = False
        result, _, messages = self.invoke(["1", "1", "1"])
        self.assertEqual(result, 1)
        self.assertIn("[disabled]", messages)
        self.secret_client.get_secret.assert_not_called()

    def test_quit_before_authentication(self):
        result, output, messages = self.invoke(["q"], ids=False)
        self.assertEqual(result, 130)
        self.assertEqual(output, "")
        self.assertIn("Cancelled", messages)
        self.credential_class.assert_not_called()

    def test_quit_after_selecting_secret_does_not_retrieve(self):
        result, _, _ = self.invoke(["1", "1", "1", "q"])
        self.assertEqual(result, 130)
        self.secret_client.get_secret.assert_not_called()

    def test_eof_and_keyboard_interrupt_cancel_cleanly(self):
        for error in (EOFError(), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                result, output, messages = self.invoke([error], ids=False)
                self.assertEqual(result, 130)
                self.assertEqual(output, "")
                self.assertIn("Cancelled", messages)

    def test_reveal_requires_exact_confirmation_before_get(self):
        result, output, _ = self.invoke(["1", "1", "1", "3", "no"])
        self.assertEqual(result, 130)
        self.assertEqual(output, "")
        self.secret_client.get_secret.assert_not_called()

    def test_confirmed_reveal_escapes_terminal_controls(self):
        value = "\x1b[2J" + VALUE
        self.secret_client.get_secret.return_value.value = value
        result, output, messages = self.invoke(["1", "1", "1", "3", "REVEAL"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output), value)
        self.assertNotIn("\x1b", output)
        self.assertNotIn(value, messages)
        self.assertIn("scrollback", messages)

    def test_redirected_stdout_cannot_use_terminal_reveal(self):
        result, output, messages = self.invoke(
            ["1", "1", "1", "3", ""], stdout_tty=False
        )
        self.assertEqual(result, 0)
        self.assertEqual(output, "")
        self.assertIn("requires terminal stdout", messages)

    def test_pipe_contains_only_exact_secret_value(self):
        result, output, messages = self.invoke(
            ["1", "1", "1"], extra=["--stdout"], stdout_tty=False
        )
        self.assertEqual(result, 0)
        self.assertEqual(output, VALUE)
        self.assertNotIn(VALUE, messages)
        self.assertIn("Subscriptions:", messages)

    def test_stdout_flag_refuses_terminal_before_authentication(self):
        with (
            patch.object(sys.stdin, "isatty", return_value=True),
            patch.object(sys.stdout, "isatty", return_value=True),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.main(IDS + ["--stdout"])
        self.assertEqual(caught.exception.code, 2)
        self.credential_class.assert_not_called()

    def test_nonterminal_stdin_is_rejected(self):
        with (
            patch.object(sys.stdin, "isatty", return_value=False),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as caught,
        ):
            cli.main(IDS)
        self.assertEqual(caught.exception.code, 2)
        self.credential_class.assert_not_called()

    def test_file_menu_creates_exact_value_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            result, output, messages = self.invoke(["1", "1", "1", "2", str(path)])
            self.assertEqual(result, 0)
            self.assertEqual(output, "")
            self.assertNotIn(VALUE, messages)
            self.assertEqual(path.read_bytes(), VALUE.encode())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_output_file_flag_skips_output_menu(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            result, _, messages = self.invoke(
                ["1", "1", "1"], extra=["--output-file", str(path)]
            )
            self.assertEqual(result, 0)
            self.assertEqual(path.read_bytes(), VALUE.encode())
            self.assertNotIn("Output options:", messages)

    def test_existing_file_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("existing")
            link = Path(directory) / "link"
            link.symlink_to(target)
            for destination in (target, link):
                with self.subTest(destination=destination.name):
                    result, output, messages = self.invoke(
                        ["1", "1", "1"], extra=["--output-file", str(destination)]
                    )
                    self.assertEqual(result, 1)
                    self.assertEqual(output, "")
                    self.assertNotIn(VALUE, messages)
                    self.assertEqual(target.read_text(), "existing")

    def test_resource_id_cannot_escape_selected_subscription(self):
        self.vault.id = self.vault.id.replace(SUBSCRIPTION, CLIENT)
        result, _, messages = self.invoke(["1", "1"])
        self.assertEqual(result, 1)
        self.assertIn("does not match", messages)
        self.secret_class.assert_not_called()

    def test_membership_check_failure_does_not_fall_back(self):
        self.manager.vaults.get.side_effect = RuntimeError(VALUE)
        result, output, messages = self.invoke(["1", "1"])
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertNotIn(VALUE, messages)
        self.secret_class.assert_not_called()

    def test_sdk_failure_is_sanitized(self):
        error = cli.kv.HttpResponseError(message=VALUE)
        error.status_code = 403
        self.secret_client.get_secret.side_effect = error
        result, output, messages = self.invoke(["1", "1", "1", ""])
        self.assertEqual(result, 1)
        self.assertEqual(output, "")
        self.assertIn("Access denied", messages)
        self.assertNotIn(VALUE, messages)

    def test_untrusted_subscription_labels_are_escaped(self):
        self.subscription.display_name = "\x1b[2J"
        result, _, messages = self.invoke(["1", "1", "1", ""])
        self.assertEqual(result, 0)
        self.assertNotIn("\x1b", messages)
        self.assertIn("\\u001b", messages)

    @unittest.skipUnless(hasattr(os, "openpty"), "Requires a POSIX pseudo-terminal")
    def test_offline_real_terminal_flow(self):
        # Exercise actual terminal input/output, but use the mocked Azure fixture
        # in a child process with no inherited Azure credentials or network calls.
        master, slave = os.openpty()
        code = (
            "import test_interactive as t; "
            "case=t.InteractiveTests(); case.setUp(); "
            "raise SystemExit(t.cli.main(t.IDS))"
        )
        child = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parent,
            env={"PATH": os.defpath},
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)
        captured = bytearray()
        try:
            os.write(master, b"1\n1\n1\n\n")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    captured.extend(chunk)
                elif child.poll() is not None:
                    break
            self.assertEqual(child.wait(timeout=2), 0)
            output = captured.decode()
            self.assertIn("Subscriptions:", output)
            self.assertIn("Vaults:", output)
            self.assertIn("Secrets:", output)
            self.assertIn("Retrieval succeeded. Value hidden", output)
            self.assertNotIn(VALUE, output)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            os.close(master)


if __name__ == "__main__":
    unittest.main()
