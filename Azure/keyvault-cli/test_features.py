"""No live Azure calls: fixtures replace every SDK client and credential."""

import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import warnings
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import commands
import doctor
import keyvault_cli as cli
import test_interactive as fixtures

VALUE = fixtures.VALUE
ROOT = Path(__file__).resolve().parent
TARGET = ["--vault", "demo-vault", "--secret", "api-token"]


class FeatureTests(unittest.TestCase):
    setUp = fixtures.InteractiveTests.setUp
    enter_patch = fixtures.InteractiveTests.enter_patch
    invoke = fixtures.InteractiveTests.invoke

    def test_auth_uses_only_explicit_principal_without_resource_calls(self):
        result, output, messages = self.invoke([], extra=["auth"])
        self.assertEqual(result, 0)
        self.assertEqual(output, "")
        self.prompt.assert_called_once()
        self.credential_class.assert_called_once_with(
            tenant_id=fixtures.TENANT,
            client_id=fixtures.CLIENT,
            client_secret="synthetic-client-secret",
            logging_enable=False,
        )
        self.sub_class.assert_not_called()
        self.secret_class.assert_not_called()
        self.assertIn("not displayed or persisted", messages)

    def test_targeted_secrets_does_not_need_subscription_discovery(self):
        result, output, messages = self.invoke(
            [], extra=["secrets", "--vault", "demo-vault"]
        )
        self.assertEqual(result, 0)
        self.assertEqual(output, "")
        self.assertIn("api-token", messages)
        self.assertNotIn(VALUE, messages)
        self.sub_class.assert_not_called()
        self.secret_client.get_secret.assert_not_called()

    def test_blank_make_identifiers_prompt_instead_of_rejecting_empty_uuids(self):
        with patch.dict(os.environ, {"AZURE_TENANT_ID": "", "AZURE_CLIENT_ID": ""}):
            result, _, _ = self.invoke(
                [fixtures.TENANT, fixtures.CLIENT], extra=["auth"], ids=False
            )
        self.assertEqual(result, 0)
        self.credential_class.assert_called_once()

    def test_make_environment_selectors_are_used(self):
        with patch.dict(os.environ, {"VAULT": "demo-vault", "SECRET": "api-token"}):
            result, _, _ = self.invoke([""], extra=["get"])
        self.assertEqual(result, 0)
        self.sub_class.assert_not_called()
        self.secret_client.get_secret.assert_called_once_with("api-token")

    def test_create_hidden_value_never_leaks_response(self):
        self.secret_client.list_properties_of_secrets.return_value = []
        self.prompt.side_effect = ["synthetic-client-secret", VALUE, VALUE]
        result, output, messages = self.invoke(["CREATE"], extra=["create", *TARGET])
        self.assertEqual(result, 0)
        self.assertEqual(output, "")
        self.assertNotIn(VALUE, messages)
        self.secret_client.set_secret.assert_called_once_with("api-token", VALUE)
        self.secret_client.get_secret.assert_not_called()

    def test_create_refuses_existing_secret(self):
        result, _, messages = self.invoke([], extra=["create", *TARGET])
        self.assertEqual(result, 1)
        self.assertIn("already exists", messages)
        self.secret_client.set_secret.assert_not_called()

    def test_create_cannot_bypass_existence_check_by_changing_case(self):
        self.secret_properties.name = "API-TOKEN"
        result, _, messages = self.invoke([], extra=["create", *TARGET])
        self.assertEqual(result, 1)
        self.assertIn("already exists", messages)
        self.secret_client.set_secret.assert_not_called()

    def test_write_transport_failure_is_reported_as_unknown_not_a_safe_retry(self):
        self.prompt.side_effect = ["synthetic-client-secret", VALUE, VALUE]
        self.secret_client.set_secret.side_effect = cli.kv.ServiceRequestError(VALUE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report"
            result, _, messages = self.invoke(
                ["UPDATE"], extra=["update", *TARGET, "--report-file", str(path)]
            )
            self.assertEqual(result, 1)
            self.assertEqual(
                json.loads(path.read_text())["events"][-1]["status"], "unknown"
            )
            self.assertIn("before retrying", messages)
            self.assertNotIn(VALUE, messages + path.read_text())

    def test_update_refuses_missing_secret(self):
        self.secret_client.list_properties_of_secrets.return_value = []
        result, _, messages = self.invoke([], extra=["update", *TARGET])
        self.assertEqual(result, 1)
        self.assertIn("does not exist", messages)
        self.secret_client.set_secret.assert_not_called()

    def test_update_preserves_metadata_without_getting_old_value(self):
        properties = {
            "enabled": False,
            "expires_on": "synthetic-expiry",
            "not_before": "synthetic-date",
            "content_type": "text/plain",
            "tags": {"private": VALUE},
        }
        for name, value in properties.items():
            setattr(self.secret_properties, name, value)
        self.prompt.side_effect = ["synthetic-client-secret", VALUE, VALUE]
        result, _, messages = self.invoke(["UPDATE"], extra=["update", *TARGET])
        self.assertEqual(result, 0)
        self.assertNotIn(VALUE, messages)
        self.secret_client.set_secret.assert_called_once_with(
            "api-token", VALUE, **properties
        )
        self.secret_client.get_secret.assert_not_called()

    def test_write_decline_never_reads_value_or_writes(self):
        self.secret_client.list_properties_of_secrets.return_value = []
        result, _, _ = self.invoke(["no"], extra=["create", *TARGET])
        self.assertEqual(result, 130)
        self.prompt.assert_called_once()  # Authentication only, no new-value prompts.
        self.secret_client.set_secret.assert_not_called()

    def test_mismatched_hidden_values_are_rejected(self):
        self.prompt.side_effect = ["synthetic-client-secret", VALUE, "different"]
        result, _, messages = self.invoke(["UPDATE"], extra=["update", *TARGET])
        self.assertEqual(result, 1)
        self.assertIn("do not match", messages)
        self.assertNotIn(VALUE, messages)
        self.secret_client.set_secret.assert_not_called()

    def test_no_echo_control_rejects_hidden_value_input(self):
        def unsafe(*_):
            warnings.warn("echo unavailable", cli.kv.getpass.GetPassWarning)
            return VALUE

        self.prompt.side_effect = unsafe
        with self.assertRaises(cli.kv.getpass.GetPassWarning):
            cli.read_value(None)

    def test_import_preserves_utf8_and_multiline_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(VALUE.encode())
            path.chmod(0o600)
            result, _, messages = self.invoke(
                ["UPDATE"], extra=["update", *TARGET, "--input-file", str(path)]
            )
            self.assertEqual(result, 0)
            self.assertNotIn(VALUE, messages)
            self.secret_client.set_secret.assert_called_once_with(
                "api-token", VALUE, enabled=True
            )

    def test_permissive_symlink_empty_binary_and_oversized_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            link = Path(directory) / "link"
            path.write_bytes(VALUE.encode())
            path.chmod(0o644)
            with self.assertRaises(cli.kv.SafeError):
                cli.read_value(path)
            path.chmod(0o600)
            link.symlink_to(path)
            with self.assertRaises(OSError):
                cli.read_value(link)
            for data in (b"", b"\xff", b"x" * 25601):
                path.write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaises(cli.kv.SafeError):
                    cli.read_value(path)

    def test_repeated_gets_reuse_one_login_and_report_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            result, output, messages = self.invoke(
                ["2", "", "2", "", "5", "q"],
                extra=["session", *TARGET, "--report-file", str(path)],
            )
            self.assertEqual(result, 0)
            self.assertEqual(output, "")
            self.credential_class.assert_called_once()
            self.credential.get_token.assert_called_once()
            self.assertEqual(self.secret_client.get_secret.call_count, 2)
            report = json.loads(path.read_text())
            self.assertEqual(
                [item["operation"] for item in report["events"]], ["auth", "get", "get"]
            )
            self.assertNotIn(VALUE, path.read_text() + messages)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for event in report["events"]:
                self.assertEqual(
                    set(event),
                    {
                        "timestamp_utc",
                        "operation",
                        "subscription",
                        "vault",
                        "secret",
                        "status",
                    },
                )

    def test_session_records_failure_cancellation_and_continues(self):
        self.secret_client.get_secret.side_effect = RuntimeError(VALUE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report"
            result, _, messages = self.invoke(
                ["2", "", "2", "q", "5", "q"],
                extra=["session", *TARGET, "--report-file", str(path)],
            )
            self.assertEqual(result, 0)
            events = json.loads(path.read_text())["events"]
            self.assertEqual(
                [item["status"] for item in events], ["success", "failed", "cancelled"]
            )
            self.assertNotIn(VALUE, messages + path.read_text())

    def test_auth_failure_report_contains_no_raw_error(self):
        self.credential.get_token.side_effect = cli.kv.ClientAuthenticationError(
            message=VALUE
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report"
            result, _, messages = self.invoke(
                [], extra=["auth", "--report-file", str(path)]
            )
            self.assertEqual(result, 1)
            self.assertEqual(
                json.loads(path.read_text())["events"][0]["status"], "failed"
            )
            self.assertNotIn(VALUE, messages + path.read_text())

    def test_report_export_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report"
            path.write_text("existing")
            result, _, messages = self.invoke(
                [], extra=["auth", "--report-file", str(path)]
            )
            self.assertEqual(result, 1)
            self.assertEqual(path.read_text(), "existing")
            self.assertIn("Report export failed", messages)

    def test_report_cannot_leak_arbitrary_attributes(self):
        report = cli.SessionReport()
        args = SimpleNamespace(
            subscription=None,
            vault="demo-vault",
            secret="api-token",
            password=VALUE,
            tags={"secret": VALUE},
            input_file=VALUE,
        )
        report.record("get", args, "success")
        self.assertNotIn(VALUE, report.render())


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_local_mode_never_authenticates_or_contacts_network(self):
        with (
            patch.object(doctor, "online_checks") as online,
            patch.object(doctor.socket, "create_connection") as network,
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(doctor.run(), 0)
        online.assert_not_called()
        network.assert_not_called()
        self.assertIn("Not required", output.getvalue())

    def test_missing_packages_give_setup_guidance_without_tracebacks(self):
        with (
            patch.object(
                doctor.importlib, "import_module", side_effect=ImportError(VALUE)
            ),
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(doctor.run(online=True), 1)
        self.assertIn("make setup", output.getvalue())
        self.assertNotIn(VALUE, output.getvalue())

    def test_python_without_site_packages_can_run_doctor(self):
        result = subprocess.run(
            [sys.executable, "-S", str(ROOT / "doctor.py")],
            env={"PATH": os.defpath},
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("make setup", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_proxy_and_bad_identifiers_never_expose_values(self):
        with (
            patch.dict(os.environ, {"HTTPS_PROXY": VALUE, "AZURE_CLIENT_ID": VALUE}),
            redirect_stderr(io.StringIO()) as output,
        ):
            self.assertEqual(doctor.run(), 1)
        self.assertNotIn(VALUE, output.getvalue())
        self.assertIn("Invalid UUID", output.getvalue())

    def test_guidance_distinguishes_observed_failures_and_redacts_details(self):
        forbidden = cli.kv.HttpResponseError(message=VALUE)
        forbidden.status_code = 403
        self.assertIn("ARM denied", doctor.guidance(forbidden, "subscription"))
        self.assertIn("403 alone", doctor.guidance(forbidden, "vault List"))
        self.assertIn("DNS lookup", doctor.guidance(socket.gaierror(VALUE), "network"))
        self.assertIn(
            "never disable TLS",
            doctor.guidance(ssl.SSLCertVerificationError(VALUE), "network"),
        )
        self.assertNotIn(VALUE, doctor.guidance(forbidden, "vault List"))

    def test_online_probes_never_write_or_display_secrets(self):
        credential = MagicMock()
        client = MagicMock()
        client.list_properties_of_secrets.return_value = []
        client.get_secret.return_value = SimpleNamespace(value=VALUE)
        with (
            patch.object(doctor, "probe_tls"),
            patch.object(cli.kv, "SecretClient") as factory,
            redirect_stderr(io.StringIO()) as output,
        ):
            factory.return_value.__enter__.return_value = client
            self.assertEqual(
                doctor.run(
                    online=True,
                    credential=credential,
                    vault="demo-vault",
                    secret="api-token",
                ),
                0,
            )
        client.get_secret.assert_called_once_with("api-token")
        client.set_secret.assert_not_called()
        self.assertNotIn(VALUE, output.getvalue())
        self.assertIn("[UNKNOWN] write permissions", output.getvalue())

    def test_online_list_failure_does_not_skip_explicit_get_probe(self):
        client = MagicMock()
        error = cli.kv.HttpResponseError(message=VALUE)
        error.status_code = 403
        client.list_properties_of_secrets.side_effect = error
        with (
            patch.object(doctor, "probe_tls"),
            patch.object(cli.kv, "SecretClient") as factory,
            redirect_stderr(io.StringIO()) as output,
        ):
            factory.return_value.__enter__.return_value = client
            self.assertEqual(
                doctor.run(
                    online=True,
                    credential=MagicMock(),
                    vault="demo-vault",
                    secret="api-token",
                ),
                1,
            )
        client.get_secret.assert_called_once()
        self.assertNotIn(VALUE, output.getvalue())

    def test_invalid_vault_never_triggers_network(self):
        with (
            patch.object(doctor, "probe_tls") as probe,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                doctor.run(
                    online=True, credential=MagicMock(), vault="untrusted.example/"
                ),
                1,
            )
        probe.assert_not_called()


class MakeTests(unittest.TestCase):
    def test_login_alias_dispatches_explicit_auth_without_values_in_argv(self):
        with (
            patch.object(
                commands, "VENV_PYTHON", MagicMock(**{"exists.return_value": True})
            ),
            patch.object(commands.os, "execv") as execute,
        ):
            commands.main(["login"])
        self.assertEqual(execute.call_args.args[1][-1], "auth")
        self.assertNotIn("synthetic-client-secret", repr(execute.call_args))

    def test_doctor_dispatches_without_virtualenv(self):
        with (
            patch.object(
                commands, "VENV_PYTHON", MagicMock(**{"exists.return_value": False})
            ),
            patch.object(commands.os, "execv") as execute,
        ):
            commands.main(["Doctor"])
        self.assertTrue(execute.call_args.args[1][-1].endswith("doctor.py"))

    def test_make_selectors_are_not_interpolated_in_shell_recipe(self):
        payload = "demo; printf MAKE_INJECTION"
        result = subprocess.run(
            ["make", "-n", "-C", str(ROOT), "get", f"VAULT={payload}"],
            capture_output=True,
            text=True,
            env={"PATH": os.defpath},
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(payload, result.stdout)
        self.assertNotIn("MAKE_INJECTION", result.stdout)

    def test_make_help_works_from_both_directories(self):
        for directory in (ROOT, ROOT.parent / "keyvault"):
            with self.subTest(directory=directory.name):
                result = subprocess.run(
                    ["make", "-C", str(directory), "help"],
                    capture_output=True,
                    text=True,
                    env={"PATH": os.defpath},
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("make auth | make login", result.stdout)


if __name__ == "__main__":
    unittest.main()
