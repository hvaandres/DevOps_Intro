"""Full workflow verification using Make dry runs and synthetic in-memory Azure state."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import commands
import doctor
import test_interactive as fixtures

ROOT = Path(__file__).resolve().parent
TARGETS = (
    "help",
    "setup",
    "auth",
    "login",
    "vaults",
    "check",
    "secrets",
    "get",
    "create",
    "import",
    "update",
    "session",
    "report",
    "doctor",
    "Doctor",
    "test",
    "lint",
)


class MakeWorkflowTests(unittest.TestCase):
    def test_every_declared_target_is_documented_and_dry_run(self):
        declared = next(
            line.removeprefix(".PHONY:").split()
            for line in (ROOT / "Makefile").read_text().splitlines()
            if line.startswith(".PHONY:")
        )
        self.assertEqual(set(declared), set(TARGETS))
        documentation = (ROOT / "README.md").read_text()
        for target in TARGETS:
            self.assertIn(f"make {target}", documentation)
        for directory in (ROOT, ROOT.parent / "keyvault"):
            for target in TARGETS:
                with self.subTest(directory=directory.name, target=target):
                    result = subprocess.run(
                        [
                            "make",
                            "--no-print-directory",
                            "-n",
                            "-C",
                            str(directory),
                            target,
                            "VAULT=example-vault",
                            "SECRET=example-token",
                            "SUBSCRIPTION=Example Subscription",
                            "RESOURCE_GROUP=example-rg",
                            "INPUT_FILE=/tmp/example-input.txt",
                            "OUTPUT_FILE=/tmp/example-output.txt",
                            "REPORT_FILE=/tmp/example-report.json",
                            "ONLINE=1",
                        ],
                        env={"PATH": os.defpath},
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('"$$TOOL_DIR', (ROOT / "Makefile").read_text())
                    self.assertIn('"$TOOL_DIR/commands.py"', result.stdout)
                    self.assertIn(f'"{target}"', result.stdout)
                    # The script's output would appear only if the recipe ran.
                    self.assertNotIn(
                        "Service-principal authentication succeeded", result.stdout
                    )
                    self.assertNotIn("[PASS]", result.stdout)

    def test_all_cli_aliases_dispatch_without_running_azure(self):
        mapping = {
            "auth": "auth",
            "login": "auth",
            "vaults": "vaults",
            "check": "check",
            "secrets": "secrets",
            "get": "get",
            "create": "create",
            "import": "create",
            "update": "update",
            "session": "session",
            "report": "session",
        }
        for target, action in mapping.items():
            with (
                self.subTest(target=target),
                patch.object(commands, "VENV_PYTHON", Path(sys.executable)),
                patch.object(commands.os, "execv") as execute,
            ):
                commands.main([target])
                execute.assert_called_once_with(
                    sys.executable,
                    [sys.executable, str(ROOT / "keyvault_cli.py"), action],
                )

    def test_setup_help_doctor_test_and_lint_dispatch_without_side_effects(self):
        with (
            patch.object(commands, "VENV_PYTHON", Path(sys.executable)),
            patch.object(commands.subprocess, "run") as run,
            patch.object(commands.subprocess, "call", return_value=0) as call,
        ):
            self.assertEqual(commands.main(["setup"]), 0)
            run.assert_called_once_with(
                [sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True
            )
            self.assertIn("pip", call.call_args.args[0])
            self.assertIn(str(ROOT / "requirements.txt"), call.call_args.args[0])
            call.reset_mock()
            self.assertEqual(commands.main(["test"]), 0)
            self.assertEqual(call.call_count, 2)
            call.reset_mock()
            self.assertEqual(commands.main(["lint"]), 0)
            self.assertEqual(call.call_count, 2)
            self.assertIn("--check", call.call_args.args[0])
        for target in ("doctor", "Doctor"):
            with (
                patch.object(commands, "VENV_PYTHON", Path(sys.executable)),
                patch.object(commands.os, "execv") as execute,
            ):
                commands.main([target])
                execute.assert_called_once_with(
                    sys.executable, [sys.executable, str(ROOT / "doctor.py")]
                )
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(commands.main(["help"]), 0)
        self.assertIn("Complete guide:", output.getvalue())


class StatefulSessionWorkflowTests(unittest.TestCase):
    setUp = fixtures.InteractiveTests.setUp
    enter_patch = fixtures.InteractiveTests.enter_patch
    invoke = fixtures.InteractiveTests.invoke

    def test_create_retrieve_update_retrieve_report_with_one_login(self):
        # No credential leaves this fixture. set/get operate only on this dict.
        first_value = "synthetic-initial-workflow-value\n"
        second_value = "synthetic-rotated-workflow-value\n"
        store = {"api-token": "synthetic-existing"}
        observed_values = []

        def list_properties():
            return [
                SimpleNamespace(name=name, enabled=True, tags={"environment": "test"})
                for name in store
            ]

        def set_secret(name, value, **properties):
            store[name] = value
            return SimpleNamespace(value=value)

        def get_secret(name):
            observed_values.append(store[name])
            return SimpleNamespace(value=store[name])

        self.secret_client.list_properties_of_secrets.side_effect = list_properties
        self.secret_client.set_secret.side_effect = set_secret
        self.secret_client.get_secret.side_effect = get_secret
        self.prompt.side_effect = [
            "synthetic-client-secret",
            first_value,
            first_value,
            second_value,
            second_value,
        ]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "session.json"
            with patch.object(doctor, "run", return_value=0) as diagnose:
                result, output, messages = self.invoke(
                    [
                        "1",
                        "3",
                        "workflow-token",
                        "CREATE",
                        "2",
                        "2",
                        "",
                        "4",
                        "workflow-token",
                        "UPDATE",
                        "2",
                        "2",
                        "",
                        "5",
                        "7",
                        "6",
                        str(report),
                        "q",
                    ],
                    extra=["session", "--vault", "demo-vault"],
                )
            self.assertEqual(result, 0)
            self.assertEqual(output, "")
            self.assertEqual(store["workflow-token"], second_value)
            self.assertEqual(observed_values, [first_value, second_value])
            self.credential_class.assert_called_once()
            self.credential.get_token.assert_called_once()
            self.assertEqual(self.secret_client.set_secret.call_count, 2)
            self.assertEqual(self.secret_client.get_secret.call_count, 2)
            self.assertEqual(
                self.secret_client.set_secret.call_args.kwargs,
                {"enabled": True, "tags": {"environment": "test"}},
            )
            self.assertIs(diagnose.call_args.kwargs["credential"], self.credential)

            saved = report.read_text()
            events = json.loads(saved)["events"]
            self.assertEqual(
                [event["operation"] for event in events],
                ["auth", "secrets", "create", "get", "update", "get", "doctor"],
            )
            self.assertTrue(all(event["status"] == "success" for event in events))
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            for value in (first_value, second_value, "synthetic-client-secret"):
                self.assertNotIn(value, output + messages + saved)


if __name__ == "__main__":
    unittest.main()
