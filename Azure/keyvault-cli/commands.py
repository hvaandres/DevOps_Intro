"""Standard-library Make dispatcher; diagnostics work before Azure SDK installation."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
HELP = """Key Vault commands (service-principal authentication only)
  make help                  Show this quick reference (also the default target)
  make setup                 Create tool-local .venv and install dependencies + Ruff
  make auth | make login     Validate the service principal (hidden client-secret prompt)
  make vaults                Discover vaults in a subscription
  make check VAULT=name      Check vault connection and secret List permission
  make secrets VAULT=name    List secret names, never values
  make get VAULT=name SECRET=name
                             Retrieve one secret; value hidden by default
  make create | make import  Add a secret; refuses an existing name
  make update                Create a new version of an existing secret
  make session | make report Persistent session: one login, operations, request report
  make doctor | make Doctor  Local checks and repair suggestions; no Azure calls
  make doctor ONLINE=1 VAULT=name
                             Add read-only network/auth/vault diagnostics
  make test | make lint      Offline tests / lint and format checks

Selectors: VAULT, SECRET, SUBSCRIPTION (name/UUID), RESOURCE_GROUP.
Use SUBSCRIPTION + RESOURCE_GROUP together to verify a named vault's membership.
Identifiers: AZURE_TENANT_ID, AZURE_CLIENT_ID; missing IDs are prompted.
INPUT_FILE: owner-only UTF-8 file for create/update; otherwise hidden double-entry.
OUTPUT_FILE: new owner-only retrieval file. REPORT_FILE: new owner-only JSON report.
Never put secret VALUES or client secrets into Make variables or shell history.
Writes ALWAYS require confirmation; update preserves metadata and creates a version.
Existence checks are advisory: Azure set is an upsert, not a concurrency lock.
Read permissions: List/Get. Writes additionally need Set (prefer a custom scoped role;
Key Vault Secrets Officer is broader). Resource discovery needs ARM read access.
make auth does not persist a login or alter your Azure CLI session.
History covers one make session process only, not other invocations or Azure audit logs.
Keep the keyvault and keyvault-cli folders together. Python 3.10+; Azure Public Cloud.
Complete guide: keyvault-cli/README.md (all targets, examples, permissions and dry runs).
Dry-run every recipe without execution: make -n help setup auth login vaults check secrets get create import update session report doctor Doctor test lint
"""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    target = argv[0] if argv else "help"
    if target == "help":
        print(HELP)
        return 0
    if sys.version_info < (3, 10):  # noqa: UP036 - Bootstrap can run before a supported environment exists.
        print(
            "Python 3.10+ is required. Install it and rerun make setup.",
            file=sys.stderr,
        )
        return 1
    if target == "setup":
        subprocess.run([sys.executable, "-m", "venv", str(ROOT / ".venv")], check=True)
        return subprocess.call(
            [
                str(VENV_PYTHON),
                "-m",
                "pip",
                "install",
                "-r",
                str(ROOT / "requirements.txt"),
                "ruff",
            ]
        )
    python = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable
    if target in {"doctor", "Doctor"}:
        return os.execv(python, [python, str(ROOT / "doctor.py")])
    if not VENV_PYTHON.exists():
        print(
            "Tool environment is missing. Run make setup, then make doctor.",
            file=sys.stderr,
        )
        return 1
    if target == "test":
        for directory in (ROOT, ROOT.parent / "keyvault"):
            result = subprocess.call(
                [
                    python,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(directory),
                    "-p",
                    "test_*.py",
                ]
            )
            if result:
                return result
        return 0
    if target == "lint":
        directories = [str(ROOT), str(ROOT.parent / "keyvault")]
        for flags in (["check"], ["format", "--check"]):
            result = subprocess.call(
                [python, "-m", "ruff", *flags, *directories, "--exclude", ".venv"]
            )
            if result:
                return result
        return 0
    action = {"login": "auth", "import": "create", "report": "session"}.get(
        target, target
    )
    if action not in {
        "auth",
        "vaults",
        "check",
        "secrets",
        "get",
        "create",
        "update",
        "session",
    }:
        print("Unknown command. Run make help.", file=sys.stderr)
        return 2
    os.execv(python, [python, str(ROOT / "keyvault_cli.py"), action])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError):
        print(
            "Local setup/launch failed. Run make doctor; check Python, venv, pip and permissions.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
