#!/usr/bin/env python3
"""Service-principal Key Vault commands, confirmed writes, and session history."""

import argparse
import json
import os
import re
import stat
import sys
import warnings
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

# Resolve from this file, not the caller's working directory. Keep both folders
# together; credentials and retrieved values never pass through subprocess argv.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "keyvault"))

try:
    import keyvault_common as kv
except ImportError:
    print(
        "Azure dependencies are unavailable. Run make setup, then make doctor.",
        file=sys.stderr,
    )
    raise SystemExit(1) from None


class Cancelled(Exception):
    """The user quit a menu or declined disclosure."""


def say(message):
    print(message, file=sys.stderr)


def quoted(value):
    """Escape untrusted metadata/values before writing them to a terminal."""
    return json.dumps(str(value), ensure_ascii=True)


def ask(prompt):
    say(prompt)
    value = input().strip()
    if value.lower() in {"q", "quit"}:
        raise Cancelled
    return value


def choose(title, items, label, keys):
    """Select an item by 1-based index or exact key, rejecting ambiguous names."""
    if not items:
        raise kv.SafeError(
            f"No accessible {title.lower()} found. Check scope, permissions, and available resources."
        )
    say(f"\n{title}:")
    for index, item in enumerate(items, 1):
        say(f"  {index}. {label(item)}")
    while True:
        answer = ask("Enter a number or exact name/ID (q to quit):")
        if answer.isascii() and answer.isdigit() and 1 <= int(answer) <= len(items):
            return items[int(answer) - 1]
        matches = [item for item in items if answer in keys(item)]
        if len(matches) == 1:
            return matches[0]
        if matches:
            say("That name is ambiguous. Select its number or unique resource ID.")
        else:
            say("No matching selection. Try again.")


def prompt_guid(value, label):
    if value:
        try:
            return kv.guid(value)
        except argparse.ArgumentTypeError:
            raise kv.SafeError(f"{label} must be a UUID.") from None
    while True:
        answer = ask(f"{label} (UUID; q to quit):")
        try:
            return kv.guid(answer)
        except argparse.ArgumentTypeError:
            say("Enter a valid UUID.")


def resource_group(vault, subscription_id):
    """Reject resource IDs that do not belong to the selected subscription."""
    match = re.fullmatch(
        r"/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/"
        r"Microsoft\.KeyVault/vaults/([^/]+)",
        vault.id or "",
        flags=re.IGNORECASE,
    )
    if (
        not match
        or match[1].lower() != subscription_id.lower()
        or match[3].lower() != vault.name.lower()
    ):
        raise kv.SafeError(
            "Vault resource ID does not match the selected subscription and vault."
        )
    try:
        kv.vault_name(vault.name)
    except argparse.ArgumentTypeError:
        raise kv.SafeError("Azure returned an invalid vault name.") from None
    return match[2]


def select_vault(credential, stack, args):
    if args.vault:
        client = kv.secret_client(stack, credential, args)
        return client
    if args.subscription:
        subscription = kv.resolve_subscription(credential, args.subscription)
    else:
        subscription = choose_subscription(credential)
    with kv.KeyVaultManagementClient(
        credential, subscription.subscription_id, logging_enable=False
    ) as manager:
        vaults = list(manager.vaults.list_by_subscription())
    vault = choose(
        "Vaults",
        vaults,
        lambda item: f"{quoted(item.name)} [{quoted(item.location)}]",
        lambda item: (item.name, item.id),
    )
    args.subscription = subscription.subscription_id
    args.resource_group = resource_group(vault, subscription.subscription_id)
    args.vault = vault.name
    return kv.secret_client(stack, credential, args)


def choose_subscription(credential):
    with kv.SubscriptionClient(credential, logging_enable=False) as client:
        subscriptions = [
            item for item in client.subscriptions.list() if item.state == "Enabled"
        ]
    return choose(
        "Subscriptions",
        subscriptions,
        lambda item: f"{quoted(item.display_name)} [{quoted(item.subscription_id)}]",
        lambda item: (item.display_name, item.subscription_id),
    )


def select_resources(credential, stack, args=None):
    args = args or SimpleNamespace(
        vault=None, subscription=None, resource_group=None, secret=None
    )
    client = select_vault(credential, stack, args)
    if args.secret:
        return client, args.secret
    # This operation returns names/properties, never the secret values.
    secrets = list(client.list_properties_of_secrets())
    secret = choose(
        "Secrets",
        secrets,
        lambda item: (
            f"{quoted(item.name)}" + (" [disabled]" if item.enabled is False else "")
        ),
        lambda item: (item.name,),
    )
    if secret.enabled is False:
        raise kv.SafeError(
            "The selected secret is disabled. Choose an enabled secret on the next run."
        )
    try:
        kv.secret_name(secret.name)
    except argparse.ArgumentTypeError:
        raise kv.SafeError("Azure returned an invalid secret name.") from None
    args.secret = secret.name
    say(f"\nSelected vault {quoted(args.vault)}, secret {quoted(secret.name)}.")
    return client, secret.name


def output_choice(args):
    if args.stdout:
        return "stdout", None
    if args.output_file:
        return "file", args.output_file.expanduser()
    say("\nOutput options:")
    say("  1. Verify retrieval only; keep the value hidden (default)")
    say("  2. Save to a NEW owner-only plaintext file (0600)")
    say("  3. Reveal a JSON-escaped value in this terminal (confirmation required)")
    while True:
        answer = ask("Choose output [1] (q to quit):")
        if answer in {"", "1"}:
            return "verify", None
        if answer == "2":
            path = ask("New file path (parent directory must exist; q to quit):")
            if path:
                return "file", Path(path).expanduser()
            say("A file path is required.")
        elif answer == "3":
            if not sys.stdout.isatty():
                say(
                    "Terminal reveal requires terminal stdout. Use --stdout for a trusted pipe."
                )
                continue
            say(
                "Warning: the value will remain in terminal scrollback or session recordings."
            )
            if (
                ask("Type REVEAL to display the value (anything else cancels):")
                != "REVEAL"
            ):
                raise Cancelled
            return "reveal", None
        else:
            say("Choose 1, 2, or 3.")


def retrieve(client, name, mode, path):
    # Deliberately retrieve only the selected secret and only after output consent.
    secret = client.get_secret(name)
    if secret.value is None:
        raise kv.SafeError("Azure did not return a secret value.")
    if mode == "file":
        kv.write_secret_file(path, secret.value)
        say(
            "Secret written to a new owner-only plaintext file. Delete it when no longer needed."
        )
    elif mode == "stdout":
        sys.stdout.write(secret.value)
        sys.stdout.flush()
    elif mode == "reveal":
        print(quoted(secret.value))
    else:
        say("Retrieval succeeded. Value hidden; nothing saved.")


def read_value(path):
    """Read one secret, fail closed on echoed input, symlinks, or permissive files."""
    if path:
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path.expanduser(), flags)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise kv.SafeError(
                    "Input must be a regular file owned by you with no group/other access. Use chmod 600."
                )
            data = source.read(25 * 1024 + 1)
        try:
            value = data.decode("utf-8")
        except UnicodeError:
            raise kv.SafeError(
                "Input must be UTF-8 text; binary imports are not supported."
            ) from None
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("error", kv.getpass.GetPassWarning)
            value = kv.getpass.getpass("New secret value (hidden): ")
            repeated = kv.getpass.getpass("Repeat new secret value (hidden): ")
        if value != repeated:
            raise kv.SafeError("Secret values do not match; nothing written.")
    if not value or len(value.encode("utf-8")) > 25 * 1024:
        raise kv.SafeError("Secret value must contain 1 to 25600 UTF-8 bytes.")
    return value


def write_value(client, args, action):
    if not args.secret:
        try:
            args.secret = kv.secret_name(ask("Secret name (q to quit):"))
        except argparse.ArgumentTypeError:
            raise kv.SafeError(
                "Invalid secret name: use 1-127 letters, digits, or hyphens."
            ) from None
    existing = next(
        (
            item
            for item in client.list_properties_of_secrets()
            if item.name.lower() == args.secret.lower()
        ),
        None,
    )
    if action == "create" and existing:
        raise kv.SafeError("Secret already exists. Use update to create a new version.")
    if action == "update" and not existing:
        raise kv.SafeError("Secret does not exist. Use create instead.")
    say(f"{action.upper()} vault {quoted(args.vault)}, secret {quoted(args.secret)}.")
    say(
        "Azure set creates a new version. Existence checks are advisory, not atomic concurrency locks."
    )
    if (
        ask(
            f"Type {action.upper()} to confirm the Azure write (anything else cancels):"
        )
        != action.upper()
    ):
        raise Cancelled
    value = read_value(args.input_file)
    properties = {}
    if existing:
        for name in ("enabled", "expires_on", "not_before", "content_type", "tags"):
            current = getattr(existing, name, None)
            if current is not None:
                properties[name] = current
    # Never display the SDK response: it contains the newly written value.
    args.write_started = True
    client.set_secret(args.secret, value, **properties)
    args.write_confirmed = True
    say("Secret written successfully; value hidden. Azure created a new version.")


class SessionReport:
    """An allowlisted metadata report, not a durable or tamper-proof audit log."""

    def __init__(self):
        self.events = []

    def record(self, action, args, status):
        self.events.append(
            {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 - Python 3.10 support.
                "operation": action,
                "subscription": args.subscription,
                "vault": args.vault,
                "secret": args.secret,
                "status": status,
            }
        )

    def render(self):
        return json.dumps(
            {"scope": "this CLI process only", "events": self.events},
            ensure_ascii=True,
            indent=2,
        )

    def show(self):
        say("\nSession request report (metadata only; not Azure audit logs):")
        say(self.render())

    def save(self, path):
        kv.write_secret_file(path.expanduser(), self.render())
        say("Session metadata report saved to a new owner-only JSON file.")


def perform(action, args, credential, report):
    status = "failed"
    args.write_started = False
    args.write_confirmed = False
    try:
        with ExitStack() as stack:
            if action == "auth":
                if args.subscription:
                    kv.resolve_subscription(credential, args.subscription)
                say(
                    "Service-principal authentication verified; token not displayed or persisted."
                )
            elif action == "vaults":
                subscription = (
                    kv.resolve_subscription(credential, args.subscription)
                    if args.subscription
                    else choose_subscription(credential)
                )
                args.subscription = subscription.subscription_id
                with kv.KeyVaultManagementClient(
                    credential, subscription.subscription_id, logging_enable=False
                ) as manager:
                    say(
                        json.dumps(
                            [
                                {"name": item.name, "location": item.location}
                                for item in manager.vaults.list_by_subscription()
                            ],
                            ensure_ascii=True,
                        )
                    )
            elif action == "get":
                client, name = select_resources(credential, stack, args)
                mode, path = output_choice(args)
                retrieve(client, name, mode, path)
            else:
                client = select_vault(credential, stack, args)
                if action == "check":
                    next(iter(client.list_properties_of_secrets()), None)
                    say(
                        "Vault connection and secret List permission verified. Get/Set permissions not tested."
                    )
                elif action == "secrets":
                    say(
                        json.dumps(
                            [
                                {"name": item.name, "enabled": item.enabled}
                                for item in client.list_properties_of_secrets()
                            ],
                            ensure_ascii=True,
                        )
                    )
                else:
                    write_value(client, args, action)
        status = "success"
    except (Cancelled, KeyboardInterrupt, EOFError):
        status = "cancelled"
        raise
    finally:
        if args.write_started and not args.write_confirmed:
            status = "unknown"
            say(
                "Write outcome is unknown. Check the latest secret metadata before retrying; Azure may have accepted the request."
            )
        report.record(action, args, status)


def session(args, credential, report):
    say(
        "One authenticated session. History stays in memory unless explicitly exported."
    )
    while True:
        say(
            "\nSession: 1 list secrets | 2 get | 3 create/import | 4 update | 5 report | 6 export report | 7 doctor | q exit"
        )
        answer = "q"
        try:
            answer = ask("Choose an action:")
            if answer == "5":
                report.show()
            elif answer == "6":
                path = ask("New JSON report path (q to cancel):")
                if path:
                    report.save(Path(path))
            elif answer == "7":
                import doctor

                result = doctor.run(
                    online=True,
                    credential=credential,
                    vault=args.vault,
                    subscription=args.subscription,
                    resource_group=args.resource_group,
                    secret=args.secret,
                )
                report.record("doctor", args, "success" if result == 0 else "failed")
            elif answer in {"1", "2", "3", "4"}:
                current = SimpleNamespace(**vars(args))
                # Ask each time unless the session was scoped with explicit selectors.
                perform(
                    {"1": "secrets", "2": "get", "3": "create", "4": "update"}[answer],
                    current,
                    credential,
                    report,
                )
            else:
                say("Choose an action from the menu.")
        except Cancelled:
            if answer.lower() in {"q", "quit"}:
                break
            say("Operation cancelled; session remains open.")
        except (KeyboardInterrupt, EOFError):
            break
        except Exception as error:  # noqa: BLE001 - Continue session without leaking SDK responses.
            say(f"Error: {kv.error_message(error)}")


def parser_for_cli():
    parser = argparse.ArgumentParser(
        description=(
            "Interactively select a subscription, vault, and secret using a service principal. "
            "Type q at any menu to quit. Default output verifies retrieval without displaying values."
        ),
        epilog=(
            "Requires Python 3.10+, dependencies from requirements.txt, and sibling "
            "../keyvault/keyvault_common.py. Azure Public Cloud only. "
            "Requires resource-discovery read permissions plus secret List/Get permissions "
            "(for RBAC vaults, typically vault-scoped Key Vault Secrets User). "
            "Missing identifiers are prompted; the client secret is always a hidden prompt "
            "unless AZURE_CLIENT_SECRET is injected by a trusted secret manager. "
            "Create/update require List/Set and explicit confirmation; update creates a version, "
            "preserves metadata, and uses an advisory existence check, not a concurrency lock. "
            "Secret values come only from hidden double-entry or --input-file; never arguments. "
            "Session reports contain metadata only and cover this process, not Azure audit logs. "
            "No Azure CLI login or persistent token cache is used. "
            "All menus go to stderr. Exit codes: 0 success, 1 failure, 2 usage error, 130 cancellation."
        ),
    )
    parser.add_argument(
        "--tenant-id", type=kv.guid, default=os.getenv("AZURE_TENANT_ID") or None
    )
    parser.add_argument(
        "--client-id", type=kv.guid, default=os.getenv("AZURE_CLIENT_ID") or None
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="get",
        choices=[
            "auth",
            "vaults",
            "check",
            "secrets",
            "get",
            "create",
            "update",
            "session",
        ],
    )
    parser.add_argument(
        "--vault", type=kv.vault_name, default=os.getenv("VAULT") or None
    )
    parser.add_argument(
        "--secret", type=kv.secret_name, default=os.getenv("SECRET") or None
    )
    parser.add_argument("--subscription", default=os.getenv("SUBSCRIPTION") or None)
    parser.add_argument("--resource-group", default=os.getenv("RESOURCE_GROUP") or None)
    parser.add_argument(
        "--input-file",
        type=Path,
        default=os.getenv("INPUT_FILE") or None,
        help="Create/update from an owner-only UTF-8 file; otherwise hidden double-entry.",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        default=os.getenv("REPORT_FILE") or None,
        help="Export this invocation's metadata report to a NEW 0600 JSON file.",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--output-file",
        type=Path,
        default=os.getenv("OUTPUT_FILE") or None,
        help="After selection, write a new 0600 plaintext file, refusing overwrites/symlinks.",
    )
    output.add_argument(
        "--stdout",
        action="store_true",
        help="After selection, emit the exact value to a trusted pipe; refuses terminal stdout.",
    )
    return parser


def main(argv=None):
    parser = parser_for_cli()
    args = parser.parse_args(argv)
    if args.vault and bool(args.subscription) != bool(args.resource_group):
        parser.error(
            "A named vault needs both --subscription and --resource-group for membership verification, or neither."
        )
    if args.resource_group and not args.subscription:
        parser.error("--resource-group requires --subscription.")
    if args.stdout and (args.action != "get" or args.output_file):
        parser.error(
            "--stdout is only available for one-shot get and cannot accompany an output file."
        )
    if args.input_file and args.action not in {"create", "update", "session"}:
        parser.error("--input-file is only for create/update/session.")
    if not sys.stdin.isatty():
        parser.error(
            "Interactive selection requires terminal stdin. Use the individual scripts for automation."
        )
    if args.stdout and sys.stdout.isatty():
        parser.error("--stdout refuses terminal output; pipe to a trusted consumer.")
    report = SessionReport()
    result = 0
    auth_started = False
    authenticated = False
    try:
        say("Key Vault secret retrieval — service principal only.")
        args.tenant_id = prompt_guid(args.tenant_id, "Tenant ID")
        args.client_id = prompt_guid(args.client_id, "Client ID")
        auth_started = True
        with ExitStack() as stack:
            credential = stack.enter_context(kv.create_credential(args))
            credential.get_token(kv.ARM_SCOPE)
            authenticated = True
            say("Service-principal authentication succeeded.")
            if args.action != "auth":
                report.record("auth", args, "success")
            if args.action == "session":
                session(args, credential, report)
            else:
                perform(args.action, args, credential, report)
    except (Cancelled, KeyboardInterrupt, EOFError):
        say("Cancelled.")
        result = 130
    except Exception as error:  # noqa: BLE001 - Sanitize all SDK/I/O failures.
        say(f"Error: {kv.error_message(error)}")
        result = 1
    finally:
        if auth_started and not authenticated:
            report.record("auth", args, "cancelled" if result == 130 else "failed")
        if args.action == "session":
            report.show()
        if args.report_file:
            try:
                report.save(args.report_file)
            except Exception as error:  # noqa: BLE001 - Report export must also remain sanitized.
                say(f"Report export failed: {kv.error_message(error)}")
                result = 1
    return result


if __name__ == "__main__":
    raise SystemExit(main())
