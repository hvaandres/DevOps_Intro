"""Reusable, read-only Azure Public Cloud service layer and script arguments.

Requires Python 3.10+. No Azure CLI session, persistent credential cache, or
fallback user identity is used. Python cannot guarantee zeroization of secrets
in memory; run only on a trusted host and avoid debuggers or process dumps.
"""

import argparse
import getpass
import json
import logging
import os
import re
import sys
import warnings
from contextlib import ExitStack
from pathlib import Path
from uuid import UUID

from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient

ARM_SCOPE = "https://management.azure.com/.default"
DESCRIPTIONS = {
    "login": "Validate service-principal login; optionally check subscription access.",
    "vaults": "List vault names in one subscription (control-plane permission required).",
    "check": "Check vault connectivity and secret-list permission, not secret-get permission.",
    "secrets": "List secret names and metadata without retrieving their values.",
    "get": "Retrieve a secret; default: validate access without exposing its value.",
}


class SafeError(Exception):
    """An intentionally non-sensitive message suitable for terminal output."""


def guid(value):
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError("Expected a UUID.") from None


def vault_name(value):
    if (
        not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]", value)
        or "--" in value
    ):
        raise argparse.ArgumentTypeError(
            "Vault names need 3-24 letters/digits/hyphens, start with a letter, "
            "end with a letter/digit, and cannot contain consecutive hyphens."
        )
    return value


def secret_name(value):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,127}", value):
        raise argparse.ArgumentTypeError(
            "Secret names need 1-127 letters, digits, or hyphens."
        )
    return value


def parser_for(action):
    parser = argparse.ArgumentParser(
        description=DESCRIPTIONS[action],
        epilog=(
            "Azure Public Cloud only. Use AZURE_TENANT_ID and AZURE_CLIENT_ID "
            "or the identifier flags. The client secret is read from a hidden "
            "terminal prompt, or AZURE_CLIENT_SECRET supplied by a trusted secret "
            "manager. No client-secret command-line flag exists. Exit codes: "
            "0 success, 1 operation failure, 2 input error, 130 cancelled."
        ),
    )
    parser.add_argument("--tenant-id", type=guid, default=os.getenv("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", type=guid, default=os.getenv("AZURE_CLIENT_ID"))
    parser.add_argument(
        "--subscription",
        default=os.getenv("AZURE_SUBSCRIPTION_ID"),
        help="Subscription UUID or exact display name; duplicate names are rejected.",
    )
    if action in {"check", "secrets", "get"}:
        parser.add_argument("--vault", required=True, type=vault_name)
        parser.add_argument(
            "--resource-group",
            help="With --subscription, verify this vault's subscription and resource group.",
        )
    if action == "get":
        parser.add_argument("--secret", required=True, type=secret_name)
        parser.add_argument(
            "--version", help="Optional 32-character hexadecimal version."
        )
        output = parser.add_mutually_exclusive_group()
        output.add_argument(
            "--output-file",
            type=Path,
            help="Create a new mode-0600 UTF-8 plaintext file; never overwrite.",
        )
        output.add_argument(
            "--stdout",
            action="store_true",
            help="Emit the exact value without a newline; refuses terminal stdout.",
        )
    return parser


def validate_args(parser, args, action):
    if not args.tenant_id or not args.client_id:
        parser.error("Set tenant/client IDs using environment variables or flags.")
    if action == "vaults" and not args.subscription:
        parser.error("--subscription (or AZURE_SUBSCRIPTION_ID) is required.")
    if action in {"check", "secrets", "get"} and bool(args.subscription) != bool(
        args.resource_group
    ):
        parser.error(
            "Supply both --subscription and --resource-group to verify vault "
            "membership, or neither for direct data-plane access."
        )
    if action == "get":
        if args.version and not re.fullmatch(r"[A-Fa-f0-9]{32}", args.version):
            parser.error("--version must be 32 hexadecimal characters.")
        if args.stdout and sys.stdout.isatty():
            parser.error(
                "--stdout refuses terminal output; pipe to a trusted consumer."
            )


def create_credential(args):
    # Suppress Azure diagnostics, including authentication exception messages.
    # We deliberately do not accept a debug/logging switch in these entry points.
    logging.getLogger("azure").disabled = True
    logging.getLogger("azure").propagate = False
    logging.getLogger("azure").addHandler(logging.NullHandler())
    for name in logging.root.manager.loggerDict:
        if name.startswith("azure."):
            logging.getLogger(name).disabled = True
    secret = os.environ.pop("AZURE_CLIENT_SECRET", None)
    if secret is None:
        # Fail closed if getpass cannot disable terminal echo (e.g. CI stdin).
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                secret = getpass.getpass("Service principal client secret: ")
            except getpass.GetPassWarning:
                raise SafeError(
                    "No hidden terminal input available. Inject AZURE_CLIENT_SECRET "
                    "using a trusted secret manager for noninteractive execution."
                ) from None
    if not secret:
        raise SafeError("The service-principal client secret must not be empty.")
    return ClientSecretCredential(
        tenant_id=args.tenant_id,
        client_id=args.client_id,
        client_secret=secret,
        logging_enable=False,
    )


def resolve_subscription(credential, selection):
    """Resolve exact display names without silently picking duplicate names."""
    with SubscriptionClient(credential, logging_enable=False) as client:
        try:
            subscription_id = str(UUID(selection))
        except ValueError:
            matches = [
                item
                for item in client.subscriptions.list()
                if item.display_name == selection
            ]
            if not matches:
                raise SafeError("No accessible subscription matches that exact name.")
            if len(matches) != 1:
                raise SafeError("Subscription name is ambiguous; use its UUID.")
            subscription = matches[0]
        else:
            subscription = client.subscriptions.get(subscription_id)
        if subscription.state != "Enabled":
            raise SafeError("The selected subscription is not enabled.")
        return subscription


def secret_client(stack, credential, args):
    if args.subscription:
        subscription = resolve_subscription(credential, args.subscription)
        with KeyVaultManagementClient(
            credential, subscription.subscription_id, logging_enable=False
        ) as manager:
            # A failed lookup must not fall back to another subscription/vault.
            vault = manager.vaults.get(args.resource_group, args.vault)
            expected = f"https://{args.vault}.vault.azure.net/"
            if vault.properties.vault_uri.lower().rstrip(
                "/"
            ) != expected.lower().rstrip("/"):
                raise SafeError(
                    "Vault endpoint does not match the expected public-cloud vault."
                )
    return stack.enter_context(
        SecretClient(
            vault_url=f"https://{args.vault}.vault.azure.net",
            credential=credential,
            logging_enable=False,
        )
    )


def write_secret_file(path, value):
    """Exclusive creation rejects existing files and symlinks, including dangling ones."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(value.encode("utf-8"))
    except BaseException:
        # Only remove the newly-created file, never a pre-existing destination.
        path.unlink(missing_ok=True)
        raise


def emit_metadata(value):
    # JSON escaping also prevents terminal control sequences in resource names.
    print(json.dumps(value, ensure_ascii=True))


def run_action(action, args, credential, stack):
    if action == "login":
        credential.get_token(ARM_SCOPE)
        result = {"authenticated": True, "identity": "service-principal"}
        if args.subscription:
            subscription = resolve_subscription(credential, args.subscription)
            result["subscription"] = subscription.display_name
            result["subscription_id"] = subscription.subscription_id
        emit_metadata(result)
        return
    if action == "vaults":
        subscription = resolve_subscription(credential, args.subscription)
        with KeyVaultManagementClient(
            credential, subscription.subscription_id, logging_enable=False
        ) as manager:
            emit_metadata(
                [
                    {"name": vault.name, "location": vault.location}
                    for vault in manager.vaults.list_by_subscription()
                ]
            )
        return
    client = secret_client(stack, credential, args)
    if action == "check":
        # Trigger a request even when the vault is empty, without getting values.
        next(iter(client.list_properties_of_secrets()), None)
        emit_metadata(
            {"vault": args.vault, "connected": True, "can_list_secrets": True}
        )
    elif action == "secrets":
        emit_metadata(
            [
                {
                    "name": item.name,
                    "enabled": item.enabled,
                    "expires_on": item.expires_on.isoformat()
                    if item.expires_on
                    else None,
                }
                for item in client.list_properties_of_secrets()
            ]
        )
    elif action == "get":
        secret = client.get_secret(args.secret, version=args.version)
        if secret.value is None:
            raise SafeError("Azure did not return a secret value.")
        if args.output_file:
            write_secret_file(args.output_file, secret.value)
            print("Secret written to a new owner-only file.", file=sys.stderr)
        elif args.stdout:
            sys.stdout.write(secret.value)
            sys.stdout.flush()
        else:
            emit_metadata(
                {
                    "vault": args.vault,
                    "secret": args.secret,
                    "retrieved": True,
                    "value": "[hidden]",
                }
            )


def error_message(error):
    # Never stringify SDK exceptions: responses can contain sensitive details.
    if isinstance(error, SafeError):
        return str(error)
    if isinstance(error, ClientAuthenticationError):
        return "Authentication failed. Check tenant/client IDs and credential validity."
    if isinstance(error, HttpResponseError):
        return {
            401: "Authentication was rejected by Azure.",
            403: "Access denied. Check RBAC/access policies, propagation, firewall, and private endpoint access.",
            404: "Resource not found. Check subscription, resource group, vault, secret, and version.",
            429: "Azure throttled the request. Retry later.",
        }.get(
            error.status_code,
            "Azure rejected the request. Check service health and permissions.",
        )
    if isinstance(error, (ServiceRequestError, ServiceResponseError)):
        return "Connection failed. Check DNS, TLS, VPN/private endpoint routing, and firewall rules."
    if isinstance(error, FileExistsError):
        return "Output path already exists; files and symlinks are never overwritten."
    if isinstance(error, OSError):
        return "Local I/O failed. Check the output directory, permissions, and downstream pipe."
    if isinstance(error, (EOFError, getpass.GetPassWarning)):
        return "Credential input unavailable. Use a hidden terminal prompt or a trusted secret manager."
    return "Operation failed. Check configuration and installed SDK versions; details suppressed."


def main(action, argv=None):
    parser = parser_for(action)
    args = parser.parse_args(argv)
    validate_args(parser, args, action)
    try:
        with ExitStack() as stack:
            credential = stack.enter_context(create_credential(args))
            run_action(action, args, credential, stack)
        return 0
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as error:  # noqa: BLE001 - Never leak raw SDK tracebacks or values.
        print(f"Error: {error_message(error)}", file=sys.stderr)
        return 1
