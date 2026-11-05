"""Read-only setup and Azure troubleshooting; imports Azure SDKs only when ready."""

import argparse
import importlib
import os
import shutil
import socket
import ssl
import stat
import sys
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

ROOT = Path(__file__).resolve().parent
PACKAGES = (
    "azure.identity",
    "azure.keyvault.secrets",
    "azure.mgmt.keyvault",
    "azure.mgmt.resource.subscriptions",
)


def emit(results, stage, status, message):
    results.append({"stage": stage, "status": status, "message": message})
    print(f"[{status.upper()}] {stage}: {message}", file=sys.stderr)


def guidance(error, stage):
    """Use error type/status only, never raw exceptions or HTTP bodies."""
    status = getattr(error, "status_code", None)
    if status == 403:
        if stage == "subscription":
            return "ARM denied access. Ask an administrator for read access at the intended scope; allow RBAC propagation."
        return (
            "Vault denied access. Check the principal's List/Get permissions (Key Vault Secrets User "
            "for reads), RBAC propagation, access-policy mode, firewall and private-endpoint routing. "
            "403 alone does not identify which cause applies."
        )
    if status == 404:
        return "Resource was not found. Verify the subscription, resource group, vault or secret name and Azure cloud."
    if status == 429:
        return "Azure throttled the request. Retry later; do not rotate credentials for this error."
    if status == 401 or type(error).__name__ == "ClientAuthenticationError":
        return "Authentication rejected. Verify tenant/client IDs and the client secret VALUE (not secret ID), expiry, app status and tenant policy."
    if isinstance(error, ssl.SSLCertVerificationError):
        return "TLS certificate validation failed. Check system time, trusted corporate CA and SSL_CERT_FILE/REQUESTS_CA_BUNDLE; never disable TLS verification."
    if isinstance(error, socket.gaierror):
        return "DNS lookup failed. Check internet/VPN, DNS resolvers and private-endpoint DNS configuration."
    if isinstance(error, (TimeoutError, ConnectionError, OSError)):
        return "Connection failed. Check outbound HTTPS, VPN/private routing, firewall, proxy and certificate trust."
    return (
        "Probe failed; details suppressed. Check identifiers, credential expiry, proxy/CA configuration "
        "and DNS/VPN reachability. Run make setup if SDK imports are broken."
    )


def local_checks(results):
    emit(
        results,
        "Python",
        "pass" if sys.version_info >= (3, 10) else "fail",
        "Python 3.10+ is available."
        if sys.version_info >= (3, 10)
        else "Install Python 3.10+; macOS: brew install python.",
    )
    emit(
        results,
        "Make",
        "pass" if shutil.which("make") else "fail",
        "Make is available."
        if shutil.which("make")
        else "Install Make; macOS: xcode-select --install; Debian/Ubuntu: install make via your package manager.",
    )
    emit(
        results,
        "virtual environment",
        "pass" if sys.prefix != sys.base_prefix else "warn",
        "Using an isolated environment."
        if sys.prefix != sys.base_prefix
        else "Run make setup; Make will use keyvault-cli/.venv automatically.",
    )
    ready = True
    for name in PACKAGES:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001 - Broken optional imports must be diagnosed without tracebacks.
            ready = False
            emit(
                results,
                name,
                "fail",
                "Missing/broken Azure dependency. Run make setup in keyvault or keyvault-cli.",
            )
        else:
            emit(results, name, "pass", "Import succeeded.")
    for name in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID"):
        value = os.getenv(name)
        if not value:
            emit(
                results,
                name,
                "warn",
                "Not configured; interactive commands will prompt for this non-secret UUID.",
            )
        else:
            try:
                UUID(value)
            except ValueError:
                emit(
                    results,
                    name,
                    "fail",
                    "Invalid UUID. Correct this identifier; no credential value is displayed.",
                )
            else:
                emit(results, name, "pass", "Configured identifier has UUID format.")
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.getenv(name)
        if value and not Path(value).is_file():
            emit(
                results,
                name,
                "fail",
                "Configured CA file is missing. Restore the trusted CA bundle or correct this setting.",
            )
    if any(
        os.getenv(name)
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
    ):
        emit(
            results,
            "proxy",
            "warn",
            "Proxy is configured (value hidden). Confirm trusted HTTPS proxy and CA settings; direct TLS probes may differ from SDK routing.",
        )
    for name in ("OUTPUT_FILE", "REPORT_FILE"):
        value = os.getenv(name)
        if value:
            path = Path(value).expanduser()
            bad = (
                path.exists()
                or path.is_symlink()
                or not path.parent.is_dir()
                or not os.access(path.parent, os.W_OK | os.X_OK)
            )
            emit(
                results,
                name,
                "fail" if bad else "pass",
                "Use a NEW path in an existing writable directory; existing files/symlinks are refused."
                if bad
                else "New destination has an accessible parent; actual creation is checked during use.",
            )
    if os.getenv("INPUT_FILE"):
        try:
            info = Path(os.environ["INPUT_FILE"]).expanduser().lstat()
            safe = (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and not info.st_mode & 0o077
            )
        except OSError:
            safe = False
        emit(
            results,
            "INPUT_FILE",
            "pass" if safe else "fail",
            "Protected regular input file found; contents not read."
            if safe
            else "Use an existing regular file owned by you; chmod 600. Symlinks are refused.",
        )
    emit(
        results,
        "Azure CLI",
        "info",
        "Not required: this tool authenticates the explicit service principal directly through the Azure SDK.",
    )
    return ready


def probe_tls(host):
    with (
        socket.create_connection((host, 443), timeout=5) as connection,
        ssl.create_default_context().wrap_socket(connection, server_hostname=host),
    ):
        pass


def online_checks(results, credential, vault, subscription, secret, resource_group):
    sys.path.insert(0, str(ROOT.parent / "keyvault"))
    import keyvault_common as kv

    if vault:
        try:
            kv.vault_name(vault)
            if secret:
                kv.secret_name(secret)
        except argparse.ArgumentTypeError:
            emit(
                results,
                "selectors",
                "fail",
                "Invalid vault/secret name. Use names only, not URLs.",
            )
            return
    for stage, host in (
        ("Entra DNS/TLS", "login.microsoftonline.com"),
        ("ARM DNS/TLS", "management.azure.com"),
        *(([("vault DNS/TLS", f"{vault}.vault.azure.net")]) if vault else []),
    ):
        try:
            probe_tls(host)
        except Exception as error:  # noqa: BLE001 - Each read-only probe has isolated, redacted output.
            emit(results, stage, "warn", guidance(error, stage))
        else:
            emit(
                results,
                stage,
                "pass",
                "Direct DNS/TLS connection succeeded; this does not prove Azure authorization.",
            )
    with ExitStack() as stack:
        if credential is None:
            tenant, client = os.getenv("AZURE_TENANT_ID"), os.getenv("AZURE_CLIENT_ID")
            if not tenant or not client:
                emit(
                    results,
                    "authentication",
                    "fail",
                    "Set AZURE_TENANT_ID and AZURE_CLIENT_ID, then rerun make doctor ONLINE=1. Never put a credential value in Make arguments.",
                )
                return
            try:
                args = SimpleNamespace(
                    tenant_id=kv.guid(tenant), client_id=kv.guid(client)
                )
                credential = stack.enter_context(kv.create_credential(args))
            except Exception as error:  # noqa: BLE001
                emit(
                    results, "authentication", "fail", guidance(error, "authentication")
                )
                return
        try:
            credential.get_token(kv.ARM_SCOPE)
        except Exception as error:  # noqa: BLE001
            emit(results, "authentication", "fail", guidance(error, "authentication"))
            return
        emit(
            results,
            "authentication",
            "pass",
            "Explicit service-principal token obtained; token hidden and not persisted.",
        )
        if subscription:
            try:
                kv.resolve_subscription(credential, subscription)
            except Exception as error:  # noqa: BLE001
                emit(results, "subscription", "fail", guidance(error, "subscription"))
                return
            emit(
                results,
                "subscription",
                "pass",
                "Selected subscription is accessible and enabled.",
            )
        if not vault:
            emit(
                results,
                "vault List/Get",
                "skip",
                "Supply VAULT=name; optionally SECRET=name to test Get with the value discarded.",
            )
            return
        try:
            if bool(subscription) != bool(resource_group):
                emit(
                    results,
                    "vault membership",
                    "fail",
                    "Supply SUBSCRIPTION and RESOURCE_GROUP together, or neither for direct vault checks.",
                )
                return
            if subscription:
                kv.secret_client(
                    stack,
                    credential,
                    SimpleNamespace(
                        vault=vault,
                        subscription=subscription,
                        resource_group=resource_group,
                    ),
                )
            client = stack.enter_context(
                kv.SecretClient(
                    vault_url=f"https://{vault}.vault.azure.net",
                    credential=credential,
                    logging_enable=False,
                    connection_timeout=5,
                    read_timeout=10,
                    retry_total=0,
                )
            )
        except Exception as error:  # noqa: BLE001
            emit(results, "vault membership", "fail", guidance(error, "subscription"))
            return
        for stage, probe in (
            (
                "vault List",
                lambda: next(iter(client.list_properties_of_secrets()), None),
            ),
            *(([("vault Get", lambda: client.get_secret(secret))]) if secret else []),
        ):
            try:
                probe()  # Returned values are deliberately discarded, never printed.
            except Exception as error:  # noqa: BLE001
                emit(results, stage, "fail", guidance(error, stage))
            else:
                emit(
                    results,
                    stage,
                    "pass",
                    "Read-only probe succeeded; no secret value displayed or saved.",
                )


def run(
    online=False,
    credential=None,
    vault=None,
    subscription=None,
    secret=None,
    resource_group=None,
):
    results = []
    ready = local_checks(results)
    if online and ready:
        online_checks(results, credential, vault, subscription, secret, resource_group)
    elif online:
        emit(
            results,
            "online checks",
            "skip",
            "Install dependencies with make setup before online checks.",
        )
    else:
        emit(
            results,
            "online checks",
            "skip",
            "Local-only mode. Run make doctor ONLINE=1 VAULT=name for read-only Azure checks.",
        )
    emit(
        results,
        "write permissions",
        "unknown",
        "Not tested: Doctor never creates secrets or changes RBAC/networking. Writes require Set permission; ask an administrator for a narrowly scoped role.",
    )
    return 1 if any(item["status"] == "fail" for item in results) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--online", action="store_true", default=os.getenv("ONLINE") == "1"
    )
    parser.add_argument("--vault", default=os.getenv("VAULT") or None)
    parser.add_argument("--subscription", default=os.getenv("SUBSCRIPTION") or None)
    parser.add_argument("--resource-group", default=os.getenv("RESOURCE_GROUP") or None)
    parser.add_argument("--secret", default=os.getenv("SECRET") or None)
    args = parser.parse_args()
    return run(**vars(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("Doctor cancelled.", file=sys.stderr)
        raise SystemExit(130) from None
    except Exception:  # noqa: BLE001 - Last-resort diagnostics must never expose secrets.
        print(
            "Doctor could not finish. Run make setup; check Python, file permissions and configured CA/proxy settings.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
