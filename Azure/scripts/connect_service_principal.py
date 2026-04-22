"""
Connect to Azure using a Service Principal.

Prerequisites:
    pip install azure-identity azure-mgmt-resource python-dotenv

Environment variables required (set directly or via a .env file):
    AZURE_TENANT_ID       - Directory (tenant) ID
    AZURE_CLIENT_ID       - Application (client) ID of the service principal
    AZURE_CLIENT_SECRET   - Client secret value
    AZURE_SUBSCRIPTION_ID - Subscription ID to operate against
"""

import os
import sys

from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from dotenv import load_dotenv


def get_service_principal_credential() -> ClientSecretCredential:
    """Build a ClientSecretCredential from environment variables."""
    load_dotenv()

    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    missing = [
        name
        for name, value in {
            "AZURE_TENANT_ID": tenant_id,
            "AZURE_CLIENT_ID": client_id,
            "AZURE_CLIENT_SECRET": client_secret,
        }.items()
        if not value
    ]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}"
        )

    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def main() -> int:
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        print("ERROR: AZURE_SUBSCRIPTION_ID is not set.", file=sys.stderr)
        return 1

    try:
        credential = get_service_principal_credential()
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # Smoke-test the credential by listing the resource groups in the subscription.
    resource_client = ResourceManagementClient(credential, subscription_id)

    print(f"Successfully authenticated. Resource groups in {subscription_id}:")
    for group in resource_client.resource_groups.list():
        print(f"  - {group.name} ({group.location})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
