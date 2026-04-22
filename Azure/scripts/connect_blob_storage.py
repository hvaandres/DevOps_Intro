"""
Connect to Azure Blob Storage using a Service Principal.

Prerequisites:
    pip install azure-identity azure-storage-blob python-dotenv

The service principal must have an RBAC role on the storage account that grants
data-plane access, e.g. "Storage Blob Data Reader" or "Storage Blob Data Contributor".

Environment variables required (set directly or via a .env file):
    AZURE_TENANT_ID        - Directory (tenant) ID
    AZURE_CLIENT_ID        - Application (client) ID of the service principal
    AZURE_CLIENT_SECRET    - Client secret value
    AZURE_STORAGE_ACCOUNT  - Storage account name (e.g. "mystorageacct")
    AZURE_STORAGE_CONTAINER (optional) - Container to inspect/upload to
"""

import os
import sys
from datetime import datetime

from azure.core.exceptions import AzureError
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv


def get_service_principal_credential() -> ClientSecretCredential:
    """Build a ClientSecretCredential from environment variables."""
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


def get_blob_service_client(account_name: str) -> BlobServiceClient:
    """Return a BlobServiceClient authenticated via service principal."""
    credential = get_service_principal_credential()
    account_url = f"https://{account_name}.blob.core.windows.net"
    return BlobServiceClient(account_url=account_url, credential=credential)


def list_containers(blob_service_client: BlobServiceClient) -> None:
    print("Containers in this storage account:")
    for container in blob_service_client.list_containers():
        print(f"  - {container.name}")


def list_blobs(blob_service_client: BlobServiceClient, container_name: str) -> None:
    container_client = blob_service_client.get_container_client(container_name)
    print(f"Blobs in container '{container_name}':")
    for blob in container_client.list_blobs():
        size_kb = (blob.size or 0) / 1024
        print(f"  - {blob.name} ({size_kb:.2f} KB)")


def upload_sample_blob(
    blob_service_client: BlobServiceClient, container_name: str
) -> None:
    """Upload a small timestamped sample blob to verify write access."""
    container_client = blob_service_client.get_container_client(container_name)
    blob_name = f"sample-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.txt"
    content = f"Hello from service principal at {datetime.utcnow().isoformat()}Z\n"
    container_client.upload_blob(name=blob_name, data=content, overwrite=True)
    print(f"Uploaded sample blob: {blob_name}")


def main() -> int:
    load_dotenv()

    account_name = os.getenv("AZURE_STORAGE_ACCOUNT")
    if not account_name:
        print("ERROR: AZURE_STORAGE_ACCOUNT is not set.", file=sys.stderr)
        return 1

    container_name = os.getenv("AZURE_STORAGE_CONTAINER")

    try:
        blob_service_client = get_blob_service_client(account_name)
        list_containers(blob_service_client)

        if container_name:
            list_blobs(blob_service_client, container_name)
            # Uncomment the next line to test write access:
            # upload_sample_blob(blob_service_client, container_name)
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except AzureError as exc:
        print(f"Azure error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
