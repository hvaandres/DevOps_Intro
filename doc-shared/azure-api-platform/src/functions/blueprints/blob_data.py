"""Blob Storage data endpoints — read-only access with pagination and streaming."""
import json
import logging
from datetime import UTC, datetime, timedelta

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.storage.blob import (
    BlobServiceClient,
    ContainerSasPermissions,
    generate_container_sas,
)

bp = func.Blueprint()
logger = logging.getLogger(__name__)

# Lazy-initialized client (reused across invocations)
_blob_service_client: BlobServiceClient | None = None


def _get_blob_client() -> BlobServiceClient:
    """Get or create a BlobServiceClient using Managed Identity."""
    global _blob_service_client
    if _blob_service_client is None:
        import os
        account_url = os.environ.get(
            "STORAGE_ACCOUNT_URL",
            "https://<storage-account>.blob.core.windows.net",
        )
        credential = DefaultAzureCredential()
        _blob_service_client = BlobServiceClient(account_url, credential=credential)
    return _blob_service_client


@bp.route(route="blob-data", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def list_blobs(req: func.HttpRequest) -> func.HttpResponse:
    """
    List blobs in the data container with cursor-based pagination.

    Query params:
        - container: container name (default: "data")
        - prefix: blob name prefix filter
        - page_size: number of items per page (default: 100, max: 1000)
        - continuation_token: token from previous response for next page
    """
    try:
        container_name = req.params.get("container", "data")
        prefix = req.params.get("prefix", "")
        page_size = min(int(req.params.get("page_size", "100")), 1000)
        continuation_token = req.params.get("continuation_token")

        client = _get_blob_client()
        container_client = client.get_container_client(container_name)

        # Use SDK pagination
        blobs_pages = container_client.list_blobs(
            name_starts_with=prefix or None,
            results_per_page=page_size,
        ).by_page(continuation_token=continuation_token)

        page = next(blobs_pages)
        items = [
            {
                "name": blob.name,
                "size": blob.size,
                "last_modified": blob.last_modified.isoformat() if blob.last_modified else None,
                "content_type": blob.content_settings.content_type if blob.content_settings else None,
            }
            for blob in page
        ]

        response_body = {
            "items": items,
            "count": len(items),
            "continuation_token": blobs_pages.continuation_token,
        }

        return func.HttpResponse(
            body=json.dumps(response_body, default=str),
            mimetype="application/json",
            status_code=200,
        )

    except StopIteration:
        return func.HttpResponse(
            body=json.dumps({"items": [], "count": 0, "continuation_token": None}),
            mimetype="application/json",
            status_code=200,
        )
    except Exception:
        logger.exception("Error listing blobs")
        return func.HttpResponse(
            body=json.dumps({"error": "Internal server error"}),
            mimetype="application/json",
            status_code=500,
        )


@bp.route(
    route="blob-data/{container}/{blob}",
    methods=["GET"],
    auth_level=func.AuthLevel.FUNCTION,
)
def get_blob(req: func.HttpRequest) -> func.HttpResponse:
    """
    Get a specific blob. For large blobs (>50MB), returns a time-limited read-only SAS URL
    instead of streaming the content directly.

    Path params:
        - container: container name
        - blob: blob name (path)

    Query params:
        - download: if "true", stream the blob content directly (for small blobs)
    """
    try:
        container_name = req.route_params.get("container", "data")
        blob_name = req.route_params.get("blob", "")
        download = req.params.get("download", "false").lower() == "true"

        client = _get_blob_client()
        blob_client = client.get_blob_client(container_name, blob_name)
        properties = blob_client.get_blob_properties()

        size_mb = (properties.size or 0) / (1024 * 1024)

        # For large blobs, return a read-only SAS URL
        if size_mb > 50 and not download:
            # Generate user delegation key (Managed Identity)
            delegation_key = client.get_user_delegation_key(
                key_start_time=datetime.now(UTC),
                key_expiry_time=datetime.now(UTC) + timedelta(hours=1),
            )
            sas_token = generate_container_sas(
                account_name=client.account_name,
                container_name=container_name,
                user_delegation_key=delegation_key,
                permission=ContainerSasPermissions(read=True),
                expiry=datetime.now(UTC) + timedelta(hours=1),
            )
            sas_url = f"{blob_client.url}?{sas_token}"

            return func.HttpResponse(
                body=json.dumps({
                    "blob": blob_name,
                    "size_bytes": properties.size,
                    "content_type": properties.content_settings.content_type,
                    "sas_url": sas_url,
                    "expires_in": "1 hour",
                }),
                mimetype="application/json",
                status_code=200,
            )

        # For smaller blobs, stream directly
        download_stream = blob_client.download_blob()
        content = download_stream.readall()

        return func.HttpResponse(
            body=content,
            mimetype=properties.content_settings.content_type or "application/octet-stream",
            status_code=200,
        )

    except Exception as e:
        logger.exception("Error accessing blob")
        if "BlobNotFound" in str(e):
            return func.HttpResponse(
                body=json.dumps({"error": "Blob not found"}),
                mimetype="application/json",
                status_code=404,
            )
        return func.HttpResponse(
            body=json.dumps({"error": "Internal server error"}),
            mimetype="application/json",
            status_code=500,
        )
