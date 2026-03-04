"""Cosmos DB data endpoints — read-only access with continuation token pagination."""
import json
import logging
import os

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

bp = func.Blueprint()
logger = logging.getLogger(__name__)

_cosmos_client: CosmosClient | None = None


def _get_cosmos_client() -> CosmosClient:
    """Get or create a CosmosClient using Managed Identity."""
    global _cosmos_client
    if _cosmos_client is None:
        endpoint = os.environ.get("COSMOS_ENDPOINT", "")
        credential = DefaultAzureCredential()
        _cosmos_client = CosmosClient(endpoint, credential=credential)
    return _cosmos_client


@bp.route(route="cosmos-data", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def query_cosmos(req: func.HttpRequest) -> func.HttpResponse:
    """
    Query Cosmos DB container with continuation token pagination.

    Query params:
        - database: database name (required)
        - container: container name (required)
        - query: SQL query string (default: "SELECT * FROM c")
        - page_size: max items per page (default: 100, max: 1000)
        - continuation_token: token from previous response
    """
    try:
        database_name = req.params.get("database", "")
        container_name = req.params.get("container", "")

        if not database_name or not container_name:
            return func.HttpResponse(
                body=json.dumps({"error": "database and container query params are required"}),
                mimetype="application/json",
                status_code=400,
            )

        # Only allow SELECT queries (read-only enforcement)
        query = req.params.get("query", "SELECT * FROM c")
        if not query.strip().upper().startswith("SELECT"):
            return func.HttpResponse(
                body=json.dumps({"error": "Only SELECT queries are permitted"}),
                mimetype="application/json",
                status_code=403,
            )

        page_size = min(int(req.params.get("page_size", "100")), 1000)
        continuation_token = req.params.get("continuation_token")

        client = _get_cosmos_client()
        database = client.get_database_client(database_name)
        container = database.get_container_client(container_name)

        # Execute query with pagination
        query_iterable = container.query_items(
            query=query,
            max_item_count=page_size,
        )

        # Use paged results with continuation token
        pager = query_iterable.by_page(continuation_token=continuation_token)
        page = next(pager)
        items = list(page)

        response_body = {
            "items": items,
            "count": len(items),
            "continuation_token": pager.continuation_token,
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
        logger.exception("Error querying Cosmos DB")
        return func.HttpResponse(
            body=json.dumps({"error": "Internal server error"}),
            mimetype="application/json",
            status_code=500,
        )
