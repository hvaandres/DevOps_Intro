"""Health check endpoint."""
import json
from datetime import UTC, datetime

import azure.functions as func

bp = func.Blueprint()


@bp.route(route="health", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Returns service health status."""
    return func.HttpResponse(
        body=json.dumps({
            "status": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
            "service": "azure-api-platform",
        }),
        mimetype="application/json",
        status_code=200,
    )
