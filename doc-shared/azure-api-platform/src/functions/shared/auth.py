"""
Authentication utilities.

Note: Primary JWT validation is handled at the APIM layer.
This module provides optional secondary validation or token introspection
at the Function App level for defense-in-depth.
"""
import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_expected_audience() -> str:
    """Get the expected JWT audience from environment."""
    return os.environ.get("JWT_AUDIENCE", "api://azure-api-platform")


@lru_cache(maxsize=1)
def get_tenant_id() -> str:
    """Get the Entra ID tenant ID from environment."""
    return os.environ.get("AZURE_TENANT_ID", "")


def extract_bearer_token(auth_header: str | None) -> str | None:
    """Extract the Bearer token from an Authorization header value."""
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None
