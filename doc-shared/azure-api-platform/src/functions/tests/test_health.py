"""Unit tests for the health check endpoint."""
import json

import azure.functions as func
import pytest

from blueprints.health import health_check


@pytest.mark.unit
class TestHealthCheck:
    def test_returns_200(self):
        req = func.HttpRequest(method="GET", body=b"", url="/api/health")
        resp = health_check(req)
        assert resp.status_code == 200

    def test_returns_json(self):
        req = func.HttpRequest(method="GET", body=b"", url="/api/health")
        resp = health_check(req)
        body = json.loads(resp.get_body())
        assert body["status"] == "healthy"
        assert "timestamp" in body
        assert body["service"] == "azure-api-platform"

    def test_content_type_is_json(self):
        req = func.HttpRequest(method="GET", body=b"", url="/api/health")
        resp = health_check(req)
        assert resp.mimetype == "application/json"
