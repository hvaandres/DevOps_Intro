"""Unit tests for auth utilities."""
import pytest

from shared.auth import extract_bearer_token


@pytest.mark.unit
class TestExtractBearerToken:
    def test_valid_bearer_token(self):
        token = extract_bearer_token("Bearer eyJhbGciOiJSUzI1NiJ9.test.sig")
        assert token == "eyJhbGciOiJSUzI1NiJ9.test.sig"

    def test_case_insensitive_bearer(self):
        token = extract_bearer_token("bearer mytoken123")
        assert token == "mytoken123"

    def test_none_header(self):
        assert extract_bearer_token(None) is None

    def test_empty_string(self):
        assert extract_bearer_token("") is None

    def test_no_scheme(self):
        assert extract_bearer_token("just-a-token") is None

    def test_wrong_scheme(self):
        assert extract_bearer_token("Basic dXNlcjpwYXNz") is None

    def test_extra_parts(self):
        assert extract_bearer_token("Bearer token extra") is None
