#!/usr/bin/env python3
"""Validate service-principal login without showing or caching access tokens."""

from keyvault_common import main

if __name__ == "__main__":
    raise SystemExit(main("login"))
