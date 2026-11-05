#!/usr/bin/env python3
"""List secret names and selected metadata, never secret values or tags."""

from keyvault_common import main

if __name__ == "__main__":
    raise SystemExit(main("secrets"))
