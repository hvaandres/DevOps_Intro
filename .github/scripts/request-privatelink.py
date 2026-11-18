#!/usr/bin/env python3
"""Validate dispatch data before passing it to the tfvars editor (never a shell)."""

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[2]
EDITOR = REPO / "Terraform/Azure/tfm-privateLink-network/scripts/update-tfvars.py"


def matches(value, pattern):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("Invalid resource request field")
    return value


def key(value):
    return matches(value, r"[A-Za-z_][A-Za-z0-9_-]{0,62}")


def zone(value):
    value = matches(value, r"privatelink\.[a-z0-9]+(?:[.-][a-z0-9]+)*")
    if len(value) > 253 or any(len(label) > 63 for label in value.split(".")):
        raise ValueError("Invalid DNS zone length")
    return value


def update(request, editor, content):
    toggles = ("add_dns_zone", "add_dns_records", "add_spoke")
    if any(not isinstance(request.get(name, False), bool) for name in toggles):
        raise ValueError("Toggles must be booleans")
    if not any(request.get(name, False) for name in toggles):
        raise ValueError("Select at least one resource type")
    if request.get("add_dns_zone"):
        content = editor.add_dns_zone(content, key(request["zone_key"]), zone("privatelink." + request["zone_suffix"]))
    if request.get("add_dns_records"):
        records = json.loads(request["dns_records_json"])
        if not isinstance(records, list) or not records or len(records) > 100:
            raise ValueError("Supply between 1 and 100 DNS records")
        for record in records:
            record_key = key(record["key"])
            record_zone = zone(record["zone"])
            name = matches(record["name"], r"[A-Za-z0-9_*-]+(?:\.[A-Za-z0-9_-]+)*|@")
            ips = [str(ipaddress.IPv4Address(value.strip())) for value in record["ips"].split(",")]
            ttl = record.get("ttl", 300)
            if type(ttl) is not int or not 1 <= ttl <= 2147483647:
                raise ValueError("Invalid TTL")
            content = editor.add_dns_record(content, record_key, record_zone, name, ",".join(ips), ttl)
    if request.get("add_spoke"):
        spoke_key = key(request["spoke_key"])
        name = matches(request["spoke_vnet_name"], r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
        group = matches(request["spoke_rg"], r"[A-Za-z0-9_][A-Za-z0-9_.()-]{0,89}")
        vnet_id = matches(
            request["spoke_vnet_id"],
            r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9_.()-]+/providers/Microsoft\.Network/virtualNetworks/[A-Za-z0-9_.-]+",
        )
        if vnet_id.rsplit("/", 1)[1] != name or vnet_id.split("/")[4] != group:
            raise ValueError("Spoke name/group must match its resource ID")
        content = editor.add_spoke(content, spoke_key, vnet_id, name, group)
    return content


def main():
    spec = importlib.util.spec_from_file_location("tfvars_editor", EDITOR)
    editor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(editor)
    try:
        result = update(json.loads(os.environ["REQUEST_JSON"]), editor, editor.read_tfvars())
        editor.write_tfvars(result)
    except (ValueError, KeyError, TypeError, AttributeError):
        print("::error::Invalid resource request. Check resource names, JSON, IPv4 addresses, and TTL.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
