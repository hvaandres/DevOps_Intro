#!/usr/bin/env python3
"""
update-tfvars.py — Safely add entries to terraform.tfvars maps.

Used by the GitHub Actions "Add Resource" workflow to modify tfvars
programmatically. Each command is independent — teams can run any
combination in a single workflow.

Usage:
  # Single DNS zone
  python3 scripts/update-tfvars.py dns-zone --key cosmosdb --zone "privatelink.documents.azure.com"

  # Single DNS record
  python3 scripts/update-tfvars.py dns-record --key my_storage --zone-name "privatelink.blob.core.windows.net" --record-name mystorageaccount --ips "10.0.1.5"

  # Multiple DNS records (batch via JSON)
  python3 scripts/update-tfvars.py batch-records --json '[{"key":"stor1","zone":"privatelink.blob.core.windows.net","name":"mystorage","ips":"10.0.1.5"},{"key":"sql1","zone":"privatelink.database.windows.net","name":"mydb","ips":"10.0.2.5"}]'

  # Spoke VNet peering
  python3 scripts/update-tfvars.py spoke --key spoke-prod --vnet-id "/subscriptions/.../vnet-spoke" --vnet-name "vnet-spoke" --rg "rg-spoke"
"""

import argparse
import json
import re
import sys
from pathlib import Path

TFVARS_PATH = Path(__file__).resolve().parent.parent / "terraform.tfvars"


def read_tfvars() -> str:
    return TFVARS_PATH.read_text()


def write_tfvars(content: str) -> None:
    TFVARS_PATH.write_text(content)
    print(f"✅ Updated {TFVARS_PATH}")


# ---------------------------------------------------------------------------
# DNS Zone
# ---------------------------------------------------------------------------
def add_dns_zone(content: str, key: str, zone: str) -> str:
    """Add a new entry to the private_dns_zones map."""

    if not zone.startswith("privatelink."):
        print(f"❌ Zone must start with 'privatelink.' — got: {zone}")
        sys.exit(1)

    # Check duplicate by key in the private_dns_zones block
    zone_block = re.search(r'private_dns_zones\s*=\s*\{([^}]*)\}', content, re.DOTALL)
    if zone_block and re.search(rf'^\s*{re.escape(key)}\s*=', zone_block.group(1), re.MULTILINE):
        print(f"⚠️  Zone key '{key}' already exists. Skipping.")
        return content

    # Check duplicate by zone FQDN value
    if zone_block and f'"{zone}"' in zone_block.group(1):
        print(f"⚠️  Zone '{zone}' already exists under a different key. Skipping.")
        return content

    pattern = r'(private_dns_zones\s*=\s*\{[^}]*?)(})'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        print("❌ Could not find 'private_dns_zones' map in tfvars.")
        sys.exit(1)

    indent = "  "
    new_entry = f'{indent}{key:<9} = "{zone}"'
    replacement = match.group(1) + new_entry + "\n" + match.group(2)
    content = content[:match.start()] + replacement + content[match.end():]

    print(f"➕ Added DNS zone: {key} = {zone}")
    return content


# ---------------------------------------------------------------------------
# DNS A Record (single)
# ---------------------------------------------------------------------------
def add_dns_record(content: str, key: str, zone_name: str, record_name: str, ips: str, ttl: int) -> str:
    """Add a single entry to the dns_a_records map."""

    if not zone_name.startswith("privatelink."):
        print(f"❌ Zone must start with 'privatelink.' — got: {zone_name}")
        sys.exit(1)

    # Check for duplicate key in existing block
    existing = re.search(r'dns_a_records\s*=\s*\{(.*)\}', content, re.DOTALL)
    if existing and re.search(rf'^\s*{re.escape(key)}\s*=\s*\{{', existing.group(1), re.MULTILINE):
        print(f"⚠️  Record key '{key}' already exists. Skipping.")
        return content

    ip_list = ', '.join(f'"{ip.strip()}"' for ip in ips.split(','))

    record_block = f"""  {key} = {{
    zone_name = "{zone_name}"
    name      = "{record_name}"
    ttl       = {ttl}
    records   = [{ip_list}]
  }}"""

    # If dns_a_records map exists (uncommented)
    pattern = r'(dns_a_records\s*=\s*\{)(.*?)(})'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        inner = match.group(2)
        replacement = match.group(1) + inner + record_block + "\n" + match.group(3)
        content = content[:match.start()] + replacement + content[match.end():]
    else:
        # Replace the commented-out dns_a_records line with a real block
        comment_pattern = r'#\s*dns_a_records\s*=\s*\{\s*\}'
        new_block = f"dns_a_records = {{\n{record_block}\n}}"
        content = re.sub(comment_pattern, new_block, content)

    print(f"➕ Added DNS A record: {key} ({record_name} -> {ips})")
    return content


# ---------------------------------------------------------------------------
# DNS A Records (batch — multiple records from JSON)
# ---------------------------------------------------------------------------
def add_batch_records(content: str, json_str: str) -> str:
    """Add multiple DNS A records from a JSON array.

    Expected format:
    [
      {"key": "stor1", "zone": "privatelink.blob.core.windows.net", "name": "mystorage", "ips": "10.0.1.5", "ttl": 300},
      {"key": "sql1",  "zone": "privatelink.database.windows.net",  "name": "mydb",      "ips": "10.0.2.5"}
    ]
    """
    try:
        records = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON: {e}")
        sys.exit(1)

    if not isinstance(records, list) or len(records) == 0:
        print("❌ JSON must be a non-empty array of record objects.")
        sys.exit(1)

    added = 0
    skipped = 0
    for record in records:
        # Validate required fields
        required = ['key', 'zone', 'name', 'ips']
        missing = [f for f in required if f not in record or not record[f]]
        if missing:
            print(f"❌ Record is missing required fields {missing}: {record}")
            sys.exit(1)

        ttl = record.get('ttl', 300)
        prev_content = content
        content = add_dns_record(
            content,
            key=record['key'],
            zone_name=record['zone'],
            record_name=record['name'],
            ips=record['ips'],
            ttl=int(ttl),
        )
        if content == prev_content:
            skipped += 1
        else:
            added += 1

    print(f"\n📊 Batch summary: {added} added, {skipped} skipped (already exist)")
    return content


# ---------------------------------------------------------------------------
# Spoke (VNet Peering)
# ---------------------------------------------------------------------------
def add_spoke(content: str, key: str, vnet_id: str, vnet_name: str, rg: str) -> str:
    """Add a new spoke entry to the spokes map."""

    spoke_block = f"""  {key} = {{
    vnet_id             = "{vnet_id}"
    vnet_name           = "{vnet_name}"
    resource_group_name = "{rg}"
  }}"""

    # If spokes map exists (uncommented)
    pattern = r'(spokes\s*=\s*\{)(.*?)(})'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        inner = match.group(2)
        if re.search(rf'^\s*{re.escape(key)}\s*=\s*\{{', inner, re.MULTILINE):
            print(f"⚠️  Spoke '{key}' already exists. Skipping.")
            return content
        replacement = match.group(1) + inner + spoke_block + "\n" + match.group(3)
        content = content[:match.start()] + replacement + content[match.end():]
    else:
        # Replace the commented-out spokes block
        comment_pattern = r'#\s*spokes\s*=\s*\{[^}]*?#\s*\}'
        new_block = f"spokes = {{\n{spoke_block}\n}}"
        content = re.sub(comment_pattern, new_block, content, flags=re.DOTALL)

    print(f"➕ Added spoke: {key} ({vnet_name})")
    return content


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Add entries to terraform.tfvars for the Private Link Network module.",
        epilog="Each command is independent. The workflow can call multiple commands in sequence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # dns-zone
    z = subparsers.add_parser("dns-zone", help="Add a Private DNS Zone")
    z.add_argument("--key", required=True, help="Logical key (e.g. 'cosmosdb')")
    z.add_argument("--zone", required=True, help="Full zone FQDN (must start with 'privatelink.')")

    # dns-record (single)
    r = subparsers.add_parser("dns-record", help="Add a single DNS A record")
    r.add_argument("--key", required=True, help="Unique record key")
    r.add_argument("--zone-name", required=True, help="Zone FQDN the record belongs to")
    r.add_argument("--record-name", required=True, help="Record name (e.g. 'mystorageaccount')")
    r.add_argument("--ips", required=True, help="Comma-separated IP addresses")
    r.add_argument("--ttl", type=int, default=300, help="TTL in seconds (default: 300)")

    # batch-records (multiple via JSON)
    b = subparsers.add_parser("batch-records", help="Add multiple DNS A records from JSON")
    b.add_argument("--json", required=True, dest="json_str",
                   help='JSON array, e.g. [{"key":"x","zone":"privatelink...","name":"y","ips":"10.0.0.1"}]')

    # spoke
    s = subparsers.add_parser("spoke", help="Add a spoke VNet peering")
    s.add_argument("--key", required=True, help="Logical spoke name")
    s.add_argument("--vnet-id", required=True, help="Spoke VNet resource ID")
    s.add_argument("--vnet-name", required=True, help="Spoke VNet name")
    s.add_argument("--rg", required=True, help="Spoke resource group name")

    args = parser.parse_args()
    content = read_tfvars()

    if args.command == "dns-zone":
        content = add_dns_zone(content, args.key, args.zone)
    elif args.command == "dns-record":
        content = add_dns_record(content, args.key, args.zone_name, args.record_name, args.ips, args.ttl)
    elif args.command == "batch-records":
        content = add_batch_records(content, args.json_str)
    elif args.command == "spoke":
        content = add_spoke(content, args.key, args.vnet_id, args.vnet_name, args.rg)

    write_tfvars(content)


if __name__ == "__main__":
    main()
