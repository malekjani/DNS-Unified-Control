"""Per-server DUC product identity. No credentials, tokens, or private keys.

A fresh installation has exactly one durable identity; re-running setup with
another domain or IPv4 fails closed. This module does not call Cloudflare,
start engines, or modify system services.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid

from .fresh_setup import valid_domain, valid_public_ip

SCHEMA = "duc.instance.v1"
DEFAULT_FILE = Path("/etc/dns-unified/instance.json")
FIELDS = ("instance_id", "domain", "public_ipv4", "nameserver_fqdn", "panel_fqdn", "created_utc")


class InstanceError(RuntimeError):
    pass


def identity_path() -> Path:
    return Path(os.environ.get("DUC_INSTANCE_FILE", str(DEFAULT_FILE)))


def validate(data: dict) -> dict:
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise InstanceError("Unknown or invalid instance schema; refusing to overwrite")
    try:
        domain = valid_domain(data["domain"])
        public_ip = valid_public_ip(data["public_ipv4"])
        identifier = str(uuid.UUID(data["instance_id"]))
        created = data["created_utc"]
        if not isinstance(created, str) or not created:
            raise ValueError("missing created_utc")
    except (KeyError, TypeError, ValueError) as exc:
        raise InstanceError("Invalid instance identity file") from exc
    if data.get("nameserver_fqdn") != f"ns.{domain}" or data.get("panel_fqdn") != f"panel.{domain}":
        raise InstanceError("Inconsistent instance DNS names")
    return {"schema": SCHEMA, "instance_id": identifier, "domain": domain,
            "public_ipv4": public_ip, "nameserver_fqdn": f"ns.{domain}",
            "panel_fqdn": f"panel.{domain}", "created_utc": created}


def load(path: Path | None = None) -> dict:
    target = path or identity_path()
    try:
        if target.is_symlink():
            raise InstanceError("Refusing symlinked identity file")
        return validate(json.loads(target.read_text(encoding="utf-8")))
    except FileNotFoundError as exc:
        raise InstanceError("Instance identity not initialized") from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise InstanceError("Corrupt instance identity file") from exc


def initialize(domain: str, public_ipv4: str, *, resume: bool = False,
               path: Path | None = None) -> dict:
    domain, public_ipv4 = valid_domain(domain), valid_public_ip(public_ipv4)
    target = path or identity_path()
    if target.exists() or target.is_symlink() or resume:
        current = load(target)
        if not resume:
            raise InstanceError("Instance already exists; use --resume for the SAME server")
        if (current["domain"], current["public_ipv4"]) != (domain, public_ipv4):
            raise InstanceError("Resume identity mismatch: domain or public IPv4 differs")
        return current
    if os.geteuid() != 0 and path is None:
        raise InstanceError("Root required to create production instance identity")
    target.parent.mkdir(parents=True, exist_ok=True)
    entry = validate({"schema": SCHEMA, "instance_id": str(uuid.uuid4()),
                      "domain": domain, "public_ipv4": public_ipv4,
                      "nameserver_fqdn": f"ns.{domain}",
                      "panel_fqdn": f"panel.{domain}",
                      "created_utc": datetime.now(timezone.utc).isoformat()})
    # O_EXCL prevents concurrent first-run processes from silently overwriting.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(entry, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return entry


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DUC single-server product identity")
    parser.add_argument("action", choices=("init", "show", "verify"))
    parser.add_argument("--domain")
    parser.add_argument("--ip")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--field", choices=FIELDS)
    parser.add_argument("--instance-file", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "init":
            if not args.domain or not args.ip:
                parser.error("init requires --domain and --ip")
            data = initialize(args.domain, args.ip, resume=args.resume, path=args.instance_file)
        else:
            data = load(args.instance_file)
            if args.action == "verify":
                if args.domain and data["domain"] != valid_domain(args.domain):
                    raise InstanceError("Domain mismatch")
                if args.ip and data["public_ipv4"] != valid_public_ip(args.ip):
                    raise InstanceError("Public IP mismatch")
        if args.field:
            print(data[args.field])
        else:
            print(json.dumps(data, indent=2))
        return 0
    except (InstanceError, ValueError, OSError) as exc:
        print(f"DUC instance: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
