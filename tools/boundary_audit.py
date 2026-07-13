#!/usr/bin/env python3
"""Reject FreeSense system-image ports from the optional package overlay."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_ORIGINS = {
    "devel/FreeSense-composer-deps",
    "devel/php-FreeSense-module",
    "net/filterdns",
    "security/FreeSense",
    "security/FreeSense-system",
    "security/php-openssl_x509_crl",
    "security/phpseclib",
    "sysutils/FreeSense-Status_Monitoring",
    "sysutils/FreeSense-default-config",
    "sysutils/FreeSense-default-config-serial",
    "sysutils/FreeSense-platform-abi",
    "sysutils/FreeSense-repoc",
    "sysutils/FreeSense-upgrade",
    "sysutils/check_reload_status",
    "sysutils/cpustats",
    "sysutils/dhcpleases",
    "sysutils/dhcpleases6",
    "sysutils/filterlog",
    "sysutils/minicron",
    "sysutils/qstats",
    "sysutils/ssh_tunnel_shell",
    "sysutils/voucher",
    "sysutils/wrapalixresetbutton",
}

errors = [origin for origin in sorted(SYSTEM_ORIGINS) if (ROOT / origin).exists()]
if errors:
    print("System ports are not allowed in the optional package repository:", file=sys.stderr)
    for origin in errors:
        print(f"- {origin}", file=sys.stderr)
    raise SystemExit(1)

if not (ROOT / "Mk/bsd.freesense-package.mk").is_file():
    print("Missing optional-package framework: Mk/bsd.freesense-package.mk", file=sys.stderr)
    raise SystemExit(1)

print("Optional package boundary audit passed.")
