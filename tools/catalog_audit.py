#!/usr/bin/env python3
"""Validate the FreeSense-owned package catalog and release build list."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FORBIDDEN = re.compile(
    r"(?:files|packages(?:-beta)?|gitlab|codesigner)\.netgate\.com|\.nyi\.netgate\.com",
    re.IGNORECASE,
)

RETIRED_WRAPPERS = {
    "FreeSense-pkg-apcupsd", "FreeSense-pkg-arpwatch", "FreeSense-pkg-Backup",
    "FreeSense-pkg-arping", "FreeSense-pkg-cellular", "FreeSense-pkg-collectd",
    "FreeSense-pkg-Cron", "FreeSense-pkg-darkstat", "FreeSense-pkg-filer",
    "FreeSense-pkg-iperf", "FreeSense-pkg-mtr-nox11", "FreeSense-pkg-nmap",
    "FreeSense-pkg-Notes", "FreeSense-pkg-Service_Watchdog", "FreeSense-pkg-Shellcmd",
    "FreeSense-pkg-haproxy-devel", "FreeSense-pkg-LADVD",
    "FreeSense-pkg-pfBlockerNG-devel", "FreeSense-pkg-pimd", "FreeSense-pkg-RRD_Summary",
    "FreeSense-pkg-snort", "FreeSense-pkg-squid", "FreeSense-pkg-stunnel",
    "FreeSense-pkg-sudo", "FreeSense-pkg-zabbix-agent6", "FreeSense-pkg-zabbix-agent74",
    "FreeSense-pkg-zabbix-proxy6", "FreeSense-pkg-zabbix-proxy74", "FreeSense-pkg-zeek",
}


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    bulk_file = args.source / "tools/conf/pfPorts/poudriere_packages"
    errors: list[str] = []
    bulk = {
        line.strip().replace("%%PRODUCT_NAME%%", "FreeSense")
        for line in bulk_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    system_roots = args.source / "tools/conf/pfPorts/poudriere_system"
    if "sysutils/%%PRODUCT_NAME%%-platform-abi" not in system_roots.read_text(encoding="utf-8"):
        fail(errors, "system repository must publish the platform ABI marker")
    compatibility_mk = root / "Mk/bsd.freesense-package.mk"
    if not compatibility_mk.is_file() or "FreeSense-platform-abi=" not in compatibility_mk.read_text(encoding="utf-8"):
        fail(errors, "optional-package compatibility framework is missing")
    overlay_script = args.source / "tools/ci/freesense-ports-overlay.sh"
    if "bsd.freesense-package.mk" not in overlay_script.read_text(encoding="utf-8"):
        fail(errors, "ports overlay does not inject the optional-package compatibility contract")
    for page in root.glob("www/FreeSense-pkg-WebGateway/files/usr/local/www/webgateway/*.php"):
        page_text = page.read_text(encoding="utf-8", errors="replace")
        if re.search(r"\$config\s*=\s*webgateway_config\(\)", page_text):
            fail(errors, f"{page.relative_to(root)}: package page shadows the firewall's global $config")
    exclusions_file = root / "policy/rc-exclusions.txt"
    exclusions = {
        line.split("|", 1)[0].strip()
        for line in exclusions_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    templates = {
        line.strip()
        for line in (root / "policy/catalog-templates.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    product_catalog_file = args.source / "src/etc/freesense-package-catalog.json"
    try:
        product_catalog = json.loads(product_catalog_file.read_text(encoding="utf-8"))
        if product_catalog.get("schema_version") != 1:
            fail(errors, "unsupported package catalog schema version")
        product_packages = product_catalog.get("packages", {})
        if not isinstance(product_packages, dict):
            raise ValueError("packages must be an object")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fail(errors, f"invalid product package catalog: {exc}")
        product_packages = {}

    wrappers: set[str] = set()
    published_names: set[str] = set()
    for makefile in root.glob("*/*/Makefile"):
        origin = makefile.parent.relative_to(root).as_posix()
        text = makefile.read_text(encoding="utf-8", errors="replace")
        plist = makefile.parent / "pkg-plist"
        if plist.is_file():
            plist_lines = plist.read_text(encoding="utf-8", errors="replace").splitlines()
            if any(line.startswith("etc/inc/priv/") for line in plist_lines):
                fail(errors, f"{origin}: firewall privilege files must use absolute /etc/inc/priv paths")
        if makefile.parent.name.startswith("FreeSense-pkg-"):
            wrappers.add(origin)
            if makefile.parent.name in RETIRED_WRAPPERS:
                fail(errors, f"{origin}: retired wrapper must not be restored")
        if FORBIDDEN.search(text):
            fail(errors, f"{origin}: active vendor infrastructure URL")
        if makefile.parent.name.startswith("FreeSense") and "MAINTAINER=" in text and "@freesense.org" not in text:
            fail(errors, f"{origin}: maintainer must use @freesense.org")
        if "NO_CHECKSUM=yes" in text and origin != "security/FreeSense-system":
            fail(errors, f"{origin}: NO_CHECKSUM is forbidden")
        if origin in {"net/haproxy", "net/ntopng"} and re.search(r"(?:PORT|DIST)VERSION\s*\??=\s*[^\n]*\.d20", text):
            fail(errors, f"{origin}: production override must not use a development snapshot version")

    for origin in sorted(bulk):
        if origin.startswith(("security/FreeSense", "net/FreeSense", "net-mgmt/FreeSense", "sysutils/FreeSense", "dns/FreeSense", "ftp/FreeSense", "benchmarks/FreeSense", "emulators/FreeSense", "www/FreeSense")):
            if not (root / origin / "Makefile").is_file():
                fail(errors, f"{origin}: listed FreeSense origin is missing")

        port_name = origin.rsplit("/", 1)[-1]
        if port_name.startswith("FreeSense-pkg-"):
            shortname = port_name.removeprefix("FreeSense-pkg-")
            published_names.add(shortname)
            metadata = product_packages.get(shortname)
            if not isinstance(metadata, dict):
                fail(errors, f"{origin}: missing product catalog metadata for {shortname}")
                continue
            for field in ("display_name", "category", "support", "last_tested_release", "resource_profile", "capabilities", "services"):
                if field not in metadata:
                    fail(errors, f"{origin}: catalog metadata is missing {field}")
            if metadata.get("support") != "supported":
                fail(errors, f"{origin}: production catalog package must be supported")
            if metadata.get("resource_profile") not in {"lightweight", "moderate", "intensive"}:
                fail(errors, f"{origin}: invalid resource profile")
            for field in ("capabilities", "services"):
                if not isinstance(metadata.get(field), list) or not all(
                    isinstance(value, str) and value for value in metadata.get(field, [])
                ):
                    fail(errors, f"{origin}: {field} must be a list of non-empty strings")
            for field in ("configure_path", "status_path"):
                path = metadata.get(field)
                if path is None:
                    continue
                if not isinstance(path, str) or not path.startswith("/"):
                    fail(errors, f"{origin}: {field} must be an absolute WebUI path")
                    continue
                web_path = path.split("?", 1)[0].lstrip("/")
                in_core = (args.source / "src/usr/local/www" / web_path).is_file()
                in_port = any(root.glob(f"*/*/files/usr/local/www/{web_path}"))
                if not in_core and not in_port:
                    fail(errors, f"{origin}: {field} target does not exist: {path}")

    extra_metadata = set(product_packages) - published_names
    for shortname in sorted(extra_metadata):
        fail(errors, f"{shortname}: catalog metadata has no published package wrapper")

    unclassified = wrappers - bulk - exclusions - templates
    for origin in sorted(unclassified):
        fail(errors, f"{origin}: package wrapper is neither in the RC catalog nor explicitly excluded")
    stale_exclusions = exclusions - wrappers
    for origin in sorted(stale_exclusions):
        fail(errors, f"{origin}: stale RC exclusion")
    for origin in sorted(templates - wrappers):
        fail(errors, f"{origin}: stale catalog template declaration")
    if args.release and exclusions:
        fail(errors, "RC release mode forbids package exclusions: " + ", ".join(sorted(exclusions)))

    if errors:
        print("Catalog audit failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"Catalog audit passed: {len(bulk)} build origins, {len(wrappers)} FreeSense package wrappers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
