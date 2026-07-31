#!/usr/bin/env python3
"""Static safety and packaging checks for FreeSense Web Gateway."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "www/FreeSense-pkg-WebGateway"


def main() -> int:
    errors: list[str] = []
    required = {
        "Makefile",
        "pkg-descr",
        "pkg-plist",
        "files/usr/local/pkg/webgateway.inc",
        "files/usr/local/pkg/webgateway.xml",
        "files/usr/local/etc/rc.d/freesense_webgateway",
        "files/usr/local/www/webgateway/webgateway.php",
        "files/usr/local/www/webgateway/webgateway_listeners.php",
        "files/usr/local/www/webgateway/webgateway_tls.php",
        "files/usr/local/www/webgateway/webgateway_policies.php",
        "files/usr/local/www/webgateway/webgateway_identity.php",
        "files/usr/local/www/webgateway/webgateway_threat.php",
        "files/usr/local/www/webgateway/webgateway_feeds.php",
        "files/usr/local/www/webgateway/webgateway_cache.php",
        "files/usr/local/www/webgateway/webgateway_status.php",
        "files/usr/local/www/webgateway/webgateway_diagnostics.php",
        "files/usr/local/www/webgateway/webgateway_pac.php",
        "files/usr/local/etc/rc.d/freesense_webgateway_watchdog",
        "files/usr/local/sbin/freesense-webgateway-feed-update",
        "files/usr/local/sbin/freesense-webgateway-watchdog",
    }
    for relative in sorted(required):
        if not (PORT / relative).is_file():
            errors.append(f"missing package file: {relative}")

    integration = (PORT / "files/usr/local/pkg/webgateway.inc").read_text(encoding="utf-8")
    manifest = (PORT / "pkg-plist").read_text(encoding="utf-8")
    makefile = (PORT / "Makefile").read_text(encoding="utf-8")
    package_xml = (PORT / "files/usr/local/pkg/webgateway.xml").read_text(encoding="utf-8")
    status_page = (PORT / "files/usr/local/www/webgateway/webgateway_status.php").read_text(encoding="utf-8")

    invariants = {
        "deny-all terminal ACL": "http_access deny all",
        "client network ACL": "acl local_clients src",
        "unsafe-port rejection": "http_access deny !Safe_ports",
        "CONNECT port restriction": "http_access deny CONNECT !SSL_ports",
        "listener interface derivation": "webgateway_interface_listeners",
        "parser gate": "webgateway_config_test",
        "atomic configuration write": "webgateway_write_file",
        "canonical WAN exclusion": "if ($interface === 'wan')",
        "import-safe LAN inclusion": "if ($interface === 'lan')",
        "XML-safe list storage": "function webgateway_config_for_storage",
        "post-write persistence verification": "webgateway_config_for_storage($persisted) !== $stored_candidate",
        "routed client network ACL": "webgateway_lines($config['additional_client_networks'])",
        "submit guard helper": "function webgateway_emit_submit_guard",
        "submit guard installation from tabs": "webgateway_emit_submit_guard();",
        "AV scan limit application": "function webgateway_apply_av_scan_limit",
        "AV maxsize managed block": "maxsize {$bytes}",
        "YouTube restrict header": "request_header_add YouTube-Restrict Strict all",
        "upload limit directive": "request_body_max_size",
        "download limit directive": "reply_body_max_size",
        "delay pool bandwidth profile": "delay_pools 1",
        "upstream cache_peer": "cache_peer ",
        "ICAP service generation": "icap_service freesense_",
        "feed empty-url validation": "Enable scheduled feed updates only after configuring at least one HTTPS feed URL",
    }
    for description, needle in invariants.items():
        if needle not in integration:
            errors.append(f"missing safety invariant: {description}")

    required_v2 = {
        "Squid 7 runtime pin": "WEBGATEWAY_MAJOR = 7",
        "transactional staging": "'/stage.' . getmypid()",
        "rollback path": "webgateway_restore_previous",
        "TLS bump support": "ssl_bump bump",
        "dynamic certificate helper": "security_file_certgen",
        "PF package hook": "webgateway_generate_rules",
        "certificate usage plugin": "webgateway_plugin_certificates",
        "native feed compiler": "webgateway_update_feeds",
        "config-managed feed scheduler": "install_cron_job(WEBGATEWAY_FEED_COMMAND",
        "staged TLS listener paths": "webgateway_interface_listeners($config, $directory)",
        "Squid-readable helper secrets": "webgateway_set_file_owner",
        "reload-readable TLS key and config": "['freesense.conf', 'inspection-ca.key', 'local-users'",
        "post-reload health gate": "webgateway_stays_running",
        "forced runtime reload": "webgateway_service_action('onereload')",
        "persistent settings rollback": "Rolled back rejected Web Gateway settings",
        "terminal access control": "http_access deny all",
    }
    for description, needle in required_v2.items():
        if needle not in integration:
            errors.append(f"missing Web Gateway 2.0 invariant: {description}")

    # Persistence paths must never write raw PHP arrays for list fields.
    if "config_set_path(WEBGATEWAY_CONFIG_PATH, $config);" in integration:
        errors.append("raw config_set_path with $config remains; use webgateway_config_for_storage")
    if "config_set_path(WEBGATEWAY_CONFIG_PATH, $wg_config);" in status_page:
        errors.append("status emergency path writes raw $wg_config arrays")
    if "webgateway_config_for_storage($wg_config)" not in status_page:
        errors.append("status emergency path missing webgateway_config_for_storage")

    save_pages = [
        "webgateway_listeners.php",
        "webgateway_tls.php",
        "webgateway_policies.php",
        "webgateway_identity.php",
        "webgateway_threat.php",
        "webgateway_feeds.php",
        "webgateway_cache.php",
    ]
    for page in save_pages:
        text = (PORT / "files/usr/local/www/webgateway" / page).read_text(encoding="utf-8")
        if "webgateway_save_candidate" not in text:
            errors.append(f"{page} does not call webgateway_save_candidate")
        if "webgateway_display_tabs" not in text:
            errors.append(f"{page} does not render tabs (submit guard is attached there)")
        if "Save and apply" not in text and "gettext('Save and apply')" not in text:
            # Allow either gettext-wrapped or already resolved pattern in source
            if "Save and apply" not in text:
                errors.append(f"{page} primary CTA is not standardized to Save and apply")

    action_pages = {
        "webgateway_status.php": ["service_action", "webgateway_display_tabs"],
        "webgateway_diagnostics.php": ["regenerate", "webgateway_display_tabs"],
    }
    for page, needles in action_pages.items():
        text = (PORT / "files/usr/local/www/webgateway" / page).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                errors.append(f"{page} missing required action wiring: {needle}")

    if "PORTVERSION=\t2.0.5" not in makefile and "PORTVERSION=	2.0.5" not in makefile:
        # Accept either tab style
        if not re.search(r"PORTVERSION=\s*2\.0\.5", makefile):
            errors.append("package version is not 2.0.5")

    if "<filter_rules_needed>webgateway_generate_rules</filter_rules_needed>" not in package_xml:
        errors.append("PF rule-generation hook is not registered")
    if "plugin_certificates" not in package_xml:
        errors.append("certificate usage plugin is not registered")

    if "squid>=7:www/squid" not in makefile:
        errors.append("wrapper does not require the supported Squid 7 port")
    if "freesense_webgateway" not in package_xml:
        errors.append("package service registration is missing")

    av_port = ROOT / "www/FreeSense-pkg-WebGateway-AV"
    for relative in ("Makefile", "pkg-descr", "pkg-plist", "files/pkg-install.in", "files/pkg-deinstall.in", "files/usr/local/pkg/webgateway_av.xml"):
        if not (av_port / relative).is_file():
            errors.append(f"missing AV companion file: {relative}")
    if av_port.is_dir():
        av_makefile = (av_port / "Makefile").read_text(encoding="utf-8")
        for dependency in ("security/clamav", "www/c-icap", "www/c-icap-modules", "www/squidclamav"):
            if dependency not in av_makefile:
                errors.append(f"AV companion missing dependency: {dependency}")
        av_install = (av_port / "files/pkg-install.in").read_text(encoding="utf-8")
        av_deinstall = (av_port / "files/pkg-deinstall.in").read_text(encoding="utf-8")
        av_xml = (av_port / "files/usr/local/pkg/webgateway_av.xml").read_text(encoding="utf-8")
        if "rc.packages" not in av_install or "rc.packages" not in av_deinstall:
            errors.append("AV companion does not register/unregister through rc.packages")
        if "webgateway_av_deinstall" not in av_xml:
            errors.append("AV companion cleanup hook is not registered")

    if "SafeSearch-Policy" in integration:
        errors.append("unsupported SafeSearch header must not be advertised or generated")
    if "http_access allow exempt_sources" in integration:
        errors.append("interception exemptions must not bypass explicit-proxy authentication and policy")
    if "&& in_array('intercept_https', $config['listener_modes'], true)" not in integration:
        errors.append("QUIC fallback must be scoped to transparent HTTPS interception")
    for dangerous in ("url_rewrite_program", "external_acl_type", "auth_param\\s+\\S+\\s+program"):
        if dangerous not in integration:
            errors.append(f"expert-directive protection missing: {dangerous}")

    # av_max_mb must drive runtime config, not be decorative.
    if "'av_max_mb'" in integration and "webgateway_apply_av_scan_limit" not in integration:
        errors.append("av_max_mb is present without runtime application")

    for relative in required:
        if not relative.startswith("files/usr/local/"):
            continue
        installed = relative.removeprefix("files/usr/local/")
        if installed == "etc/rc.d/freesense_webgateway":
            installed = "etc/rc.d/freesense_webgateway"
        if installed not in manifest:
            errors.append(f"installed file is absent from pkg-plist: {installed}")

    if errors:
        print("Web Gateway smoke test failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Web Gateway smoke test passed: packaging, UX guards, and Squid safety invariants present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
