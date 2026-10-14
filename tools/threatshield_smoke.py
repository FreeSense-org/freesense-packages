#!/usr/bin/env python3
"""Static safety and packaging checks for FreeSense Threat Shield."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "security/FreeSense-pkg-ThreatShield"
BINARY_PORT = ROOT / "www/adguardhome-bin"


def main() -> int:
    errors: list[str] = []
    required = {
        "Makefile",
        "pkg-descr",
        "pkg-plist",
        "files/pkg-install.in",
        "files/pkg-deinstall.in",
        "files/etc/inc/priv/threatshield.priv.inc",
        "files/usr/local/etc/rc.d/threatshield",
        "files/usr/local/pkg/threatshield.inc",
        "files/usr/local/pkg/threatshield.xml",
        "files/usr/local/etc/rc.d/threatshield_dnsbl",
        "files/usr/local/pkg/threatshield/threatshield_catalog.inc",
        "files/usr/local/pkg/threatshield/threatshield_dnsbl.inc",
        "files/usr/local/pkg/threatshield/threatshield_dnsbl_daemon.php",
        "files/usr/local/pkg/threatshield/threatshield_health.inc",
        "files/usr/local/pkg/threatshield/threatshield_lib.inc",
        "files/usr/local/pkg/threatshield/threatshield_pf.inc",
        "files/usr/local/pkg/threatshield/threatshield_ui.inc",
        "files/usr/local/pkg/threatshield_update.php",
        "files/usr/local/sbin/freesense-threatshield-update",
        "files/usr/local/share/FreeSense-pkg-ThreatShield/info.xml",
        "files/usr/local/www/shortcuts/pkg_threatshield.inc",
        "files/usr/local/www/widgets/widgets/threatshield.widget.php",
        "files/usr/local/www/threatshield/threatshield.php",
        "files/usr/local/www/threatshield/threatshield_status.php",
        "files/usr/local/www/threatshield/threatshield_querylog.php",
        "files/usr/local/www/threatshield/threatshield_feeds.php",
        "files/usr/local/www/threatshield/threatshield_geoip.php",
        "files/usr/local/www/threatshield/threatshield_rules.php",
        "files/usr/local/www/threatshield/threatshield_clients.php",
        "files/usr/local/www/threatshield/threatshield_rewrites.php",
        "files/usr/local/www/threatshield/threatshield_allowlist.php",
        "files/usr/local/www/threatshield/threatshield_inbound.php",
        "files/usr/local/www/threatshield/threatshield_ajax.php",
    }

    for relative in sorted(required):
        if not (PORT / relative).is_file():
            errors.append(f"missing package file: {relative}")

    if not (PORT / "files/usr/local/pkg/threatshield.inc").is_file():
        print("Threat Shield core include missing, aborting deep checks.", file=sys.stderr)
        return 1

    integration = (PORT / "files/usr/local/pkg/threatshield.inc").read_text(encoding="utf-8")
    pf_builder = (PORT / "files/usr/local/pkg/threatshield/threatshield_pf.inc").read_text(encoding="utf-8")
    library = (PORT / "files/usr/local/pkg/threatshield/threatshield_lib.inc").read_text(encoding="utf-8")
    health = (PORT / "files/usr/local/pkg/threatshield/threatshield_health.inc").read_text(encoding="utf-8")
    updater = (PORT / "files/usr/local/pkg/threatshield_update.php").read_text(encoding="utf-8")
    manifest = (PORT / "pkg-plist").read_text(encoding="utf-8")
    makefile = (PORT / "Makefile").read_text(encoding="utf-8")
    package_xml = (PORT / "files/usr/local/pkg/threatshield.xml").read_text(encoding="utf-8")
    rc_script = (PORT / "files/usr/local/etc/rc.d/threatshield").read_text(encoding="utf-8")
    install_script = (PORT / "files/pkg-install.in").read_text(encoding="utf-8")
    deinstall_script = (PORT / "files/pkg-deinstall.in").read_text(encoding="utf-8")

    invariants = {
        "config path definition": "THREATSHIELD_CONFIG_PATH",
        "YAML config generator": "function threatshield_generate_yaml",
        "resync logic": "function threatshield_sync_config",
        "removal logic": "function threatshield_remove_config",
        "GeoIP table generator": "function threatshield_update_geoip",
        "PF rule generation": "function threatshield_generate_rules",
        "API communication bridge": "function threatshield_api_request",
        "XML-safe list storage": "return array_is_list($value) ? ['item' => $out] : $out;",
        "nested lists unwrapped on load": "threatshield_unwrap_lists(threatshield_normalize_list($raw[$field]))",
        "presence-based Unbound enable": "function threatshield_set_unbound_enabled",
        "transactional save": "function threatshield_save_and_apply",
        "resolver mode manager": "function threatshield_manage_unbound",
        "policy-bound GeoIP rules": "geoip_policies",
        "HA sync send hook": "function threatshield_plugin_xmlrpc_send",
        "HA sync receive hook": "function threatshield_plugin_xmlrpc_recv(",
        "HA sync done hook": "function threatshield_plugin_xmlrpc_recv_done",
        "AdGuard Home validates the config before it is used": "--check-config",
        "configuration migration": "function threatshield_migrate_config",
        "allowlist feeds generated": "whitelist_filters:{$whitelist_filters_yaml}",
        "allowlist wins over block rules": "threatshield_allowlist_rules(",
        "rogue DNS interface binding": "dns_intercept_interfaces",
        "configured management API port": "$api_port = (int)(threatshield_config()['http_port'] ?? 3000)",
        "PF port-range normalization": "function threatshield_pf_port_spec",
    }

    for name, marker in invariants.items():
        if marker not in integration:
            errors.append(f"threatshield.inc missing invariant: {name}")

    if "/etc/inc/priv/threatshield.priv.inc" not in manifest:
        errors.append("pkg-plist missing absolute privilege definition entry")

    if "@freesense.org" not in makefile:
        errors.append("Makefile missing official maintainer domain")

    if "www/adguardhome-bin" not in makefile:
        errors.append("Makefile must use the checksum-pinned AdGuard Home binary port")

    if "--no-check-update" not in rc_script:
        errors.append("rc script must disable the upstream self-updater")
    if "-s run" in rc_script:
        errors.append("rc script uses unsupported AdGuard Home service action '-s run'")
    if "schema_version: 34" not in integration:
        errors.append("generated configuration is not pinned to AdGuard Home schema 34")
    for removed_key in ("bind_host:", "bind_port:", "all_servers:", "fastest_addr:", "stats:"):
        if removed_key in integration:
            errors.append(f"generated configuration contains obsolete key: {removed_key}")
    if 'rdr on {lan}' in integration:
        errors.append("PF generator emits invalid literal LAN interface syntax")
    if "function threatshield_restore_unbound" not in integration:
        errors.append("Unbound coordination state is not restored safely")
    if "pfsense-utils.inc" in integration:
        errors.append("ThreatShield references the removed pfSense utility include")
    if "file_put_contents(THREATSHIELD_CONFIG_FILE, $yaml)" in integration:
        errors.append("ThreatShield writes generated configuration non-atomically")
    if "rate_limit_subnet_len_ipv4: 24" in integration:
        errors.append("rate-limit IPv4 subnet setting is hard-coded")
    # FreeSense asks packages for 'nat', 'pfearly' and 'filter' rules only
    # (filter.inc discover_pkg_rules); answering any other type loads nothing.
    if "$type !== 'nat' && $type !== 'pfearly'" not in integration or "threatshield_removing" not in integration or "$type !== 'rules'" in integration:
        errors.append("rule hook does not answer the rule types the firewall asks for")
    if "table <{$name}> persist file" not in pf_builder or "($ctx['ensure'])($file, $name)" not in pf_builder:
        errors.append("pf tables are not declared from files that are guaranteed to exist")
    if "log (to pflog1)" not in pf_builder:
        errors.append("DNSBL checks do not log to the dedicated pflog1 interface")
    if "overload <' . THREATSHIELD_T_FLOOD . '> flush global" not in pf_builder:
        errors.append("flood limits do not feed the flood table")
    if re.search(r"block out[^\n]*THREATSHIELD_T_DOH", pf_builder):
        errors.append("DoH addresses must be blocked inbound on LAN, not outbound (it would block the upstreams)")
    if pf_builder.count('from <" . THREATSHIELD_T_ALLOW') != 1:
        errors.append("the IP allowlist may only pass traffic in owned-port rules")
    if "empty($ctx['healthy'])" not in pf_builder:
        errors.append("the DNS redirect is not held back while the listener is down")
    if "127.255.255." not in library:
        errors.append("DNSBL error answers (127.255.255.x) are not treated as failures")
    if "function threatshield_preflight" not in health or "function threatshield_reconcile" not in health:
        errors.append("pre-flight checks or self-repair are missing")
    if "define('THREATSHIELD_FILTER_DIR', '/var/db/threatshield/data/userfilters')" not in integration:
        errors.append("downloaded filters are not stored in AdGuard Home's safe userfilters directory")
    if "threatshield_feed_path((string)$feed['url'])" not in integration or "function threatshield_feed_path" not in integration:
        errors.append("generated filters do not reference the downloader's local files")
    if "safe_fs_patterns:" not in integration:
        errors.append("generated filters do not allowlist the package's local filter directory")
    if "filtering/refresh', 'POST', ['whitelist' => ($kind === 'allow')]" not in updater:
        errors.append("updater does not call AdGuard Home's supported local-filter refresh endpoint")
    if "ltrim($endpoint, '/') === 'filtering/refresh'" not in integration:
        errors.append("filter refresh does not have a dedicated long API timeout")
    if "filtering/refresh_filters" in updater:
        errors.append("updater calls a nonexistent AdGuard Home filter refresh endpoint")
    if "'start' => 'onestart'" not in integration or "'restart' => 'onerestart'" not in integration:
        errors.append("service control does not use FreeBSD's explicit one* actions")
    if "threatshield_sync_config" in install_script:
        errors.append("package installer bypasses rc.packages and invokes ThreatShield sync twice")
    if "threatshield_remove_config" in deinstall_script:
        errors.append("package deinstaller bypasses rc.packages and invokes ThreatShield cleanup twice")

    for relative in ("Makefile", "distinfo", "pkg-descr"):
        if not (BINARY_PORT / relative).is_file():
            errors.append(f"missing AdGuard Home binary port file: {relative}")

    if (BINARY_PORT / "Makefile").is_file():
        binary_makefile = (BINARY_PORT / "Makefile").read_text(encoding="utf-8")
        stage_bin = "${MKDIR} ${STAGEDIR}${PREFIX}/bin"
        install_binary = "${INSTALL_PROGRAM} ${WRKSRC}/AdGuardHome ${STAGEDIR}${PREFIX}/bin/AdGuardHome"
        if stage_bin not in binary_makefile:
            errors.append("AdGuard Home binary port does not create its staged bin directory")
        elif binary_makefile.index(stage_bin) > binary_makefile.index(install_binary):
            errors.append("AdGuard Home binary port creates its staged bin directory too late")

    if (BINARY_PORT / "distinfo").is_file():
        distinfo = (BINARY_PORT / "distinfo").read_text(encoding="utf-8")
        for architecture in ("amd64", "arm64"):
            if f"AdGuardHome_freebsd_{architecture}.tar.gz" not in distinfo:
                errors.append(f"distinfo missing FreeBSD {architecture} release")

    if "threatshield" not in package_xml:
        errors.append("package XML missing package declaration")
    if "<name>threatshield_dnsbl</name>" not in package_xml or "onestart" not in package_xml:
        errors.append("package XML must declare both services with explicit start commands")

    # Every installed file is listed in pkg-plist and the other way round.
    files_root = PORT / "files"
    shipped = set()
    for path in files_root.rglob("*"):
        if not path.is_file() or path.name in ("pkg-install.in", "pkg-deinstall.in"):
            continue
        rel = path.relative_to(files_root).as_posix()
        shipped.add("/" + rel if rel.startswith("etc/inc/") else rel.removeprefix("usr/local/"))
    listed = {line.strip() for line in manifest.splitlines() if line.strip() and not line.startswith("@")}
    for missing in sorted(shipped - listed):
        errors.append(f"pkg-plist does not list {missing}")
    for extra in sorted(listed - shipped):
        errors.append(f"pkg-plist lists a file that does not exist: {extra}")

    privileges = (PORT / "files/etc/inc/priv/threatshield.priv.inc").read_text(encoding="utf-8")
    for page in sorted(PORT.glob("files/usr/local/www/threatshield/*.php")):
        if f"threatshield/{page.name}*" not in privileges:
            errors.append(f"privilege list does not cover {page.name}")

    for page in PORT.glob("files/usr/local/www/threatshield/*.php"):
        page_text = page.read_text(encoding="utf-8", errors="replace")
        if re.search(r"\$config\s*=\s*", page_text):
            errors.append(f"{page.relative_to(ROOT)}: package page shadows the firewall global $config")

    querylog = (PORT / "files/usr/local/www/threatshield/threatshield_querylog.php").read_text(encoding="utf-8")
    status = (PORT / "files/usr/local/www/threatshield/threatshield_status.php").read_text(encoding="utf-8")
    if "<?=$client_ip?>" in querylog or "<?=$hostname?>" in querylog or "<?=$ip?>" in status:
        errors.append("Threat Shield status pages render unescaped client-controlled values")
    # AdGuard Home's querylog reports block-list hits as FilteredBlackList.
    if "'FilteredBlackList'" not in querylog or "'FilteredBlocked'" in querylog:
        errors.append("query log does not recognise AdGuard Home's blocked reasons")
    # Browsers submit textareas with CRLF; older systems drop CR from config.xml.
    if 'str_replace(["\\r\\n", "\\r"], "\\n"' not in integration:
        errors.append("stored settings do not normalize CRLF line breaks")

    if errors:
        print("Threat Shield smoke check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("Threat Shield smoke check passed: all files and invariants verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
