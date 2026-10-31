<?php
/*
 * threatshield.inc
 * FreeSense Threat Shield - DNS filtering, IP reputation and GeoIP protection
 *
 * Copyright (c) 2025-2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

require_once('config.inc');
require_once('util.inc');
require_once('services.inc');
require_once('filter.inc');
require_once(__DIR__ . '/threatshield/threatshield_lib.inc');
require_once(__DIR__ . '/threatshield/threatshield_catalog.inc');
require_once(__DIR__ . '/threatshield/threatshield_pf.inc');

define('THREATSHIELD_CONFIG_PATH', 'installedpackages/threatshield');
define('THREATSHIELD_CONFIG_DIR', '/usr/local/etc/threatshield');
define('THREATSHIELD_CONFIG_FILE', '/usr/local/etc/threatshield/AdGuardHome.yaml');
define('THREATSHIELD_DB_DIR', '/var/db/threatshield');
// AdGuard Home only loads local filter files from its working-directory
// userfilters area unless a path is separately allowlisted.  Keep our fetched
// copies there so they are both accepted and safely owned by this package.
define('THREATSHIELD_FILTER_DIR', '/var/db/threatshield/data/userfilters');
define('THREATSHIELD_GEOIP_DIR', '/var/db/threatshield/geoip');
define('THREATSHIELD_IP_DIR', '/var/db/threatshield/ip');
define('THREATSHIELD_DNSBL_DIR', '/var/db/threatshield/dnsbl');
define('THREATSHIELD_CACHE_DIR', '/var/db/threatshield/cache');
define('THREATSHIELD_PAUSE_FILE', '/var/db/threatshield/pause.json');
define('THREATSHIELD_FEED_STATUS', '/var/db/threatshield/feed_status.json');
define('THREATSHIELD_PID_FILE', '/var/run/threatshield.pid');
define('THREATSHIELD_DNSBL_PID_FILE', '/var/run/threatshield_dnsbl.pid');
define('THREATSHIELD_DNSBL_STATUS', '/var/run/threatshield_dnsbl.status.json');
define('THREATSHIELD_API_BASE', 'http://127.0.0.1');
define('THREATSHIELD_SCHEMA_VERSION', 34);
define('THREATSHIELD_CONFIG_VERSION', 2);
define('THREATSHIELD_MAX_FEED_BYTES', 32 * 1024 * 1024);
define('THREATSHIELD_UPDATER', '/usr/local/sbin/freesense-threatshield-update');
define('THREATSHIELD_PROBE_BLOCKED', 'blocked.threatshield.test');

function threatshield_list_fields(): array {
	return ['interfaces', 'feeds', 'geoip_countries', 'blocked_services', 'rewrites', 'clients', 'geoip_policies',
	    'dns_intercept_interfaces', 'allowlist', 'ip_allowlist', 'ip_feeds', 'ipbl_wan_interfaces', 'ipbl_lan_interfaces',
	    'services_schedule_days', 'dnsbl_zones', 'inbound_policies', 'map_panels'];
}

function threatshield_assigned_interfaces(): array {
	$result = [];
	foreach (config_get_path('interfaces', []) as $name => $entry) {
		if (!is_array($entry) || empty($entry['if'])) continue;
		$result[(string)$name] = (string)($entry['descr'] ?? strtoupper((string)$name));
	}
	return $result;
}

/* Interfaces with a gateway (WAN type): the only place inbound policies and
 * allow-only GeoIP may apply, because pfearly rules run before anti-lockout. */
function threatshield_wan_interfaces(): array {
	$out = [];
	foreach (threatshield_assigned_interfaces() as $name => $descr) {
		if (function_exists('interface_has_gateway') && (interface_has_gateway($name) || (function_exists('interface_has_gatewayv6') && interface_has_gatewayv6($name)))) {
			$out[$name] = $descr;
		}
	}
	return $out;
}

function threatshield_normalize_list($value): array {
	if (is_array($value) && array_key_exists('item', $value)) {
		$value = $value['item'];
	}
	return is_array($value) ? array_values($value) : [];
}

/* Lists inside list records (a GeoIP policy's interfaces and countries) need
 * the same 'item' wrapper as top-level lists: a numeric PHP array is written
 * as <0>, <1>, ..., which makes config.xml unreadable, so write_config() fell
 * back to the previous config and the save was lost. */
function threatshield_storage_value($value) {
	if (!is_array($value)) {
		return is_scalar($value) ? (string)$value : '';
	}
	if (count($value) === 1 && array_key_exists('item', $value)) {
		$value = threatshield_normalize_list($value);
	}
	$out = [];
	foreach ($value as $k => $v) {
		$out[$k] = threatshield_storage_value($v);
	}
	return array_is_list($value) ? ['item' => $out] : $out;
}

/* Reverse of threatshield_storage_value() for values read from config.xml. */
function threatshield_unwrap_lists($value) {
	if (!is_array($value)) {
		return $value;
	}
	if (count($value) === 1 && array_key_exists('item', $value)) {
		$value = threatshield_normalize_list($value);
	}
	foreach ($value as $k => $v) {
		$value[$k] = threatshield_unwrap_lists($v);
	}
	return $value;
}

function threatshield_feed_path(string $url): string {
	return THREATSHIELD_FILTER_DIR . '/feed_' . md5($url) . '.txt';
}

function threatshield_valid_port_spec(string $value): bool {
	$value = trim($value);
	if ($value === '' || strtolower($value) === 'any') return true;
	foreach (explode(',', $value) as $part) {
		$part = trim($part);
		if (!preg_match('/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/', $part, $match)) return false;
		$first = (int)$match[1];
		$last = isset($match[2]) ? (int)$match[2] : $first;
		if ($first < 1 || $last > 65535 || $first > $last) return false;
	}
	return true;
}

function threatshield_pf_port_spec(string $value): string {
	$value = trim($value);
	if ($value === '' || strtolower($value) === 'any') return '';
	return preg_replace('/\s*-\s*/', ':', $value);
}

function threatshield_dns_bind_hosts(array $cfg): array {
	if (($cfg['dns_coordination_mode'] ?? 'primary') === 'proxy') return ['127.0.0.1'];
	$interfaces = threatshield_normalize_list($cfg['interfaces'] ?? ['all']);
	if (empty($interfaces) || in_array('all', $interfaces, true)) return ['0.0.0.0'];
	// The DNS redirect and the health probe reach the filter on loopback.
	$hosts = ['127.0.0.1'];
	foreach ($interfaces as $interface) {
		if (function_exists('get_interface_ip')) {
			$ipv4 = get_interface_ip((string)$interface);
			if (is_string($ipv4) && filter_var($ipv4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $hosts[] = $ipv4;
		}
		if (function_exists('get_interface_ipv6')) {
			$ipv6 = get_interface_ipv6((string)$interface);
			if (is_string($ipv6) && filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) $hosts[] = $ipv6;
		}
	}
	return array_values(array_unique($hosts));
}

function threatshield_default_config(): array {
	$feeds = [];
	foreach (threatshield_feed_catalog() as $preset => $c) {
		if (in_array('normal', $c['levels'], true)) $feeds[] = threatshield_feed_from_catalog($preset, true);
	}
	$ip_feeds = [];
	foreach (threatshield_ipfeed_catalog() as $preset => $c) {
		$ip_feeds[] = threatshield_ipfeed_from_catalog($preset, in_array($preset, ['spamhaus_drop', 'spamhaus_drop6', 'doh_ipv4', 'doh_ipv6'], true));
	}
	$zones = [];
	foreach (threatshield_dnsbl_zone_catalog() as $preset => $c) {
		$zones[] = threatshield_dnsbl_zone_from_catalog($preset, $preset === 'zen');
	}
	return [
		'config_version' => (string)THREATSHIELD_CONFIG_VERSION,
		'enable' => 'off',
		'listen_port' => '53',
		'http_port' => '3000',
		'dns_coordination_mode' => 'primary', // 'primary' (Unbound to 5335), 'proxy' (ThreatShield on 5354), 'standalone'
		'interfaces' => ['all'],
		'upstreams' => "https://dns.quad9.net/dns-query\nhttps://cloudflare-dns.com/dns-query",
		'fallback_dns' => "9.9.9.9\n1.1.1.1",
		'bootstrap_dns' => "9.9.9.9\n1.1.1.1",
		'upstream_mode' => 'parallel', // 'parallel', 'fastest_addr', 'load_balance'
		'enable_dnssec' => 'on',
		'enable_safesearch' => 'off',
		'enable_parental' => 'off',
		'safebrowsing_enabled' => 'on',
		'blocking_mode' => 'default', // 'default', 'refused', 'nxdomain', 'null_ip', 'custom_ip'
		'blocking_ipv4' => '',
		'blocking_ipv6' => '',
		'block_doh_canary' => 'on',
		'block_icloud_private_relay' => 'on',
		'cache_size' => '4', // In MB
		'cache_ttl_min' => '0',
		'cache_ttl_max' => '0',
		'cache_optimistic' => 'on',
		'edns_client_subnet' => 'off',
		'ratelimit' => '0',
		'rate_limit_subnet_len_ipv4' => '24',
		'rate_limit_subnet_len_ipv6' => '56',
		'rate_limit_whitelist' => '',
		'querylog_enabled' => 'on',
		'querylog_retention' => '2160',
		'anonymize_client_ip' => 'off',
		'ignored_domains' => '',
		'catch_rogue_dns' => 'off',
		'dns_intercept_interfaces' => [],
		'dns_redirect_exclude' => '',
		'block_dot' => 'off',
		'block_doh_ips' => 'off',
		'block_dns6_bypass' => 'on',
		'ha_sync' => 'off',
		'feed_update_interval' => 'daily',
		'feed_level' => 'normal',
		'feeds' => $feeds,
		'custom_rules' => '',
		'allowlist' => [],
		'ip_allowlist' => [],
		'ipbl_enable' => 'off',
		'ipbl_update_interval' => 'daily',
		'ipbl_wan_interfaces' => ['wan'],
		'ipbl_lan_interfaces' => ['lan'],
		'ip_feeds' => $ip_feeds,
		'geoip_enable' => 'on',
		'geoip_mode' => 'block_inbound', // 'block_inbound', 'block_both', 'whitelist_inbound'
		'geoip_countries' => ['RU', 'CN', 'KP', 'IR', 'BY'],
		'geoip_update_interval' => 'weekly',
		'geoip_ipv6' => 'off',
		'geoip_policies' => [],
		'blocked_services' => [],
		'services_schedule_enable' => 'off',
		'services_schedule_tz' => 'Local',
		'services_schedule_days' => [],
		'rewrites' => [],
		'clients' => [],
		'dnsbl_enable' => 'off',
		'dnsbl_resolver' => 'auto',
		'dnsbl_zones' => $zones,
		'dnsbl_quorum' => '1',
		'dnsbl_ttl_good' => '21600',
		'dnsbl_ttl_bad' => '86400',
		'dnsbl_ttl_fail' => '60',
		'dnsbl_max_qps' => '20',
		'dnsbl_concurrency' => '8',
		'dnsbl_timeout_ms' => '2000',
		'dnsbl_retries' => '1',
		'dnsbl_queue_max' => '2000',
		'dnsbl_cache_max' => '100000',
		'dnsbl_breaker_secs' => '30',
		'inbound_policies' => [],
		'flood_release_secs' => '3600',
		'health_test_domain' => 'freesense.org',
		/* threat map */
		'map_overview' => 'on',
		'map_geodb' => 'off',               // off | country | country_asn (DB-IP Lite, monthly)
		'map_location' => 'auto',           // auto (time zone) | manual
		'map_lat' => '',
		'map_lon' => '',
		'map_background' => 'on',
		'map_dns' => 'on',
		'map_log_allowed' => 'off',
		'map_retention_days' => '7',
		'map_style' => 'freesense',         // freesense | pro | hacker
		'map_theme' => 'auto',              // auto | light | dark (full screen)
		'map_window' => '1h',
		'map_animations' => 'full',         // full | reduced | off
		'map_mask_ips' => 'off',
		'map_layout' => 'wall',             // map | side | wall (full screen)
		'map_panels' => ['kpis', 'mix', 'timeline', 'countries', 'sources', 'ports', 'feed', 'spotlight', 'status'],
		'map_alerts' => 'on',
		'map_alert_factor' => '4',
		'map_alert_sound' => 'off',
		'map_title' => '',
	];
}

/* Upgrades a configuration saved by an older package (pure, idempotent).
 * New firewall behaviour stays off for existing installs: an upgrade must
 * not start blocking traffic nobody asked to block. */
function threatshield_migrate_config(array $raw, int $now): array {
	if (empty($raw)) return $raw;
	$version = (int)($raw['config_version'] ?? 1);
	foreach (threatshield_list_fields() as $field) {
		if (array_key_exists($field, $raw)) {
			$raw[$field] = threatshield_unwrap_lists(threatshield_normalize_list($raw[$field]));
		}
	}
	// The original single GeoIP selector becomes a policy record.
	if (empty($raw['geoip_policies']) && !empty($raw['geoip_countries'])) {
		$raw['geoip_policies'] = [[
			'id' => 'default', 'enable' => ($raw['geoip_enable'] ?? 'on'),
			'action' => (($raw['geoip_mode'] ?? 'block_inbound') === 'whitelist_inbound') ? 'allow_selected' : 'block_selected',
			'direction' => (($raw['geoip_mode'] ?? '') === 'block_both') ? 'both' : 'in',
			'interfaces' => ['wan'], 'protocol' => 'any', 'ports' => 'any',
			'countries' => threatshield_normalize_list($raw['geoip_countries']),
		]];
	}
	if (isset($raw['feeds']) && is_array($raw['feeds'])) {
		$by_url = [];
		foreach (threatshield_feed_catalog() as $preset => $c) $by_url[$c['url']] = $preset;
		foreach ($raw['feeds'] as $i => $feed) {
			if (!is_array($feed)) continue;
			$url = (string)($feed['url'] ?? '');
			if (empty($feed['id'])) $raw['feeds'][$i]['id'] = substr(md5($url), 0, 8);
			if (!isset($feed['kind'])) $raw['feeds'][$i]['kind'] = 'block';
			if (!isset($feed['preset'])) $raw['feeds'][$i]['preset'] = $by_url[$url] ?? '';
		}
	}
	if ($version < 2) {
		[$entries, $remaining] = threatshield_split_custom_allow_rules((string)($raw['custom_rules'] ?? ''), $now);
		$allow = threatshield_normalize_list($raw['allowlist'] ?? []);
		foreach ($entries as $entry) {
			if (threatshield_allowlist_find($allow, $entry['domain']) === null) $allow[] = $entry;
		}
		$raw['allowlist'] = $allow;
		$raw['custom_rules'] = $remaining;
		if (!isset($raw['feed_level'])) $raw['feed_level'] = 'custom';
		if (!isset($raw['block_dns6_bypass'])) $raw['block_dns6_bypass'] = 'off';
		$raw['config_version'] = (string)THREATSHIELD_CONFIG_VERSION;
	}
	return $raw;
}

/* Defaults merged under a saved configuration; lists replace defaults as a
 * unit, since recursive replacement would keep tail entries of a default
 * list when the saved list is shorter. */
function threatshield_merge_defaults(array $raw): array {
	$config = array_replace_recursive(threatshield_default_config(), $raw);
	foreach (threatshield_list_fields() as $field) {
		if (array_key_exists($field, $raw)) {
			$config[$field] = threatshield_unwrap_lists(threatshield_normalize_list($raw[$field]));
		}
	}
	return $config;
}

function threatshield_config(): array {
	$raw = config_get_path(THREATSHIELD_CONFIG_PATH, []);
	if (!is_array($raw)) {
		$raw = [];
	}
	return threatshield_merge_defaults(threatshield_migrate_config($raw, time()));
}

/* Persists the upgrade once, so later releases read the new layout. */
function threatshield_persist_migration(): void {
	$raw = config_get_path(THREATSHIELD_CONFIG_PATH, []);
	if (!is_array($raw) || empty($raw) || (int)($raw['config_version'] ?? 1) >= THREATSHIELD_CONFIG_VERSION) return;
	$migrated = threatshield_migrate_config($raw, time());
	if (isset($raw['_unbound_state'])) $migrated['_unbound_state'] = $raw['_unbound_state'];
	config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($migrated));
	write_config(gettext('Threat Shield: migrated settings to package 1.1'));
}

function threatshield_config_for_storage(array $candidate): array {
	$clean = [];
	foreach ($candidate as $k => $v) {
		if (in_array($k, threatshield_list_fields(), true)) {
			// config.xml list tags must use a valid element name. Writing a PHP
			// numeric array directly would emit invalid tags such as <0>.
			$clean[$k] = threatshield_storage_value(threatshield_normalize_list($v));
		} elseif (is_array($v)) {
			$clean[$k] = threatshield_storage_value($v);
		} elseif (is_scalar($v)) {
			// Browsers submit textareas with CRLF. Store LF only: older system
			// releases drop CR line breaks from config.xml, so the saved value never
			// matched the persisted one and every save was rolled back.
			$clean[$k] = str_replace(["\r\n", "\r"], "\n", (string)$v);
		}
	}
	return $clean;
}

function threatshield_yaml_quote(string $value): string {
	return (string)json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function threatshield_alias_names(): array {
	$names = [];
	foreach (config_get_path('aliases/alias', []) as $alias) {
		if (is_array($alias) && !empty($alias['name'])) $names[] = (string)$alias['name'];
	}
	return $names;
}

function threatshield_validate_config(array $cfg): array {
	$errors = [];
	$port = (int)($cfg['listen_port'] ?? 53);
	$mode = $cfg['dns_coordination_mode'] ?? 'primary';
	if ($port < 1 || $port > 65535) {
		$errors[] = gettext('A valid DNS listening port (1-65535) must be specified.');
	}
	if (($cfg['enable'] ?? 'off') === 'on' && $mode === 'primary' && $port !== 53) {
		$errors[] = gettext('Primary DNS mode requires Threat Shield to listen on port 53.');
	}
	if (!in_array($mode, ['primary', 'proxy', 'standalone'], true)) {
		$errors[] = gettext('The DNS coordination mode is invalid.');
	}
	foreach (['http_port', 'listen_port'] as $field) {
		$value = (int)($cfg[$field] ?? 0);
		if ($value < 1 || $value > 65535) $errors[] = gettext('All listener ports must be between 1 and 65535.');
	}
	if (!in_array((string)($cfg['querylog_retention'] ?? ''), ['6','24','168','720','2160'], true)) {
		$errors[] = gettext('The query-log retention period is invalid.');
	}
	foreach (['feeds' => gettext('Every DNS list must use a valid HTTPS URL.'), 'ip_feeds' => gettext('Every IP list must use a valid HTTPS URL.')] as $key => $message) {
		foreach (threatshield_normalize_list($cfg[$key] ?? []) as $feed) {
			$url = is_array($feed) ? (string)($feed['url'] ?? '') : '';
			$p = parse_url($url);
			if ($url === '' || !is_array($p) || strtolower($p['scheme'] ?? '') !== 'https' || empty($p['host'])) {
				$errors[] = $message; break;
			}
		}
	}
	$ids = [];
	foreach (threatshield_normalize_list($cfg['ip_feeds'] ?? []) as $feed) {
		$id = is_array($feed) ? threatshield_pf_ident((string)($feed['id'] ?? '')) : '';
		if ($id === '' || isset($ids[$id]) || !in_array(($feed['direction'] ?? ''), ['in', 'out', 'both'], true) ||
		    !in_array(($feed['kind'] ?? ''), ['threat', 'doh'], true)) {
			$errors[] = gettext('Every IP list needs a unique identifier, a type and a direction.'); break;
		}
		$ids[$id] = true;
	}
	foreach (threatshield_normalize_list($cfg['blocked_services'] ?? []) as $service) {
		if (!in_array((string)$service, threatshield_services_catalog(), true)) {
			$errors[] = gettext('An unsupported blocked-service identifier was submitted.'); break;
		}
	}
	$assigned = array_keys(threatshield_assigned_interfaces());
	$listener_interfaces = threatshield_normalize_list($cfg['interfaces'] ?? ['all']);
	if (!in_array('all', $listener_interfaces, true) && !empty(array_diff($listener_interfaces, $assigned))) {
		$errors[] = gettext('A DNS listener references an unassigned interface.');
	}
	foreach (['dns_intercept_interfaces', 'ipbl_wan_interfaces', 'ipbl_lan_interfaces'] as $key) {
		if (!empty(array_diff(array_map('strval', threatshield_normalize_list($cfg[$key] ?? [])), $assigned))) {
			$errors[] = gettext('A protection setting references an unassigned interface.'); break;
		}
	}
	$wan = array_keys(threatshield_wan_interfaces());
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		if (!is_array($policy) || empty($policy['countries']) || empty($policy['interfaces']) ||
			!in_array(($policy['action'] ?? ''), ['block_selected','allow_selected'], true) ||
			!in_array(($policy['direction'] ?? ''), ['in','out','both'], true) ||
			!in_array(($policy['protocol'] ?? ''), ['any','tcp','udp'], true)) {
			$errors[] = gettext('Every GeoIP policy needs countries, interfaces, a valid action, direction, and protocol.'); break;
		}
		if (!preg_match('/^[a-z0-9_]{1,15}$/', (string)($policy['id'] ?? 'default'))) {
			$errors[] = gettext('A GeoIP policy ID may only use a-z, 0-9 and _ (up to 15 characters).'); break;
		}
		$policy_ifs = array_map('strval', threatshield_normalize_list($policy['interfaces']));
		if (!empty(array_diff($policy_ifs, $assigned))) {
			$errors[] = gettext('A GeoIP policy references an unassigned interface.'); break;
		}
		if (($policy['enable'] ?? 'on') === 'on' && ($policy['action'] ?? '') === 'allow_selected' && !empty($wan) && !empty(array_diff($policy_ifs, $wan))) {
			$errors[] = gettext('"Allow selected countries only" can only apply to interfaces with a gateway (WAN). On a LAN it would lock out local clients.'); break;
		}
		if (!threatshield_valid_port_spec((string)($policy['ports'] ?? 'any'))) {
			$errors[] = gettext('A GeoIP policy has an invalid port or port range.'); break;
		}
	}
	foreach (threatshield_normalize_list($cfg['rewrites'] ?? []) as $rewrite) {
		$domain = is_array($rewrite) ? strtolower(trim((string)($rewrite['domain'] ?? ''))) : '';
		$answer = is_array($rewrite) ? trim((string)($rewrite['answer'] ?? '')) : '';
		if ($domain === '' || $answer === '' || !preg_match('/^(\\*\\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/', $domain) ||
			(!filter_var($answer, FILTER_VALIDATE_IP) && !preg_match('/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i', $answer))) {
			$errors[] = gettext('Each DNS rewrite needs a valid domain and an IP address or hostname answer.'); break;
		}
	}
	if (($cfg['blocking_mode'] ?? '') === 'custom_ip') {
		if (!filter_var($cfg['blocking_ipv4'] ?? '', FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$errors[] = gettext('A valid custom IPv4 sinkhole address is required.');
		}
		if (($cfg['blocking_ipv6'] ?? '') !== '' && !filter_var($cfg['blocking_ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$errors[] = gettext('The custom IPv6 sinkhole address is invalid.');
		}
	}
	foreach (threatshield_text_list((string)($cfg['dns_redirect_exclude'] ?? '')) as $item) {
		if (threatshield_cidr_normalize($item) === null) {
			$errors[] = sprintf(gettext('"%s" in the DNS redirection exceptions is not an IP address or network.'), $item); break;
		}
	}
	foreach (threatshield_normalize_list($cfg['allowlist'] ?? []) as $entry) {
		if (!is_array($entry) || threatshield_normalize_domain((string)($entry['domain'] ?? '')) === null) {
			$errors[] = gettext('Every allowlist entry needs a valid domain name.'); break;
		}
	}
	foreach (threatshield_normalize_list($cfg['ip_allowlist'] ?? []) as $entry) {
		if (!is_array($entry) || threatshield_cidr_normalize((string)($entry['address'] ?? '')) === null) {
			$errors[] = gettext('Every IP allowlist entry needs a valid IP address or network.'); break;
		}
	}
	$schedules = [['enable' => $cfg['services_schedule_enable'] ?? 'off', 'days' => $cfg['services_schedule_days'] ?? []]];
	foreach (threatshield_normalize_list($cfg['clients'] ?? []) as $client) {
		if (is_array($client)) $schedules[] = ['enable' => $client['schedule_enable'] ?? 'off', 'days' => $client['schedule_days'] ?? []];
	}
	foreach ($schedules as $s) {
		if ($s['enable'] !== 'on') continue;
		foreach (threatshield_normalize_list($s['days']) as $day) {
			$start = (string)($day['start'] ?? '');
			$end = (string)($day['end'] ?? '');
			if (!in_array(($day['day'] ?? ''), threatshield_schedule_days(), true) || !threatshield_valid_hhmm($start) ||
			    !threatshield_valid_hhmm($end, true) || strcmp($end, $start) <= 0) {
				$errors[] = gettext('Each schedule day needs a start time before its end time (HH:MM).'); break 2;
			}
		}
	}
	$errors = array_merge($errors, threatshield_validate_inbound($cfg, $assigned, $wan));
	return array_values(array_unique($errors));
}

function threatshield_validate_inbound(array $cfg, array $assigned, array $wan): array {
	$errors = [];
	$zones = threatshield_normalize_list($cfg['dnsbl_zones'] ?? []);
	$enabled_zones = 0;
	foreach ($zones as $zone) {
		if (!is_array($zone)) continue;
		$z = trim((string)($zone['zone'] ?? ''));
		if ($z === '' || !preg_match('/^(\{key\}\.)?[a-z0-9.-]+$/i', $z) || !threatshield_dnsbl_valid_match((string)($zone['match'] ?? 'any'))) {
			$errors[] = gettext('Every DNSBL zone needs a valid zone name and answer match.'); break;
		}
		if (strpos($z, '{key}') !== false && ($zone['enabled'] ?? 'off') === 'on' && !preg_match('/^[a-z0-9]{16,64}$/i', (string)($zone['access_key'] ?? ''))) {
			$errors[] = sprintf(gettext('The DNSBL zone %s needs its access key.'), (string)($zone['name'] ?? $z)); break;
		}
		if (($zone['enabled'] ?? 'off') === 'on') $enabled_zones++;
	}
	$quorum = (int)($cfg['dnsbl_quorum'] ?? 1);
	if ($quorum < 1 || ($enabled_zones > 0 && $quorum > $enabled_zones)) {
		$errors[] = gettext('The DNSBL quorum must be between 1 and the number of enabled zones.');
	}
	foreach (['dnsbl_ttl_good' => [60, 2592000], 'dnsbl_ttl_bad' => [60, 2592000], 'dnsbl_ttl_fail' => [10, 3600],
	    'dnsbl_max_qps' => [1, 1000], 'dnsbl_concurrency' => [1, 64], 'dnsbl_timeout_ms' => [200, 10000], 'dnsbl_retries' => [0, 5],
	    'dnsbl_queue_max' => [10, 100000], 'dnsbl_cache_max' => [1000, 1000000], 'dnsbl_breaker_secs' => [5, 3600],
	    'flood_release_secs' => [60, 604800]] as $key => [$min, $max]) {
		$v = (string)($cfg[$key] ?? '');
		if (!ctype_digit($v) || (int)$v < $min || (int)$v > $max) {
			$errors[] = sprintf(gettext('%1$s must be a whole number from %2$d to %3$d.'), $key, $min, $max);
		}
	}
	$resolver = trim((string)($cfg['dnsbl_resolver'] ?? 'auto'));
	if ($resolver !== 'auto' && threatshield_resolver_target($resolver) === null) {
		$errors[] = gettext('The DNSBL resolver must be "auto" or an IP address with an optional port.');
	}
	$mode = $cfg['dns_coordination_mode'] ?? 'primary';
	$uses_dnsbl = false;
	$ids = [];
	$aliases = threatshield_alias_names();
	foreach (threatshield_normalize_list($cfg['inbound_policies'] ?? []) as $p) {
		if (!is_array($p)) continue;
		$id = threatshield_pf_ident((string)($p['id'] ?? ''));
		$name = (string)($p['name'] ?? $id);
		if ($id === '' || isset($ids[$id])) {
			$errors[] = gettext('Every inbound policy needs a unique identifier.'); break;
		}
		$ids[$id] = true;
		$ifs = array_map('strval', threatshield_normalize_list($p['interfaces'] ?? []));
		if (empty($ifs) || !empty(array_diff($ifs, $assigned))) {
			$errors[] = sprintf(gettext('Inbound policy "%s" needs one or more assigned interfaces.'), $name);
		} elseif (!empty($wan) && !empty(array_diff($ifs, $wan))) {
			$errors[] = sprintf(gettext('Inbound policy "%s" may only use interfaces with a gateway (WAN).'), $name);
		}
		if (!in_array(($p['protocol'] ?? ''), ['tcp', 'udp', 'both'], true) || !in_array(($p['dnsbl_mode'] ?? ''), ['off', 'greylist', 'failopen'], true) ||
		    !in_array(($p['on_failure'] ?? ''), ['allow', 'deny'], true)) {
			$errors[] = sprintf(gettext('Inbound policy "%s" has an invalid protocol, mode or failure action.'), $name);
		}
		$ports = trim((string)($p['ports'] ?? ''));
		if ($ports === '' || strtolower($ports) === 'any' || !threatshield_valid_port_spec($ports)) {
			$errors[] = sprintf(gettext('Inbound policy "%s" needs one or more ports; protecting "any" port is not supported.'), $name);
		}
		if (threatshield_pf_policy_dest((string)($p['dest'] ?? 'self'), ['aliases' => $aliases]) === null) {
			$errors[] = sprintf(gettext('Inbound policy "%s" needs a destination: This firewall, an address, a network or an alias.'), $name);
		}
		$flood = (int)($p['flood_max_conn'] ?? 0) > 0 || trim((string)($p['flood_conn_rate'] ?? '')) !== '' || (int)($p['flood_max_states'] ?? 0) > 0 || ($p['synproxy'] ?? 'off') === 'on';
		if ($flood && ($p['owned'] ?? 'off') !== 'on') {
			$errors[] = sprintf(gettext('Inbound policy "%s": flood limits and SYN proxy need "Threat Shield passes this traffic", because pf limits only apply to the rule that creates the connection.'), $name);
		}
		$rate = trim((string)($p['flood_conn_rate'] ?? ''));
		if ($rate !== '' && !threatshield_valid_rate($rate)) {
			$errors[] = sprintf(gettext('Inbound policy "%s": the connection rate must look like 15/5 (connections per seconds).'), $name);
		}
		if (($p['enable'] ?? 'on') === 'on' && ($p['dnsbl_mode'] ?? 'off') !== 'off') $uses_dnsbl = true;
	}
	if (($cfg['dnsbl_enable'] ?? 'off') === 'on' && $uses_dnsbl) {
		if ($enabled_zones === 0) {
			$errors[] = gettext('Enable at least one DNSBL zone, or turn the reputation check off.');
		}
		if ($resolver === 'auto' && $mode !== 'primary') {
			$dqs_only = $enabled_zones > 0;
			foreach ($zones as $zone) {
				if (($zone['enabled'] ?? 'off') === 'on' && strpos((string)($zone['zone'] ?? ''), '{key}') === false) $dqs_only = false;
			}
			if (!$dqs_only) {
				$errors[] = gettext('In proxy and standalone DNS mode, set the DNSBL resolver to a recursive resolver of your own: public resolvers are refused by most DNSBLs.');
			}
		}
	}

	/* threat map */
	$choices = ['map_geodb' => ['off', 'country', 'country_asn'], 'map_location' => ['auto', 'manual'], 'map_style' => ['freesense', 'pro', 'hacker'],
	    'map_theme' => ['auto', 'light', 'dark'], 'map_window' => array_keys(THREATSHIELD_MAP_WINDOWS), 'map_animations' => ['full', 'reduced', 'off'],
	    'map_layout' => ['map', 'side', 'wall']];
	foreach ($choices as $key => $allowed) {
		if (isset($cfg[$key]) && !in_array((string)$cfg[$key], $allowed, true)) $errors[] = sprintf(gettext('Invalid threat map setting: %s.'), $key);
	}
	if (($cfg['map_location'] ?? 'auto') === 'manual') {
		$lat = (string)($cfg['map_lat'] ?? '');
		$lon = (string)($cfg['map_lon'] ?? '');
		if (!is_numeric($lat) || !is_numeric($lon) || abs((float)$lat) > 90 || abs((float)$lon) > 180) {
			$errors[] = gettext('Enter the firewall location as latitude (-90 to 90) and longitude (-180 to 180).');
		}
	}
	foreach (['map_retention_days' => [1, 30], 'map_alert_factor' => [2, 50]] as $key => [$min, $max]) {
		$v = (string)($cfg[$key] ?? $min);
		if (!ctype_digit($v) || (int)$v < $min || (int)$v > $max) $errors[] = sprintf(gettext('%1$s must be between %2$d and %3$d.'), $key, $min, $max);
	}
	if (strlen((string)($cfg['map_title'] ?? '')) > 60) $errors[] = gettext('The threat map title can be 60 characters at most.');
	$panels = ['kpis', 'mix', 'timeline', 'countries', 'sources', 'ports', 'feed', 'spotlight', 'status', 'asns', 'rules', 'domains'];
	if (!empty(array_diff(array_map('strval', threatshield_normalize_list($cfg['map_panels'] ?? [])), $panels))) $errors[] = gettext('Unknown threat map panel.');
	return $errors;
}

/* "auto", "ip" or "ip:port" / "[v6]:port" -> [ip, port] */
function threatshield_resolver_target(string $value): ?array {
	$value = trim($value);
	if (preg_match('/^\[([0-9a-f:.]+)\](?::(\d{1,5}))?$/i', $value, $m) || preg_match('/^([0-9.]+)(?::(\d{1,5}))?$/', $value, $m)) {
		$port = isset($m[2]) ? (int)$m[2] : 53;
		if (filter_var($m[1], FILTER_VALIDATE_IP) && $port >= 1 && $port <= 65535) return [$m[1], $port];
		return null;
	}
	if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return [$value, 53];
	return null;
}

/* The resolver the DNSBL daemon queries: Unbound's recursion in primary mode. */
function threatshield_dnsbl_resolver(array $cfg): array {
	$explicit = threatshield_resolver_target((string)($cfg['dnsbl_resolver'] ?? 'auto'));
	if ($explicit !== null) return $explicit;
	if (($cfg['dns_coordination_mode'] ?? 'primary') === 'primary') return ['127.0.0.1', 5335];
	return ['127.0.0.1', 53];
}

function threatshield_save_and_apply(array $candidate, string $description, array &$errors = [], array &$warnings = []): bool {
	$errors = threatshield_validate_config($candidate);
	if (!empty($errors)) return false;
	if (function_exists('threatshield_preflight')) {
		$check = threatshield_preflight($candidate, threatshield_config());
		$warnings = $check['warn'];
		if (!empty($check['block'])) {
			$errors = $check['block'];
			return false;
		}
	}
	$previous = threatshield_config();
	$stored = threatshield_config_for_storage($candidate);
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', null);
	if (is_array($state)) $stored['_unbound_state'] = $state;
	config_set_path(THREATSHIELD_CONFIG_PATH, $stored);
	$result = write_config($description);
	$persisted = config_get_path(THREATSHIELD_CONFIG_PATH, null);
	if (!is_array($result) || !is_array($persisted) || threatshield_config_for_storage($persisted) !== threatshield_config_for_storage($stored)) {
		$restore = threatshield_config_for_storage($previous);
		if (is_array($state)) $restore['_unbound_state'] = $state;
		config_set_path(THREATSHIELD_CONFIG_PATH, $restore);
		write_config(gettext('Rolled back failed Threat Shield settings save'));
		$errors[] = gettext('Settings could not be saved to config.xml; the previous settings were restored.');
		return false;
	}
	if (!threatshield_sync_config()) {
		$restore = threatshield_config_for_storage($previous);
		$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', null);
		if (is_array($state)) $restore['_unbound_state'] = $state;
		config_set_path(THREATSHIELD_CONFIG_PATH, $restore);
		write_config(gettext('Rolled back rejected Threat Shield settings'));
		threatshield_sync_config();
		$errors[] = gettext('Activation failed; the previous Threat Shield settings were restored.') .
		    ((threatshield_last_error() !== '') ? ' ' . threatshield_last_error() : '');
		return false;
	}
	return true;
}

/* The last reason threatshield_sync_config() refused a configuration. */
function threatshield_last_error(?string $set = null): string {
	static $error = '';
	if ($set !== null) $error = $set;
	return $error;
}

/* Unbound counts as enabled when the 'enable' key exists, even when empty.
 * Saved state uses 'on'/'off'; older state stored '', so only 'off' disables. */
function threatshield_set_unbound_enabled(bool $enabled): void {
	if ($enabled) {
		config_set_path('unbound/enable', '');
	} else {
		config_del_path('unbound/enable');
	}
}

function threatshield_restore_unbound(): bool {
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', []);
	if (!is_array($state) || ($state['managed'] ?? '') !== 'on') {
		return false;
	}
	config_set_path('unbound/port', (string)($state['port'] ?? '53'));
	config_set_path('unbound/active_interface', (string)($state['active_interface'] ?? 'all'));
	threatshield_set_unbound_enabled(($state['enable'] ?? '') !== 'off');
	config_set_path('unbound/custom_options', (string)($state['custom_options'] ?? ''));
	config_del_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state');
	write_config(gettext('Threat Shield: restored the previous Unbound DNS settings'));
	services_unbound_configure();
	return true;
}

function threatshield_manage_unbound(array $cfg): bool {
	$mode = $cfg['dns_coordination_mode'] ?? 'primary';
	if (($cfg['enable'] ?? 'off') !== 'on') return threatshield_restore_unbound() || true;
	// Anything saved since this request began (a package, another page) would be
	// lost by the write below, which saves the whole file: read it again first.
	if (function_exists('config_read_file')) {
		config_read_file(true, false);
	}
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', []);
	if (!is_array($state) || ($state['managed'] ?? '') !== 'on') {
		$state = [
			'managed' => 'on', 'port' => (string)config_get_path('unbound/port', '53'),
			'active_interface' => (string)config_get_path('unbound/active_interface', 'all'),
			'enable' => config_path_enabled('unbound') ? 'on' : 'off',
			'custom_options' => (string)config_get_path('unbound/custom_options', ''),
		];
		config_set_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', $state);
	}
	if ($mode === 'primary') {
		threatshield_set_unbound_enabled(($state['enable'] ?? '') !== 'off');
		config_set_path('unbound/port', '5335');
		config_set_path('unbound/active_interface', 'lo0');
		config_set_path('unbound/custom_options', $state['custom_options']);
	} elseif ($mode === 'proxy') {
		// Keep Unbound client-facing and send ordinary recursion to the local
		// filtering listener. Existing local-zone settings remain managed by Unbound.
		threatshield_set_unbound_enabled(true);
		config_set_path('unbound/port', $state['port'] ?: '53');
		config_set_path('unbound/active_interface', $state['active_interface'] ?: 'all');
		// Unbound won't forward to 127.0.0.1 unless do-not-query-localhost is off
		$forward = "# FreeSense Threat Shield managed proxy forwarder\nserver:\n  do-not-query-localhost: no\nforward-zone:\n  name: \".\"\n  forward-addr: 127.0.0.1@5354\n";
		// unbound/custom_options is stored base64-encoded (unbound.inc decodes it)
		$custom = base64_decode((string)$state['custom_options']);
		config_set_path('unbound/custom_options', base64_encode(trim($custom . "\n" . $forward)));
	} elseif ($mode === 'standalone') {
		threatshield_set_unbound_enabled(false);
		config_set_path('unbound/custom_options', $state['custom_options']);
	} else return false;
	if (!is_array(write_config(gettext('Threat Shield: coordinated Unbound DNS mode')))) return false;
	services_unbound_configure();
	return true;
}

function threatshield_pid_running(string $pidfile): bool {
	if (!file_exists($pidfile)) {
		return false;
	}
	$pid = trim((string)@file_get_contents($pidfile));
	if ($pid === '' || !ctype_digit($pid)) {
		return false;
	}
	exec('/bin/ps -p ' . escapeshellarg($pid) . ' -o pid=', $out, $rc);
	return ($rc === 0 && !empty($out));
}

function threatshield_is_running(): bool {
	return threatshield_pid_running(THREATSHIELD_PID_FILE);
}

function threatshield_dnsbl_running(): bool {
	return threatshield_pid_running(THREATSHIELD_DNSBL_PID_FILE);
}

function threatshield_service_control(string $action, string $service = 'threatshield'): bool {
	if (!in_array($service, ['threatshield', 'threatshield_dnsbl'], true)) return false;
	$commands = ['start' => 'onestart', 'stop' => 'onestop', 'restart' => 'onerestart', 'reload' => 'onereload'];
	if (!isset($commands[$action])) return false;
	// The package deliberately does not persist an rc.conf enable flag;
	// configuration controls its lifecycle.  FreeBSD's normal actions are
	// no-ops when that flag is unset, so use the explicit one* variants.
	$command = "/usr/sbin/service {$service} {$commands[$action]}";
	$should_run = ($action !== 'stop');
	$running = ($service === 'threatshield') ? 'threatshield_is_running' : 'threatshield_dnsbl_running';
	if (mwexec($command) !== 0) {
		// "already running" is what a start wants, also when something
		// else started the daemon a moment earlier.
		return $should_run && $running();
	}
	// The rc wrapper can return before the daemon has finished binding its
	// sockets.  Do not report a successful Save & Apply until its pid is alive.
	for ($check = 0; $check < 20; $check++) {
		if ($running() === $should_run) return true;
		usleep(250000);
	}
	return $running() === $should_run;
}

/* ------------------------------------------------------------------ pause */

/* ['active' => bool, 'until' => unix time, 0 = until resumed] */
function threatshield_pause_state(): array {
	$state = is_file(THREATSHIELD_PAUSE_FILE) ? json_decode((string)@file_get_contents(THREATSHIELD_PAUSE_FILE), true) : null;
	if (!is_array($state)) return ['active' => false, 'until' => 0];
	$until = (int)($state['until'] ?? 0);
	return ['active' => ($until === 0 || $until > time()), 'until' => $until];
}

function threatshield_pause(int $seconds): bool {
	$until = ($seconds > 0) ? time() + $seconds : 0;
	$payload = ['enabled' => false];
	if ($seconds > 0) $payload['duration'] = $seconds * 1000;
	safe_mkdir(THREATSHIELD_DB_DIR, 0750);
	file_put_contents(THREATSHIELD_PAUSE_FILE, json_encode(['until' => $until, 'since' => time()]) . "\n", LOCK_EX);
	return threatshield_api_request('protection', 'POST', $payload) !== null;
}

function threatshield_resume(): bool {
	@unlink(THREATSHIELD_PAUSE_FILE);
	return threatshield_api_request('protection', 'POST', ['enabled' => true]) !== null;
}

/* ------------------------------------------------------------------- YAML */

/* Stable AdGuard filter ids: the list index changed whenever a feed was
 * removed, which reset AdGuard's per-filter statistics. */
function threatshield_filter_ids(array $feeds): array {
	$ids = [];
	$used = [];
	foreach ($feeds as $i => $feed) {
		$key = (string)($feed['id'] ?? '') . '|' . (string)($feed['url'] ?? '');
		$id = (crc32($key) & 0x7fffffff) ?: 1;
		while (isset($used[$id])) $id = ($id + 1) & 0x7fffffff ?: 1;
		$used[$id] = true;
		$ids[$i] = $id;
	}
	return $ids;
}

/*
 * The zones the DNS Resolver (Unbound) must answer in primary mode: the system
 * domain, the domains of its host overrides and their aliases, its domain
 * overrides (Unbound forwards those to their own servers) and the domains the
 * DHCP servers hand out. AdGuard Home sends only these, and the reverse zones,
 * to Unbound; everything else goes to the public upstreams, so a local zone
 * missing here silently stops resolving. Sorted and de-duplicated; names that
 * are not valid DNS names are dropped, so nothing else can reach the YAML.
 */
function threatshield_local_zones(string $system_domain = ''): array {
	$zones = [];
	$label = '[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?';
	$add = function ($name) use (&$zones, $label) {
		$name = strtolower(trim((string)$name, " ."));
		if ((strlen($name) <= 253) && preg_match("/^{$label}(\\.{$label})*\$/D", $name)) {
			$zones[$name] = true;
		}
	};
	$add($system_domain);
	foreach (threatshield_normalize_list(config_get_path('unbound/hosts', [])) as $host) {
		if (!is_array($host)) {
			continue;
		}
		$add($host['domain'] ?? '');
		$aliases = $host['aliases'] ?? [];
		foreach (threatshield_normalize_list($aliases) as $alias) {
			if (is_array($alias)) {
				$add($alias['domain'] ?? '');
			}
		}
	}
	foreach (threatshield_normalize_list(config_get_path('unbound/domainoverrides', [])) as $override) {
		if (is_array($override)) {
			$add($override['domain'] ?? '');
		}
	}
	foreach (['dhcpd', 'dhcpdv6'] as $section) {
		foreach (config_get_path($section, []) as $server) {
			if (is_array($server)) {
				$add($server['domain'] ?? '');
			}
		}
	}
	$zones = array_keys($zones);
	sort($zones, SORT_STRING);
	return $zones;
}

/* The zones an AdGuard Home YAML sends to Unbound (the reverse zones left out). AdGuard Home rewrites
 * the file with single quotes once it has run, so both quote styles are read. */
function threatshield_yaml_local_zones(string $yaml): array {
	$zones = [];
	if (preg_match_all('#^    - ["\']\\[/([^/"\']+)/\\]127\\.0\\.0\\.1:5335["\']$#m', $yaml, $m)) {
		foreach ($m[1] as $zone) {
			if (($zone !== 'in-addr.arpa') && ($zone !== 'ip6.arpa')) {
				$zones[] = $zone;
			}
		}
	}
	sort($zones, SORT_STRING);
	return $zones;
}

function threatshield_generate_yaml(array $cfg, array $ctx = []): string {
	$listen_port = ($cfg['dns_coordination_mode'] === 'proxy') ? 5354 : (int)($cfg['listen_port'] ?: 53);
	$dns_binds = $ctx['bind_hosts'] ?? threatshield_dns_bind_hosts($cfg);
	if (empty($dns_binds)) $dns_binds = ['0.0.0.0'];
	$dns_binds_yaml = '';
	foreach ($dns_binds as $dns_bind) $dns_binds_yaml .= "    - " . threatshield_yaml_quote($dns_bind) . "\n";
	$http_port = (int)($cfg['http_port'] ?? 3000);
	$upstreams = array_filter(array_map('trim', explode("\n", (string)$cfg['upstreams'])));
	if (empty($upstreams)) {
		$upstreams = ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query'];
	}

	// If primary mode, send every local zone and the reverse zones to Unbound on 5335.
	if ($cfg['dns_coordination_mode'] === 'primary') {
		$domain = $ctx['domain'] ?? config_get_path('system/domain', 'localdomain');
		foreach (threatshield_local_zones((string)$domain) as $zone) {
			$upstreams[] = "[/{$zone}/]127.0.0.1:5335";
		}
		$upstreams[] = "[/in-addr.arpa/]127.0.0.1:5335";
		$upstreams[] = "[/ip6.arpa/]127.0.0.1:5335";
	}

	$bootstrap = array_filter(array_map('trim', explode("\n", (string)$cfg['bootstrap_dns'])));
	$fallbacks = array_filter(array_map('trim', explode("\n", (string)$cfg['fallback_dns'])));

	$feeds = array_values(array_filter(threatshield_normalize_list($cfg['feeds'] ?? []),
	    fn($f) => is_array($f) && (string)($f['url'] ?? '') !== ''));
	$filter_ids = threatshield_filter_ids($feeds);
	$filters_yaml = ['block' => '', 'allow' => ''];
	foreach ($feeds as $i => $feed) {
		$kind = (($feed['kind'] ?? 'block') === 'allow') ? 'allow' : 'block';
		$enabled_val = (($feed['enabled'] ?? '') === 'on') ? 'true' : 'false';
		$filters_yaml[$kind] .= "  - enabled: {$enabled_val}\n";
		$filters_yaml[$kind] .= "    url: " . threatshield_yaml_quote(threatshield_feed_path((string)$feed['url'])) . "\n";
		$filters_yaml[$kind] .= "    name: " . threatshield_yaml_quote((string)($feed['name'] ?? 'Feed')) . "\n";
		$filters_yaml[$kind] .= "    id: {$filter_ids[$i]}\n";
	}
	$whitelist_filters_yaml = ($filters_yaml['allow'] === '') ? ' []' : "\n" . rtrim($filters_yaml['allow']);
	$filters_block_yaml = ($filters_yaml['block'] === '') ? ' []' : "\n" . rtrim($filters_yaml['block']);

	/* Allowlist entries first: an $important allow rule beats every block
	 * rule from the lists, the anti-bypass rules and the custom rules. */
	$user_rules_list = threatshield_allowlist_rules(threatshield_normalize_list($cfg['allowlist'] ?? []));
	if (($cfg['block_doh_canary'] ?? 'off') === 'on') {
		$user_rules_list[] = '||use-application-dns.net^';
	}
	if (($cfg['block_icloud_private_relay'] ?? 'off') === 'on') {
		$user_rules_list[] = '||mask.icloud.com^';
		$user_rules_list[] = '||mask-h2.icloud.com^';
	}
	// Health probe: proves the filter engine blocks (see threatshield_health()).
	$user_rules_list[] = '||' . THREATSHIELD_PROBE_BLOCKED . '^';
	foreach (threatshield_lines((string)($cfg['custom_rules'] ?? '')) as $r) {
		$r = trim($r);
		if ($r !== '') $user_rules_list[] = $r;
	}

	$user_rules_yaml = '';
	foreach ($user_rules_list as $r) {
		$user_rules_yaml .= '  - ' . threatshield_yaml_quote((string)$r) . "\n";
	}

	$catalog = threatshield_services_catalog();
	$service_ids_yaml = function (array $ids) use ($catalog): string {
		$out = '';
		foreach ($ids as $svc) {
			if (in_array((string)$svc, $catalog, true)) $out .= "\n      - " . threatshield_yaml_quote((string)$svc);
		}
		return ($out === '') ? ' []' : $out;
	};
	$blocked_services_yaml = $service_ids_yaml(threatshield_normalize_list($cfg['blocked_services'] ?? []));
	$global_schedule = threatshield_schedule_yaml(($cfg['services_schedule_enable'] ?? 'off') === 'on',
	    (string)($cfg['services_schedule_tz'] ?? 'Local'), threatshield_normalize_list($cfg['services_schedule_days'] ?? []), '      ');

	$rewrites_yaml = ' []';
	foreach (threatshield_normalize_list($cfg['rewrites'] ?? []) as $rw) {
		if (is_array($rw) && !empty($rw['domain']) && !empty($rw['answer'])) {
			$rewrites_yaml .= "\n    - domain: " . threatshield_yaml_quote((string)$rw['domain']);
			$rewrites_yaml .= "\n      answer: " . threatshield_yaml_quote((string)$rw['answer']);
			$rewrites_yaml .= "\n      enabled: " . ((($rw['enabled'] ?? 'on') === 'on') ? 'true' : 'false');
		}
	}
	if ($rewrites_yaml !== ' []') $rewrites_yaml = substr($rewrites_yaml, 3);

	$ignored_domains_yaml = '    - ' . threatshield_yaml_quote('||' . THREATSHIELD_PROBE_BLOCKED . '^') . "\n";
	foreach (array_filter(array_map('trim', threatshield_lines((string)($cfg['ignored_domains'] ?? '')))) as $ig) {
		$ignored_domains_yaml .= '    - ' . threatshield_yaml_quote((string)$ig) . "\n";
	}

	$safebrowsing_bool = (($cfg['safebrowsing_enabled'] ?? 'on') === 'on') ? 'true' : 'false';
	$parental_bool = (($cfg['enable_parental'] ?? 'off') === 'on') ? 'true' : 'false';
	$safesearch_bool = (($cfg['enable_safesearch'] ?? 'off') === 'on') ? 'true' : 'false';
	/* Without explicit providers a client's SafeSearch enforces nothing. */
	$safesearch_providers = function (string $indent): string {
		$out = '';
		foreach (['bing', 'duckduckgo', 'ecosia', 'google', 'pixabay', 'yandex', 'youtube'] as $provider) {
			$out .= "\n{$indent}{$provider}: true";
		}
		return $out;
	};
	$global_providers = $safesearch_providers('    ');

	$clients_yaml = ' []';
	foreach (threatshield_normalize_list($cfg['clients'] ?? []) as $client) {
		$ids = is_array($client) ? array_values(array_filter(array_map('strval', threatshield_normalize_list($client['ids'] ?? [])))) : [];
		if (empty($ids)) continue;
		$filtering = (string)($client['filtering'] ?? 'inherit');
		$services = threatshield_normalize_list($client['blocked_services'] ?? []);
		$own_schedule = (($client['schedule_enable'] ?? 'off') === 'on');
		$clients_yaml .= "\n    - name: " . threatshield_yaml_quote((string)($client['name'] ?? 'Threat Shield client'));
		$clients_yaml .= "\n      ids:";
		foreach ($ids as $id) $clients_yaml .= "\n        - " . threatshield_yaml_quote($id);
		/* A client without global settings would otherwise lose safe browsing,
		 * parental control and SafeSearch: copy the global values. */
		$clients_yaml .= "\n      use_global_settings: " . (($filtering === 'inherit') ? 'true' : 'false');
		$clients_yaml .= "\n      filtering_enabled: " . (($filtering === 'off') ? 'false' : 'true');
		$clients_yaml .= "\n      parental_enabled: " . (($filtering === 'off') ? 'false' : $parental_bool);
		$clients_yaml .= "\n      safebrowsing_enabled: " . (($filtering === 'off') ? 'false' : $safebrowsing_bool);
		$clients_yaml .= "\n      safe_search:\n        enabled: " . (($filtering === 'off') ? 'false' : $safesearch_bool) . $safesearch_providers('        ');
		$clients_yaml .= "\n      use_global_blocked_services: " . ((empty($services) && !$own_schedule) ? 'true' : 'false');
		$clients_yaml .= "\n      blocked_services:\n        schedule:\n" . threatshield_schedule_yaml($own_schedule,
		    (string)($client['schedule_tz'] ?? 'Local'), threatshield_normalize_list($client['schedule_days'] ?? []), '          ');
		$client_ids = '';
		foreach ($services as $svc) {
			if (in_array((string)$svc, $catalog, true)) $client_ids .= "\n          - " . threatshield_yaml_quote((string)$svc);
		}
		$clients_yaml .= "\n        ids:" . (($client_ids === '') ? ' []' : $client_ids);
	}
	// ' []' only stands for an empty list; drop it once there are entries.
	if ($clients_yaml !== ' []') $clients_yaml = substr($clients_yaml, 3);

	$pause = $ctx['pause'] ?? threatshield_pause_state();
	$protection_bool = $pause['active'] ? 'false' : 'true';
	$disabled_until = ($pause['active'] && $pause['until'] > 0) ? threatshield_yaml_quote(gmdate('Y-m-d\TH:i:s\Z', $pause['until'])) : 'null';

	$upstream_mode = threatshield_yaml_quote((string)($cfg['upstream_mode'] ?? 'parallel'));
	$dnssec_bool = (($cfg['enable_dnssec'] ?? 'on') === 'on') ? 'true' : 'false';
	$optimistic_bool = (($cfg['cache_optimistic'] ?? 'on') === 'on') ? 'true' : 'false';
	$ecs_bool = (($cfg['edns_client_subnet'] ?? 'off') === 'on') ? 'true' : 'false';
	$querylog_bool = (($cfg['querylog_enabled'] ?? 'on') === 'on') ? 'true' : 'false';
	$anonymize_bool = (($cfg['anonymize_client_ip'] ?? 'off') === 'on') ? 'true' : 'false';

	$cache_bytes = max(1, (int)($cfg['cache_size'] ?? 4)) * 1048576;
	$feed_hours = ['6hours' => 6, '12hours' => 12, 'daily' => 24, 'weekly' => 168][(string)($cfg['feed_update_interval'] ?? 'daily')] ?? 24;
	$safe_filter_path = THREATSHIELD_FILTER_DIR . '/*';
	$ttl_min = (int)($cfg['cache_ttl_min'] ?? 0);
	$ttl_max = (int)($cfg['cache_ttl_max'] ?? 0);
	$ratelimit = (int)($cfg['ratelimit'] ?? 0);
	$subnet4 = (int)($cfg['rate_limit_subnet_len_ipv4'] ?? 24);
	$subnet6 = (int)($cfg['rate_limit_subnet_len_ipv6'] ?? 56);
	$retention = (int)($cfg['querylog_retention'] ?? 2160);
	$blocking_mode = threatshield_yaml_quote((string)($cfg['blocking_mode'] ?? 'default'));
	$rate_whitelist_yaml = '';
	foreach (array_filter(array_map('trim', preg_split('/[\r\n,]+/', (string)($cfg['rate_limit_whitelist'] ?? '')))) as $address) {
		if (filter_var($address, FILTER_VALIDATE_IP)) $rate_whitelist_yaml .= "\n    - " . threatshield_yaml_quote($address);
	}
	if ($rate_whitelist_yaml === '') $rate_whitelist_yaml = ' []';
	$blocking_ipv4 = threatshield_yaml_quote((string)($cfg['blocking_ipv4'] ?? ''));
	$blocking_ipv6 = threatshield_yaml_quote((string)($cfg['blocking_ipv6'] ?? ''));
	$local_ptr_yaml = ($cfg['dns_coordination_mode'] === 'primary') ? "\n    - 127.0.0.1:5335" : ' []';

	$yaml = <<<YAML
# FreeSense Threat Shield Generated Configuration
# Do not edit manually - managed via FreeSense WebUI
http:
  address: 127.0.0.1:{$http_port}
  session_ttl: 720h
  pprof:
    port: 6060
    enabled: false
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
users: []

dns:
  bind_hosts:
{$dns_binds_yaml}  port: {$listen_port}
  upstream_dns:
YAML;

	foreach ($upstreams as $u) {
		$yaml .= "\n    - " . threatshield_yaml_quote((string)$u);
	}

	$yaml .= "\n  upstream_dns_file: \"\"\n  bootstrap_dns:";
	foreach ($bootstrap as $b) {
		$yaml .= "\n    - " . threatshield_yaml_quote((string)$b);
	}

	$yaml .= "\n  fallback_dns:";
	foreach ($fallbacks as $f) {
		$yaml .= "\n    - " . threatshield_yaml_quote((string)$f);
	}

	$yaml .= <<<YAML

  fastest_timeout: 1s
  ratelimit: {$ratelimit}
  ratelimit_subnet_len_ipv4: {$subnet4}
  ratelimit_subnet_len_ipv6: {$subnet6}
  ratelimit_whitelist:{$rate_whitelist_yaml}
  edns_client_subnet:
    custom_ip: ""
    enabled: {$ecs_bool}
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  serve_http3: false
  use_http3_upstreams: false
  use_dns64: false
  enable_dnssec: {$dnssec_bool}
  cache_size: {$cache_bytes}
  cache_ttl_min: {$ttl_min}
  cache_ttl_max: {$ttl_max}
  cache_optimistic: {$optimistic_bool}
  bogus_nxdomain: []
  upstream_mode: {$upstream_mode}
  use_private_ptr_resolvers: true
  local_ptr_upstreams:{$local_ptr_yaml}

tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  port_dnscrypt: 0
  dnscrypt_config_file: ""
  allow_unencrypted_doh: true
  certificate_chain: ""
  private_key: ""

filtering:
  filtering_enabled: true
  protection_enabled: {$protection_bool}
  protection_disabled_until: {$disabled_until}
  filters_update_interval: {$feed_hours}
  safe_fs_patterns:
    - "{$safe_filter_path}"
  parental_enabled: {$parental_bool}
  safebrowsing_enabled: {$safebrowsing_bool}
  safe_search:
    enabled: {$safesearch_bool}{$global_providers}
  blocking_mode: {$blocking_mode}
  blocking_ipv4: {$blocking_ipv4}
  blocking_ipv6: {$blocking_ipv6}
  rewrites:{$rewrites_yaml}
  blocked_services:
    schedule:
{$global_schedule}
    ids:{$blocked_services_yaml}
filters:{$filters_block_yaml}
whitelist_filters:{$whitelist_filters_yaml}
user_rules:
{$user_rules_yaml}
dhcp:
  enabled: false

clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
  persistent:{$clients_yaml}

querylog:
  enabled: {$querylog_bool}
  file_enabled: {$querylog_bool}
  interval: {$retention}h
  size_memory: 1000
  anonymize_client_ip: {$anonymize_bool}
  ignored:
{$ignored_domains_yaml}
statistics:
  enabled: true
  interval: 24h
  ignored:
    - "||blocked.threatshield.test^"

schema_version: 34

YAML;

	return $yaml;
}

/* Writes the AdGuard Home configuration only if AdGuard Home accepts it. */
function threatshield_write_yaml(string $yaml): bool {
	$tmp = THREATSHIELD_CONFIG_FILE . '.new.' . getmypid();
	if (file_put_contents($tmp, $yaml, LOCK_EX) === false || !@chmod($tmp, 0640)) {
		@unlink($tmp);
		threatshield_last_error(gettext('The AdGuard Home configuration could not be written.'));
		return false;
	}
	if (is_executable('/usr/local/bin/AdGuardHome')) {
		$out = [];
		exec('/usr/local/bin/AdGuardHome --no-check-update --check-config -c ' . escapeshellarg($tmp) .
		    ' -w ' . escapeshellarg(THREATSHIELD_DB_DIR) . ' 2>&1', $out, $rc);
		if ($rc !== 0) {
			@unlink($tmp);
			$detail = trim(implode(' ', array_slice($out, -3)));
			logger(LOG_ERR, 'Threat Shield: AdGuard Home rejected the generated configuration: ' . $detail);
			threatshield_last_error(sprintf(gettext('AdGuard Home rejected the configuration: %s'), $detail));
			return false;
		}
	}
	if (!@rename($tmp, THREATSHIELD_CONFIG_FILE)) {
		@unlink($tmp);
		threatshield_last_error(gettext('The AdGuard Home configuration could not be replaced.'));
		return false;
	}
	return true;
}

/*
 * Held while a configuration is applied. The 5-minute self-repair
 * (threatshield_reconcile()) skips its run meanwhile: it used to see AdGuard
 * Home stopped by the apply, start it, and make the apply's own start fail.
 */
define('THREATSHIELD_APPLY_LOCK', '/var/run/threatshield-apply.lock');

/* The lock (a file handle), false when it is held elsewhere, null when it can't be used.
 * $wait waits up to two minutes for another apply, then goes ahead without it. */
function threatshield_apply_lock(bool $wait) {
	$fp = @fopen(THREATSHIELD_APPLY_LOCK, 'c');
	if ($fp === false) return null;
	for ($i = 0; !flock($fp, LOCK_EX | LOCK_NB); $i++) {
		if (!$wait || ($i >= 480)) {
			fclose($fp);
			if ($wait) logger(LOG_WARNING, 'Threat Shield: another apply still runs after two minutes; applying anyway.');
			return $wait ? null : false;
		}
		usleep(250000);
	}
	return $fp;
}

function threatshield_apply_unlock($fp): void {
	if (is_resource($fp)) {
		flock($fp, LOCK_UN);
		fclose($fp);
	}
}

function threatshield_sync_config(): bool {
	$lock = threatshield_apply_lock(true);
	try {
		return threatshield_sync_config_locked();
	} finally {
		threatshield_apply_unlock($lock);
	}
}

function threatshield_sync_config_locked(): bool {
	threatshield_persist_migration();
	$cfg = threatshield_config();
	$enabled = ($cfg['enable'] ?? 'off') === 'on';

	foreach ([THREATSHIELD_CONFIG_DIR, THREATSHIELD_DB_DIR, THREATSHIELD_FILTER_DIR, THREATSHIELD_GEOIP_DIR,
	    THREATSHIELD_IP_DIR, THREATSHIELD_IP_DIR . '/raw', THREATSHIELD_DNSBL_DIR, THREATSHIELD_CACHE_DIR] as $dir) {
		safe_mkdir($dir, 0750);
	}

	// The YAML references the local list files, so an empty file stands in for
	// each one that has not been downloaded yet; the download itself runs in the
	// background (threatshield_update_start_background below), with a progress
	// bar in the WebUI, instead of holding up Save & Apply for minutes.
	$background_update = false;
	if ($enabled && !threatshield_feed_cache_complete($cfg)) {
		threatshield_feed_placeholders($cfg);
		$background_update = true;
	}
	if (!threatshield_write_yaml(threatshield_generate_yaml($cfg))) return false;
	// Stop AdGuard Home before Unbound is moved: when Unbound goes back to
	// port 53 (disable, or primary -> proxy) it can't bind while AdGuard Home
	// still holds the port, and DNS was left down. Started again below.
	if (threatshield_is_running() && !threatshield_service_control('stop')) return false;
	if (!threatshield_manage_unbound($cfg)) return false;

	// Country and IP data missing on first application are fetched in the
	// background as well; the PF tables fill as the lists arrive.
	if ($enabled && ($cfg['geoip_enable'] ?? 'off') === 'on' && !threatshield_geoip_cache_complete($cfg)) {
		$background_update = true;
	}
	if ($enabled && !threatshield_ipfeed_cache_complete($cfg)) {
		$background_update = true;
	}
	threatshield_update_geoip();
	threatshield_update_ip_tables();

	if ($enabled) {
		threatshield_install_cron($cfg);
		if (!threatshield_service_control('start')) {
			threatshield_last_error(gettext('AdGuard Home did not start. Check the system log.'));
			return false;
		}
	} else {
		threatshield_remove_cron();
	}
	threatshield_dnsbl_sync($cfg);
	@unlink(THREATSHIELD_CACHE_DIR . '/health.json');

	filter_configure();
	if ($background_update) {
		threatshield_update_start_background();
	}
	return true;
}

/*
 * Starts the list download in the background unless one is already running.
 * The updater writes its progress (threatshield_progress_*), which the pages
 * show as a bar. Returns whether a new run was started.
 */
function threatshield_update_start_background(): bool {
	if (!empty(threatshield_progress_state()['active'])) {
		return false;
	}
	mwexec_bg(THREATSHIELD_UPDATER . ' all force');
	return true;
}

/* An empty file for every enabled DNS list not downloaded yet, so AdGuard Home can start without waiting. */
function threatshield_feed_placeholders(array $cfg): void {
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? 'on') !== 'on') continue;
		$url = (string)($feed['url'] ?? '');
		if ($url === '') continue;
		$file = threatshield_feed_path($url);
		if (!is_file($file) || filesize($file) === 0) {
			@file_put_contents($file, '');
		}
	}
}

/* Starts, reloads or stops the DNSBL daemon to match the configuration. */
function threatshield_dnsbl_wanted(array $cfg): bool {
	if (($cfg['enable'] ?? 'off') !== 'on' || ($cfg['dnsbl_enable'] ?? 'off') !== 'on') return false;
	foreach (threatshield_normalize_list($cfg['inbound_policies'] ?? []) as $p) {
		if (is_array($p) && ($p['enable'] ?? 'on') === 'on' && ($p['dnsbl_mode'] ?? 'off') !== 'off') return true;
	}
	return false;
}

function threatshield_dnsbl_sync(array $cfg): void {
	if (!is_file('/usr/local/etc/rc.d/threatshield_dnsbl')) return;
	if (threatshield_dnsbl_wanted($cfg)) {
		if (threatshield_dnsbl_running()) {
			$pid = (int)trim((string)@file_get_contents(THREATSHIELD_DNSBL_PID_FILE));
			if ($pid > 0) posix_kill($pid, 1);    // SIGHUP: reload settings
		} else {
			threatshield_service_control('start', 'threatshield_dnsbl');
		}
	} elseif (threatshield_dnsbl_running()) {
		threatshield_service_control('stop', 'threatshield_dnsbl');
	}
}

function threatshield_geoip_cache_complete(array $cfg): bool {
	$v6 = ($cfg['geoip_ipv6'] ?? 'off') === 'on';
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		foreach (threatshield_normalize_list(is_array($policy) ? ($policy['countries'] ?? []) : []) as $cc) {
			$cc = strtoupper(preg_replace('/[^A-Za-z]/', '', (string)$cc));
			if ($cc === '' || !is_file(THREATSHIELD_GEOIP_DIR . '/' . $cc . '.zone')) return false;
			if ($v6 && !is_file(THREATSHIELD_GEOIP_DIR . '/' . $cc . '.zone6')) return false;
		}
	}
	return true;
}

function threatshield_feed_cache_complete(array $cfg): bool {
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? 'on') !== 'on') continue;
		$url = (string)($feed['url'] ?? '');
		if ($url === '' || !is_file(threatshield_feed_path($url)) || filesize(threatshield_feed_path($url)) === 0) return false;
	}
	return true;
}

/* IP lists the configuration needs: threat lists when IP blocking is on, the
 * DoH resolver lists when that anti-bypass option is on. */
function threatshield_active_ipfeeds(array $cfg): array {
	$out = [];
	foreach (threatshield_normalize_list($cfg['ip_feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? 'off') !== 'on') continue;
		$kind = (string)($feed['kind'] ?? 'threat');
		if (($kind === 'threat' && ($cfg['ipbl_enable'] ?? 'off') === 'on') || ($kind === 'doh' && ($cfg['block_doh_ips'] ?? 'off') === 'on')) {
			$out[] = $feed;
		}
	}
	return $out;
}

function threatshield_ipfeed_raw_path(array $feed): string {
	return THREATSHIELD_IP_DIR . '/raw/' . threatshield_pf_ident((string)($feed['id'] ?? '')) . '.txt';
}

function threatshield_ipfeed_cache_complete(array $cfg): bool {
	foreach (threatshield_active_ipfeeds($cfg) as $feed) {
		if (!is_file(threatshield_ipfeed_raw_path($feed))) return false;
	}
	return true;
}

/* Networks of the firewall's own interfaces: never put into a block table. */
function threatshield_local_networks(): array {
	$out = [];
	foreach (array_keys(threatshield_assigned_interfaces()) as $if) {
		$ip = function_exists('get_interface_ip') ? get_interface_ip($if) : null;
		$sn = function_exists('get_interface_subnet') ? get_interface_subnet($if) : null;
		if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) && is_numeric($sn)) $out[] = "{$ip}/{$sn}";
		$ip6 = function_exists('get_interface_ipv6') ? get_interface_ipv6($if) : null;
		$sn6 = function_exists('get_interface_subnetv6') ? get_interface_subnetv6($if) : null;
		if (is_string($ip6) && filter_var($ip6, FILTER_VALIDATE_IP) && is_numeric($sn6)) $out[] = "{$ip6}/{$sn6}";
	}
	return $out;
}

function threatshield_ip_allow_entries(array $cfg): array {
	$out = [];
	foreach (threatshield_normalize_list($cfg['ip_allowlist'] ?? []) as $entry) {
		if (!is_array($entry) || ($entry['enabled'] ?? 'on') !== 'on') continue;
		$n = threatshield_cidr_normalize((string)($entry['address'] ?? ''));
		if ($n !== null) $out[] = $n;
	}
	return $out;
}

function threatshield_write_table_file(string $file, array $lines): bool {
	safe_mkdir(dirname($file), 0750);
	$tmp = $file . '.tmp.' . getmypid();
	if (file_put_contents($tmp, implode("\n", $lines) . "\n", LOCK_EX) === false || !@rename($tmp, $file)) {
		@unlink($tmp);
		return false;
	}
	@chmod($file, 0640);
	return true;
}

/* Loads a table file into the running ruleset.  A table the ruleset doesn't
 * reference yet is filled by the next filter reload instead. */
function threatshield_pfctl_replace(string $table, string $file): bool {
	if (!file_exists('/sbin/pfctl')) return true;
	exec('/sbin/pfctl -t ' . escapeshellarg($table) . ' -T replace -f ' . escapeshellarg($file) . ' 2>&1', $out, $rc);
	if ($rc !== 0 && !preg_grep('/Table does not exist/i', $out)) {
		logger(LOG_WARNING, "Threat Shield: could not load pf table {$table}: " . implode(' ', $out));
		return false;
	}
	return true;
}

/* Builds every IP list table file (exclusions, protected ranges) and loads
 * them; the GeoIP tables are handled by threatshield_update_geoip(). */
function threatshield_update_ip_tables(?array $cfg = null): void {
	$cfg = $cfg ?? threatshield_config();
	$allow = threatshield_ip_allow_entries($cfg);
	$protected = array_merge(threatshield_protected_ranges(), threatshield_local_networks());
	threatshield_write_table_file(THREATSHIELD_IP_DIR . '/allow.txt', $allow);
	threatshield_pfctl_replace(THREATSHIELD_T_ALLOW, THREATSHIELD_IP_DIR . '/allow.txt');
	$doh = [];
	foreach (threatshield_active_ipfeeds($cfg) as $feed) {
		$raw = threatshield_ipfeed_raw_path($feed);
		$entries = is_file($raw) ? threatshield_parse_ip_list((string)file_get_contents($raw)) : [];
		if (($feed['kind'] ?? 'threat') === 'doh') {
			$doh = array_merge($doh, $entries);
			continue;
		}
		$id = threatshield_pf_ident((string)$feed['id']);
		$file = THREATSHIELD_IP_DIR . "/{$id}.txt";
		threatshield_write_table_file($file, threatshield_build_table_lines($entries, $allow, $protected));
		threatshield_pfctl_replace('ts_ipf_' . $id, $file);
	}
	// DoH resolvers are blocked as destinations from the LAN, so the
	// allowlist (trusted sources) doesn't apply; protected ranges still do.
	threatshield_write_table_file(THREATSHIELD_IP_DIR . '/doh.txt', threatshield_build_table_lines($doh, [], $protected));
	threatshield_pfctl_replace(THREATSHIELD_T_DOH, THREATSHIELD_IP_DIR . '/doh.txt');
	if (threatshield_dnsbl_wanted($cfg)) threatshield_dnsbl_seed_known($cfg);
}

function threatshield_remove_config(): void {
	threatshield_service_control('stop');
	if (threatshield_dnsbl_running()) threatshield_service_control('stop', 'threatshield_dnsbl');
	threatshield_remove_cron();
	@unlink(THREATSHIELD_PAUSE_FILE);

	threatshield_restore_unbound();

	@unlink(THREATSHIELD_CONFIG_FILE);
	/* The package entry is still in config.xml here and FreeSense does not
	 * reload the filter after a removal: reload now, in this process, with
	 * the rule hook answering nothing. */
	$GLOBALS['threatshield_removing'] = true;
	filter_configure_sync();
	if (file_exists('/sbin/pfctl')) {
		exec('/sbin/pfctl -sT 2>/dev/null', $tables);
		foreach ($tables as $table) {
			$table = trim($table);
			if (preg_match('/^(threatshield_|ts_ipf_|freesense_geoip_)[A-Za-z0-9_]+$/', $table)) {
				mwexec('/sbin/pfctl -t ' . escapeshellarg($table) . ' -T kill');
			}
		}
	}
	if (is_file(THREATSHIELD_DNSBL_DIR . '/pflog1.created')) {
		mwexec('/sbin/ifconfig pflog1 destroy');
		@unlink(THREATSHIELD_DNSBL_DIR . '/pflog1.created');
	}
}

function threatshield_cron_jobs(): array {
	// The updater enforces the selected intervals using persisted timestamps.
	return [
		[THREATSHIELD_UPDATER . ' feeds', '17', '*'],
		[THREATSHIELD_UPDATER . ' geoip', '43', '*'],
		[THREATSHIELD_UPDATER . ' ipfeeds', '29', '*'],
		[THREATSHIELD_UPDATER . ' health', '*/5', '*'],
		[THREATSHIELD_UPDATER . ' geodb', '51', '3'],
		[THREATSHIELD_UPDATER . ' map-collect', '*', '*'],
		[THREATSHIELD_UPDATER . ' map-prune', '7', '*'],
		[THREATSHIELD_UPDATER . ' flood-expire', '*', '*'],
	];
}

function threatshield_install_cron(?array $cfg = null): void {
	$cfg = $cfg ?? threatshield_config();
	$flood = false;
	foreach (threatshield_normalize_list($cfg['inbound_policies'] ?? []) as $p) {
		if (is_array($p) && ($p['enable'] ?? 'on') === 'on' && threatshield_pf_policy_has_flood($p)) $flood = true;
	}
	$map = ($cfg['enable'] ?? 'off') === 'on' && ($cfg['map_background'] ?? 'on') === 'on';
	foreach (threatshield_cron_jobs() as [$command, $minute, $hour]) {
		$wanted = (!str_ends_with($command, 'flood-expire') || $flood) && (!str_ends_with($command, 'map-collect') || $map)
		    && (!str_ends_with($command, 'map-prune') || ($cfg['enable'] ?? 'off') === 'on')
		    && (!str_ends_with($command, 'geodb') || ($cfg['map_geodb'] ?? 'off') !== 'off');
		install_cron_job($command, $wanted, $minute, $hour, '*', '*', '*', 'root');
	}
}

function threatshield_remove_cron(): void {
	foreach (threatshield_cron_jobs() as [$command]) {
		install_cron_job($command, false);
	}
}

/* ----------------------------------------------------------------- rules */

function threatshield_rule_context(array $cfg, string $type): array {
	$ctx = ['ifmap' => [], 'gw4' => [], 'gw6' => [], 'db' => THREATSHIELD_DB_DIR,
	    'replyto' => !config_path_enabled('system', 'disablereplyto'),
	    'aliases' => threatshield_alias_names(), 'healthy' => false, 'dnsbl_up' => false,
	    'log_pass' => (($cfg['map_log_allowed'] ?? 'off') === 'on'),
	    /* pf keeps the contents of an existing persist table when the ruleset
	     * reloads, so "persist file" alone would leave a flushed or once-empty
	     * table empty; load every table from its file before the rules load. */
	    'ensure' => function (string $file, string $table = ''): void {
		    if (!is_file($file)) {
			    safe_mkdir(dirname($file), 0750);
			    @file_put_contents($file, '');
			    @chmod($file, 0640);
		    }
		    if ($table !== '') threatshield_pfctl_replace($table, $file);
	    }];
	foreach (array_keys(threatshield_assigned_interfaces()) as $friendly) {
		$ctx['ifmap'][$friendly] = (string)get_real_interface($friendly);
		if (function_exists('get_interface_gateway')) $ctx['gw4'][$friendly] = (string)get_interface_gateway($friendly);
		if (function_exists('get_interface_gateway_v6')) $ctx['gw6'][$friendly] = (string)get_interface_gateway_v6($friendly);
	}
	if ($type === 'nat') $ctx['healthy'] = threatshield_listener_healthy($cfg);
	if ($type === 'pfearly') {
		$ctx['dnsbl_up'] = threatshield_dnsbl_running();
		if (threatshield_dnsbl_wanted($cfg)) {
			threatshield_ensure_pflog1();
			threatshield_dnsbl_seed_known($cfg);
		}
		threatshield_dump_flood_table();
	}
	return $ctx;
}

/* pflog1 carries only the DNSBL lookups; the system log reads pflog0.
 * FreeBSD 16 provides pflog0..N-1 as BPF taps (net.pflog.if_count) that
 * ifconfig cannot see or create; older releases need a cloned interface. */
function threatshield_ensure_pflog1(): void {
	if ((int)trim((string)@shell_exec('/sbin/sysctl -n net.pflog.if_count 2>/dev/null')) >= 2) return;
	exec('/sbin/ifconfig pflog1 2>/dev/null', $out, $rc);
	if ($rc !== 0) {
		exec('/sbin/ifconfig pflog1 create 2>/dev/null', $out, $rc);
		if ($rc !== 0) return;
		safe_mkdir(THREATSHIELD_DNSBL_DIR, 0750);
		@touch(THREATSHIELD_DNSBL_DIR . '/pflog1.created');
	}
	exec('/sbin/ifconfig pflog1 up 2>/dev/null');
}

/* A filter reload would empty the flood table; carry offenders over. */
function threatshield_dump_flood_table(): void {
	if (!file_exists('/sbin/pfctl')) return;
	exec('/sbin/pfctl -t ' . THREATSHIELD_T_FLOOD . ' -T show 2>/dev/null', $out, $rc);
	if ($rc === 0) threatshield_write_table_file(THREATSHIELD_DB_DIR . '/flood.txt', array_filter(array_map('trim', $out)));
}

/* The firewall's discover_pkg_rules() hook. */
function threatshield_generate_rules(string $type): string {
	if ($type !== 'nat' && $type !== 'pfearly') return '';
	if (!empty($GLOBALS['threatshield_removing'])) return '';
	/* The firewall writes this file when it rejects our rules and never
	 * removes it; start each reload clean (nat and pfearly run in the same
	 * process, so a rejection in either one is kept). */
	static $cleared = false;
	if (!$cleared) {
		@unlink('/tmp/rules.packages.threatshield');
		$cleared = true;
	}
	$cfg = threatshield_config();
	if (($cfg['enable'] ?? 'off') !== 'on') return '';
	$ctx = threatshield_rule_context($cfg, $type);
	return ($type === 'nat') ? threatshield_pf_nat_rules($cfg, $ctx) : threatshield_pf_early_rules($cfg, $ctx);
}

/* True when the DNS filter answers on the port the redirect points at. */
function threatshield_listener_healthy(array $cfg, int $timeout_ms = 800): bool {
	if (!threatshield_is_running()) return false;
	$target = threatshield_pf_redirect_target($cfg);
	$domain = (string)($cfg['health_test_domain'] ?? 'freesense.org');
	$r = threatshield_dns_query_many('127.0.0.1', $target, [$domain], $timeout_ms);
	return ($r[$domain]['rcode'] ?? null) !== null;
}

function threatshield_geoip_table(string $id): string {
	return 'freesense_geoip_' . substr($id, 0, 15);
}

function threatshield_update_geoip(?array $cfg = null): void {
	$cfg = $cfg ?? threatshield_config();
	safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);
	$v6 = ($cfg['geoip_ipv6'] ?? 'off') === 'on';
	$allow = threatshield_ip_allow_entries($cfg);
	$protected = array_merge(threatshield_protected_ranges(), threatshield_local_networks());
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		if (!is_array($policy) || ($policy['enable'] ?? 'on') !== 'on') continue;
		$id = threatshield_geoip_policy_id($policy);
		$cidrs = [];
		foreach (threatshield_normalize_list($policy['countries'] ?? []) as $cc) {
			$cc_clean = strtoupper(preg_replace('/[^A-Za-z]/', '', (string)$cc));
			if ($cc_clean === '') continue;
			foreach ($v6 ? ['.zone', '.zone6'] : ['.zone'] as $ext) {
				$cache = THREATSHIELD_GEOIP_DIR . "/{$cc_clean}{$ext}";
				if (is_file($cache)) $cidrs = array_merge($cidrs, threatshield_parse_ip_list((string)file_get_contents($cache)));
			}
		}
		/* allow-only: local and private sources must stay allowed;
		 * block: the IP allowlist punches holes into the blocked countries */
		$lines = (($policy['action'] ?? 'block_selected') === 'allow_selected')
		    ? threatshield_build_table_lines($cidrs, [], [], array_merge($protected, $allow))
		    : threatshield_build_table_lines($cidrs, $allow, $protected);
		$file = THREATSHIELD_GEOIP_DIR . '/' . $id . '.cidrs';
		if (threatshield_write_table_file($file, $lines)) {
			threatshield_pfctl_replace(threatshield_geoip_table($id), $file);
		} else {
			logger(LOG_ERR, "Threat Shield: could not write GeoIP table file {$file}");
		}
	}
}

/* -------------------------------------------------------------------- API */

function threatshield_api_request(string $endpoint, string $method = 'GET', ?array $payload = null, ?float $timeout = null): ?array {
	$api_port = (int)(threatshield_config()['http_port'] ?? 3000);
	$url = THREATSHIELD_API_BASE . ':' . $api_port . '/control/' . ltrim($endpoint, '/');
	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	// Refreshing several multi-megabyte local lists is synchronous in AdGuard
	// Home and routinely exceeds the short timeout appropriate for UI queries.
	if ($timeout === null) {
		$timeout = (ltrim($endpoint, '/') === 'filtering/refresh') ? 120 : 3;
	}
	curl_setopt($ch, CURLOPT_TIMEOUT_MS, (int)($timeout * 1000));
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 1000);

	if ($method === 'POST') {
		curl_setopt($ch, CURLOPT_POST, true);
		if ($payload !== null) {
			$json = json_encode($payload);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
			curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Content-Length: ' . strlen($json)]);
		}
	}

	$res = curl_exec($ch);
	$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

	if ($res === false || $code < 200 || $code >= 300) {
		return null;
	}

	$data = json_decode($res, true);
	return is_array($data) ? $data : ['status' => 'ok', 'raw' => $res];
}

/* API reads for pages and the widget: a short-lived file cache keeps them
 * instant and a stopped engine never stalls a page for long. */
function threatshield_api_cached(string $endpoint, int $ttl = 10, float $timeout = 1.5): ?array {
	$file = THREATSHIELD_CACHE_DIR . '/api_' . md5($endpoint) . '.json';
	if (is_file($file) && (time() - (int)filemtime($file)) < $ttl) {
		$data = json_decode((string)@file_get_contents($file), true);
		if (is_array($data)) return $data;
	}
	if (!threatshield_is_running()) return null;
	$data = threatshield_api_request($endpoint, 'GET', null, $timeout);
	if (is_array($data) && is_dir(THREATSHIELD_CACHE_DIR)) {
		@file_put_contents($file, json_encode($data), LOCK_EX);
	}
	return $data;
}

function threatshield_get_stats(): array {
	$stats = threatshield_api_cached('stats', 15);
	if (!$stats) {
		return [
			'num_dns_queries' => 0,
			'num_blocked_filtering' => 0,
			'num_replaced_safebrowsing' => 0,
			'num_replaced_parental' => 0,
			'avg_processing_time' => 0,
			'top_queried_domains' => [],
			'top_blocked_domains' => [],
			'top_clients' => []
		];
	}
	return $stats;
}

/* Per-feed health: download status joined with the rule counts AdGuard
 * Home actually loaded.  Keyed by feed URL. */
function threatshield_feed_health(array $cfg): array {
	$status = is_file(THREATSHIELD_FEED_STATUS) ? json_decode((string)@file_get_contents(THREATSHIELD_FEED_STATUS), true) : [];
	$status = is_array($status) ? $status : [];
	$loaded = [];
	$filtering = threatshield_api_cached('filtering/status', 30);
	foreach (['filters', 'whitelist_filters'] as $key) {
		foreach ((array)($filtering[$key] ?? []) as $f) {
			if (is_array($f) && isset($f['url'])) $loaded[(string)$f['url']] = (int)($f['rules_count'] ?? 0);
		}
	}
	$out = [];
	$lists = array_merge(
	    array_map(fn($f) => [$f, false], threatshield_normalize_list($cfg['feeds'] ?? [])),
	    array_map(fn($f) => [$f, true], threatshield_normalize_list($cfg['ip_feeds'] ?? [])));
	foreach ($lists as [$feed, $ip]) {
		if (!is_array($feed)) continue;
		$url = (string)($feed['url'] ?? '');
		$s = is_array($status[$url] ?? null) ? $status[$url] : [];
		$local = $ip ? threatshield_ipfeed_raw_path($feed) : threatshield_feed_path($url);
		$rules = $ip ? null : ($loaded[$local] ?? null);
		/* lists downloaded before the status file existed (1.0.x) */
		if (empty($s['last_success']) && empty($s['error']) && is_file($local) && filesize($local) > 0) {
			$s['last_success'] = (int)filemtime($local);
			$s['bytes'] = (int)filesize($local);
		}
		$state = 'pending';
		if (!empty($s['error']) && empty($s['last_success'])) $state = 'failing';
		elseif (!empty($s['error'])) $state = 'stale';
		elseif (!empty($s['last_success'])) $state = 'ok';
		$dns_list = in_array((string)($feed['kind'] ?? 'block'), ['block', 'allow'], true);
		if ($state === 'ok' && $dns_list && $rules === 0 && ($feed['enabled'] ?? 'off') === 'on') {
			$state = 'empty';    // downloaded, but AdGuard Home found no rules in it
		}
		$out[$url] = $s + ['state' => $state, 'rules' => $rules];
	}
	return $out;
}

function threatshield_get_dhcp_hostnames(): array {
	$leases = [];
	$lease_file = '/var/dhcpd/var/db/dhcpd.leases';
	if (file_exists($lease_file) && is_readable($lease_file)) {
		$content = file_get_contents($lease_file);
		if (preg_match_all('/lease\s+([0-9\.]+)\s*\{[^}]*client-hostname\s+"([^"]+)";/s', $content, $m, PREG_SET_ORDER)) {
			foreach ($m as $match) {
				$leases[$match[1]] = $match[2];
			}
		}
	}

	// Merge static DHCP mappings
	$dhcp_ifaces = config_get_path('dhcpd', []);
	if (is_array($dhcp_ifaces)) {
		foreach ($dhcp_ifaces as $if => $settings) {
			if (!empty($settings['staticmap']) && is_array($settings['staticmap'])) {
				foreach ($settings['staticmap'] as $sm) {
					if (!empty($sm['ipaddr']) && !empty($sm['hostname'])) {
						$leases[$sm['ipaddr']] = $sm['hostname'];
					}
				}
			}
		}
	}

	return $leases;
}

/* --------------------------------------------------------- allowlist edits */

/* Adds a domain to the allowlist; false and $message when it already is. */
function threatshield_allowlist_add(array &$cfg, string $domain, bool $subdomains, string $source, string $comment = '', ?string &$message = null): bool {
	$normalized = threatshield_normalize_domain($domain);
	if ($normalized === null) {
		$message = sprintf(gettext('"%s" is not a valid domain name.'), $domain);
		return false;
	}
	$list = threatshield_normalize_list($cfg['allowlist'] ?? []);
	$found = threatshield_allowlist_find($list, $normalized);
	if ($found !== null) {
		if (($list[$found]['enabled'] ?? 'on') !== 'on') {
			$list[$found]['enabled'] = 'on';
			$cfg['allowlist'] = $list;
			$message = sprintf(gettext('The existing allowlist entry %s was turned on again.'), $list[$found]['domain']);
			return true;
		}
		$message = ($list[$found]['domain'] === $normalized)
		    ? sprintf(gettext('%s is already on the allowlist.'), $normalized)
		    : sprintf(gettext('%1$s is already allowed by the entry %2$s.'), $normalized, $list[$found]['domain']);
		return false;
	}
	$list[] = ['domain' => $normalized, 'subdomains' => $subdomains ? 'on' : 'off', 'comment' => trim($comment),
	    'enabled' => 'on', 'added' => (string)time(), 'source' => $source];
	$cfg['allowlist'] = $list;
	$message = sprintf(gettext('%s was added to the allowlist.'), $normalized);
	return true;
}

/* Blocks a domain and its subdomains with a custom rule; an allowlist entry
 * for exactly this domain is removed, since it would win over the rule. */
function threatshield_block_domain(array &$cfg, string $domain, ?string &$message = null): bool {
	$d = threatshield_normalize_domain($domain);
	if ($d === null) {
		$message = gettext('The selected domain is invalid.');
		return false;
	}
	$rule = "||{$d}^";
	$rules = array_map('trim', threatshield_lines((string)($cfg['custom_rules'] ?? '')));
	if (in_array($rule, $rules, true)) {
		$message = sprintf(gettext('%s is already blocked by a custom rule.'), $d);
		return false;
	}
	$list = threatshield_normalize_list($cfg['allowlist'] ?? []);
	$found = threatshield_allowlist_find($list, $d);
	if ($found !== null && ($list[$found]['domain'] ?? '') === $d) {
		array_splice($list, $found, 1);
		$cfg['allowlist'] = $list;
	}
	$cfg['custom_rules'] = trim(implode("\n", $rules) . "\n" . $rule);
	$message = sprintf(gettext('%s is blocked with its subdomains.'), $d);
	return true;
}

function threatshield_ip_allowlist_add(array &$cfg, string $address, string $source, string $comment = '', ?string &$message = null): bool {
	$normalized = threatshield_cidr_normalize($address);
	if ($normalized === null) {
		$message = sprintf(gettext('"%s" is not a valid IP address or network.'), $address);
		return false;
	}
	$list = threatshield_normalize_list($cfg['ip_allowlist'] ?? []);
	foreach ($list as $i => $entry) {
		$existing = threatshield_cidr_normalize((string)($entry['address'] ?? ''));
		if ($existing !== null && threatshield_cidr_contains($existing, $normalized)) {
			if (($entry['enabled'] ?? 'on') !== 'on') {
				$list[$i]['enabled'] = 'on';
				$cfg['ip_allowlist'] = $list;
				return true;
			}
			$message = sprintf(gettext('%1$s is already allowed by the entry %2$s.'), $normalized, $existing);
			return false;
		}
	}
	$list[] = ['address' => $normalized, 'comment' => trim($comment), 'enabled' => 'on', 'added' => (string)time(), 'source' => $source];
	$cfg['ip_allowlist'] = $list;
	$message = sprintf(gettext('%s was added to the IP allowlist.'), $normalized);
	return true;
}

/* ---------------------------------------------------------------- HA sync */

function threatshield_plugin_xmlrpc_send() {
	if ((threatshield_config()['ha_sync'] ?? 'off') !== 'on') {
		return [];
	}
	return [THREATSHIELD_CONFIG_PATH];
}

function threatshield_plugin_xmlrpc_recv($new_sections) {
	$new = is_array($new_sections) ? array_get_path($new_sections, THREATSHIELD_CONFIG_PATH, null) : null;
	if (!is_array($new) || ($new['ha_sync'] ?? 'off') !== 'on') {
		return [];
	}
	// The Unbound snapshot belongs to this node; the pause is node-local.
	unset($new['_unbound_state']);
	$merged = threatshield_merge_defaults(threatshield_migrate_config($new, time()));
	if (!empty(threatshield_validate_config($merged))) {
		logger(LOG_ERR, 'Threat Shield: ignored settings from the HA peer that do not validate here.');
		return [];
	}
	$stored = threatshield_config_for_storage($merged);
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', null);
	if (is_array($state)) $stored['_unbound_state'] = $state;
	$old = config_get_path(THREATSHIELD_CONFIG_PATH, []);
	if ($old === $stored) {
		return ['xmlrpc_recv_result' => false];
	}
	return [THREATSHIELD_CONFIG_PATH => $stored, 'xmlrpc_recv_result' => true];
}

function threatshield_plugin_xmlrpc_recv_done($xmlrpc_recv_result) {
	if (array_get_path((array)$xmlrpc_recv_result, 'threatshield/xmlrpc_recv_result') !== true) {
		return;
	}
	threatshield_sync_config();
}

/* -------------------------------------------------------------- UI helpers */

/* Unix time of the last completed 'feeds', 'geoip' or 'ipfeeds' download (0 = never). */
function threatshield_last_update(string $kind): int {
	$file = THREATSHIELD_DB_DIR . '/last_' . $kind . '_update';
	return is_file($file) ? max(0, (int)trim((string)@file_get_contents($file))) : 0;
}

/* Short relative age for the WebUI ("5 min ago", "3 days ago"). */
function threatshield_age(int $timestamp): string {
	if ($timestamp <= 0) return gettext('Never');
	$age = max(0, time() - $timestamp);
	if ($age < 90) return gettext('Just now');
	if ($age < 5400) return sprintf(gettext('%d min ago'), (int)round($age / 60));
	if ($age < 129600) return sprintf(gettext('%d h ago'), (int)round($age / 3600));
	return sprintf(gettext('%d days ago'), (int)round($age / 86400));
}

function threatshield_display_tabs(string $active_tab): void {
	$tabs = [
		[gettext('Overview'), $active_tab === 'status', '/threatshield/threatshield_status.php'],
		[gettext('Threat map'), $active_tab === 'map', '/threatshield/threatshield_map.php'],
		[gettext('Settings'), $active_tab === 'general', '/threatshield/threatshield.php'],
		[gettext('Blocklists'), $active_tab === 'feeds', '/threatshield/threatshield_feeds.php'],
		[gettext('Allowlist'), $active_tab === 'allowlist', '/threatshield/threatshield_allowlist.php'],
		[gettext('Inbound protection'), $active_tab === 'inbound', '/threatshield/threatshield_inbound.php'],
		[gettext('GeoIP'), $active_tab === 'geoip', '/threatshield/threatshield_geoip.php'],
		[gettext('Clients & services'), $active_tab === 'clients', '/threatshield/threatshield_clients.php'],
		[gettext('DNS rules'), $active_tab === 'rules', '/threatshield/threatshield_rules.php'],
		[gettext('Query log'), $active_tab === 'querylog', '/threatshield/threatshield_querylog.php'],
	];
	display_top_tabs($tabs);
}

require_once(__DIR__ . '/threatshield/threatshield_health.inc');
require_once(__DIR__ . '/threatshield/threatshield_dnsbl.inc');
require_once(__DIR__ . '/threatshield/threatshield_map.inc');
