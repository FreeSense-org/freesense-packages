<?php
/*
 * threatshield.inc
 * FreeSense Threat Shield - Unified DNS Filtering & GeoIP Protection
 * (C) 2026 FreeSense Project
 */

require_once('config.inc');
require_once('util.inc');
require_once('services.inc');
require_once('filter.inc');

define('THREATSHIELD_CONFIG_PATH', 'installedpackages/threatshield');
define('THREATSHIELD_CONFIG_DIR', '/usr/local/etc/threatshield');
define('THREATSHIELD_CONFIG_FILE', '/usr/local/etc/threatshield/AdGuardHome.yaml');
define('THREATSHIELD_DB_DIR', '/var/db/threatshield');
define('THREATSHIELD_GEOIP_DIR', '/var/db/threatshield/geoip');
define('THREATSHIELD_PID_FILE', '/var/run/threatshield.pid');
define('THREATSHIELD_API_BASE', 'http://127.0.0.1:3000/control');
define('THREATSHIELD_GEOIP_INBOUND_TABLE', 'freesense_geoip_inbound');
define('THREATSHIELD_GEOIP_OUTBOUND_TABLE', 'freesense_geoip_outbound');
define('THREATSHIELD_SCHEMA_VERSION', 34);
define('THREATSHIELD_MAX_FEED_BYTES', 32 * 1024 * 1024);

function threatshield_list_fields(): array {
	return ['interfaces', 'feeds', 'geoip_countries', 'blocked_services', 'rewrites', 'clients', 'geoip_policies', 'dns_intercept_interfaces'];
}

function threatshield_services_catalog(): array {
	return ['tiktok','discord','youtube','facebook','instagram','roblox','steam','netflix','twitter','twitch','reddit','epic_games','snapchat','telegram'];
}

function threatshield_assigned_interfaces(): array {
	$result = [];
	foreach (config_get_path('interfaces', []) as $name => $entry) {
		if (!is_array($entry) || empty($entry['if'])) continue;
		$result[(string)$name] = (string)($entry['descr'] ?? strtoupper((string)$name));
	}
	return $result;
}

function threatshield_normalize_list($value): array {
	if (is_array($value) && array_key_exists('item', $value)) {
		$value = $value['item'];
	}
	return is_array($value) ? array_values($value) : [];
}

function threatshield_default_config(): array {
	return [
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
		'feed_update_interval' => 'daily',
		'feeds' => [
			[
				'name' => 'AdGuard DNS Filter',
				'url' => 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
				'enabled' => 'on',
				'category' => 'Ads & Tracking'
			],
			[
				'name' => 'OISD Basic Filter',
				'url' => 'https://small.oisd.nl',
				'enabled' => 'on',
				'category' => 'General Telemetry'
			],
			[
				'name' => 'Phishing Army Blocklist',
				'url' => 'https://phishing.army/download/phishing_army_blocklist_extended.txt',
				'enabled' => 'on',
				'category' => 'Phishing & Malware'
			],
			[
				'name' => 'Steven Black Unified Hosts',
				'url' => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
				'enabled' => 'on',
				'category' => 'Malware & Ads'
			]
		],
		'custom_rules' => '',
		'geoip_enable' => 'on',
		'geoip_mode' => 'block_inbound', // 'block_inbound', 'block_both', 'whitelist_inbound'
		'geoip_countries' => ['RU', 'CN', 'KP', 'IR', 'BY'],
		'geoip_update_interval' => 'weekly',
		'geoip_policies' => [],
		'blocked_services' => [],
		'rewrites' => [],
		'clients' => []
	];
}

function threatshield_config(): array {
	$raw = config_get_path(THREATSHIELD_CONFIG_PATH, []);
	if (!is_array($raw)) {
		$raw = [];
	}
	foreach (threatshield_list_fields() as $field) {
		if (array_key_exists($field, $raw)) {
			$raw[$field] = threatshield_normalize_list($raw[$field]);
		}
	}
	// Upgrade the original single GeoIP selector without changing an existing
	// administrator's effective country set.  New installs use policy records.
	if (empty($raw['geoip_policies']) && !empty($raw['geoip_countries'])) {
		$raw['geoip_policies'] = [[
			'id' => 'default', 'enable' => ($raw['geoip_enable'] ?? 'on'),
			'action' => (($raw['geoip_mode'] ?? 'block_inbound') === 'whitelist_inbound') ? 'allow_selected' : 'block_selected',
			'direction' => (($raw['geoip_mode'] ?? '') === 'block_both') ? 'both' : 'in',
			'interfaces' => ['wan'], 'protocol' => 'any', 'ports' => 'any',
			'countries' => threatshield_normalize_list($raw['geoip_countries']),
		]];
	}
	$defaults = threatshield_default_config();
	$config = array_replace_recursive($defaults, $raw);
	// Lists replace defaults as a unit. Recursive replacement would retain tail
	// entries from a default list when the saved list is shorter.
	foreach (threatshield_list_fields() as $field) {
		if (array_key_exists($field, $raw)) {
			$config[$field] = $raw[$field];
		}
	}
	return $config;
}

function threatshield_config_for_storage(array $candidate): array {
	$clean = [];
	foreach ($candidate as $k => $v) {
		if (in_array($k, threatshield_list_fields(), true)) {
			// config.xml list tags must use a valid element name. Writing a PHP
			// numeric array directly would emit invalid tags such as <0>.
			$clean[$k] = ['item' => threatshield_normalize_list($v)];
		} elseif (is_array($v)) {
			$clean[$k] = $v;
		} elseif (is_scalar($v)) {
			$clean[$k] = (string)$v;
		}
	}
	return $clean;
}

function threatshield_yaml_quote(string $value): string {
	return (string)json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
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
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		$url = is_array($feed) ? (string)($feed['url'] ?? '') : '';
		$p = parse_url($url);
		if ($url === '' || !is_array($p) || strtolower($p['scheme'] ?? '') !== 'https' || empty($p['host'])) {
			$errors[] = gettext('Every DNS feed must use a valid HTTPS URL.'); break;
		}
	}
	foreach (threatshield_normalize_list($cfg['blocked_services'] ?? []) as $service) {
		if (!in_array((string)$service, threatshield_services_catalog(), true)) {
			$errors[] = gettext('An unsupported blocked-service identifier was submitted.'); break;
		}
	}
	$assigned = array_keys(threatshield_assigned_interfaces());
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		if (!is_array($policy) || empty($policy['countries']) || empty($policy['interfaces']) ||
			!in_array(($policy['action'] ?? ''), ['block_selected','allow_selected'], true) ||
			!in_array(($policy['direction'] ?? ''), ['in','out','both'], true) ||
			!in_array(($policy['protocol'] ?? ''), ['any','tcp','udp'], true)) {
			$errors[] = gettext('Every GeoIP policy needs countries, interfaces, a valid action, direction, and protocol.'); break;
		}
		if (!empty(array_diff(threatshield_normalize_list($policy['interfaces']), $assigned))) {
			$errors[] = gettext('A GeoIP policy references an unassigned interface.'); break;
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
	return $errors;
}

function threatshield_save_and_apply(array $candidate, string $description, array &$errors = []): bool {
	$errors = threatshield_validate_config($candidate);
	if (!empty($errors)) return false;
	$previous = threatshield_config();
	$stored = threatshield_config_for_storage($candidate);
	config_set_path(THREATSHIELD_CONFIG_PATH, $stored);
	$result = write_config($description);
	$persisted = config_get_path(THREATSHIELD_CONFIG_PATH, null);
	if (!is_array($result) || !is_array($persisted) || threatshield_config_for_storage($persisted) !== $stored) {
		config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($previous));
		write_config(gettext('Rolled back failed Threat Shield settings save'));
		$errors[] = gettext('Settings could not be saved to config.xml; the previous settings were restored.');
		return false;
	}
	if (!threatshield_sync_config()) {
		config_set_path(THREATSHIELD_CONFIG_PATH, threatshield_config_for_storage($previous));
		write_config(gettext('Rolled back rejected Threat Shield settings'));
		threatshield_sync_config();
		$errors[] = gettext('Activation failed; the previous Threat Shield settings were restored.');
		return false;
	}
	return true;
}

function threatshield_restore_unbound(): bool {
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', []);
	if (!is_array($state) || ($state['managed'] ?? '') !== 'on') {
		return false;
	}
	config_set_path('unbound/port', (string)($state['port'] ?? '53'));
	config_set_path('unbound/active_interface', (string)($state['active_interface'] ?? 'all'));
	config_set_path('unbound/enable', (string)($state['enable'] ?? ''));
	config_set_path('unbound/custom_options', (string)($state['custom_options'] ?? ''));
	config_del_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state');
	write_config(gettext('Threat Shield: restored the previous Unbound DNS settings'));
	services_unbound_configure();
	return true;
}

function threatshield_manage_unbound(array $cfg): bool {
	$mode = $cfg['dns_coordination_mode'] ?? 'primary';
	if (($cfg['enable'] ?? 'off') !== 'on') return threatshield_restore_unbound() || true;
	$state = config_get_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', []);
	if (!is_array($state) || ($state['managed'] ?? '') !== 'on') {
		$state = [
			'managed' => 'on', 'port' => (string)config_get_path('unbound/port', '53'),
			'active_interface' => (string)config_get_path('unbound/active_interface', 'all'),
			'enable' => (string)config_get_path('unbound/enable', ''),
			'custom_options' => (string)config_get_path('unbound/custom_options', ''),
		];
		config_set_path(THREATSHIELD_CONFIG_PATH . '/_unbound_state', $state);
	}
	if ($mode === 'primary') {
		config_set_path('unbound/enable', $state['enable']);
		config_set_path('unbound/port', '5335');
		config_set_path('unbound/active_interface', 'lo0');
		config_set_path('unbound/custom_options', $state['custom_options']);
	} elseif ($mode === 'proxy') {
		// Keep Unbound client-facing and send ordinary recursion to the local
		// filtering listener. Existing local-zone settings remain managed by Unbound.
		config_set_path('unbound/enable', $state['enable'] ?: 'on');
		config_set_path('unbound/port', $state['port'] ?: '53');
		config_set_path('unbound/active_interface', $state['active_interface'] ?: 'all');
		$forward = "# FreeSense Threat Shield managed proxy forwarder\nforward-zone:\n  name: \".\"\n  forward-addr: 127.0.0.1@5354\n";
		config_set_path('unbound/custom_options', trim($state['custom_options'] . "\n" . $forward));
	} elseif ($mode === 'standalone') {
		config_set_path('unbound/enable', '');
		config_set_path('unbound/custom_options', $state['custom_options']);
	} else return false;
	if (!is_array(write_config(gettext('Threat Shield: coordinated Unbound DNS mode')))) return false;
	services_unbound_configure();
	return true;
}

function threatshield_is_running(): bool {
	if (!file_exists(THREATSHIELD_PID_FILE)) {
		return false;
	}
	$pid = trim((string)@file_get_contents(THREATSHIELD_PID_FILE));
	if ($pid === '' || !is_numeric($pid)) {
		return false;
	}
	exec('/bin/ps -p ' . escapeshellarg($pid) . ' -o pid=', $out, $rc);
	return ($rc === 0 && !empty($out));
}

function threatshield_service_control(string $action): bool {
	switch ($action) {
		case 'start':
			return mwexec('/usr/sbin/service threatshield start') === 0;
			break;
		case 'stop':
			return mwexec('/usr/sbin/service threatshield stop') === 0;
			break;
		case 'restart':
			return mwexec('/usr/sbin/service threatshield restart') === 0;
			break;
		case 'reload':
			return mwexec('/usr/sbin/service threatshield reload') === 0;
			break;
		default:
			return false;
	}
}

function threatshield_generate_yaml(array $cfg): string {
	$listen_port = ($cfg['dns_coordination_mode'] === 'proxy') ? 5354 : (int)($cfg['listen_port'] ?: 53);
	$dns_bind = ($cfg['dns_coordination_mode'] === 'proxy') ? '127.0.0.1' : '0.0.0.0';
	$http_port = (int)($cfg['http_port'] ?? 3000);
	$upstreams = array_filter(array_map('trim', explode("\n", (string)$cfg['upstreams'])));
	if (empty($upstreams)) {
		$upstreams = ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query'];
	}
	
	// If primary mode, add local Unbound on 5335 for local domain & reverse PTR
	if ($cfg['dns_coordination_mode'] === 'primary') {
		$domain = config_get_path('system/domain', 'localdomain');
		$upstreams[] = "[/{$domain}/]127.0.0.1:5335";
		$upstreams[] = "[/in-addr.arpa/]127.0.0.1:5335";
		$upstreams[] = "[/ip6.arpa/]127.0.0.1:5335";
	}

	$bootstrap = array_filter(array_map('trim', explode("\n", (string)$cfg['bootstrap_dns'])));
	$fallbacks = array_filter(array_map('trim', explode("\n", (string)$cfg['fallback_dns'])));

	$filters_yaml = '';
	if (!empty($cfg['feeds']) && is_array($cfg['feeds'])) {
		$idx = 1;
		foreach ($cfg['feeds'] as $feed) {
			$enabled_val = (!empty($feed['enabled']) && $feed['enabled'] === 'on') ? 'true' : 'false';
			$name_esc = threatshield_yaml_quote((string)($feed['name'] ?? "Feed #{$idx}"));
			$source_url = (string)($feed['url'] ?? '');
			$url_esc = threatshield_yaml_quote(THREATSHIELD_DB_DIR . '/feed_' . md5($source_url) . '.txt');
			if ($source_url !== '') {
				$filters_yaml .= "    - enabled: {$enabled_val}\n";
				$filters_yaml .= "      url: {$url_esc}\n";
				$filters_yaml .= "      name: {$name_esc}\n";
				$filters_yaml .= "      id: {$idx}\n";
				$idx++;
			}
		}
	}

	$user_rules_list = [];
	if (!empty($cfg['block_doh_canary']) && $cfg['block_doh_canary'] === 'on') {
		$user_rules_list[] = '||use-application-dns.net^';
	}
	if (!empty($cfg['block_icloud_private_relay']) && $cfg['block_icloud_private_relay'] === 'on') {
		$user_rules_list[] = '||mask.icloud.com^';
		$user_rules_list[] = '||mask-h2.icloud.com^';
	}
	if (!empty($cfg['custom_rules'])) {
		$rules = array_filter(array_map('trim', explode("\n", (string)$cfg['custom_rules'])));
		foreach ($rules as $r) {
			$user_rules_list[] = $r;
		}
	}

	$user_rules_yaml = '';
	foreach ($user_rules_list as $r) {
		$user_rules_yaml .= '    - ' . threatshield_yaml_quote((string)$r) . "\n";
	}

	$blocked_services_yaml = ' []';
	if (!empty($cfg['blocked_services']) && is_array($cfg['blocked_services'])) {
		foreach ($cfg['blocked_services'] as $svc) {
			$blocked_services_yaml .= "\n      - " . threatshield_yaml_quote((string)$svc);
		}
	}

	$rewrites_yaml = ' []';
	if (!empty($cfg['rewrites']) && is_array($cfg['rewrites'])) {
		foreach ($cfg['rewrites'] as $rw) {
			if (!empty($rw['domain']) && !empty($rw['answer'])) {
				$rewrites_yaml .= "\n    - domain: " . threatshield_yaml_quote((string)$rw['domain']);
				$rewrites_yaml .= "\n      answer: " . threatshield_yaml_quote((string)$rw['answer']);
				$rewrites_yaml .= "\n      enabled: true";
			}
		}
	}

	$ignored_domains_yaml = '';
	if (!empty($cfg['ignored_domains'])) {
		$ign = array_filter(array_map('trim', explode("\n", (string)$cfg['ignored_domains'])));
		foreach ($ign as $ig) {
			$ignored_domains_yaml .= '    - ' . threatshield_yaml_quote((string)$ig) . "\n";
		}
	}
	$clients_yaml = ' []';
	foreach (threatshield_normalize_list($cfg['clients'] ?? []) as $client) {
		if (!is_array($client) || empty($client['ids']) || !is_array($client['ids'])) continue;
		$clients_yaml .= "\n    - ids:";
		foreach ($client['ids'] as $id) $clients_yaml .= "\n        - " . threatshield_yaml_quote((string)$id);
		$clients_yaml .= "\n      name: " . threatshield_yaml_quote((string)($client['name'] ?? 'Threat Shield client'));
		$clients_yaml .= "\n      use_global_settings: " . (($client['filtering'] ?? 'inherit') === 'inherit' ? 'true' : 'false');
		$clients_yaml .= "\n      filtering_enabled: " . (($client['filtering'] ?? 'inherit') === 'off' ? 'false' : 'true');
		$clients_yaml .= "\n      use_global_blocked_services: " . (empty($client['blocked_services']) ? 'true' : 'false');
		$clients_yaml .= "\n      blocked_services:";
		foreach (threatshield_normalize_list($client['blocked_services'] ?? []) as $service) $clients_yaml .= "\n        - " . threatshield_yaml_quote((string)$service);
	}

	$upstream_mode = $cfg['upstream_mode'] ?? 'parallel';
	$dnssec_bool = ($cfg['enable_dnssec'] === 'on') ? 'true' : 'false';
	$safesearch_bool = ($cfg['enable_safesearch'] === 'on') ? 'true' : 'false';
	$parental_bool = ($cfg['enable_parental'] === 'on') ? 'true' : 'false';
	$safebrowsing_bool = (($cfg['safebrowsing_enabled'] ?? 'on') === 'on') ? 'true' : 'false';
	$optimistic_bool = (($cfg['cache_optimistic'] ?? 'on') === 'on') ? 'true' : 'false';
	$ecs_bool = (($cfg['edns_client_subnet'] ?? 'off') === 'on') ? 'true' : 'false';
	$querylog_bool = (($cfg['querylog_enabled'] ?? 'on') === 'on') ? 'true' : 'false';
	$anonymize_bool = (($cfg['anonymize_client_ip'] ?? 'off') === 'on') ? 'true' : 'false';

	$cache_bytes = max(1, (int)($cfg['cache_size'] ?? 4)) * 1048576;
	$feed_hours = ['6hours' => 6, '12hours' => 12, 'daily' => 24, 'weekly' => 168][(string)($cfg['feed_update_interval'] ?? 'daily')] ?? 24;
	$ttl_min = (int)($cfg['cache_ttl_min'] ?? 0);
	$ttl_max = (int)($cfg['cache_ttl_max'] ?? 0);
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
    - {$dns_bind}
  port: {$listen_port}
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
  rate_limit: {$cfg['ratelimit']}
  rate_limit_subnet_len_ipv4: {$cfg['rate_limit_subnet_len_ipv4']}
  rate_limit_subnet_len_ipv6: {$cfg['rate_limit_subnet_len_ipv6']}
  rate_limit_whitelist:{$rate_whitelist_yaml}
  edns_client_subnet:
    custom_ip: ""
    enabled: {$ecs_bool}
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  serve_http3: false
  use_http3_upstreams: false
  use_dns64: false
  dnssec_enabled: {$dnssec_bool}
  cache_size: {$cache_bytes}
  cache_ttl_min: {$ttl_min}
  cache_ttl_max: {$ttl_max}
  cache_optimistic: {$optimistic_bool}
  bogus_nxdomain: []
  upstream_mode: "{$upstream_mode}"
  use_private_ptr_resolvers: true
  local_ptr_upstreams:
{$local_ptr_yaml}

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
  protection_enabled: true
  filters_update_interval: {$feed_hours}
  parental_enabled: {$parental_bool}
  safebrowsing_enabled: {$safebrowsing_bool}
  safe_search:
    enabled: {$safesearch_bool}
  blocking_mode: {$blocking_mode}
  blocking_ipv4: {$blocking_ipv4}
  blocking_ipv6: {$blocking_ipv6}
  rewrites:{$rewrites_yaml}
  blocked_services:
    schedule:
      time_zone: Local
    ids:{$blocked_services_yaml}
filters:
{$filters_yaml}
whitelist_filters: []
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
  interval: {$cfg['querylog_retention']}h
  size_memory: 1000
  anonymize_client_ip: {$anonymize_bool}
  ignored:
{$ignored_domains_yaml}

statistics:
  enabled: true
  interval: 24h
  ignored: []

schema_version: 34

YAML;

	return $yaml;
}

function threatshield_sync_config(): bool {
	$cfg = threatshield_config();

	safe_mkdir(THREATSHIELD_CONFIG_DIR, 0750);
	safe_mkdir(THREATSHIELD_DB_DIR, 0750);
	safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);

	// Materialize filter subscriptions before AdGuard Home reads its generated
	// configuration.  The YAML references these local, atomically-written files.
	if (($cfg['enable'] ?? 'off') === 'on' && !threatshield_feed_cache_complete($cfg)) {
		mwexec('/usr/local/sbin/freesense-threatshield-update feeds force');
	}
	$yaml = threatshield_generate_yaml($cfg);
	$tmp = THREATSHIELD_CONFIG_FILE . '.tmp.' . getmypid();
	if (file_put_contents($tmp, $yaml, LOCK_EX) === false || !@chmod($tmp, 0640) || !@rename($tmp, THREATSHIELD_CONFIG_FILE)) {
		@unlink($tmp);
		return false;
	}
	if (!threatshield_manage_unbound($cfg)) return false;

	// Bootstrap country data on first application so an enabled policy never
	// reports success with empty PF tables while waiting for a later cron run.
	if (($cfg['geoip_enable'] ?? 'off') === 'on' && !threatshield_geoip_cache_complete($cfg)) {
		mwexec('/usr/local/sbin/freesense-threatshield-update geoip force');
	}
	// Sync GeoIP Tables
	threatshield_update_geoip();

	// Service lifecycle
	if ($cfg['enable'] === 'on') {
		threatshield_install_cron();
		if (!threatshield_service_control(threatshield_is_running() ? 'restart' : 'start')) return false;
	} else {
		threatshield_remove_cron();
		if (threatshield_is_running()) {
			if (!threatshield_service_control('stop')) return false;
		}
	}

	filter_configure();
	return true;
}

function threatshield_geoip_cache_complete(array $cfg): bool {
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		foreach (threatshield_normalize_list(is_array($policy) ? ($policy['countries'] ?? []) : []) as $cc) {
			$cc = strtoupper(preg_replace('/[^A-Z]/', '', (string)$cc));
			if ($cc === '' || !is_file(THREATSHIELD_GEOIP_DIR . '/' . $cc . '.zone')) return false;
		}
	}
	return true;
}

function threatshield_feed_cache_complete(array $cfg): bool {
	foreach (threatshield_normalize_list($cfg['feeds'] ?? []) as $feed) {
		if (!is_array($feed) || ($feed['enabled'] ?? 'on') !== 'on') continue;
		$url = (string)($feed['url'] ?? '');
		if ($url === '' || !is_file(THREATSHIELD_DB_DIR . '/feed_' . md5($url) . '.txt')) return false;
	}
	return true;
}

function threatshield_remove_config(): void {
	threatshield_service_control('stop');
	threatshield_remove_cron();

	threatshield_restore_unbound();

	@unlink(THREATSHIELD_CONFIG_FILE);
	filter_configure();
}

function threatshield_install_cron(): void {
	// The updater enforces the selected interval using persisted timestamps.
	install_cron_job('/usr/local/sbin/freesense-threatshield-update feeds', true, '17', '*', '*', '*', '*', 'root');
	install_cron_job('/usr/local/sbin/freesense-threatshield-update geoip', true, '43', '*', '*', '*', '*', 'root');
}

function threatshield_remove_cron(): void {
	install_cron_job('/usr/local/sbin/freesense-threatshield-update feeds', false);
	install_cron_job('/usr/local/sbin/freesense-threatshield-update geoip', false);
}

function threatshield_generate_rules(string $type): string {
	$cfg = threatshield_config();
	if ($cfg['enable'] !== 'on') {
		return '';
	}

	$rules = '';

	if ($type !== 'rules') return '';
	$rules .= "# FreeSense Threat Shield managed rules\n";
	foreach (threatshield_normalize_list($cfg['geoip_policies'] ?? []) as $policy) {
		if (!is_array($policy) || ($policy['enable'] ?? 'on') !== 'on' || empty($policy['countries'])) continue;
		$id = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($policy['id'] ?? 'default')));
		if ($id === '') $id = 'default';
		$table = 'freesense_geoip_' . $id;
		$file = THREATSHIELD_GEOIP_DIR . '/' . $id . '.cidrs';
		$proto = in_array(($policy['protocol'] ?? 'any'), ['tcp','udp'], true) ? ' proto ' . $policy['protocol'] : '';
		$ports = trim((string)($policy['ports'] ?? 'any'));
		$port = ($ports === '' || $ports === 'any') ? '' : ' port { ' . preg_replace('/[^0-9,: -]/', '', $ports) . ' }';
		$interfaces = threatshield_normalize_list($policy['interfaces'] ?? []);
		foreach ($interfaces as $friendly) {
			$real = function_exists('get_real_interface') ? get_real_interface((string)$friendly) : (string)$friendly;
			if ($real === '' || !preg_match('/^[A-Za-z0-9_.:-]+$/', $real)) continue;
			$rules .= "table <{$table}> persist file \"{$file}\"\n";
			if (in_array(($policy['direction'] ?? 'in'), ['in','both'], true)) {
				$source = (($policy['action'] ?? 'block_selected') === 'allow_selected') ? '! <' . $table . '>' : '<' . $table . '>';
				$rules .= "block in log quick on {$real}{$proto} from {$source} to any{$port} label \"ThreatShield GeoIP {$id} inbound\"\n";
			}
			if (in_array(($policy['direction'] ?? 'in'), ['out','both'], true)) {
				$destination = '<' . $table . '>';
				$rules .= "block out log quick on {$real}{$proto} from any to {$destination}{$port} label \"ThreatShield GeoIP {$id} outbound\"\n";
			}
		}
	}
	if (($cfg['catch_rogue_dns'] ?? 'off') === 'on') {
		$target_port = (($cfg['dns_coordination_mode'] ?? 'primary') === 'proxy') ? 5354 : (int)($cfg['listen_port'] ?? 53);
		foreach (threatshield_normalize_list($cfg['dns_intercept_interfaces'] ?? []) as $friendly) {
			$real = function_exists('get_real_interface') ? get_real_interface((string)$friendly) : (string)$friendly;
			if ($real !== '' && preg_match('/^[A-Za-z0-9_.:-]+$/', $real)) {
				$rules .= "rdr on {$real} proto { tcp udp } from any to any port 53 -> 127.0.0.1 port {$target_port}\n";
			}
		}
	}

	return $rules;
}

function threatshield_update_geoip(): void {
	$cfg = threatshield_config();
	safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);
	$policies = threatshield_normalize_list($cfg['geoip_policies'] ?? []);
	foreach ($policies as $policy) {
		if (!is_array($policy) || ($policy['enable'] ?? 'on') !== 'on') continue;
		$id = preg_replace('/[^a-z0-9_]/', '', strtolower((string)($policy['id'] ?? 'default'))) ?: 'default';
		$cidrs = [];
		foreach (threatshield_normalize_list($policy['countries'] ?? []) as $cc) {
		$cc_clean = strtoupper(preg_replace('/[^A-Z]/', '', $cc));
		if ($cc_clean === '') continue;
		$cc_cache = THREATSHIELD_GEOIP_DIR . "/{$cc_clean}.zone";
		if (file_exists($cc_cache)) {
			$lines = file($cc_cache, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			foreach ($lines as $line) {
				$line = trim($line);
				if ($line !== '' && !str_starts_with($line, '#')) {
					$cidrs[] = $line;
				}
			}
		}
		}
		$file = THREATSHIELD_GEOIP_DIR . '/' . $id . '.cidrs';
		$tmp = $file . '.tmp.' . getmypid();
		file_put_contents($tmp, implode("\n", array_unique($cidrs)) . "\n", LOCK_EX);
		@rename($tmp, $file);
		if (file_exists('/sbin/pfctl')) {
			mwexec('/sbin/pfctl -t ' . escapeshellarg('freesense_geoip_' . $id) . ' -T replace -f ' . escapeshellarg($file));
		}
	}
}

function threatshield_api_request(string $endpoint, string $method = 'GET', ?array $payload = null): ?array {
	$url = THREATSHIELD_API_BASE . '/' . ltrim($endpoint, '/');
	$ch = curl_init($url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_TIMEOUT, 3);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 1);

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
	curl_close($ch);

	if ($res === false || $code < 200 || $code >= 300) {
		return null;
	}

	$data = json_decode($res, true);
	return is_array($data) ? $data : ['status' => 'ok', 'raw' => $res];
}

function threatshield_get_stats(): array {
	$stats = threatshield_api_request('stats');
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

function threatshield_display_tabs(string $active_tab): void {
	$tabs = [
		[gettext('Dashboard & Metrics'), $active_tab === 'status', '/threatshield/threatshield_status.php'],
		[gettext('General Settings'), $active_tab === 'general', '/threatshield/threatshield.php'],
		[gettext('Live Query Inspector'), $active_tab === 'querylog', '/threatshield/threatshield_querylog.php'],
		[gettext('DNS Feeds & Lists'), $active_tab === 'feeds', '/threatshield/threatshield_feeds.php'],
		[gettext('GeoIP Country Shield'), $active_tab === 'geoip', '/threatshield/threatshield_geoip.php'],
		[gettext('Custom Rules'), $active_tab === 'rules', '/threatshield/threatshield_rules.php'],
		[gettext('Client Profiles'), $active_tab === 'clients', '/threatshield/threatshield_clients.php'],
		[gettext('DNS Rewrites'), $active_tab === 'rewrites', '/threatshield/threatshield_rewrites.php']
	];
	display_top_tabs($tabs);
}
