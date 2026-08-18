<?php
/*
 * threatshield.inc
 * FreeSense Threat Shield - Unified DNS Filtering & GeoIP Protection
 * (C) 2026 FreeSense Project
 */

require_once('config.inc');
require_once('util.inc');
require_once('services.inc');
require_once('pfsense-utils.inc');
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

function threatshield_default_config(): array {
	return [
		'enable' => 'off',
		'listen_port' => '53',
		'http_port' => '3000',
		'dns_coordination_mode' => 'primary', // 'primary' (Unbound to 5353), 'proxy' (ThreatShield on 5354), 'standalone'
		'interfaces' => ['all'],
		'upstreams' => "https://dns.quad9.net/dns-query\nhttps://cloudflare-dns.com/dns-query",
		'fallback_dns' => "9.9.9.9\n1.1.1.1",
		'bootstrap_dns' => "9.9.9.9\n1.1.1.1",
		'upstream_mode' => 'parallel', // 'parallel', 'fastest_addr', 'load_balance'
		'enable_dnssec' => 'on',
		'enable_safesearch' => 'off',
		'enable_parental' => 'off',
		'blocking_mode' => 'default',
		'ratelimit' => '0',
		'querylog_retention' => '90',
		'catch_rogue_dns' => 'on',
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
	$defaults = threatshield_default_config();
	return array_replace_recursive($defaults, $raw);
}

function threatshield_config_for_storage(array $candidate): array {
	$clean = [];
	foreach ($candidate as $k => $v) {
		if (is_array($v)) {
			$clean[$k] = $v;
		} elseif (is_scalar($v)) {
			$clean[$k] = (string)$v;
		}
	}
	return $clean;
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
			mwexec('/usr/sbin/service threatshield start');
			break;
		case 'stop':
			mwexec('/usr/sbin/service threatshield stop');
			break;
		case 'restart':
			mwexec('/usr/sbin/service threatshield restart');
			break;
		case 'reload':
			mwexec('/usr/sbin/service threatshield reload');
			break;
		default:
			return false;
	}
	return true;
}

function threatshield_generate_yaml(array $cfg): string {
	$listen_port = ($cfg['dns_coordination_mode'] === 'proxy') ? 5354 : (int)($cfg['listen_port'] ?: 53);
	$upstreams = array_filter(array_map('trim', explode("\n", (string)$cfg['upstreams'])));
	if (empty($upstreams)) {
		$upstreams = ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query'];
	}
	
	// If primary mode, add local Unbound on 5353 for local domain & reverse PTR
	if ($cfg['dns_coordination_mode'] === 'primary') {
		$domain = config_get_path('system/domain', 'localdomain');
		$upstreams[] = "[/{$domain}/]127.0.0.1:5353";
		$upstreams[] = "[/in-addr.arpa/]127.0.0.1:5353";
		$upstreams[] = "[/ip6.arpa/]127.0.0.1:5353";
	}

	$bootstrap = array_filter(array_map('trim', explode("\n", (string)$cfg['bootstrap_dns'])));
	$fallbacks = array_filter(array_map('trim', explode("\n", (string)$cfg['fallback_dns'])));

	$filters_yaml = '';
	if (!empty($cfg['feeds']) && is_array($cfg['feeds'])) {
		$idx = 1;
		foreach ($cfg['feeds'] as $feed) {
			$enabled_val = (!empty($feed['enabled']) && $feed['enabled'] === 'on') ? 'true' : 'false';
			$name_esc = addslashes((string)($feed['name'] ?? "Feed #{$idx}"));
			$url_esc = addslashes((string)($feed['url'] ?? ''));
			if ($url_esc !== '') {
				$filters_yaml .= "    - enabled: {$enabled_val}\n";
				$filters_yaml .= "      url: \"{$url_esc}\"\n";
				$filters_yaml .= "      name: \"{$name_esc}\"\n";
				$filters_yaml .= "      id: {$idx}\n";
				$idx++;
			}
		}
	}

	$user_rules_yaml = '';
	if (!empty($cfg['custom_rules'])) {
		$rules = array_filter(array_map('trim', explode("\n", (string)$cfg['custom_rules'])));
		foreach ($rules as $r) {
			$r_esc = addslashes($r);
			$user_rules_yaml .= "    - \"{$r_esc}\"\n";
		}
	}

	$blocked_services_yaml = '';
	if (!empty($cfg['blocked_services']) && is_array($cfg['blocked_services'])) {
		foreach ($cfg['blocked_services'] as $svc) {
			$svc_esc = addslashes((string)$svc);
			$blocked_services_yaml .= "    - \"{$svc_esc}\"\n";
		}
	}

	$rewrites_yaml = '';
	if (!empty($cfg['rewrites']) && is_array($cfg['rewrites'])) {
		foreach ($cfg['rewrites'] as $rw) {
			if (!empty($rw['domain']) && !empty($rw['answer'])) {
				$d_esc = addslashes($rw['domain']);
				$a_esc = addslashes($rw['answer']);
				$rewrites_yaml .= "  - domain: \"{$d_esc}\"\n";
				$rewrites_yaml .= "    answer: \"{$a_esc}\"\n";
			}
		}
	}

	$upstream_mode = $cfg['upstream_mode'] ?? 'parallel';
	$dnssec_bool = ($cfg['enable_dnssec'] === 'on') ? 'true' : 'false';
	$safesearch_bool = ($cfg['enable_safesearch'] === 'on') ? 'true' : 'false';
	$parental_bool = ($cfg['enable_parental'] === 'on') ? 'true' : 'false';

	$yaml = <<<YAML
# FreeSense Threat Shield Generated Configuration
# Do not edit manually - managed via FreeSense WebUI
bind_host: 0.0.0.0
bind_port: 3000
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: en
theme: auto
debug_pprof: false
web_session_ttl: 720

dns:
  bind_hosts:
    - 0.0.0.0
  port: {$listen_port}
  upstream_dns:
YAML;

	foreach ($upstreams as $u) {
		$yaml .= "\n    - \"" . addslashes($u) . "\"";
	}

	$yaml .= "\n  upstream_dns_file: \"\"\n  bootstrap_dns:";
	foreach ($bootstrap as $b) {
		$yaml .= "\n    - \"" . addslashes($b) . "\"";
	}

	$yaml .= "\n  fallback_dns:";
	foreach ($fallbacks as $f) {
		$yaml .= "\n    - \"" . addslashes($f) . "\"";
	}

	$yaml .= <<<YAML

  all_servers: {$upstream_mode}
  fastest_addr: false
  fastest_timeout: 1s
  rate_limit: {$cfg['ratelimit']}
  rate_limit_subnet_len_ipv4: 24
  rate_limit_subnet_len_ipv6: 56
  rate_limit_whitelist: []
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  serve_http3: false
  use_http3_upstreams: false
  use_dns64: false
  dnssec_enabled: {$dnssec_bool}
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 0
  cache_optimistic: true
  bogus_nxdomain: []
  filtering_enabled: true
  filters_update_interval: 24
  parental_enabled: {$parental_bool}
  safesearch_enabled: {$safesearch_bool}
  safebrowsing_enabled: true
  safebrowsing_cache_size: 1048576
  safesearch_cache_size: 1048576
  parental_cache_size: 1048576
  cache_time: 30
  rewrites:
{$rewrites_yaml}
  blocked_services:
{$blocked_services_yaml}
  upstream_mode: "{$upstream_mode}"
  use_private_ptr_resolvers: true
  local_ptr_upstreams:
    - 127.0.0.1:5353

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

filters:
{$filters_yaml}
whitelist_filters: []
user_rules:
{$user_rules_yaml}

dhcp:
  enabled: false

querylog:
  enabled: true
  file_enabled: true
  interval: {$cfg['querylog_retention']}h
  size_memory: 1000
  ignored: []

stats:
  enabled: true
  interval: 24h
  ignored: []

YAML;

	return $yaml;
}

function threatshield_sync_config(): bool {
	$cfg = threatshield_config();

	safe_mkdir(THREATSHIELD_CONFIG_DIR, 0750);
	safe_mkdir(THREATSHIELD_DB_DIR, 0750);
	safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);

	// Handle Unbound DNS port coordination
	if ($cfg['enable'] === 'on' && $cfg['dns_coordination_mode'] === 'primary') {
		$unbound_port = (int)config_get_path('unbound/port', 53);
		if ($unbound_port === 53) {
			config_set_path('unbound/port', '5353');
			config_set_path('unbound/active_interface', 'lo0');
			write_config(gettext('Threat Shield: coordinated Unbound port to 127.0.0.1:5353'));
			services_unbound_configure();
		}
	}

	$yaml = threatshield_generate_yaml($cfg);
	file_put_contents(THREATSHIELD_CONFIG_FILE, $yaml);
	chmod(THREATSHIELD_CONFIG_FILE, 0640);

	// Sync GeoIP Tables
	threatshield_update_geoip();

	// Service lifecycle
	if ($cfg['enable'] === 'on') {
		threatshield_install_cron();
		if (threatshield_is_running()) {
			threatshield_service_control('restart');
		} else {
			threatshield_service_control('start');
		}
	} else {
		threatshield_remove_cron();
		if (threatshield_is_running()) {
			threatshield_service_control('stop');
		}
	}

	filter_configure();
	return true;
}

function threatshield_remove_config(): void {
	threatshield_service_control('stop');
	threatshield_remove_cron();

	// Restore Unbound if shifted
	$unbound_port = (int)config_get_path('unbound/port', 53);
	if ($unbound_port === 5353) {
		config_set_path('unbound/port', '53');
		config_set_path('unbound/active_interface', 'all');
		write_config(gettext('Threat Shield: restored Unbound port to 53'));
		services_unbound_configure();
	}

	@unlink(THREATSHIELD_CONFIG_FILE);
	filter_configure();
}

function threatshield_install_cron(): void {
	$cfg = threatshield_config();
	install_cron_job('/usr/local/sbin/freesense-threatshield-update feeds', true, '0', '3', '*', '*', '*', 'root');
	if ($cfg['geoip_enable'] === 'on') {
		install_cron_job('/usr/local/sbin/freesense-threatshield-update geoip', true, '0', '4', '*', '*', '0', 'root');
	}
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

	// GeoIP Packet Filter Drop Rules
	if ($cfg['geoip_enable'] === 'on' && !empty($cfg['geoip_countries'])) {
		$in_table = THREATSHIELD_GEOIP_INBOUND_TABLE;
		$out_table = THREATSHIELD_GEOIP_OUTBOUND_TABLE;

		if ($type === 'rules') {
			$rules .= "# FreeSense Threat Shield: GeoIP Country Rules\n";
			$rules .= "table <{$in_table}> persist file \"" . THREATSHIELD_GEOIP_DIR . "/inbound_cidrs.txt\"\n";
			$rules .= "block in log quick from <{$in_table}> to any label \"ThreatShield: GeoIP Inbound Country Drop\"\n";

			if (in_array($cfg['geoip_mode'], ['block_both', 'whitelist_inbound'], true)) {
				$rules .= "table <{$out_table}> persist file \"" . THREATSHIELD_GEOIP_DIR . "/outbound_cidrs.txt\"\n";
				$rules .= "block out log quick from any to <{$out_table}> label \"ThreatShield: GeoIP Outbound Country Drop\"\n";
			}
		}
	}

	// Rogue DNS Interception (Catch Port 53)
	if ($cfg['catch_rogue_dns'] === 'on' && $type === 'nat') {
		$listen_port = (int)($cfg['listen_port'] ?: 53);
		$rules .= "# FreeSense Threat Shield: Rogue DNS Interception\n";
		$rules .= "rdr on {lan} proto {udp tcp} from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port {$listen_port}\n";
	}

	return $rules;
}

function threatshield_update_geoip(): void {
	$cfg = threatshield_config();
	safe_mkdir(THREATSHIELD_GEOIP_DIR, 0750);
	$in_file = THREATSHIELD_GEOIP_DIR . '/inbound_cidrs.txt';
	$out_file = THREATSHIELD_GEOIP_DIR . '/outbound_cidrs.txt';

	if ($cfg['geoip_enable'] !== 'on' || empty($cfg['geoip_countries'])) {
		@file_put_contents($in_file, '');
		@file_put_contents($out_file, '');
		return;
	}

	$cidrs = [];
	foreach ($cfg['geoip_countries'] as $cc) {
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

	$cidrs_unique = array_unique($cidrs);
	file_put_contents($in_file, implode("\n", $cidrs_unique) . "\n");
	file_put_contents($out_file, implode("\n", $cidrs_unique) . "\n");

	// Update active pf tables in kernel
	if (file_exists('/sbin/pfctl')) {
		mwexec('/sbin/pfctl -t ' . escapeshellarg(THREATSHIELD_GEOIP_INBOUND_TABLE) . ' -T replace -f ' . escapeshellarg($in_file));
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
