<?php
/*
 * FreeSense Web Gateway 2.0 integration.
 * Copyright (c) 2026 The FreeSense Project.
 * Licensed under the Apache License, Version 2.0.
 */

require_once('config.inc');
require_once('config.lib.inc');
require_once('interfaces.inc');
require_once('service-utils.inc');
require_once('services.inc');
require_once('util.inc');
require_once('certs.inc');
require_once('auth.inc');
require_once('filter.inc');

const WEBGATEWAY_CONFIG_PATH = 'installedpackages/webgateway';
const WEBGATEWAY_CONF_DIR = '/usr/local/etc/squid';
const WEBGATEWAY_FRAGMENT_DIR = WEBGATEWAY_CONF_DIR . '/freesense.d';
const WEBGATEWAY_CONF_FILE = WEBGATEWAY_CONF_DIR . '/freesense.conf';
const WEBGATEWAY_STATE_DIR = '/var/db/freesense-webgateway';
const WEBGATEWAY_SSL_DB = '/var/squid/ssl_db';
const WEBGATEWAY_LOG_FILE = '/var/log/squid/access.log';
const WEBGATEWAY_RC = '/usr/local/etc/rc.d/freesense_webgateway';
const WEBGATEWAY_FEED_COMMAND = '/usr/local/sbin/freesense-webgateway-feed-update';
const WEBGATEWAY_MAJOR = 7;

function webgateway_defaults() {
	return [
		'schema' => '2',
		'enable' => '',
		'interfaces' => [],
		'listener_modes' => ['explicit'],
		'port' => '3128',
		'http_intercept_port' => '3129',
		'https_intercept_port' => '3130',
		'quic_policy' => 'allow',
		'failure_policy' => 'open',
		'tls_mode' => 'tunnel',
		'tls_ack' => '',
		'caref' => '',
		'inspect_domains' => '',
		'splice_domains' => '',
		'policy_mode' => 'standard',
		'allowed_domains' => '',
		'blocked_domains' => '',
		'blocked_regex' => '',
		'blocked_user_agents' => '',
		'blocked_mime_types' => '',
		'schedules' => '',
		'max_upload_mb' => '0',
		'max_download_mb' => '0',
		'youtube_restrict' => '',
		'auth_mode' => 'none',
		'auth_server' => '',
		'auth_realm' => 'FreeSense Web Gateway',
		'auth_ttl' => '60',
		'kerberos_principal' => '',
		'kerberos_keytab' => '/usr/local/etc/squid/freesense.keytab',
		'cache_profile' => 'disabled',
		'cache_size_mb' => '1024',
		'memory_cache_mb' => '128',
		'max_object_mb' => '64',
		'bandwidth_profile' => 'unlimited',
		'upstream_enable' => '',
		'upstream_host' => '',
		'upstream_port' => '3128',
		'upstream_user' => '',
		'upstream_password' => '',
		'upstream_never_direct' => '',
		'privacy_headers' => 'on',
		'access_log' => 'on',
		'log_anonymize' => 'on',
		'icap_enable' => '',
		'icap_req_url' => '',
		'icap_resp_url' => '',
		'icap_failure' => 'bypass',
		'local_av_enable' => '',
		'av_failure' => 'closed',
		'av_max_mb' => '100',
		'feeds_enable' => '',
		'feed_urls' => '',
		'feed_interval' => '24',
		'feed_max_mb' => '50',
		'feed_max_entries' => '1000000',
		'ha_sync' => '',
		'exempt_sources' => '',
		'exempt_destinations' => '',
		'custom_options' => '',
	];
}

function webgateway_config() {
	$config = config_get_path(WEBGATEWAY_CONFIG_PATH, []);
	if (!is_array($config) || ($config['schema'] ?? '') !== '2') {
		/* Development-only reset: v1 was never a supported installed configuration. */
		$config = [];
	}
	$config = array_merge(webgateway_defaults(), $config);
	foreach (['interfaces', 'listener_modes'] as $field) {
		if (!is_array($config[$field])) {
			$config[$field] = array_values(array_filter(explode(',', (string)$config[$field])));
		}
	}
	return $config;
}

function webgateway_decode_list($value) {
	if ($value === null || $value === '') {
		return '';
	}
	$decoded = base64_decode((string)$value, true);
	return ($decoded === false) ? (string)$value : $decoded;
}

function webgateway_encode_list($value) {
	return base64_encode(str_replace("\r\n", "\n", trim((string)$value)));
}

function webgateway_lines($value) {
	$decoded = webgateway_decode_list($value);
	$result = [];
	foreach (preg_split('/\R/', $decoded) as $line) {
		$line = trim(preg_replace('/\s+#.*$/', '', $line));
		if ($line !== '' && !str_starts_with($line, '#')) {
			$result[] = $line;
		}
	}
	return array_values(array_unique($result));
}

function webgateway_is_client_interface($interface) {
	if ($interface === 'wan') {
		return false;
	}
	if ($interface === 'lan') {
		return true;
	}
	return !interface_has_gateway($interface) && !interface_has_gatewayv6($interface);
}

function webgateway_client_interfaces() {
	$interfaces = get_configured_interface_with_descr();
	foreach (array_keys($interfaces) as $interface) {
		if (!webgateway_is_client_interface($interface)) {
			unset($interfaces[$interface]);
		}
	}
	return $interfaces;
}

function webgateway_internal_cas() {
	$result = [];
	foreach (config_get_path('ca', []) as $ca) {
		if (!empty($ca['refid']) && !empty($ca['crt']) && !empty($ca['prv'])) {
			$result[$ca['refid']] = $ca['descr'] ?: $ca['refid'];
		}
	}
	return $result;
}

function webgateway_auth_servers() {
	$result = [];
	foreach (auth_get_authserver_list() as $name => $server) {
		$type = strtolower((string)($server['type'] ?? ''));
		if (in_array($type, ['ldap', 'radius'], true)) {
			$result[$name] = sprintf('%s (%s)', $name, strtoupper($type));
		}
	}
	return $result;
}

function webgateway_normalize_domains($value, &$errors) {
	$domains = [];
	foreach (preg_split('/\R/', (string)$value) as $line) {
		$line = strtolower(trim(preg_replace('/\s+#.*$/', '', $line)));
		if ($line === '' || str_starts_with($line, '#')) {
			continue;
		}
		if (!preg_match('/^\.?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/', $line) || str_contains($line, '..')) {
			$errors[] = sprintf(gettext('Invalid destination domain: %s'), htmlspecialchars($line));
			continue;
		}
		$domains[$line] = true;
	}
	return implode("\n", array_keys($domains));
}

function webgateway_normalize_networks($value, &$errors) {
	$networks = [];
	foreach (preg_split('/\R/', (string)$value) as $line) {
		$line = trim(preg_replace('/\s+#.*$/', '', $line));
		if ($line === '') {
			continue;
		}
		if (!is_ipaddr($line) && !is_subnet($line)) {
			$errors[] = sprintf(gettext('Invalid address or network: %s'), htmlspecialchars($line));
			continue;
		}
		$networks[$line] = true;
	}
	return implode("\n", array_keys($networks));
}

function webgateway_valid_icap_url($url) {
	$parts = parse_url((string)$url);
	return !preg_match('/[\r\n\s]/', (string)$url) && is_array($parts) &&
	    in_array(($parts['scheme'] ?? ''), ['icap', 'icaps'], true) &&
	    !empty($parts['host']) && !empty($parts['path']) &&
	    empty($parts['user']) && empty($parts['pass']) && empty($parts['query']) && empty($parts['fragment']) &&
	    (!isset($parts['port']) || ((int)$parts['port'] >= 1 && (int)$parts['port'] <= 65535));
}

function webgateway_validate_config($config, &$errors) {
	$errors = [];
	$available = webgateway_client_interfaces();
	$interfaces = is_array($config['interfaces'] ?? null) ? $config['interfaces'] : [];
	$modes = is_array($config['listener_modes'] ?? null) ? $config['listener_modes'] : [];
	if (($config['enable'] ?? '') === 'on' && (empty($interfaces) || empty($modes))) {
		$errors[] = gettext('Select at least one client interface and listener mode before enabling the Web Gateway.');
	}
	foreach ($interfaces as $interface) {
		if (!isset($available[$interface])) {
			$errors[] = sprintf(gettext('Unknown or unsafe listener interface: %s'), htmlspecialchars($interface));
		}
	}
	foreach ($modes as $mode) {
		if (!in_array($mode, ['explicit', 'intercept_http', 'intercept_https'], true)) {
			$errors[] = gettext('Unknown listener mode.');
		}
	}
	foreach (['port', 'http_intercept_port', 'https_intercept_port', 'upstream_port'] as $field) {
		$value = (string)($config[$field] ?? '');
		if (!ctype_digit($value) || (int)$value < 1 || (int)$value > 65535) {
			$errors[] = sprintf(gettext('%s must be between 1 and 65535.'), $field);
		}
	}
	$listener_ports = [];
	foreach (['explicit' => 'port', 'intercept_http' => 'http_intercept_port', 'intercept_https' => 'https_intercept_port'] as $mode => $field) {
		if (in_array($mode, $modes, true)) {
			$listener_ports[$field] = (string)($config[$field] ?? '');
		}
	}
	if (count($listener_ports) !== count(array_unique($listener_ports))) {
		$errors[] = gettext('Every enabled listener mode must use a distinct TCP port.');
	}
	foreach (['cache_size_mb' => [64, 1048576], 'memory_cache_mb' => [16, 65536], 'max_object_mb' => [1, 10240],
	    'av_max_mb' => [1, 4096], 'feed_interval' => [1, 720], 'feed_max_mb' => [1, 1024], 'feed_max_entries' => [1, 5000000],
	    'auth_ttl' => [1, 1440], 'max_upload_mb' => [0, 102400], 'max_download_mb' => [0, 102400]] as $field => $limits) {
		$value = (string)($config[$field] ?? '');
		if (!ctype_digit($value) || (int)$value < $limits[0] || (int)$value > $limits[1]) {
			$errors[] = sprintf(gettext('%s must be between %d and %d.'), $field, $limits[0], $limits[1]);
		}
	}
	if (!in_array(($config['tls_mode'] ?? ''), ['tunnel', 'selective', 'full'], true)) {
		$errors[] = gettext('Unknown TLS handling mode.');
	}
	$inspection = in_array(($config['tls_mode'] ?? ''), ['selective', 'full'], true);
	if ($inspection && ($config['tls_ack'] ?? '') !== 'on') {
		$errors[] = gettext('Acknowledge the legal and operational impact before enabling TLS inspection.');
	}
	if ($inspection) {
		$ca = lookup_ca((string)($config['caref'] ?? ''));
		$ca = $ca['item'] ?? $ca;
		if (!is_array($ca) || empty($ca['crt']) || empty($ca['prv'])) {
			$errors[] = gettext('TLS inspection requires an internal certificate authority with its private key.');
		}
	}
	if (in_array('intercept_https', $modes, true) && !$inspection) {
		$errors[] = gettext('Transparent HTTPS interception requires Selective or Full inspection. Tunnel-only HTTPS remains available through the explicit proxy.');
	}
	if (!in_array(($config['auth_mode'] ?? ''), ['none', 'local', 'ldap', 'radius', 'kerberos'], true)) {
		$errors[] = gettext('Unknown identity provider.');
	}
	if (($config['auth_mode'] ?? 'none') !== 'none' && !in_array('explicit', $modes, true)) {
		$errors[] = gettext('Proxy authentication requires an explicit listener. Transparent listeners cannot authenticate browsers reliably.');
	}
	if (in_array(($config['auth_mode'] ?? ''), ['ldap', 'radius'], true) && !isset(webgateway_auth_servers()[$config['auth_server'] ?? ''])) {
		$errors[] = gettext('Select a matching FreeSense authentication server.');
	}
	if (($config['auth_mode'] ?? '') === 'kerberos' && (empty($config['kerberos_principal']) || empty($config['kerberos_keytab']))) {
		$errors[] = gettext('Kerberos authentication requires a service principal and keytab path.');
	}
	if (($config['icap_enable'] ?? '') === 'on') {
		if (empty($config['icap_req_url']) && empty($config['icap_resp_url'])) {
			$errors[] = gettext('Configure at least one ICAP request or response service URL.');
		}
		foreach (['icap_req_url', 'icap_resp_url'] as $field) {
			if (!empty($config[$field]) && !webgateway_valid_icap_url($config[$field])) {
				$errors[] = gettext('ICAP URLs must be complete icap:// or icaps:// URLs without embedded credentials, query parameters, or whitespace.');
			}
		}
	}
	if (($config['local_av_enable'] ?? '') === 'on' &&
	    (!is_executable('/usr/local/bin/c-icap') || !is_executable('/usr/local/sbin/clamd') || !is_file('/usr/local/lib/c_icap/squidclamav.so'))) {
		$errors[] = gettext('Install the Web Gateway Local Antivirus companion before enabling local scanning.');
	}
	if (($config['upstream_enable'] ?? '') === 'on' && (!is_hostname($config['upstream_host']) && !is_ipaddr($config['upstream_host']))) {
		$errors[] = gettext('The upstream proxy host must be a hostname or IP address.');
	}
	if (($config['feeds_enable'] ?? '') === 'on') {
		foreach (webgateway_lines($config['feed_urls']) as $url) {
			$parts = parse_url($url);
			if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user'])) {
				$errors[] = sprintf(gettext('Feed URLs must use HTTPS without embedded credentials: %s'), htmlspecialchars($url));
			}
		}
	}
	$protected = '(?:include|http_port|https_port|cache_effective_(?:user|group)|pid_filename|chroot|'
		. 'url_rewrite_program|store_id_program|external_acl_type|sslcrtd_program|unlinkd_program|'
		. 'logfile_daemon|pinger_program|dns_program|diskd_program|auth_param\s+\S+\s+program|'
		. 'http_access\s+(?:allow|deny)\s+all)';
	if (preg_match('/(^|\R)\s*' . $protected . '\b/im', webgateway_decode_list($config['custom_options'] ?? ''))) {
		$errors[] = gettext('Custom options contain a protected directive. FreeSense manages listeners, includes, helper programs, runtime identity, PID handling, and terminal access policy.');
	}
	foreach (webgateway_lines($config['schedules'] ?? '') as $schedule) {
		if (!preg_match('/^[A-Za-z][A-Za-z0-9_-]*\|[SMTWHFA]+\|(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]$/', $schedule)) {
			$errors[] = sprintf(gettext('Invalid blocked schedule definition: %s'), htmlspecialchars($schedule));
		}
	}
}

function webgateway_interface_networks($interfaces, $include_exempt = false) {
	$networks = [];
	foreach ((array)$interfaces as $interface) {
		$address = get_interface_ip($interface);
		$bits = get_interface_subnet($interface);
		if (is_ipaddrv4($address) && is_numeric($bits)) {
			$networks[] = gen_subnet($address, $bits) . '/' . $bits;
		}
		$address6 = get_interface_ipv6($interface);
		$bits6 = get_interface_subnetv6($interface);
		if (is_ipaddrv6($address6) && is_numeric($bits6)) {
			$networks[] = gen_subnetv6($address6, $bits6) . '/' . $bits6;
		}
	}
	if ($include_exempt) {
		$networks = array_merge($networks, webgateway_lines(webgateway_config()['exempt_sources']));
	}
	return array_values(array_unique($networks));
}

function webgateway_interface_listeners($config, $directory = WEBGATEWAY_FRAGMENT_DIR) {
	$listeners = [];
	if (in_array('explicit', $config['listener_modes'], true)) {
		foreach ((array)$config['interfaces'] as $interface) {
			foreach ([get_interface_ip($interface), get_interface_ipv6($interface)] as $address) {
				if (is_ipaddr($address)) {
					$listeners[] = 'http_port ' . (is_ipaddrv6($address) ? '[' . $address . ']' : $address) . ':' . (int)$config['port'];
				}
			}
		}
	}
	if (in_array('intercept_http', $config['listener_modes'], true)) {
		$listeners[] = 'http_port 127.0.0.1:' . (int)$config['http_intercept_port'] . ' intercept';
		$listeners[] = 'http_port [::1]:' . (int)$config['http_intercept_port'] . ' intercept';
	}
	if (in_array('intercept_https', $config['listener_modes'], true)) {
		$tls = ' intercept ssl-bump cert=' . $directory . '/inspection-ca.pem key=' . $directory . '/inspection-ca.key generate-host-certificates=on dynamic_cert_mem_cache_size=16MB';
		$listeners[] = 'https_port 127.0.0.1:' . (int)$config['https_intercept_port'] . $tls;
		$listeners[] = 'https_port [::1]:' . (int)$config['https_intercept_port'] . $tls;
	}
	return array_values(array_unique($listeners));
}

function webgateway_squid_quote($value) {
	$value = str_replace(["\\", '"', "\r", "\n", "\0"], ["\\\\", '\\"', '', '', ''], (string)$value);
	return '"' . $value . '"';
}

function webgateway_auth_config($config, $directory = WEBGATEWAY_FRAGMENT_DIR) {
	$mode = $config['auth_mode'];
	if ($mode === 'none') {
		return ['', ''];
	}
	$realm = str_replace(['"', "\r", "\n"], '', $config['auth_realm']);
	$ttl = max(1, (int)$config['auth_ttl']);
	$lines = [];
	if ($mode === 'local') {
		$lines[] = 'auth_param basic program /usr/local/libexec/squid/basic_ncsa_auth ' . webgateway_squid_quote($directory . '/local-users');
		$lines[] = 'auth_param basic realm "' . $realm . '"';
		$lines[] = 'auth_param basic credentialsttl ' . $ttl . ' minutes';
		$acl = 'acl authenticated proxy_auth REQUIRED';
	} elseif ($mode === 'ldap') {
		$server = auth_get_authserver($config['auth_server']);
		$secure = str_contains(strtoupper((string)($server['ldap_urltype'] ?? '')), 'SSL');
		$helper = '/usr/local/libexec/squid/basic_ldap_auth -P -R -b ' . webgateway_squid_quote((string)($server['ldap_basedn'] ?? ''));
		$helper .= ' -D ' . webgateway_squid_quote((string)($server['ldap_binddn'] ?? ''));
		if (!empty($server['ldap_bindpw'])) {
			$helper .= ' -W ' . webgateway_squid_quote($directory . '/ldap-bind-password');
		}
		$helper .= ' -f ' . webgateway_squid_quote('(' . ($server['ldap_attr_user'] ?: 'uid') . '=%s)');
		$helper .= $secure ? ' -H ldaps://' : ' -H ldap://';
		$helper .= (is_ipaddrv6($server['host'] ?? '') ? '[' . $server['host'] . ']' : $server['host']) . ':' . (int)($server['ldap_port'] ?: ($secure ? 636 : 389));
		$lines[] = 'auth_param basic program ' . $helper;
		$lines[] = 'auth_param basic realm "' . $realm . '"';
		$lines[] = 'auth_param basic credentialsttl ' . $ttl . ' minutes';
		$acl = 'acl authenticated proxy_auth REQUIRED';
	} elseif ($mode === 'radius') {
		$lines[] = 'auth_param basic program /usr/local/libexec/squid/basic_radius_auth -f ' . webgateway_squid_quote($directory . '/radius.conf');
		$lines[] = 'auth_param basic realm "' . $realm . '"';
		$lines[] = 'auth_param basic credentialsttl ' . $ttl . ' minutes';
		$acl = 'acl authenticated proxy_auth REQUIRED';
	} else {
		$lines[] = 'auth_param negotiate program /usr/local/libexec/squid/negotiate_kerberos_auth -s ' . webgateway_squid_quote($config['kerberos_principal']) . ' -k ' . webgateway_squid_quote($config['kerberos_keytab']);
		$lines[] = 'auth_param negotiate keep_alive on';
		$acl = 'acl authenticated proxy_auth REQUIRED';
	}
	return [implode("\n", $lines) . "\n", $acl];
}

function webgateway_render_config($config = null, $directory = WEBGATEWAY_FRAGMENT_DIR) {
	$config = $config ?? webgateway_config();
	$listeners = webgateway_interface_listeners($config, $directory);
	if (empty($listeners)) {
		$listeners[] = 'http_port 127.0.0.1:' . (int)$config['port'];
	}
	$path = fn($name) => $directory . '/' . $name;
	$identity_log = ($config['log_anonymize'] === 'on') ? '- -' : '%>a %un';
	$lines = [
		'# Generated by FreeSense Web Gateway 2.0. Manual changes are overwritten.',
		'visible_hostname freesense-web-gateway',
		'pid_filename /var/run/squid/squid.pid',
		'coredump_dir /var/squid/cache',
		'cache_mem ' . (int)$config['memory_cache_mb'] . ' MB',
		'maximum_object_size ' . (int)$config['max_object_mb'] . ' MB',
		'cache_log /var/log/squid/cache.log',
		'logformat freesense %ts.%03tu %6tr ' . $identity_log . ' %Ss/%03>Hs %<st %rm %ru %ssl::>sni %ssl::bump_mode',
		'access_log ' . (($config['access_log'] === 'on') ? 'daemon:/var/log/squid/access.log freesense' : 'none'),
		'',
	];
	$lines = array_merge($lines, $listeners, [
		'',
		'acl local_clients src "' . $path('clients.acl') . '"',
		'acl exempt_destinations dst "' . $path('exempt-destinations.acl') . '"',
		'acl always_allowed dstdomain "' . $path('allow-domains.acl') . '"',
		'acl blocked_destinations dstdomain "' . $path('block-domains.acl') . '"',
		'acl blocked_urls url_regex -i "' . $path('block-regex.acl') . '"',
		'acl blocked_agents browser -i "' . $path('block-agents.acl') . '"',
		'acl blocked_mime rep_mime_type -i "' . $path('block-mime.acl') . '"',
		'acl inspect_sites ssl::server_name "' . $path('inspect-domains.acl') . '"',
		'acl splice_sites ssl::server_name "' . $path('splice-domains.acl') . '"',
		'acl SSL_ports port 443 563',
		'acl Safe_ports port 80 443 563 70 210 1025-65535',
		'acl CONNECT method CONNECT',
		'acl step1 at_step SslBump1',
		'acl step2 at_step SslBump2',
		'http_access deny !Safe_ports',
		'http_access deny CONNECT !SSL_ports',
		'http_access deny !local_clients',
	]);
	[$auth, $auth_acl] = webgateway_auth_config($config, $directory);
	if ($auth !== '') {
		$lines[] = trim($auth);
		$lines[] = $auth_acl;
		$lines[] = 'http_access deny !authenticated';
	}
	$lines[] = 'http_access allow always_allowed';
	$lines[] = 'http_access deny blocked_destinations';
	$lines[] = 'http_access deny blocked_urls';
	$lines[] = 'http_access deny blocked_agents';
	foreach (webgateway_lines($config['schedules']) as $schedule) {
		[$name, $days, $time] = explode('|', $schedule, 3);
		$lines[] = 'acl schedule_' . $name . ' time ' . $days . ' ' . $time;
		$lines[] = 'http_access deny schedule_' . $name;
	}
	$lines[] = ($config['policy_mode'] === 'allowlist') ? 'http_access deny local_clients' : 'http_access allow local_clients';
	$lines[] = 'http_access deny all';
	$lines[] = 'http_reply_access deny blocked_mime';
	$lines[] = 'http_reply_access allow all';
	if ((int)$config['max_upload_mb'] > 0) {
		$lines[] = 'request_body_max_size ' . (int)$config['max_upload_mb'] . ' MB local_clients';
	}
	if ((int)$config['max_download_mb'] > 0) {
		$lines[] = 'reply_body_max_size ' . (int)$config['max_download_mb'] . ' MB local_clients';
	}
	if (in_array($config['tls_mode'], ['selective', 'full'], true)) {
		$lines[] = '';
		$lines[] = 'sslcrtd_program /usr/local/libexec/squid/security_file_certgen -s ' . WEBGATEWAY_SSL_DB . ' -M 16MB';
		$lines[] = 'sslcrtd_children 16 startup=4 idle=2';
		$lines[] = 'tls_outgoing_options cafile=/etc/ssl/cert.pem options=NO_SSLv3';
		$lines[] = 'ssl_bump peek step1';
		$lines[] = 'ssl_bump splice splice_sites';
		if ($config['tls_mode'] === 'selective') {
			$lines[] = 'ssl_bump bump inspect_sites';
			$lines[] = 'ssl_bump splice all';
		} else {
			$lines[] = 'ssl_bump bump all';
		}
	}
	$lines[] = '';
	if ($config['cache_profile'] !== 'disabled') {
		$storage = ($config['cache_profile'] === 'metadata') ? 'rock' : 'ufs';
		$lines[] = 'cache_dir ' . $storage . ' /var/squid/cache ' . (int)$config['cache_size_mb'] . (($storage === 'ufs') ? ' 16 256' : ' max-size=32768');
	} else {
		$lines[] = 'cache deny all';
	}
	if ($config['privacy_headers'] === 'on') {
		$lines[] = 'forwarded_for delete';
		$lines[] = 'via off';
		$lines[] = 'request_header_access X-Forwarded-For deny all';
	}
	if ($config['log_anonymize'] === 'on') {
		$lines[] = 'strip_query_terms on';
	}
	if ($config['upstream_enable'] === 'on') {
		$peer = 'cache_peer ' . $config['upstream_host'] . ' parent ' . (int)$config['upstream_port'] . ' 0 no-query default';
		if ($config['upstream_user'] !== '') {
			$peer .= ' login=' . rawurlencode($config['upstream_user']) . ':' . rawurlencode($config['upstream_password']);
		}
		$lines[] = $peer;
		$lines[] = ($config['upstream_never_direct'] === 'on') ? 'never_direct allow all' : 'prefer_direct off';
	}
	if ($config['bandwidth_profile'] !== 'unlimited') {
		$rate = ($config['bandwidth_profile'] === 'low_latency') ? 1048576 : (($config['bandwidth_profile'] === 'balanced') ? 5242880 : 20971520);
		$lines[] = 'delay_pools 1';
		$lines[] = 'delay_class 1 2';
		$lines[] = 'delay_parameters 1 ' . ($rate * 4) . '/' . $rate . ' ' . $rate . '/' . intdiv($rate, 4);
		$lines[] = 'delay_access 1 allow local_clients';
	}
	if ($config['icap_enable'] === 'on' || $config['local_av_enable'] === 'on') {
		$bypass = (($config['local_av_enable'] === 'on' ? $config['av_failure'] : $config['icap_failure']) === 'closed') ? '0' : '1';
		$lines[] = 'icap_enable on';
		$req = ($config['local_av_enable'] === 'on') ? 'icap://127.0.0.1:1344/squidclamav' : $config['icap_req_url'];
		$resp = ($config['local_av_enable'] === 'on') ? 'icap://127.0.0.1:1344/squidclamav' : $config['icap_resp_url'];
		if ($req !== '') {
			$lines[] = 'icap_service freesense_request reqmod_precache ' . $req . ' bypass=' . $bypass;
			$lines[] = 'adaptation_access freesense_request allow local_clients';
		}
		if ($resp !== '') {
			$lines[] = 'icap_service freesense_response respmod_precache ' . $resp . ' bypass=' . $bypass;
			$lines[] = 'adaptation_access freesense_response allow local_clients';
		}
	}
	if ($config['youtube_restrict'] === 'on') {
		$lines[] = 'request_header_add YouTube-Restrict Strict all';
	}
	$custom = trim(webgateway_decode_list($config['custom_options']));
	if ($custom !== '') {
		$lines[] = '';
		$lines[] = '# Validated expert directives';
		$lines[] = $custom;
	}
	$lines[] = '';
	$lines[] = 'refresh_pattern ^ftp: 1440 20% 10080';
	$lines[] = 'refresh_pattern -i (/cgi-bin/|\?) 0 0% 0';
	$lines[] = 'refresh_pattern . 0 20% 4320';
	return implode("\n", $lines) . "\n";
}

function webgateway_local_users() {
	$lines = [];
	foreach (config_get_path('system/user', []) as $user) {
		if (!empty($user['name']) && !empty($user['password']) &&
		    !isset($user['disabled']) && !is_account_expired($user['name'])) {
			$lines[] = preg_replace('/[^A-Za-z0-9_.@-]/', '', $user['name']) . ':' . $user['password'];
		}
	}
	return implode("\n", $lines) . "\n";
}

function webgateway_radius_config($config) {
	$server = auth_get_authserver($config['auth_server']);
	if (!is_array($server)) {
		return '';
	}
	return 'server ' . ($server['host'] ?? '') . "\nsecret " . ($server['radius_secret'] ?? $server['secret'] ?? '') . "\n";
}

function webgateway_render_files($config, $directory) {
	$splice = array_merge([
		'.apple.com', '.icloud.com', '.microsoftonline.com', '.windowsupdate.com', '.mozilla.org',
		'.googleapis.com', '.gstatic.com', '.letsencrypt.org', '.digicert.com', '.globalsign.com',
	], webgateway_lines($config['splice_domains']));
	$files = [
		'clients.acl' => implode("\n", webgateway_interface_networks($config['interfaces'])) . "\n",
		'exempt-destinations.acl' => implode("\n", webgateway_lines($config['exempt_destinations'])) . "\n",
		'allow-domains.acl' => implode("\n", webgateway_lines($config['allowed_domains'])) . "\n",
		'block-domains.acl' => implode("\n", array_merge(webgateway_lines($config['blocked_domains']), webgateway_feed_domains())) . "\n",
		'block-regex.acl' => implode("\n", webgateway_lines($config['blocked_regex'])) . "\n",
		'block-agents.acl' => implode("\n", webgateway_lines($config['blocked_user_agents'])) . "\n",
		'block-mime.acl' => implode("\n", webgateway_lines($config['blocked_mime_types'])) . "\n",
		'inspect-domains.acl' => implode("\n", webgateway_lines($config['inspect_domains'])) . "\n",
		'splice-domains.acl' => implode("\n", array_unique($splice)) . "\n",
	];
	if ($config['auth_mode'] === 'local') {
		$files['local-users'] = webgateway_local_users();
	}
	if ($config['auth_mode'] === 'radius') {
		$files['radius.conf'] = webgateway_radius_config($config);
	}
	if ($config['auth_mode'] === 'ldap') {
		$server = auth_get_authserver($config['auth_server']);
		if (!empty($server['ldap_bindpw'])) {
			$files['ldap-bind-password'] = (string)$server['ldap_bindpw'] . "\n";
		}
	}
	if (in_array($config['tls_mode'], ['selective', 'full'], true)) {
		$ca = lookup_ca($config['caref']);
		$ca = $ca['item'] ?? $ca;
		$files['inspection-ca.pem'] = base64_decode($ca['crt']);
		$files['inspection-ca.key'] = base64_decode($ca['prv']);
	}
	$files['freesense.conf'] = webgateway_render_config($config, $directory);
	return $files;
}

function webgateway_write_file($path, $contents, $mode = 0644) {
	$tmp = $path . '.tmp.' . getmypid();
	if (file_put_contents($tmp, $contents, LOCK_EX) === false) {
		return false;
	}
	chmod($tmp, $mode);
	return rename($tmp, $path);
}

function webgateway_file_mode($name) {
	if (in_array($name, ['freesense.conf', 'inspection-ca.key', 'local-users', 'radius.conf', 'ldap-bind-password'], true)) {
		return 0640;
	}
	return 0644;
}

function webgateway_set_file_owner($path, $name) {
	if (!in_array($name, ['freesense.conf', 'inspection-ca.key', 'local-users', 'radius.conf', 'ldap-bind-password'], true)) {
		return;
	}
	@chown($path, 'root');
	@chgrp($path, 'squid');
	@chmod($path, 0640);
}

function webgateway_remove_tree($path) {
	$real = realpath($path);
	$root = realpath(WEBGATEWAY_STATE_DIR);
	if ($real === false || $root === false || !str_starts_with($real, $root . DIRECTORY_SEPARATOR)) {
		return false;
	}
	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($real, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ($iterator as $item) {
		$item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
	}
	return @rmdir($real);
}

function webgateway_squid_version(&$version = '') {
	$status = 1;
	$lines = [];
	exec('/usr/local/sbin/squid -v 2>&1', $lines, $status);
	$text = implode("\n", $lines);
	if (preg_match('/Squid Cache:\s*Version\s+([0-9.]+)/i', $text, $match)) {
		$version = $match[1];
	}
	return $status === 0 && (int)$version === WEBGATEWAY_MAJOR;
}

function webgateway_config_test(&$output = null, $file = WEBGATEWAY_CONF_FILE) {
	$lines = [];
	$status = 1;
	exec('/usr/local/sbin/squid -k parse -f ' . escapeshellarg($file) . ' 2>&1', $lines, $status);
	$output = implode("\n", $lines);
	return $status === 0;
}

function webgateway_prepare_files($config = null) {
	$config = $config ?? webgateway_config();
	$errors = [];
	webgateway_validate_config($config, $errors);
	if (!empty($errors)) {
		return implode(' ', $errors);
	}
	$version = '';
	if (!webgateway_squid_version($version)) {
		return sprintf('Web Gateway requires Squid 7.x; detected %s.', $version ?: 'no usable Squid binary');
	}
	foreach ([WEBGATEWAY_CONF_DIR, WEBGATEWAY_FRAGMENT_DIR, WEBGATEWAY_STATE_DIR, '/var/log/squid', '/var/run/squid', '/var/squid/cache'] as $directory) {
		if (!is_dir($directory) && !mkdir($directory, 0750, true)) {
			return sprintf('Unable to create %s', $directory);
		}
	}
	$stage = WEBGATEWAY_STATE_DIR . '/stage.' . getmypid();
	if (!mkdir($stage, 0750, true)) {
		return 'Unable to create the transactional staging directory.';
	}
	$fail = function ($message) use ($stage) {
		webgateway_remove_tree($stage);
		return $message;
	};
	$files = webgateway_render_files($config, $stage);
	foreach ($files as $name => $contents) {
		if (!webgateway_write_file($stage . '/' . $name, $contents, webgateway_file_mode($name))) {
			return $fail(sprintf('Unable to stage %s.', $name));
		}
	}
	if (in_array($config['tls_mode'], ['selective', 'full'], true)) {
		if (!is_dir(WEBGATEWAY_SSL_DB)) {
			if (mwexec('/usr/local/libexec/squid/security_file_certgen -c -s ' . escapeshellarg(WEBGATEWAY_SSL_DB) . ' -M 16MB') !== 0) {
				return $fail('Unable to initialize the Squid dynamic certificate database.');
			}
		}
		mwexec('/usr/sbin/chown -R squid:squid ' . escapeshellarg(WEBGATEWAY_SSL_DB));
	}
	$output = '';
	if (!webgateway_config_test($output, $stage . '/freesense.conf')) {
		return $fail('Squid rejected the staged configuration: ' . $output);
	}
	$backup = WEBGATEWAY_STATE_DIR . '/previous';
	if (!is_dir($backup)) {
		mkdir($backup, 0750, true);
	}
	$managed_secrets = ['inspection-ca.pem', 'inspection-ca.key', 'local-users', 'radius.conf', 'ldap-bind-password'];
	foreach ($managed_secrets as $name) {
		$destination = WEBGATEWAY_FRAGMENT_DIR . '/' . $name;
		if (!array_key_exists($name, $files) && is_file($destination)) {
			@copy($destination, $backup . '/' . $name);
			@unlink($destination);
		}
	}
	foreach ($files as $name => $contents) {
		$destination = ($name === 'freesense.conf') ? WEBGATEWAY_CONF_FILE : WEBGATEWAY_FRAGMENT_DIR . '/' . $name;
		if (is_file($destination)) {
			@copy($destination, $backup . '/' . $name);
		}
		$final_contents = ($name === 'freesense.conf') ? webgateway_render_config($config, WEBGATEWAY_FRAGMENT_DIR) : $contents;
		if (!webgateway_write_file($destination, $final_contents, webgateway_file_mode($name))) {
			webgateway_restore_previous();
			return $fail(sprintf('Unable to activate %s.', $name));
		}
		webgateway_set_file_owner($destination, $name);
	}
	foreach (['/var/log/squid', '/var/run/squid', '/var/squid', '/var/squid/cache', WEBGATEWAY_SSL_DB] as $directory) {
		@chown($directory, 'squid');
		@chgrp($directory, 'squid');
	}
	@chown(WEBGATEWAY_FRAGMENT_DIR, 'root');
	@chgrp(WEBGATEWAY_FRAGMENT_DIR, 'squid');
	@chmod(WEBGATEWAY_FRAGMENT_DIR, 0750);
	@chown(WEBGATEWAY_CONF_DIR, 'root');
	@chgrp(WEBGATEWAY_CONF_DIR, 'squid');
	@chmod(WEBGATEWAY_CONF_DIR, 0750);
	/* Remove the legacy pseudo-WPAD file. PAC deployment uses the authenticated download endpoint. */
	@unlink('/usr/local/www/wpad.dat');
	webgateway_remove_tree($stage);
	return null;
}

function webgateway_restore_previous() {
	$backup = WEBGATEWAY_STATE_DIR . '/previous';
	if (!is_dir($backup)) {
		return false;
	}
	foreach (glob($backup . '/*') ?: [] as $source) {
		$name = basename($source);
		$destination = ($name === 'freesense.conf') ? WEBGATEWAY_CONF_FILE : WEBGATEWAY_FRAGMENT_DIR . '/' . $name;
		@copy($source, $destination);
		@chmod($destination, webgateway_file_mode($name));
		webgateway_set_file_owner($destination, $name);
	}
	return true;
}

function webgateway_service_action($action) {
	if (!in_array($action, ['onestart', 'onestop', 'onerestart', 'reload'], true)) {
		return 1;
	}
	return mwexec(WEBGATEWAY_RC . ' ' . $action);
}

function webgateway_watchdog_action($action) {
	if (!in_array($action, ['onestart', 'onestop'], true)) {
		return 1;
	}
	return mwexec('/usr/local/etc/rc.d/freesense_webgateway_watchdog ' . $action);
}

function webgateway_sync_feed_schedule($config = null, $write_config = true) {
	$config = $config ?? webgateway_config();
	$enabled = ($config['feeds_enable'] ?? '') === 'on';
	/* Run hourly; the updater enforces the configured 1-720 hour interval. */
	install_cron_job(WEBGATEWAY_FEED_COMMAND, $enabled, '17', '*', '*', '*', '*', 'root', $write_config);
}

function webgateway_stays_running($seconds = 5) {
	$checks = max(1, (int)$seconds * 4);
	for ($check = 0; $check < $checks; $check++) {
		usleep(250000);
		if (!webgateway_is_running()) {
			return false;
		}
	}
	return true;
}

function webgateway_sync_config() {
	$config = webgateway_config();
	webgateway_sync_feed_schedule($config);
	$error = webgateway_prepare_files($config);
	if ($error !== null) {
		log_error('Web Gateway: ' . $error);
		webgateway_service_action('onestop');
		filter_configure();
		return false;
	}
	if ($config['enable'] !== 'on') {
		webgateway_watchdog_action('onestop');
		webgateway_service_action('onestop');
		webgateway_set_av_services(false);
		filter_configure();
		return true;
	}
	if ($config['cache_profile'] !== 'disabled') {
		mwexec('/usr/local/sbin/squid -z -f ' . escapeshellarg(WEBGATEWAY_CONF_FILE));
	}
	webgateway_set_av_services($config['local_av_enable'] === 'on');
	if (webgateway_is_running()) {
		$result = webgateway_service_action('reload');
		if ($result === 0 && !webgateway_stays_running()) {
			$result = 1;
		}
		if ($result !== 0) {
			$result = webgateway_service_action('onerestart');
		}
	} else {
		$result = webgateway_service_action('onestart');
	}
	if ($result === 0 && !webgateway_stays_running(2)) {
		$result = 1;
	}
	if ($result !== 0) {
		webgateway_restore_previous();
		webgateway_service_action('onestart');
		filter_configure();
		return false;
	}
	if (array_intersect($config['listener_modes'], ['intercept_http', 'intercept_https'])) {
		webgateway_watchdog_action('onestart');
	} else {
		webgateway_watchdog_action('onestop');
	}
	filter_configure();
	return true;
}

function webgateway_is_running() {
	return is_service_running('freesense_webgateway');
}

function webgateway_feed_domains() {
	$file = WEBGATEWAY_STATE_DIR . '/feeds/active.domains';
	return is_readable($file) ? array_values(array_filter(array_map('trim', file($file, FILE_IGNORE_NEW_LINES) ?: []))) : [];
}

function webgateway_update_feeds(&$message = '') {
	$config = webgateway_config();
	if ($config['feeds_enable'] !== 'on') {
		$message = gettext('Feed updates are disabled.');
		return false;
	}
	$urls = webgateway_lines($config['feed_urls']);
	if (empty($urls)) {
		$message = gettext('No feeds are configured.');
		return false;
	}
	$feed_dir = WEBGATEWAY_STATE_DIR . '/feeds';
	$stage = $feed_dir . '/stage.' . getmypid();
	if (!is_dir($feed_dir) && !mkdir($feed_dir, 0750, true)) {
		$message = gettext('Unable to create the feed database directory.');
		return false;
	}
	if (!mkdir($stage, 0750, true)) {
		$message = gettext('Unable to create the feed staging directory.');
		return false;
	}
	$fail = function ($text) use ($stage, &$message) {
		$message = $text;
		webgateway_remove_tree($stage);
		return false;
	};
	$domains = [];
	$max_bytes = (int)$config['feed_max_mb'] * 1048576;
	foreach ($urls as $index => $url) {
		$file = $stage . '/feed-' . $index;
		$command = '/usr/local/bin/curl --fail --silent --show-error --location --proto =https --max-time 120 --max-filesize ' . $max_bytes . ' --output ' . escapeshellarg($file) . ' ' . escapeshellarg($url);
		if (mwexec($command) !== 0 || !is_file($file) || filesize($file) > $max_bytes) {
			return $fail(sprintf(gettext('Feed download failed; the last-known-good database remains active: %s'), $url));
		}
		foreach (file($file, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
			$line = strtolower(trim(preg_replace('/\s+#.*$/', '', $line)));
			$line = preg_replace('/^0\.0\.0\.0\s+/', '', $line);
			if ($line !== '' && preg_match('/^\.?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/', $line) && !str_contains($line, '..')) {
				$domains[$line] = true;
			}
			if (count($domains) > (int)$config['feed_max_entries']) {
				return $fail(gettext('A feed exceeded the configured entry limit; the last-known-good database remains active.'));
			}
		}
	}
	ksort($domains);
	if (!webgateway_write_file($feed_dir . '/active.domains', implode("\n", array_keys($domains)) . "\n")) {
		return $fail(gettext('Unable to activate the compiled feed database.'));
	}
	webgateway_write_file($feed_dir . '/status.json', json_encode(['updated' => time(), 'entries' => count($domains), 'sources' => count($urls)], JSON_PRETTY_PRINT));
	$message = sprintf(gettext('Activated %d unique domains from %d feeds.'), count($domains), count($urls));
	webgateway_remove_tree($stage);
	return webgateway_sync_config();
}

function webgateway_generate_rules($type) {
	$config = webgateway_config();
	if ($config['enable'] !== 'on' || ($config['failure_policy'] === 'open' && !webgateway_is_running())) {
		return '';
	}
	$rules = '';
	if ($type === 'nat') {
		foreach ($config['interfaces'] as $interface) {
			if (!webgateway_is_client_interface($interface)) {
				continue;
			}
			$real = get_real_interface($interface);
			foreach (webgateway_interface_networks([$interface]) as $network) {
				$family = is_ipaddrv6(explode('/', $network)[0]) ? 'inet6' : 'inet';
				$loopback = ($family === 'inet6') ? '::1' : '127.0.0.1';
				$private = ($family === 'inet6') ? ['::1/128', 'fc00::/7', 'fe80::/10'] : ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'];
				foreach (array_merge($private, webgateway_interface_networks(array_keys(webgateway_client_interfaces())), webgateway_lines($config['exempt_destinations'])) as $destination) {
					if (($family === 'inet6') !== is_ipaddrv6(explode('/', $destination)[0])) {
						continue;
					}
					$rules .= "no rdr on {$real} {$family} proto tcp from {$network} to {$destination} port { 80, 443 }\n";
				}
				foreach (webgateway_lines($config['exempt_sources']) as $source) {
					if (($family === 'inet6') === is_ipaddrv6(explode('/', $source)[0])) {
						$rules .= "no rdr on {$real} {$family} proto tcp from {$source} to any port { 80, 443 }\n";
					}
				}
				if (in_array('intercept_http', $config['listener_modes'], true)) {
					$rules .= "rdr on {$real} {$family} proto tcp from {$network} to any port 80 -> {$loopback} port " . (int)$config['http_intercept_port'] . "\n";
				}
				if (in_array('intercept_https', $config['listener_modes'], true)) {
					$rules .= "rdr on {$real} {$family} proto tcp from {$network} to any port 443 -> {$loopback} port " . (int)$config['https_intercept_port'] . "\n";
				}
			}
		}
	} elseif ($type === 'filter' && $config['quic_policy'] === 'block' && in_array('intercept_https', $config['listener_modes'], true)) {
		foreach ($config['interfaces'] as $interface) {
			$real = get_real_interface($interface);
			$rules .= "block quick on {$real} proto udp from any to any port 443 label \"FreeSense Web Gateway QUIC fallback\"\n";
		}
	}
	return $rules;
}

function webgateway_plugin_certificates($pluginparams) {
	$result = ['pkgname' => 'FreeSense Web Gateway', 'certificatelist' => []];
	$config = webgateway_config();
	/*
	 * Certificate Manager currently uses used_ca for display but its delete
	 * guard calls cert_in_use(), which asks packages for used_certificates.
	 * Report the selected CA for both events so it cannot be removed while
	 * Squid still depends on its public certificate and private key.
	 */
	if (in_array(($pluginparams['event'] ?? ''), ['used_ca', 'used_certificates'], true) && !empty($config['caref'])) {
		$result['certificatelist'][$config['caref']][] = ['usedby' => 'TLS inspection'];
	}
	return $result;
}

function webgateway_deinstall() {
	$config = webgateway_config();
	$config['enable'] = '';
	config_set_path(WEBGATEWAY_CONFIG_PATH, $config);
	webgateway_watchdog_action('onestop');
	webgateway_service_action('onestop');
	webgateway_set_av_services(false);
	install_cron_job(WEBGATEWAY_FEED_COMMAND, false, '*', '*', '*', '*', '*', 'root', true);
	filter_configure();
	@unlink('/usr/local/www/wpad.dat');
	foreach (['inspection-ca.key', 'local-users', 'radius.conf', 'ldap-bind-password'] as $secret) {
		@unlink(WEBGATEWAY_FRAGMENT_DIR . '/' . $secret);
		@unlink(WEBGATEWAY_STATE_DIR . '/previous/' . $secret);
	}
	/* The generated config may contain parent-proxy credentials. */
	@unlink(WEBGATEWAY_CONF_FILE);
	@unlink(WEBGATEWAY_STATE_DIR . '/previous/freesense.conf');
}

function webgateway_pac_script($config, $host) {
	if (str_starts_with($host, '[')) {
		$host = preg_replace('/^\[([^]]+)\](?::\d+)?$/', '$1', $host);
	} else {
		$host = preg_replace('/:\d+$/', '', $host);
	}
	if (!is_ipaddr($host) && !is_hostname($host)) {
		$host = get_interface_ip($config['interfaces'][0] ?? 'lan');
	}
	$proxy_host = is_ipaddrv6($host) ? '[' . $host . ']' : $host;
	$proxy = addslashes($proxy_host . ':' . (int)$config['port']);
	return <<<PAC
// Generated by FreeSense Web Gateway 2.0.
function FindProxyForURL(url, host) {
	if (isPlainHostName(host) || shExpMatch(host, "localhost") ||
	    isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
	    isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
	    isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
	    isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
		return "DIRECT";
	}
	return "PROXY {$proxy}";
}
PAC;
}

function webgateway_set_av_services($enable) {
	if (!$enable) {
		mwexec('/usr/sbin/service c-icap onestop');
		mwexec('/usr/sbin/service clamav_clamd onestop');
		mwexec('/usr/sbin/service clamav_freshclam onestop');
		return true;
	}
	if (!is_executable('/usr/local/bin/c-icap') || !is_executable('/usr/local/sbin/clamd')) {
		log_error('Web Gateway AV companion is incomplete: c-icap or clamd is missing.');
		return false;
	}
	mwexec('/usr/sbin/service clamav_freshclam onestart');
	mwexec('/usr/sbin/service clamav_clamd onestart');
	mwexec('/usr/sbin/service c-icap onestart');
	return true;
}

function webgateway_sync_av() {
	$config = webgateway_config();
	webgateway_set_av_services($config['local_av_enable'] === 'on');
	return webgateway_sync_config();
}

function webgateway_av_deinstall() {
	$config = webgateway_config();
	$config['local_av_enable'] = '';
	config_set_path(WEBGATEWAY_CONFIG_PATH, $config);
	write_config(gettext('Disabled Web Gateway local antivirus before package removal'));
	webgateway_set_av_services(false);
	return webgateway_sync_config();
}

function webgateway_plugin_xmlrpc_send() {
	return webgateway_config()['ha_sync'] === 'on' ? [WEBGATEWAY_CONFIG_PATH] : [];
}

function webgateway_plugin_xmlrpc_recv($new_sections) {
	$new = array_get_path($new_sections, WEBGATEWAY_CONFIG_PATH, []);
	if (!is_array($new) || ($new['ha_sync'] ?? '') !== 'on') {
		return [];
	}
	return [WEBGATEWAY_CONFIG_PATH => $new, 'xmlrpc_recv_result' => true];
}

function webgateway_plugin_xmlrpc_recv_done($result) {
	if (array_get_path($result, 'webgateway/xmlrpc_recv_result') === true || ($result['xmlrpc_recv_result'] ?? false) === true) {
		webgateway_sync_config();
	}
}

function webgateway_display_tabs($active) {
	$tabs = [
		['Overview', $active === 'overview', '/webgateway/webgateway.php'],
		['Listeners', $active === 'listeners', '/webgateway/webgateway_listeners.php'],
		['TLS Inspection', $active === 'tls', '/webgateway/webgateway_tls.php'],
		['Policies', $active === 'policies', '/webgateway/webgateway_policies.php'],
		['Identity', $active === 'identity', '/webgateway/webgateway_identity.php'],
		['Threat Protection', $active === 'threat', '/webgateway/webgateway_threat.php'],
		['Feeds', $active === 'feeds', '/webgateway/webgateway_feeds.php'],
		['Cache & Upstreams', $active === 'cache', '/webgateway/webgateway_cache.php'],
		['Status', $active === 'status', '/webgateway/webgateway_status.php'],
		['Diagnostics', $active === 'diagnostics', '/webgateway/webgateway_diagnostics.php'],
	];
	display_top_tabs($tabs);
}

function webgateway_save_candidate($candidate, $description, &$errors) {
	webgateway_validate_config($candidate, $errors);
	if (!empty($errors)) {
		return false;
	}
	$previous = webgateway_config();
	config_set_path(WEBGATEWAY_CONFIG_PATH, $candidate);
	write_config($description);
	if (!webgateway_sync_config()) {
		config_set_path(WEBGATEWAY_CONFIG_PATH, $previous);
		write_config(gettext('Rolled back rejected Web Gateway settings'));
		webgateway_sync_config();
		$errors[] = gettext('Activation failed. FreeSense restored both the previous runtime files and the previous saved settings. Check Diagnostics.');
		return false;
	}
	return true;
}
