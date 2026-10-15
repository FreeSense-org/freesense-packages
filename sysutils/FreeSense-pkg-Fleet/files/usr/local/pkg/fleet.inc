<?php
/*
 * fleet.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2026 The FreeSense Project
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * FreeSense Fleet controller: package hooks and the system side.
 *
 * Settings (config.xml installedpackages/fleet, kept small): enable,
 * public_host (what boxes use to reach this controller), enroll_port (TCP,
 * default 8443) and wg_port (UDP, default 51830). Everything else is in the
 * data directory (fleet/fleet_store.inc).
 *
 * The controller runs
 *   - the WireGuard interface wgfctl0 at host 1 of the overlay, one peer per box,
 *   - its own nginx for the enrollment endpoint, serving only /fleet/join/,
 *     with a pid file outside the nginx*.pid pattern that rc.restart_webgui kills,
 *   - pass rules for those two ports, and
 *   - a status poll every minute (freesense-fleet-poll): each box's
 *     /api/v1/management/status through the tunnel, its certificate pinned.
 */

require_once('fleet/fleet_store.inc');
require_once('fleet/fleet_enroll.inc');

define('FLEET_CTL_IF', 'wgfctl0');
define('FLEET_ENROLL_CONF', '/var/etc/fleet-enroll.conf');
define('FLEET_ENROLL_PID', '/var/run/fleet-enroll.pid');
define('FLEET_ENROLL_DOCROOT', '/usr/local/pkg/fleet/enroll');
define('FLEET_NODE_API_PORT_DEFAULT', 8444);
define('FLEET_MISSES_DEGRADED', 3);
define('FLEET_MISSES_OFFLINE', 10);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: the package settings with defaults. */
function fleet_ctl_settings_from(array $s): array {
	$port = function ($v, $d) {
		return (ctype_digit((string)$v) && ((int)$v >= 1) && ((int)$v <= 65535)) ? (int)$v : $d;
	};
	return array(
		'enable' => isset($s['enable']) && ($s['enable'] !== false) && ($s['enable'] !== ''),
		'public_host' => trim((string)($s['public_host'] ?? '')),
		'enroll_port' => $port($s['enroll_port'] ?? '', 8443),
		'wg_port' => $port($s['wg_port'] ?? '', 51830),
	);
}

/* pure: "host:port" with IPv6 bracketed. */
function fleet_hostport(string $host, int $port): string {
	return ((strpos($host, ':') !== false) ? "[{$host}]" : $host) . ":{$port}";
}

/* pure: the enrollment nginx configuration. */
function fleet_enroll_nginx_conf(int $port, string $tls, string $socket = '/var/run/php-fpm.socket'): string {
	return "# FreeSense Fleet enrollment endpoint (fleet.inc); serves only /fleet/join/\n" .
	    "pid " . FLEET_ENROLL_PID . ";\nuser root wheel;\nworker_processes 1;\n" .
	    "error_log syslog:server=unix:/var/run/log,facility=local5;\n\n" .
	    "events {\n\tworker_connections 256;\n}\n\n" .
	    "http {\n\tdefault_type application/json;\n\tserver_tokens off;\n\taccess_log off;\n" .
	    "\tclient_max_body_size 64k;\n\tclient_header_timeout 10;\n\tclient_body_timeout 10;\n\tkeepalive_timeout 5;\n" .
	    "\tlimit_req_status 429;\n\tlimit_req_zone \$binary_remote_addr zone=fleetjoin:2m rate=2r/s;\n\n" .
	    "\tserver {\n\t\tlisten {$port} ssl;\n\t\tlisten [::]:{$port} ssl;\n" .
	    "\t\tssl_certificate {$tls};\n\t\tssl_certificate_key {$tls};\n\t\tssl_protocols TLSv1.2 TLSv1.3;\n" .
	    "\t\tssl_session_tickets off;\n\t\tadd_header X-Content-Type-Options nosniff always;\n" .
	    "\t\tlocation ^~ /fleet/join/ {\n\t\t\tlimit_req zone=fleetjoin burst=10 nodelay;\n" .
	    "\t\t\tfastcgi_pass unix:{$socket};\n\t\t\tfastcgi_param SCRIPT_FILENAME " . FLEET_ENROLL_DOCROOT . "/index.php;\n" .
	    "\t\t\tfastcgi_param HTTP_PROXY \"\";\n\t\t\tinclude /usr/local/etc/nginx/fastcgi_params;\n\t\t}\n" .
	    "\t\tlocation / {\n\t\t\treturn 404 '{\"error\":{\"code\":\"not_found\"}}';\n\t\t}\n\t}\n}\n";
}

/* pure: the pass rules for the enrollment port and the tunnel. */
function fleet_ctl_filter_rules(array $s): string {
	if (!$s['enable']) {
		return '';
	}
	return "pass in quick proto tcp from any to (self) port {$s['enroll_port']} keep state label \"USER_RULE: FreeSense Fleet enrollment\"\n" .
	    "pass in quick proto udp from any to (self) port {$s['wg_port']} keep state label \"USER_RULE: FreeSense Fleet tunnel\"\n" .
	    "pass in quick on " . FLEET_CTL_IF . " all keep state label \"USER_RULE: FreeSense Fleet overlay\"\n";
}

/* pure: a box's state from its consecutive missed polls. */
function fleet_box_state(int $misses): string {
	if ($misses >= FLEET_MISSES_OFFLINE) {
		return 'offline';
	}
	return ($misses >= FLEET_MISSES_DEGRADED) ? 'degraded' : 'online';
}

/* ------------------------------------------------------------------ */
/* Settings and tunnel                                                 */
/* ------------------------------------------------------------------ */

function fleet_ctl_settings(): array {
	return fleet_ctl_settings_from((array)config_get_path('installedpackages/fleet/config/0', []));
}

function fleet_ctl_exec(array $argv): array {
	$p = proc_open($argv, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
	if (!is_resource($p)) {
		return array(127, '');
	}
	$out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	return array(proc_close($p), trim($out));
}

/* The controller's WireGuard public key (32 raw bytes); creates the key pair once. */
function fleet_ctl_wg_public(): string {
	$priv = trim(fleet_secret_file('wg.key', function () {
		return trim((string)shell_exec('/usr/bin/wg genkey')) . "\n";
	}));
	$p = proc_open(array('/usr/bin/wg', 'pubkey'), array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);
	fwrite($pipes[0], $priv . "\n");
	fclose($pipes[0]);
	$pub = trim((string)stream_get_contents($pipes[1]));
	fclose($pipes[1]);
	proc_close($p);
	return (string)base64_decode($pub);
}

/* Add or refresh one box's peer on the controller's tunnel. */
function fleet_ctl_peer_add(array $box): void {
	fleet_ctl_exec(array('/usr/bin/wg', 'set', FLEET_CTL_IF, 'peer', $box['wg_pub'], 'allowed-ips', $box['overlay'] . '/128'));
	fleet_ctl_exec(array('/sbin/route', '-n', 'add', '-inet6', $box['overlay'] . '/128', '-interface', FLEET_CTL_IF));
}

/* Bring the controller's tunnel up with every box as a peer. */
function fleet_ctl_tunnel_up(array $s): ?string {
	fleet_ctl_exec(array('/sbin/ifconfig', FLEET_CTL_IF, 'destroy'));
	fleet_ctl_wg_public();
	$addr = fleet_overlay_host((string)fleet_setting('overlay_prefix'), 1);
	foreach (array(
		array('/sbin/ifconfig', 'wg', 'create', 'name', FLEET_CTL_IF),
		array('/usr/bin/wg', 'set', FLEET_CTL_IF, 'private-key', FLEET_DATA . '/wg.key', 'listen-port', (string)$s['wg_port']),
		array('/sbin/ifconfig', FLEET_CTL_IF, 'inet6', $addr, 'prefixlen', '128'),
		array('/sbin/ifconfig', FLEET_CTL_IF, 'mtu', '1380', 'up'),
	) as $argv) {
		list($rc, $out) = fleet_ctl_exec($argv);
		if ($rc !== 0) {
			return basename($argv[0]) . ': ' . $out;
		}
	}
	foreach (fleet_db()->query('SELECT * FROM boxes') as $box) {
		fleet_ctl_peer_add($box);
	}
	return null;
}

function fleet_ctl_enroll_stop(): void {
	if (is_file(FLEET_ENROLL_PID)) {
		killbypid(FLEET_ENROLL_PID, 5);
		@unlink(FLEET_ENROLL_PID);
	}
}

function fleet_ctl_enroll_start(array $s): ?string {
	fleet_ctl_enroll_stop();
	$tls = FLEET_DATA . '/tls.pem';
	file_put_contents(FLEET_ENROLL_CONF, fleet_enroll_nginx_conf($s['enroll_port'], $tls));
	list($rc, $out) = fleet_ctl_exec(array('/usr/local/sbin/nginx', '-c', FLEET_ENROLL_CONF));
	return ($rc === 0) ? null : 'nginx: ' . $out;
}

/* ------------------------------------------------------------------ */
/* Package hooks                                                       */
/* ------------------------------------------------------------------ */

/* Apply the settings: data, keys, tunnel, enrollment endpoint, rules. Returns the problems found. */
function fleet_sync_config(): array {
	$s = fleet_ctl_settings();
	$problems = array();
	if (!$s['enable']) {
		fleet_ctl_enroll_stop();
		fleet_ctl_exec(array('/sbin/ifconfig', FLEET_CTL_IF, 'destroy'));
		return $problems;
	}
	$err = fleet_data_prepare();
	if ($err !== null) {
		return array($err);
	}
	fleet_controller_init();
	/* What the enrollment endpoint needs without reading config.xml. */
	fleet_setting_set('wg_public', base64_encode(fleet_ctl_wg_public()));
	fleet_setting_set('wg_endpoint', fleet_hostport($s['public_host'], $s['wg_port']));
	foreach (array(fleet_ctl_tunnel_up($s), fleet_ctl_enroll_start($s)) as $err) {
		if ($err !== null) {
			$problems[] = $err;
			logger(LOG_ERR, localize_text('FreeSense Fleet: %s', $err));
		}
	}
	install_cron_job('/usr/local/bin/php /usr/local/sbin/freesense-fleet-poll', true, '*', '*', '*', '*', '*', 'root');
	filter_configure();
	return $problems;
}

function fleet_generate_rules(string $type): string {
	return ($type === 'filter') ? fleet_ctl_filter_rules(fleet_ctl_settings()) : '';
}

function fleet_remove_config(): void {
	fleet_ctl_enroll_stop();
	fleet_ctl_exec(array('/sbin/ifconfig', FLEET_CTL_IF, 'destroy'));
	install_cron_job('/usr/local/bin/php /usr/local/sbin/freesense-fleet-poll', false);
	/* The data directory stays: removing the package must never delete a fleet. */
}

/* ------------------------------------------------------------------ */
/* Status poll                                                         */
/* ------------------------------------------------------------------ */

/* Poll one box; returns its new state. */
function fleet_poll_box(array $box, int $now): string {
	$key = fleet_unseal((string)$box['api_key'], fleet_master_key());
	$target = array('host' => $box['overlay'], 'port' => FLEET_NODE_API_PORT_DEFAULT, 'authority' => fleet_hostport($box['overlay'], FLEET_NODE_API_PORT_DEFAULT),
	    'cert_sha256' => $box['cert_sha256']);
	$status = null;
	$error = '';
	try {
		list($code, $json) = fleet_http_pinned($target, 'GET', '/api/v1/management/status', null, (string)$key);
		if (($code === 200) && is_array($json['data'] ?? null)) {
			$status = $json['data'];
		} else {
			$error = "HTTP {$code} " . (string)($json['error']['code'] ?? '');
		}
	} catch (FleetJoinError $e) {
		$error = "FLEET-{$e->fleet_code}: " . $e->getMessage();
	}
	$misses = ($status === null) ? ((int)$box['misses'] + 1) : 0;
	$state = ($status === null) ? fleet_box_state($misses) : 'online';
	fleet_db()->prepare('UPDATE boxes SET misses = ?, state = ?, last_seen = COALESCE(?, last_seen), status = COALESCE(?, status), error = ? WHERE node_id = ?')
	    ->execute(array($misses, $state, ($status === null) ? null : $now, ($status === null) ? null : json_encode($status), $error, $box['node_id']));
	if ($state !== $box['state']) {
		fleet_audit('poll', 'state', "{$box['node_id']} ({$box['label']}): {$box['state']} -> {$state}" . (($error !== '') ? " ({$error})" : ''));
	}
	return $state;
}
