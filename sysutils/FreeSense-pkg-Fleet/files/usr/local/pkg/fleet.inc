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
require_once('fleet/fleet_backup.inc');

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

/* pure: the pass rules for the enrollment port and the tunnel port (normal filter rules). */
function fleet_ctl_filter_rules(array $s): string {
	if (!$s['enable']) {
		return '';
	}
	return "pass in quick proto tcp from any to (self) port {$s['enroll_port']} keep state label \"USER_RULE: FreeSense Fleet enrollment\"\n" .
	    "pass in quick proto udp from any to (self) port {$s['wg_port']} keep state label \"USER_RULE: FreeSense Fleet tunnel\"\n";
}

/*
 * pure: the overlay rules, both directions. Early rules: they come before
 * "Block all IPv6", so the IPv6 overlay works when "Allow IPv6" is off.
 */
function fleet_ctl_early_rules(array $s): string {
	if (!$s['enable']) {
		return '';
	}
	return "pass in quick on " . FLEET_CTL_IF . " all keep state label \"USER_RULE: FreeSense Fleet overlay\"\n" .
	    "pass out quick on " . FLEET_CTL_IF . " all keep state label \"USER_RULE: FreeSense Fleet overlay out\"\n";
}

/* pure: a box's state from its consecutive missed polls. */
function fleet_box_state(int $misses): string {
	if ($misses >= FLEET_MISSES_OFFLINE) {
		return 'offline';
	}
	return ($misses >= FLEET_MISSES_DEGRADED) ? 'degraded' : 'online';
}

/*
 * pure: the dashboard's view of the fleet from the box rows and the number
 * of boxes waiting for approval. Boxes are ordered worst state first, then
 * by label; nothing secret (API keys, certificates) leaves this function.
 */
function fleet_dashboard_data(array $rows, int $pending, int $now): array {
	$rank = array('offline' => 0, 'degraded' => 1, 'new' => 2, 'online' => 3);
	$boxes = array();
	$counts = array('online' => 0, 'degraded' => 0, 'offline' => 0, 'new' => 0, 'unprotected' => 0);
	$last_check = 0;
	foreach ($rows as $r) {
		$st = json_decode((string)($r['status'] ?? ''), true) ?: array();
		$state = isset($rank[$r['state']]) ? $r['state'] : 'new';
		$protected = isset($st['rollback_protection']) ? (bool)$st['rollback_protection'] : null;
		$counts[$state]++;
		if ($protected === false) {
			$counts['unprotected']++;
		}
		$last_check = max($last_check, (int)$r['last_seen']);
		$boxes[] = array(
			'id' => (string)$r['node_id'],
			'label' => (string)$r['label'],
			'host' => (string)($st['hostname'] ?? $r['name']),
			'state' => $state,
			'version' => (string)($st['version'] ?? ''),
			'overlay' => (string)$r['overlay'],
			'role' => (string)$r['role'],
			'rollback' => $protected,
			'carp' => (string)($st['carp'] ?? 'none'),
			'policy' => isset($st['policy_bundle']['version']) ? (int)$st['policy_bundle']['version'] : null,
			'breakglass' => !empty($st['breakglass']),
			'seen' => $r['last_seen'] ? (int)$r['last_seen'] : null,
			'backup' => !empty($r['last_backup']) ? (int)$r['last_backup'] : null,
			'problem' => ($state === 'online') ? '' : (string)$r['error'],
		);
	}
	usort($boxes, function ($a, $b) use ($rank) {
		return array($rank[$a['state']], strtolower($a['label'])) <=> array($rank[$b['state']], strtolower($b['label']));
	});
	$total = count($boxes);
	$attention = $counts['offline'] + $counts['degraded'];
	if ($total === 0) {
		$headline = 'No firewalls yet';
	} elseif ($attention === 0) {
		$headline = ($total === 1) ? 'The firewall is online' : "All {$total} firewalls are online";
	} else {
		$headline = "{$attention} of {$total} " . (($total === 1) ? 'firewall needs' : 'firewalls need') . ' attention';
	}
	return array('headline' => $headline, 'total' => $total, 'counts' => $counts + array('pending' => $pending),
	    'boxes' => $boxes, 'checked' => $last_check ?: null, 'now' => $now);
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

/*
 * Bring the controller's tunnel up with every box as a peer. An existing
 * interface is kept and only reconfigured: destroying it would drop every
 * box's session until its next handshake (up to about 3 minutes).
 */
function fleet_ctl_tunnel_up(array $s): ?string {
	fleet_ctl_wg_public();
	$addr = fleet_overlay_host((string)fleet_setting('overlay_prefix'), 1);
	list($exists) = fleet_ctl_exec(array('/sbin/ifconfig', FLEET_CTL_IF));
	foreach (array_merge(($exists === 0) ? array() : array(array('/sbin/ifconfig', 'wg', 'create', 'name', FLEET_CTL_IF)), array(
		array('/usr/bin/wg', 'set', FLEET_CTL_IF, 'private-key', FLEET_DATA . '/wg.key', 'listen-port', (string)$s['wg_port']),
		array('/sbin/ifconfig', FLEET_CTL_IF, 'inet6', $addr, 'prefixlen', '128'),
		array('/sbin/ifconfig', FLEET_CTL_IF, 'mtu', '1380', 'up'),
	)) as $argv) {
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
	install_cron_job('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup nightly', true, '17', '3', '*', '*', '*', 'root');
	filter_configure();
	return $problems;
}

function fleet_generate_rules(string $type): string {
	switch ($type) {
	case 'filter':
		return fleet_ctl_filter_rules(fleet_ctl_settings());
	case 'pfearly':
		return fleet_ctl_early_rules(fleet_ctl_settings());
	}
	return '';
}

function fleet_remove_config(): void {
	fleet_ctl_enroll_stop();
	fleet_ctl_exec(array('/sbin/ifconfig', FLEET_CTL_IF, 'destroy'));
	install_cron_job('/usr/local/bin/php /usr/local/sbin/freesense-fleet-poll', false);
	install_cron_job('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup nightly', false);
	/* The data directory stays: removing the package must never delete a fleet. */
}

/* ------------------------------------------------------------------ */
/* Status poll                                                         */
/* ------------------------------------------------------------------ */

/*
 * pure: what the dashboard says when a box does not answer. The join client's
 * errors speak from the box's side ("the controller is unreachable"); here
 * the controller is the one asking.
 */
function fleet_poll_problem(string $code, string $message): string {
	$reason = preg_match('/\(([^)]+)\)/', $message, $m) ? " ({$m[1]})" : '';
	switch ($code) {
	case 'E105':
		return "FLEET-E105: The box did not answer over the tunnel{$reason}. Check that it is powered on and online.";
	case 'E101':
		return 'FLEET-E101: The box answered with a different certificate. Check it before trusting it again.';
	}
	return "FLEET-{$code}: {$message}";
}

/*
 * pure: an audit line about one box as (what happened, details) for its
 * event list: the box's own ID and label are left out.
 */
function fleet_event_text(string $node_id, string $action, string $detail): array {
	$rest = trim((string)preg_replace('/^' . preg_quote($node_id, '/') . '(\s*\([^)]*\))?:?\s*/', '', $detail));
	switch ($action) {
	case 'joined':
		return array('Joined the fleet', preg_replace('/^at\s+/', 'tunnel address ', $rest));
	case 'state':
		if (preg_match('/^(\w+) -> (\w+)(?: \((.*)\))?$/s', $rest, $m)) {
			return array(ucfirst($m[1]) . ' to ' . $m[2], (string)($m[3] ?? ''));
		}
		break;
	case 'handoff':
		return array('Opened the WebUI', preg_replace('/^WebUI\s+/', '', $rest));
	case 'backup':
		return array('Backed up', preg_replace(array('/, [0-9a-f]{12}$/', '/^Backed up /'), '', $rest));
	case 'backup_failed':
		return array('Backup failed', $rest);
	case 'restore':
		return array('Restored a backup', preg_replace('/^backup of /', 'from ', $rest));
	case 'restore_failed':
		return array('Restore failed', $rest);
	case 'backup_download':
		return array('Downloaded a backup', preg_replace('/^backup of /', 'from ', $rest));
	}
	return array(ucfirst($action), $rest);
}

/* pure: how the controller reaches a box's API: its overlay address, pinned to its certificate. */
function fleet_box_target(array $box): array {
	return array('host' => $box['overlay'], 'port' => FLEET_NODE_API_PORT_DEFAULT,
	    'authority' => fleet_hostport($box['overlay'], FLEET_NODE_API_PORT_DEFAULT), 'cert_sha256' => $box['cert_sha256']);
}

/* One box row, or null. */
function fleet_box_get(string $node_id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM boxes WHERE node_id = ?');
	$q->execute(array($node_id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

/*
 * pure: the URL that signs the browser in on a box. Only a WebGUI address
 * the box itself reported, and only a handoff path, so the controller can
 * never be used to send a browser somewhere else.
 */
function fleet_handoff_url(array $status, string $base, string $path): ?string {
	if (!in_array($base, array_column((array)($status['webgui'] ?? array()), 'url'), true)) {
		return null;
	}
	if (!preg_match('#^/\?fleet_handoff=[A-Za-z0-9_-]{43}$#D', $path)) {
		return null;
	}
	return $base . $path;
}

/*
 * Ask a box for a one-time sign-in to its WebGUI as $user. Returns the path
 * to open on the box, or throws RuntimeException with a message for the admin.
 */
function fleet_box_handoff(array $box, string $user, string $operator): string {
	$key = (string)fleet_unseal((string)$box['api_key'], fleet_master_key());
	try {
		list($code, $json) = fleet_http_pinned(fleet_box_target($box), 'POST', '/api/v1/auth/handoff',
		    array('user' => $user, 'operator' => $operator, 'seconds' => 60), $key);
	} catch (FleetJoinError $e) {
		throw new RuntimeException(fleet_poll_problem($e->fleet_code, $e->getMessage()));
	}
	if (($code === 201) && is_string($json['data']['path'] ?? null)) {
		return $json['data']['path'];
	}
	throw new RuntimeException((string)($json['error']['message'] ?? "The box answered HTTP {$code}."));
}

/* Poll one box; returns its new state. */
function fleet_poll_box(array $box, int $now): string {
	$key = fleet_unseal((string)$box['api_key'], fleet_master_key());
	$target = fleet_box_target($box);
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
		$error = fleet_poll_problem($e->fleet_code, $e->getMessage());
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
