<?php
/*
 * fleet_conn.inc
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
 * Connection manager: how the controller reaches each firewall.
 *
 *   wireguard  the Fleet management tunnel every firewall joins with
 *   direct     the firewall's address on an internal interface (LAN,
 *              MPLS, an existing VPN)
 *   tailscale  the firewall's tailnet address
 *
 * The method is chosen for the fleet, a group or one firewall (the most
 * specific wins; two groups that disagree are a conflict, shown, never
 * resolved silently). A direct or Tailscale path is set up over the
 * tunnel (System fleet_paths.inc) and used only once the controller has
 * reached the firewall over it; the tunnel stays, so when a path stops
 * answering the controller falls back to the tunnel at once, raises an
 * alert and tries the path again later. Functions marked "pure" touch
 * neither the system nor the database.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_CONN_METHODS', array(
	'wireguard' => array('Fleet tunnel (WireGuard)', 'fa-shield-halved'),
	'direct' => array('Direct (LAN, MPLS or VPN)', 'fa-network-wired'),
	'tailscale' => array('Tailscale', 'fa-circle-nodes'),
));
/* Retry a path that stopped answering after this many seconds. */
define('FLEET_CONN_RETRY', 600);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/*
 * pure: what a firewall should use: array(method, iface, from, conflict).
 * $box_cfg, $group_cfgs (name => cfg) and $fleet_cfg are {method, iface}
 * with method '' meaning "as above". from: 'firewall', 'group:<name>' or
 * 'fleet'; conflict: null or the names of the groups that disagree.
 */
function fleet_conn_effective(array $box_cfg, array $group_cfgs, array $fleet_cfg): array {
	if (($box_cfg['method'] ?? '') !== '') {
		return array($box_cfg['method'], (string)($box_cfg['iface'] ?? ''), 'firewall', null);
	}
	$set = array_filter($group_cfgs, function ($c) { return ($c['method'] ?? '') !== ''; });
	if (!empty($set)) {
		ksort($set, SORT_NATURAL | SORT_FLAG_CASE);
		$distinct = array_unique(array_map(function ($c) { return $c['method'] . '|' . ($c['iface'] ?? ''); }, $set));
		$first = array_key_first($set);
		return array($set[$first]['method'], (string)($set[$first]['iface'] ?? ''), 'group:' . $first, (count($distinct) > 1) ? array_keys($set) : null);
	}
	return array(($fleet_cfg['method'] ?? '') ?: 'wireguard', (string)($fleet_cfg['iface'] ?? ''), 'fleet', null);
}

/* pure: an interface key a direct path may name (lan, opt3, a VIP key like _vip5f...). */
function fleet_conn_iface_ok(string $iface): bool {
	return (bool)preg_match('/^[a-z_][a-z0-9_]{0,31}$/Di', $iface) && ($iface !== 'fleet') && ($iface !== 'lo0');
}

/*
 * pure: the advisor. $a: public (the controller has a public address or a
 * port forward), private (the firewalls share a private network, MPLS or
 * VPN with the controller), thirdparty (a third-party coordination
 * service is fine), udp (the sites allow outbound UDP); each 'yes', 'no'
 * or 'unsure'. Returns array(method, reasons[], cautions[]).
 */
function fleet_conn_advise(array $a): array {
	$yes = function ($k) use ($a) { return ($a[$k] ?? '') === 'yes'; };
	$no = function ($k) use ($a) { return ($a[$k] ?? '') === 'no'; };
	if ($yes('private')) {
		return array('direct', array('The firewalls and the controller already share a private network, so the controller can reach them without another tunnel.'),
		    array('Each firewall needs a fixed address on that network, without NAT between it and the controller.', 'Keep the Fleet tunnel as the fallback: it takes over when the private network is down.'));
	}
	if ($yes('public') && !$no('udp')) {
		return array('wireguard', array('Your controller can be reached from the internet and the sites can send UDP, which is all the Fleet tunnel needs.', 'No third party is involved.'),
		    array('Open UDP 51830 and TCP 8443 to the controller.'));
	}
	if (!$no('thirdparty')) {
		return array('tailscale', array($no('public') ? 'Your controller cannot be reached from the internet; Tailscale connects through its coordination service instead.' :
		    'Some sites block UDP; Tailscale falls back to relays over HTTPS (TCP 443).'),
		    array('Tailscale must run on the controller and every firewall, in the same tailnet.', 'Turn key expiry off for the firewalls, or they drop off when it expires.',
		    'The tailnet ACL must let the controller reach the firewalls on TCP 8444.'));
	}
	return array('wireguard', array('Without a third-party service and without a shared private network, the Fleet tunnel is the way.'),
	    array('The controller needs a public address or a port forward for UDP 51830 and TCP 8443.', 'Sites that block all outbound UDP cannot use it: give those a private network or allow Tailscale.'));
}

/* pure: the "works only if" list of a method. */
function fleet_conn_requirements(string $method): array {
	return array(
		'wireguard' => array('The controller is reachable on UDP 51830 (tunnel) and TCP 8443 (joining): a public address or a port forward.',
		    'The sites may send outbound UDP.'),
		'direct' => array('The controller routes to each firewall\'s fixed address on the chosen interface, without NAT in between.',
		    'For a VPN: the tunnel is up. When the route is down the firewall falls back to the Fleet tunnel.', 'Not on WAN: the API would face the internet (FLEET-E135).'),
		'tailscale' => array('Tailscale runs on the controller and on every firewall, in the same tailnet.', 'The tailnet ACL lets the controller reach the firewalls on TCP 8444.',
		    'Key expiry is off for the firewalls (FLEET-E136 otherwise).'),
	)[$method] ?? array();
}

/*
 * pure: the state after a call over a path: array(state, alert or null).
 * $state: {method, address, ok, since, checked, error}.
 */
function fleet_conn_after(array $state, bool $ok, string $error, int $now): array {
	$was = !empty($state['ok']);
	$state['checked'] = $now;
	$state['ok'] = $ok;
	$state['error'] = $ok ? '' : $error;
	if ($ok !== $was) {
		$state['since'] = $now;
	}
	$alert = null;
	if ($was && !$ok) {
		$alert = 'down';
	} elseif (!$was && $ok && isset($state['since'])) {
		$alert = 'up';
	}
	return array($state, $alert);
}

/* pure: should a call use the path now? (It answered last time, or it is time to try again.) */
function fleet_conn_use_path(?array $state, int $now): bool {
	if (($state === null) || (($state['method'] ?? 'wireguard') === 'wireguard') || (($state['address'] ?? '') === '')) {
		return false;
	}
	return !empty($state['ok']) || ($now - (int)($state['checked'] ?? 0) >= FLEET_CONN_RETRY);
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

function fleet_conn_fleet_cfg(): array {
	return array('method' => (string)fleet_setting('conn_method', 'wireguard'), 'iface' => (string)fleet_setting('conn_iface', 'lan'));
}

/* Check and normalise a {method, iface} from a form ('' = as above, except for the fleet). */
function fleet_conn_cfg_from(array $in, bool $fleet_level): array {
	$method = (string)($in['conn_method'] ?? '');
	if (($method === '') && !$fleet_level) {
		return array('method' => '', 'iface' => '');
	}
	if (!isset(FLEET_CONN_METHODS[$method])) {
		throw new InvalidArgumentException('Choose how Fleet reaches these firewalls.');
	}
	$iface = strtolower(trim((string)($in['conn_iface'] ?? '')));
	if ($method === 'direct') {
		if (!fleet_conn_iface_ok($iface)) {
			throw new InvalidArgumentException('Give the interface the controller reaches the firewalls on, like lan or opt2 (not wan).');
		}
		if ($iface === 'wan') {
			throw new InvalidArgumentException('FLEET-E135: not on WAN. A direct path there puts the API on the internet.');
		}
	} else {
		$iface = ($method === 'tailscale') ? 'tailscale' : '';
	}
	return array('method' => $method, 'iface' => $iface);
}

function fleet_conn_set_fleet(array $in, string $who): void {
	$c = fleet_conn_cfg_from($in, true);
	fleet_setting_set('conn_method', $c['method']);
	fleet_setting_set('conn_iface', ($c['method'] === 'direct') ? $c['iface'] : (string)fleet_setting('conn_iface', 'lan'));
	fleet_audit($who, 'connections', 'Fleet default: ' . FLEET_CONN_METHODS[$c['method']][0] . (($c['method'] === 'direct') ? " on {$c['iface']}" : ''));
}

function fleet_conn_set_group(int $gid, array $in, string $who): void {
	$c = fleet_conn_cfg_from($in, false);
	fleet_db()->prepare('UPDATE fleet_groups SET conn_method = ?, conn_iface = ? WHERE id = ?')->execute(array($c['method'], $c['iface'], $gid));
	$g = fleet_group_get($gid);
	fleet_audit($who, 'connections', 'Group ' . ($g['name'] ?? $gid) . ': ' . (($c['method'] === '') ? 'as the fleet' : FLEET_CONN_METHODS[$c['method']][0] .
	    (($c['method'] === 'direct') ? " on {$c['iface']}" : '')));
}

function fleet_conn_set_box(string $node, array $in, string $who): void {
	$c = fleet_conn_cfg_from($in, false);
	fleet_db()->prepare('UPDATE boxes SET conn_method = ?, conn_iface = ? WHERE node_id = ?')->execute(array($c['method'], $c['iface'], $node));
	$b = fleet_box_get($node);
	fleet_audit($who, 'connections', ($b['label'] ?? $node) . ': ' . (($c['method'] === '') ? 'as its groups' : FLEET_CONN_METHODS[$c['method']][0] .
	    (($c['method'] === 'direct') ? " on {$c['iface']}" : '')));
}

/* Every firewall with what it should use and what it uses: node => {box, want: [method, iface, from, conflict], state}. */
function fleet_conn_overview(): array {
	$fleet = fleet_conn_fleet_cfg();
	$gcfg = array();
	foreach (fleet_db()->query('SELECT bg.node_id, g.name, g.conn_method, g.conn_iface FROM box_groups bg JOIN fleet_groups g ON g.id = bg.group_id') as $r) {
		$gcfg[$r['node_id']][$r['name']] = array('method' => (string)$r['conn_method'], 'iface' => (string)$r['conn_iface']);
	}
	$out = array();
	foreach (fleet_db()->query('SELECT * FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll() as $b) {
		$out[$b['node_id']] = array('box' => $b, 'want' => fleet_conn_effective(array('method' => (string)$b['conn_method'], 'iface' => (string)$b['conn_iface']),
		    $gcfg[$b['node_id']] ?? array(), $fleet), 'state' => json_decode((string)($b['conn_state'] ?? ''), true) ?: null);
	}
	return $out;
}

/* pure: does a firewall's path differ from what it should use? */
function fleet_conn_pending(array $row): bool {
	list($method, $iface) = $row['want'];
	$st = $row['state'];
	$have = ($st === null) ? 'wireguard' : (string)$st['method'];
	if ($method !== $have) {
		return true;
	}
	return ($method === 'direct') && ((string)($st['iface'] ?? '') !== $iface);
}

/* ------------------------------------------------------------------ */
/* Reaching a firewall                                                 */
/* ------------------------------------------------------------------ */

/* The controller's own address towards $dst (no packet is sent: a UDP socket only picks the route). */
function fleet_conn_source_for(string $dst): ?string {
	if (!function_exists('socket_create')) {
		return null;
	}
	$v6 = strpos($dst, ':') !== false;
	$s = @socket_create($v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, SOL_UDP);
	if ($s === false) {
		return null;
	}
	$ip = null;
	if (@socket_connect($s, $dst, 9) && @socket_getsockname($s, $addr)) {
		$ip = $addr;
	}
	socket_close($s);
	return (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) ? $ip : null;
}

/* The pinned target of a firewall over a path address. */
function fleet_conn_target(array $box, string $address): array {
	return array('host' => $address, 'port' => FLEET_NODE_API_PORT_DEFAULT, 'authority' => fleet_hostport($address, FLEET_NODE_API_PORT_DEFAULT),
	    'cert_sha256' => $box['cert_sha256']);
}

function fleet_conn_state_save(string $node, ?array $state): void {
	fleet_db()->prepare('UPDATE boxes SET conn_state = ? WHERE node_id = ?')->execute(array(($state === null) ? null : json_encode($state), $node));
}

/*
 * A call to a firewall: over its path when that answers, otherwise (and
 * when the path just failed) over the tunnel. Returns what
 * fleet_http_pinned() returns.
 */
function fleet_conn_call(array $box, string $method, string $path, ?array $body, string $key): array {
	$state = json_decode((string)($box['conn_state'] ?? ''), true) ?: null;
	$now = time();
	if (fleet_conn_use_path($state, $now)) {
		try {
			$r = fleet_http_pinned(fleet_conn_target($box, (string)$state['address']), $method, $path, $body, $key);
			if (empty($state['ok']) || ($now - (int)($state['checked'] ?? 0) > 60)) {
				fleet_conn_note($box, $state, true, '', $now);
			}
			return $r;
		} catch (FleetJoinError $e) {
			fleet_conn_note($box, $state, false, $e->getMessage(), $now);
		}
	}
	return fleet_http_pinned(fleet_box_target($box), $method, $path, $body, $key);
}

/* Record how a path answered; a path that stops (or starts again) answering raises an alert once. */
function fleet_conn_note(array $box, array $state, bool $ok, string $error, int $now): void {
	list($state, $alert) = fleet_conn_after($state, $ok, $error, $now);
	fleet_conn_state_save($box['node_id'], $state);
	if (($alert !== null) && function_exists('fleet_alert')) {
		fleet_alert($alert === 'down' ? 'path_down' : 'path_up', $box['node_id'], sprintf($alert === 'down' ?
		    '%1$s: the %2$s path (%3$s) does not answer (%4$s); Fleet uses the tunnel until it does.' : '%1$s: the %2$s path (%3$s) answers again.',
		    $box['label'], $state['method'], $state['address'], $error));
	}
}

/*
 * Set a firewall's connection to what it should use: create the path
 * over the tunnel, prove it by calling the firewall over it, keep it only
 * then. Back to the tunnel removes the path. $say(text, percent).
 * Returns the words for the result; throws RuntimeException.
 */
function fleet_conn_apply_box(array $box, array $want, string $who, ?callable $say = null): string {
	$say = $say ?? function () {};
	list($method, $iface) = $want;
	$key = (string)fleet_unseal((string)$box['api_key'], fleet_master_key());
	$tunnel = function ($verb, $path, $body = null) use ($box, $key) {
		try {
			return fleet_http_pinned(fleet_box_target($box), $verb, $path, $body, $key);
		} catch (FleetJoinError $e) {
			throw new RuntimeException('Over the tunnel: ' . fleet_poll_problem($e->fleet_code, $e->getMessage()));
		}
	};
	$st = json_decode((string)($box['conn_state'] ?? ''), true) ?: array('method' => 'wireguard');
	if ($method === 'wireguard') {
		if (($st['method'] ?? 'wireguard') !== 'wireguard') {
			$say('Removing the ' . $st['method'] . ' path', 50);
			$tunnel('DELETE', '/api/v1/management/paths/' . $st['method']);
		}
		fleet_conn_state_save($box['node_id'], null);
		fleet_audit($who, 'connections', "{$box['label']}: the Fleet tunnel only");
		return 'Uses the Fleet tunnel.';
	}
	$status = json_decode((string)($box['status'] ?? ''), true) ?: array();
	if ((int)($status['api_level'] ?? 0) < 10) {
		throw new RuntimeException('FLEET-E401: This firewall is too old for connection paths (it needs the System update with API level 10).');
	}
	$say('Reading the firewall\'s interfaces', 15);
	list($code, $json) = $tunnel('GET', '/api/v1/management/paths');
	if ($code !== 200) {
		throw new RuntimeException('The firewall\'s interfaces could not be read: ' . fleet_box_error($code, $json));
	}
	$choices = (array)($json['data']['choices'] ?? array());
	$want_key = ($method === 'tailscale') ? 'tailscale' : $iface;
	if (!isset($choices[$want_key])) {
		throw new RuntimeException(($method === 'tailscale') ? 'FLEET-E131: Tailscale is not running on this firewall (no tailnet address).' :
		    "This firewall has no interface \"{$iface}\". Choose another for it or its group.");
	}
	$address = (string)($choices[$want_key]['addresses'][0] ?? '');
	if ($address === '') {
		throw new RuntimeException("The interface {$want_key} has no address on this firewall.");
	}
	$src = fleet_conn_source_for($address);
	if ($src === null) {
		throw new RuntimeException("FLEET-E134: The controller has no route to {$address}. Check the routing (or the tailnet) between them.");
	}
	/* Another method's path first goes away: a firewall has one path besides the tunnel. */
	foreach (array('direct', 'tailscale') as $other) {
		if (($other !== $method) && (($st['method'] ?? '') === $other)) {
			$tunnel('DELETE', '/api/v1/management/paths/' . $other);
		}
	}
	$say("Opening the {$method} path on {$address} for {$src}", 40);
	list($code, $json) = $tunnel('PUT', '/api/v1/management/paths/' . $method, array('address' => $want_key, 'allowed' => array($src)));
	if (($code < 200) || ($code >= 300)) {
		throw new RuntimeException(fleet_box_error($code, $json));
	}
	$say('Checking the controller reaches the firewall over it', 70);
	$ok = false;
	$err = '';
	for ($i = 0; ($i < 5) && !$ok; $i++) {
		try {
			list($code) = fleet_http_pinned(fleet_conn_target($box, $address), 'GET', '/api/v1/management/status', null, $key);
			$ok = ($code === 200);
			$err = $ok ? '' : "HTTP {$code}";
		} catch (FleetJoinError $e) {
			$err = $e->getMessage();
			sleep(2);
		}
	}
	if (!$ok) {
		$tunnel('DELETE', '/api/v1/management/paths/' . $method);
		fleet_conn_state_save($box['node_id'], null);
		fleet_audit($who, 'connections', "{$box['label']}: FLEET-E134 {$method} path on {$address} did not answer ({$err}); removed, the tunnel stays");
		throw new RuntimeException("FLEET-E134: The controller could not reach {$address}:" . FLEET_NODE_API_PORT_DEFAULT . " ({$err}). The path was removed again; the firewall stays on the Fleet tunnel. " .
		    (($method === 'tailscale') ? 'Check the tailnet ACL allows the controller to TCP 8444.' : 'Check the route and any firewall between the controller and that address.'));
	}
	$now = time();
	fleet_conn_state_save($box['node_id'], array('method' => $method, 'iface' => $iface, 'address' => $address, 'source' => $src, 'ok' => true, 'since' => $now,
	    'checked' => $now, 'error' => ''));
	fleet_audit($who, 'connections', "{$box['label']}: {$method} path on {$address} (allowed {$src}), the tunnel stays as fallback");
	return "Uses the {$method} path on {$address}; the Fleet tunnel is the fallback.";
}

/* Start applying the connection changes of these firewalls in the background. Returns the operation id. */
function fleet_conn_launch(array $nodes, string $who): int {
	if (empty($nodes)) {
		throw new RuntimeException('No firewall has a connection change to apply.');
	}
	$op = fleet_op_group_start('connections', sprintf('Apply connection changes (%d firewalls)', count($nodes)), $who);
	foreach ($nodes as $node) {
		$box = fleet_box_get($node);
		if ($box === null) {
			continue;
		}
		if (!fleet_manage_allowed($box)) {
			fleet_op_set(fleet_op_start($node, 'connections', '', $who, $op, 'skipped'), 'skipped', 'Skipped: monitor only');
		} elseif ($box['state'] !== 'online') {
			fleet_op_set(fleet_op_start($node, 'connections', '', $who, $op, 'skipped'), 'skipped', 'Skipped: the firewall is ' . $box['state']);
		} else {
			fleet_op_start($node, 'connections', 'Waiting', $who, $op, 'queued');
		}
	}
	fleet_op_group_update($op);
	fleet_audit($who, 'connections', sprintf('Applying connection changes to %d firewalls', count($nodes)));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run connections ' . (int)$op);
	return $op;
}
