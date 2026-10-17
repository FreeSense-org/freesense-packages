<?php
/*
 * fleet_access.inc
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
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
 * Who may reach the controller's public ports (enrollment TCP, tunnel
 * UDP): anyone, or an allowed list. The list is the admin's entries plus
 * what Fleet knows: the addresses firewalls connect from, the standby
 * controller, and the address given with an open invitation. "Open for
 * joining" lets anyone in for a while. Too many wrong keys from one
 * address block it on both ports for a while (never an allowed one).
 *
 * The check: is the public address on this controller or forwarded to it
 * (then: what to forward where), and does the enrollment port answer from
 * outside (a firewall in the fleet probes it, API level 14)?
 */

/* Wrong keys within this window count towards a block (seconds). */
define('FLEET_ACCESS_WINDOW', 600);
define('FLEET_ACCESS_BLOCK_AFTER', array(3, 5, 10, 20));
define('FLEET_ACCESS_BLOCK_MINUTES', array(15, 60, 240, 1440));
define('FLEET_ACCESS_OPEN_MINUTES', array(30, 60, 240, 1440));
/* The probe needs this firewall API level. */
define('FLEET_ACCESS_PROBE_LEVEL', 14);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: an address or network as the allowed list keeps it ("a.b.c.d", "a.b.c.0/24", IPv6 alike), or null. */
function fleet_access_cidr(string $in): ?string {
	$in = trim($in);
	$parts = explode('/', $in, 2);
	$ip = $parts[0];
	if (!filter_var($ip, FILTER_VALIDATE_IP)) {
		return null;
	}
	$max = (strpos($ip, ':') !== false) ? 128 : 32;
	if (!isset($parts[1])) {
		return $ip;
	}
	if (!ctype_digit($parts[1]) || ((int)$parts[1] > $max) || ((int)$parts[1] < 1)) {
		return null;
	}
	return ((int)$parts[1] === $max) ? $ip : $ip . '/' . (int)$parts[1];
}

/* pure: is $ip in $cidr (an address or a network)? */
function fleet_access_in(string $ip, string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$a = @inet_pton($ip);
	$n = @inet_pton($parts[0]);
	if (($a === false) || ($n === false) || (strlen($a) !== strlen($n))) {
		return false;
	}
	$bits = isset($parts[1]) ? (int)$parts[1] : strlen($a) * 8;
	$bytes = intdiv($bits, 8);
	if (substr($a, 0, $bytes) !== substr($n, 0, $bytes)) {
		return false;
	}
	$rest = $bits % 8;
	if ($rest === 0) {
		return true;
	}
	$mask = (0xff << (8 - $rest)) & 0xff;
	return (ord($a[$bytes]) & $mask) === (ord($n[$bytes]) & $mask);
}

/* pure: the access settings with defaults. */
function fleet_access_from(array $j): array {
	$entries = array();
	foreach ((array)($j['entries'] ?? array()) as $e) {
		$c = fleet_access_cidr((string)($e['cidr'] ?? ''));
		if ($c !== null) {
			$entries[$c] = array('cidr' => $c, 'note' => mb_substr((string)($e['note'] ?? ''), 0, 80), 'added' => (int)($e['added'] ?? 0));
		}
	}
	return array(
		'enroll' => (($j['enroll'] ?? 'any') === 'list') ? 'list' : 'any',
		'tunnel' => (($j['tunnel'] ?? 'any') === 'list') ? 'list' : 'any',
		'entries' => array_values($entries),
		'firewalls' => !array_key_exists('firewalls', $j) || !empty($j['firewalls']),
		'block' => !array_key_exists('block', $j) || !empty($j['block']),
		'block_after' => in_array((int)($j['block_after'] ?? 0), FLEET_ACCESS_BLOCK_AFTER, true) ? (int)$j['block_after'] : 5,
		'block_minutes' => in_array((int)($j['block_minutes'] ?? 0), FLEET_ACCESS_BLOCK_MINUTES, true) ? (int)$j['block_minutes'] : 60,
		'open_until' => (int)($j['open_until'] ?? 0),
	);
}

/*
 * pure: the allowed addresses with where each comes from: cidr =>
 * reason. $seen: node label => address firewalls connect from; $invites:
 * {ip, label, expires}; $extra: cidr => reason (the standby).
 */
function fleet_access_allowed(array $acc, array $seen, array $invites, array $extra, int $now): array {
	$out = array();
	foreach ($acc['entries'] as $e) {
		$out[$e['cidr']] = ($e['note'] !== '') ? $e['note'] : 'Added by hand';
	}
	if ($acc['firewalls']) {
		foreach ($seen as $label => $ip) {
			if ((fleet_access_cidr($ip) !== null) && !isset($out[$ip])) {
				$out[$ip] = "Firewall {$label}";
			}
		}
	}
	foreach ($invites as $i) {
		if (((int)$i['expires'] > $now) && (fleet_access_cidr((string)$i['ip']) !== null) && !isset($out[$i['ip']])) {
			$out[$i['ip']] = "Invitation {$i['label']}";
		}
	}
	foreach ($extra as $c => $why) {
		if (!isset($out[$c])) {
			$out[$c] = $why;
		}
	}
	return $out;
}

/* pure: is the address allowed (in any allowed entry)? */
function fleet_access_is_allowed(string $ip, array $allowed): bool {
	foreach (array_keys($allowed) as $c) {
		if (fleet_access_in($ip, (string)$c)) {
			return true;
		}
	}
	return false;
}

/* Fleet's aliases: who may use the enrollment port, the tunnel port, and who is blocked. */
define('FLEET_ACCESS_ALIASES', array('FleetEnroll' => 'FreeSense Fleet: may join (enrollment port)', 'FleetTunnel' => 'FreeSense Fleet: may use the tunnel port',
    'FleetBlocked' => 'FreeSense Fleet: blocked after wrong join keys'));

/* pure: a rule tracker that stays the same for the same rule (so its counters do too). */
function fleet_access_tracker(string $what): string {
	return (string)(1700000000 + (crc32('fleet:' . $what) % 90000000));
}

/*
 * pure: Fleet's firewall rules and aliases, as they go into the
 * configuration (Firewall > Rules > Floating and Firewall > Aliases), each
 * marked fleet_auto (shown locked: change them in Fleet). $ifaces: the
 * interfaces the ports are open on. Blocked addresses first; then each port
 * open to anyone or only to the allowed list (empty list: nothing passes).
 * Returns array(aliases => [name => alias], rules => [rule]); empty when the
 * controller is off or the admin opens the ports by hand.
 */
function fleet_access_rule_set(array $s, array $ifaces, array $acc, array $allowed, array $blocked, int $now): array {
	if (!$s['enable'] || !empty($s['rules_manual']) || empty($ifaces)) {
		return array('aliases' => array(), 'rules' => array());
	}
	$any = array('0.0.0.0/0', '::/0');
	$list = array_keys($allowed);
	$src = array(
		'FleetEnroll' => (($acc['enroll'] === 'any') || ($acc['open_until'] > $now)) ? $any : $list,
		'FleetTunnel' => ($acc['tunnel'] === 'any') ? $any : $list,
		'FleetBlocked' => array_keys(array_filter($blocked, function ($until) use ($now) { return (int)$until > $now; })),
	);
	$aliases = array();
	foreach (FLEET_ACCESS_ALIASES as $name => $descr) {
		$aliases[$name] = array('name' => $name, 'type' => 'network', 'address' => implode(' ', $src[$name]), 'descr' => $descr,
		    'detail' => implode('||', array_fill(0, count($src[$name]), '')), 'fleet_auto' => '1');
	}
	$on = implode(',', $ifaces);
	$rule = function (string $type, string $proto, string $from, int $port, string $descr) use ($on) {
		return array('type' => $type, 'interface' => $on, 'ipprotocol' => 'inet46', 'protocol' => $proto, 'source' => array('address' => $from),
		    'destination' => array('network' => '(self)', 'port' => (string)$port), 'descr' => $descr, 'floating' => 'yes', 'quick' => 'yes', 'direction' => 'in',
		    /* Answer the way the packet came: firewalls on the WAN's own network must not be answered through its gateway. */
		    'disablereplyto' => 'yes',
		    'tracker' => fleet_access_tracker("{$type}-{$proto}-{$from}"), 'fleet_auto' => '1');
	};
	return array('aliases' => $aliases, 'rules' => array(
		$rule('block', 'tcp', 'FleetBlocked', $s['enroll_port'], 'FreeSense Fleet: blocked after wrong join keys (enrollment)'),
		$rule('block', 'udp', 'FleetBlocked', $s['wg_port'], 'FreeSense Fleet: blocked after wrong join keys (tunnel)'),
		$rule('pass', 'tcp', 'FleetEnroll', $s['enroll_port'], 'FreeSense Fleet: enrollment'),
		$rule('pass', 'udp', 'FleetTunnel', $s['wg_port'], 'FreeSense Fleet: tunnel'),
	));
}

/*
 * pure: $items (config list) with Fleet's entries replaced by $mine: the
 * others keep their order; for rules Fleet's go first (block before pass).
 */
function fleet_access_merge(array $items, array $mine, bool $first): array {
	$keep = array_values(array_filter($items, function ($i) { return !is_array($i) || empty($i['fleet_auto']); }));
	return $first ? array_merge(array_values($mine), $keep) : array_merge($keep, array_values($mine));
}

/* pure: wrong keys from $ip within the window, with this one; array(updated failures, count). */
function fleet_access_fail_add(array $fails, string $ip, int $now): array {
	$keep = array();
	foreach ($fails as $a => $times) {
		$t = array_values(array_filter((array)$times, function ($x) use ($now) { return ($now - (int)$x) < FLEET_ACCESS_WINDOW; }));
		if (!empty($t)) {
			$keep[$a] = $t;
		}
	}
	$keep[$ip][] = $now;
	return array($keep, count($keep[$ip]));
}

/* pure: peer public key => source address from "wg show <if> endpoints" lines. */
function fleet_access_endpoints_parse(array $lines): array {
	$out = array();
	foreach ($lines as $l) {
		$f = preg_split('/\s+/', trim((string)$l));
		if ((count($f) === 2) && preg_match('/^\[?([0-9a-fA-F:.]+)\]?:\d+$/', $f[1], $m)) {
			$out[$f[0]] = $m[1];
		}
	}
	return $out;
}

/*
 * pure: what the address firewalls use means: array(kind, addresses)
 * with kind 'local' (the address is on this controller), 'forward' (it
 * points elsewhere: a port forward to this controller), 'unresolved'.
 */
function fleet_access_reach_kind(array $resolved, array $local): array {
	if (empty($resolved)) {
		return array('unresolved', array());
	}
	return array(empty(array_intersect($resolved, $local)) ? 'forward' : 'local', $resolved);
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

function fleet_access(): array {
	return fleet_access_from(json_decode((string)fleet_setting('access', '{}'), true) ?: array());
}

function fleet_access_json(string $name): array {
	return json_decode((string)fleet_setting($name, '{}'), true) ?: array();
}

/* Save the access settings and reload the rules. */
function fleet_access_save(array $acc, string $who, string $what): void {
	fleet_setting_set('access', json_encode(fleet_access_from($acc)));
	fleet_audit($who, 'access', $what);
	fleet_access_reload();
}

/* Update Fleet's rules and aliases and reload the filter (in the background where the WebGUI code is not loaded). */
function fleet_access_reload(): void {
	if (function_exists('filter_configure') && function_exists('write_config')) {
		fleet_access_sync_config();
		filter_configure();
	} else {
		exec('/usr/local/bin/php /usr/local/sbin/freesense-fleet-rules > /dev/null 2>&1 &');
	}
}

/* Everything that is allowed now: cidr => reason. */
function fleet_access_allowed_now(int $now): array {
	$seen = array();
	$labels = array();
	foreach (fleet_db()->query('SELECT node_id, label FROM boxes')->fetchAll() as $b) {
		$labels[$b['node_id']] = $b['label'];
	}
	foreach (fleet_access_json('access_seen') as $node => $ip) {
		if (isset($labels[$node])) {
			$seen[$labels[$node]] = $ip;
		}
	}
	$extra = array();
	if (function_exists('fleet_standby_pairing')) {
		$p = fleet_standby_pairing();
		foreach (($p['peer_addr'] ?? '') === '' ? array() : (filter_var($p['peer_addr'], FILTER_VALIDATE_IP) ? array($p['peer_addr']) : (array)@gethostbynamel($p['peer_addr'])) as $ip) {
			$extra[$ip] = 'Standby controller';
		}
	}
	return fleet_access_allowed(fleet_access(), $seen, fleet_access_json('access_invites'), $extra, $now);
}

/* The interfaces Fleet opens its ports on: the chosen ones, or every assigned interface. */
function fleet_access_ifaces(array $s): array {
	$all = function_exists('get_configured_interface_list') ? array_keys(get_configured_interface_list()) : array();
	$chosen = array_values(array_filter($s['listen'], function ($i) { return $i !== 'tailscale'; }));
	return empty($s['listen']) ? $all : array_values(array_intersect($chosen, $all));
}

/* The rule set for now. */
function fleet_access_rule_set_now(): array {
	$s = fleet_ctl_settings();
	if (!$s['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
		return array('aliases' => array(), 'rules' => array());
	}
	return fleet_access_rule_set($s, fleet_access_ifaces($s), fleet_access(), fleet_access_allowed_now(time()), fleet_access_json('access_blocked'), time());
}

/* Put a rule set into the configuration (not written). Returns true when something changed. */
function fleet_access_config_apply(array $set): bool {
	$rules = (array)config_get_path('filter/rule', array());
	$aliases = (array)config_get_path('aliases/alias', array());
	$new_rules = fleet_access_merge($rules, $set['rules'], true);
	$new_aliases = fleet_access_merge($aliases, $set['aliases'], false);
	if (($new_rules == $rules) && ($new_aliases == $aliases)) {
		return false;
	}
	config_set_path('filter/rule', $new_rules);
	config_set_path('aliases/alias', $new_aliases);
	return true;
}

/* Bring Fleet's rules and aliases in the configuration up to date; true when they changed (and were written). */
function fleet_access_sync_config(): bool {
	if (!function_exists('config_set_path')) {
		return false;
	}
	if (!fleet_access_config_apply(fleet_access_rule_set_now())) {
		return false;
	}
	write_config('FreeSense Fleet: its firewall rules and aliases were updated.');
	return true;
}

/*
 * The tailnet is no assigned interface, so its pass rules for the two ports
 * come from the filter hook, with the same aliases as source.
 */
function fleet_access_tailnet_rules(array $s): string {
	if (!$s['enable'] || !empty($s['rules_manual']) || !(empty($s['listen']) || in_array('tailscale', $s['listen'], true)) ||
	    !function_exists('does_interface_exist') || !does_interface_exist('tailscale0')) {
		return '';
	}
	return "pass in quick on tailscale0 proto tcp from <FleetEnroll> to (self) port {$s['enroll_port']} keep state label \"USER_RULE: FreeSense Fleet enrollment (tailnet)\"\n" .
	    "pass in quick on tailscale0 proto udp from <FleetTunnel> to (self) port {$s['wg_port']} keep state label \"USER_RULE: FreeSense Fleet tunnel (tailnet)\"\n";
}

/* An invitation's expected address: allowed until the invitation expires. */
function fleet_access_invite_ip(string $token_id, string $ip, string $label, int $expires): ?string {
	$c = fleet_access_cidr($ip);
	if ($c === null) {
		return 'The firewall\'s public address is not an IP address or network.';
	}
	$inv = fleet_access_json('access_invites');
	$inv[$token_id] = array('ip' => $c, 'label' => $label, 'expires' => $expires);
	fleet_setting_set('access_invites', json_encode($inv));
	fleet_access_reload();
	return null;
}

/*
 * A wrong key (or unknown invitation) from $ip, called by the enrollment
 * endpoint. Blocks the address on both ports after too many; never an
 * allowed one. Returns true when it is now blocked.
 */
function fleet_access_failed(string $ip, int $now): bool {
	$acc = fleet_access();
	if (!$acc['block'] || (fleet_access_cidr($ip) === null) || fleet_access_is_allowed($ip, fleet_access_allowed_now($now))) {
		return false;
	}
	list($fails, $n) = fleet_access_fail_add(fleet_access_json('access_fails'), $ip, $now);
	fleet_setting_set('access_fails', json_encode($fails));
	if ($n < $acc['block_after']) {
		return false;
	}
	$blocked = fleet_access_json('access_blocked');
	if ((int)($blocked[$ip] ?? 0) > $now) {
		return true;
	}
	$blocked[$ip] = $now + 60 * $acc['block_minutes'];
	fleet_setting_set('access_blocked', json_encode($blocked));
	unset($fails[$ip]);
	fleet_setting_set('access_fails', json_encode($fails));
	fleet_audit('system', 'access', sprintf('%s blocked for %d minutes after %d wrong keys', $ip, $acc['block_minutes'], $n));
	if (function_exists('fleet_alert')) {
		fleet_alert('access_blocked', '', sprintf('%s was blocked on the Fleet ports for %d minutes after %d wrong join keys.', $ip, $acc['block_minutes'], $n));
	}
	fleet_access_reload();
	exec('/sbin/pfctl -k ' . escapeshellarg($ip) . ' > /dev/null 2>&1');
	return true;
}

function fleet_access_unblock(string $ip, string $who): void {
	$blocked = fleet_access_json('access_blocked');
	unset($blocked[$ip]);
	fleet_setting_set('access_blocked', json_encode($blocked, JSON_FORCE_OBJECT));
	fleet_audit($who, 'access', "{$ip} unblocked");
	fleet_access_reload();
}

/*
 * Once a minute (poll): learn the addresses firewalls connect from,
 * forget old invitations and expired blocks; reload the rules when the
 * allowed or blocked set changed and it matters.
 */
function fleet_access_tick(int $now): void {
	$by_key = array();
	foreach (fleet_db()->query('SELECT node_id, wg_pub FROM boxes')->fetchAll() as $b) {
		$by_key[$b['wg_pub']] = $b['node_id'];
	}
	list(, $out) = fleet_ctl_exec(array('/usr/bin/wg', 'show', FLEET_CTL_IF, 'endpoints'));
	$seen = $was_seen = fleet_access_json('access_seen');
	foreach (fleet_access_endpoints_parse(explode("\n", (string)$out)) as $key => $ip) {
		if (isset($by_key[$key])) {
			$seen[$by_key[$key]] = $ip;
		}
	}
	$seen = array_intersect_key($seen, array_flip($by_key));
	$inv = $was_inv = fleet_access_json('access_invites');
	$inv = array_filter($inv, function ($i) use ($now) { return (int)$i['expires'] > $now; });
	$blocked = $was_blocked = fleet_access_json('access_blocked');
	$blocked = array_filter($blocked, function ($until) use ($now) { return (int)$until > $now; });
	$acc = fleet_access();
	$changed = false;
	if ($seen != $was_seen) {
		fleet_setting_set('access_seen', json_encode($seen, JSON_FORCE_OBJECT));
		$changed = $changed || ($acc['firewalls'] && (($acc['enroll'] === 'list') || ($acc['tunnel'] === 'list')));
	}
	if ($inv != $was_inv) {
		fleet_setting_set('access_invites', json_encode($inv, JSON_FORCE_OBJECT));
		$changed = true;
	}
	if ($blocked != $was_blocked) {
		fleet_setting_set('access_blocked', json_encode($blocked, JSON_FORCE_OBJECT));
		$changed = true;
	}
	/* "Open for joining" ran out. */
	if (($acc['open_until'] > 0) && ($acc['open_until'] <= $now)) {
		$acc['open_until'] = 0;
		fleet_setting_set('access', json_encode($acc));
		$changed = true;
	}
	if ($changed) {
		fleet_access_reload();
	}
}

/* The controller's own addresses (interfaces). */
function fleet_access_local_addresses(): array {
	$out = array();
	foreach (function_exists('get_configured_interface_list') ? get_configured_interface_list() : array() as $if) {
		foreach (array(get_interface_ip($if), get_interface_ipv6($if)) as $ip) {
			if (is_string($ip) && ($ip !== '')) {
				$out[] = $ip;
			}
		}
	}
	return array_values(array_unique($out));
}

/*
 * The reachability check: what the public address is, and whether the
 * enrollment port answers from outside, probed by a firewall in the fleet
 * (one that connects from another address when there is one). Firewalls
 * that reached the tunnel in the last 5 minutes prove the tunnel port.
 */
function fleet_access_check(int $now): array {
	$s = fleet_ctl_settings();
	$host = $s['public_host'];
	$resolved = filter_var($host, FILTER_VALIDATE_IP) ? array($host) : (array)@gethostbynamel($host);
	$local = fleet_access_local_addresses();
	list($kind) = fleet_access_reach_kind($resolved, $local);
	$probe = null;
	$seen = fleet_access_json('access_seen');
	$boxes = fleet_db()->query("SELECT * FROM boxes WHERE state = 'online' ORDER BY label")->fetchAll();
	usort($boxes, function ($a, $b) use ($seen, $local) {
		/* Prefer a firewall that connects from outside this controller's networks. */
		$ra = in_array($seen[$a['node_id']] ?? '', $local, true) ? 1 : 0;
		$rb = in_array($seen[$b['node_id']] ?? '', $local, true) ? 1 : 0;
		return $ra <=> $rb;
	});
	foreach ($boxes as $b) {
		$st = json_decode((string)$b['status'], true) ?: array();
		if ((int)($st['api_level'] ?? 0) < FLEET_ACCESS_PROBE_LEVEL) {
			continue;
		}
		list($code, $json) = fleet_box_call($b, 'POST', '/api/v1/management/probe', array('host' => $host, 'port' => $s['enroll_port']));
		/* Only a complete answer counts; otherwise ask the next firewall. */
		if (($code === 200) && is_array($json['data'] ?? null) && isset($json['data']['open'])) {
			$probe = array('from' => $b['label'], 'from_addr' => $seen[$b['node_id']] ?? '') + $json['data'] + array('ms' => 0, 'error' => '');
			break;
		}
	}
	$recent = 0;
	list(, $hs) = fleet_ctl_exec(array('/usr/bin/wg', 'show', FLEET_CTL_IF, 'latest-handshakes'));
	foreach (explode("\n", (string)$hs) as $l) {
		$f = preg_split('/\s+/', trim($l));
		if ((count($f) === 2) && ((int)$f[1] > 0) && (($now - (int)$f[1]) < 300)) {
			$recent++;
		}
	}
	$result = array('host' => $host, 'resolved' => $resolved, 'local' => $local, 'kind' => $kind, 'enroll_port' => $s['enroll_port'], 'wg_port' => $s['wg_port'],
	    'probe' => $probe, 'tunnel_recent' => $recent, 'checked' => $now);
	fleet_setting_set('access_check', json_encode($result));
	return $result;
}
