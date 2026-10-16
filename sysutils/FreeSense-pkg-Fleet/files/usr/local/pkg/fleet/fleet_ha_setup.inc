<?php
/*
 * fleet_ha_setup.inc
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
 * Set up an HA pair from Fleet. Two managed firewalls with the same
 * interfaces get CARP addresses (the primary preferred, skew 0; the
 * secondary skew 100) on the interfaces chosen, pfsync on the sync
 * interface, and HA configuration sync from the primary to the
 * secondary, which gets a fleet-hasync user to log in as.
 *
 * Order: the secondary's sync user, then the primary (it becomes MASTER),
 * then the secondary (it sees the primary and stays BACKUP). Each firewall
 * changes under commit-confirm; at the end Fleet checks the pair: found,
 * one MASTER per address and that is the primary. Anything failing undoes
 * what was set up, on both. The CARP and sync passwords are made for the
 * run and never stored by Fleet.
 */

require_once('fleet/fleet_store.inc');

/* Marks the addresses Fleet made, so an undo removes only those. */
define('FLEET_HA_MARK', '[Fleet:HA]');
define('FLEET_HA_CONFIRM', 300);
define('FLEET_HA_LABEL', 'Fleet HA pair setup');
/* How long the pair may take to settle after setup. */
define('FLEET_HA_SETTLE', 90);
/*
 * What HA sync may push. Not users or certificates: they would replace the
 * secondary's Fleet API user and pinned certificate, and Fleet would lose
 * it. Not virtual IPs: Fleet sets the CARP addresses on both itself.
 */
define('FLEET_HA_SECTIONS', array('rules' => 'Firewall rules', 'aliases' => 'Aliases', 'nat' => 'NAT', 'schedules' => 'Schedules',
    'staticroutes' => 'Static routes', 'dhcpd' => 'DHCP server', 'dnsforwarder' => 'DNS forwarder', 'trafficshaper' => 'Traffic shaper',
    'wol' => 'Wake-on-LAN'));

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: "255.255.255.0" or "24" as a prefix length, or null. */
function fleet_ha_bits(string $mask): ?int {
	if (preg_match('/^\d{1,2}$/', $mask)) {
		return ((int)$mask <= 32) ? (int)$mask : null;
	}
	$n = ip2long($mask);
	if ($n === false) {
		return null;
	}
	$bits = substr_count(decbin($n), '1');
	return ((($n << $bits) & 0xffffffff) === 0) ? $bits : null;
}

/* pure: is $ip inside $net/$bits (IPv4)? */
function fleet_ha_in_net(string $ip, string $net, int $bits): bool {
	$a = ip2long($ip);
	$b = ip2long($net);
	if (($a === false) || ($b === false)) {
		return false;
	}
	$m = ($bits === 0) ? 0 : ((0xffffffff << (32 - $bits)) & 0xffffffff);
	return ($a & $m) === ($b & $m);
}

/* pure: a firewall's interfaces from /v1/status/interfaces: key => {name, ip, bits, up}. IPv4 only. */
function fleet_ha_ifaces(array $status): array {
	$out = array();
	foreach ($status as $i) {
		if (!is_array($i) || (($i['name'] ?? '') === '')) {
			continue;
		}
		$bits = fleet_ha_bits((string)($i['subnet'] ?? ''));
		$out[(string)$i['name']] = array('name' => (string)($i['description'] ?? $i['name']), 'ip' => (string)($i['ipaddr'] ?? ''),
		    'bits' => $bits, 'up' => in_array($i['status'] ?? '', array('up', 'associated'), true));
	}
	return $out;
}

/* pure: the lowest VHID (1-255) neither firewall uses, or null. $used: VHIDs in use. */
function fleet_ha_free_vhid(array $used): ?int {
	for ($v = 1; $v <= 255; $v++) {
		if (!in_array($v, $used, true)) {
			return $v;
		}
	}
	return null;
}

/*
 * pure: check a setup and make its plan. $in: {primary, secondary, vips:
 * [{iface, address, vhid?}], sync_iface, sections}; $p/$s: per firewall
 * {label, role, state, api_level, in_pair, hasync_peer, ifaces (from
 * fleet_ha_ifaces), vhids (used)}. Returns array(errors, plan).
 */
function fleet_ha_setup_plan(array $in, array $p, array $s): array {
	$e = array();
	if (($in['primary'] ?? '') === ($in['secondary'] ?? '')) {
		$e[] = 'Choose two different firewalls.';
	}
	foreach (array('primary' => $p, 'secondary' => $s) as $which => $b) {
		$name = $b['label'] ?? $which;
		if (($b['role'] ?? '') !== 'managed') {
			$e[] = "{$name} is monitor only: Fleet may not change it.";
		}
		if (($b['state'] ?? '') !== 'online') {
			$e[] = "{$name} is not online.";
		}
		if ((int)($b['api_level'] ?? 0) < 12) {
			$e[] = "{$name} needs FreeSense with REST API level 12 (update it first).";
		}
		if (!empty($b['in_pair'])) {
			$e[] = "{$name} is already in an HA pair.";
		}
		if (($b['hasync_peer'] ?? '') !== '') {
			$e[] = "{$name} already syncs its configuration to {$b['hasync_peer']}.";
		}
	}
	$used = array_values(array_unique(array_merge((array)($p['vhids'] ?? array()), (array)($s['vhids'] ?? array()))));
	$vips = array();
	foreach ((array)($in['vips'] ?? array()) as $v) {
		$if = (string)($v['iface'] ?? '');
		$addr = trim((string)($v['address'] ?? ''));
		$pi = $p['ifaces'][$if] ?? null;
		$si = $s['ifaces'][$if] ?? null;
		if (($pi === null) || ($si === null)) {
			$e[] = "Interface {$if} is not on both firewalls.";
			continue;
		}
		if (($pi['ip'] === '') || ($si['ip'] === '') || ($pi['bits'] === null)) {
			$e[] = "{$pi['name']} has no IPv4 address on both firewalls.";
			continue;
		}
		if (!filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$e[] = "{$pi['name']}: {$addr} is not an IPv4 address.";
			continue;
		}
		if (!fleet_ha_in_net($addr, $pi['ip'], $pi['bits']) || !fleet_ha_in_net($si['ip'], $pi['ip'], $pi['bits'])) {
			$e[] = "{$pi['name']}: the address and both firewalls must be in {$pi['ip']}/{$pi['bits']}.";
			continue;
		}
		if (in_array($addr, array($pi['ip'], $si['ip']), true)) {
			$e[] = "{$pi['name']}: {$addr} is a firewall's own address; the shared address must be a free one.";
			continue;
		}
		$vhid = (int)($v['vhid'] ?? 0);
		if ($vhid === 0) {
			$vhid = (int)fleet_ha_free_vhid($used);
		}
		if (($vhid < 1) || ($vhid > 255) || in_array($vhid, $used, true)) {
			$e[] = "{$pi['name']}: VHID {$vhid} is in use or out of range (1-255).";
			continue;
		}
		$used[] = $vhid;
		$vips[] = array('iface' => $if, 'name' => $pi['name'], 'address' => $addr, 'bits' => $pi['bits'], 'vhid' => $vhid);
	}
	if (empty($vips)) {
		$e[] = 'Add at least one shared address.';
	}
	$sync = (string)($in['sync_iface'] ?? '');
	$ps = $p['ifaces'][$sync] ?? null;
	$ss = $s['ifaces'][$sync] ?? null;
	if (($ps === null) || ($ss === null) || ($ps['ip'] === '') || ($ss['ip'] === '')) {
		$e[] = 'Choose a sync interface with an IPv4 address on both firewalls.';
	}
	$sections = array_values(array_intersect((array)($in['sections'] ?? array()), array_keys(FLEET_HA_SECTIONS)));
	if (!empty($e)) {
		return array(array_values(array_unique($e)), null);
	}
	return array(array(), array('primary' => $in['primary'], 'secondary' => $in['secondary'], 'vips' => $vips, 'sync_iface' => $sync,
	    'primary_sync_ip' => $ps['ip'], 'secondary_sync_ip' => $ss['ip'], 'sections' => $sections));
}

/* pure: the virtual IP body for one address on one firewall. */
function fleet_ha_vip_body(array $v, int $skew, string $password): array {
	return array('mode' => 'carp', 'interface' => $v['iface'], 'vhid' => (string)$v['vhid'], 'advbase' => '1', 'advskew' => (string)$skew,
	    'password' => $password, 'subnet' => $v['address'], 'subnet_bits' => (string)$v['bits'], 'type' => 'single',
	    'descr' => FLEET_HA_MARK . ' ' . $v['name']);
}

/* pure: the HA sync settings for the primary (pushes to the secondary) or the secondary (pfsync only). */
function fleet_ha_sync_body(array $plan, bool $primary, string $password = ''): array {
	$b = array('pfsyncenabled' => true, 'pfsyncinterface' => $plan['sync_iface'],
	    'pfsyncpeerip' => $primary ? $plan['secondary_sync_ip'] : $plan['primary_sync_ip']);
	if ($primary) {
		$b += array('synchronizetoip' => $plan['secondary_sync_ip'], 'username' => 'fleet-hasync', 'password' => $password);
		foreach (array_keys(FLEET_HA_SECTIONS) as $sec) {
			$b['synchronize' . $sec] = in_array($sec, $plan['sections'], true);
		}
	}
	return $b;
}

/*
 * pure: the rules the sync interface needs on one firewall: pfsync from
 * the peer on both, and on the secondary the primary's configuration sync
 * to its WebGUI ($gui_port).
 */
function fleet_ha_rule_bodies(array $plan, bool $primary, int $gui_port): array {
	$peer = $primary ? $plan['secondary_sync_ip'] : $plan['primary_sync_ip'];
	$base = array('type' => 'pass', 'interface' => $plan['sync_iface'], 'ipprotocol' => 'inet', 'srctype' => 'single', 'src' => $peer, 'srcmask' => '',
	    'log' => false);
	$out = array($base + array('proto' => 'pfsync', 'dsttype' => 'any', 'dst' => '', 'dstmask' => '', 'dstbeginport' => '', 'dstendport' => '',
	    'descr' => FLEET_HA_MARK . ' State sync (pfsync) from the HA peer'));
	if (!$primary) {
		$out[] = $base + array('proto' => 'tcp', 'dsttype' => $plan['sync_iface'] . 'ip', 'dst' => '', 'dstmask' => '', 'dstbeginport' => (string)$gui_port,
		    'dstendport' => (string)$gui_port, 'descr' => FLEET_HA_MARK . ' Configuration sync from the HA primary');
	}
	return $out;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

/* The WebGUI port of a firewall (HA configuration sync logs in there). */
function fleet_ha_gui_port(array $box): int {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/system/advanced/admin');
	$d = ($code === 200) ? (array)($json['data'] ?? array()) : array();
	$port = (int)($d['webguiport'] ?? 0);
	return ($port > 0) ? $port : ((($d['webguiproto'] ?? 'https') === 'http') ? 80 : 443);
}

/* Does a firewall have a Fleet HA rule with this description? */
function fleet_ha_has_rule(array $box, string $descr): bool {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/rules');
	foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $r) {
		if (($r['descr'] ?? '') === $descr) {
			return true;
		}
	}
	return false;
}

/* What setup needs to know about a firewall now (reads its interfaces and virtual IPs live). */
function fleet_ha_setup_facts(array $box): array {
	$st = json_decode((string)$box['status'], true) ?: array();
	list($pairs) = fleet_ha_now();
	$f = array('label' => $box['label'], 'role' => $box['role'], 'state' => $box['state'], 'api_level' => (int)($st['api_level'] ?? 0),
	    'in_pair' => fleet_ha_pair_of($pairs, $box['node_id']) !== null, 'hasync_peer' => (string)($st['hasync']['peer'] ?? ''),
	    'ifaces' => array(), 'vhids' => array());
	if ($box['state'] !== 'online') {
		return $f;
	}
	try {
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/status/interfaces');
		if ($code === 200) {
			$f['ifaces'] = fleet_ha_ifaces((array)($json['data'] ?? array()));
		}
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/virtual-ips');
		foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $v) {
			if ((($v['mode'] ?? '') === 'carp') && ((int)($v['vhid'] ?? 0) > 0)) {
				$f['vhids'][] = (int)$v['vhid'];
			}
		}
	} catch (Throwable $e) {
		$f['state'] = 'unreachable';
	}
	return $f;
}

/* Start a reviewed setup in the background. Returns the operation id. */
function fleet_ha_setup_launch(array $plan, string $who): int {
	$p = fleet_box_get($plan['primary']);
	$s = fleet_box_get($plan['secondary']);
	$op = fleet_op_group_start('ha_setup', sprintf('Set up HA pair %s and %s', $p['label'], $s['label']), $who);
	$t = fleet_op_start($p['node_id'], 'ha_setup', 'Waiting', $who, $op, 'queued');
	fleet_db()->prepare('UPDATE ops SET data = ? WHERE id = ?')->execute(array(json_encode($plan), $op));
	fleet_op_start($s['node_id'], 'ha_setup', 'Waiting', $who, $op, 'queued');
	fleet_audit($who, 'ha_setup', sprintf('%s (primary) and %s: %s; sync on %s', $p['label'], $s['label'],
	    implode(', ', array_map(function ($v) { return "{$v['address']} on {$v['iface']} (VHID {$v['vhid']})"; }, $plan['vips'])), $plan['sync_iface']));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run ha-setup ' . (int)$op);
	return $op;
}

/* One firewall's part, under commit-confirm. $bodies: [[method, path, body], ...]. Throws with what went wrong (rolled back). */
function fleet_ha_setup_box(array $box, string $who, string $label, array $bodies, callable $say): void {
	fleet_backup_box($box, 'change', $who);
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/commit-confirm', array('seconds' => FLEET_HA_CONFIRM, 'label' => $label));
	$cid = (string)($json['data']['id'] ?? '');
	if ((($code !== 200) && ($code !== 201)) || ($cid === '')) {
		throw new RuntimeException('Commit-confirm could not start, so nothing was changed: ' . fleet_box_error($code, $json));
	}
	foreach ($bodies as list($method, $path, $body, $what, $landed)) {
		$say($what);
		try {
			list($code, $json) = fleet_box_call($box, $method, $path, $body);
		} catch (Throwable $e) {
			/* The answer can get lost in the blip a CARP change causes: wait for the firewall, then see whether the change is there. */
			$code = fleet_ha_landed($box, $landed) ? 200 : 0;
			$json = array('error' => array('message' => $e->getMessage()));
		}
		if (($code < 200) || ($code >= 300)) {
			try {
				fleet_box_call($box, 'DELETE', '/api/v1/management/commit-confirm/' . rawurlencode($cid));
			} catch (Throwable $e) {
			}
			throw new RuntimeException("{$what}: " . fleet_box_error($code, $json) . ' Rolled back on this firewall.');
		}
	}
	/*
	 * A CARP event reloads interfaces and services, so the Fleet tunnel may
	 * blip for a while: keep checking and confirming for up to two minutes
	 * (well inside the commit-confirm window) before giving up.
	 */
	$say('Checking Fleet still reaches it');
	$until = time() + 120;
	$last = '';
	do {
		sleep(5);
		try {
			$now = fleet_box_get($box['node_id']) ?? $box;
			list($code) = fleet_box_call($now, 'GET', '/api/v1/management/status');
			if ($code !== 200) {
				$last = "HTTP {$code}";
				continue;
			}
			list($code, $json) = fleet_box_call($now, 'POST', '/api/v1/management/commit-confirm/' . rawurlencode($cid) . '/confirm');
			if (($code >= 200) && ($code < 300)) {
				return;
			}
			$last = 'Confirm: ' . fleet_box_error($code, $json);
		} catch (Throwable $e) {
			$last = $e->getMessage();
		}
	} while (time() < $until);
	throw new RuntimeException("FLEET-E310: Fleet could not reach and confirm the firewall after the change ({$last}); it puts its previous configuration back by itself.");
}

/* After a lost answer: wait up to two minutes for the firewall, then ask $landed (box => bool) whether the change is there. */
function fleet_ha_landed(array $box, callable $landed): bool {
	$until = time() + 120;
	do {
		sleep(5);
		try {
			$now = fleet_box_get($box['node_id']) ?? $box;
			list($code) = fleet_box_call($now, 'GET', '/api/v1/management/status');
			if ($code === 200) {
				return (bool)$landed($now);
			}
		} catch (Throwable $e) {
		}
	} while (time() < $until);
	return false;
}

/* Undo a setup on one firewall: its Fleet CARP addresses, and the sync settings and user Fleet made. Best effort; returns problems. */
function fleet_ha_setup_undo(array $box, bool $primary): array {
	$problems = array();
	/* First any open setup window: cancelling it puts the firewall's previous configuration back at once (and it can never expire later, under another change). */
	try {
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/management/commit-confirm');
		foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $c) {
			if (($c['label'] ?? '') === FLEET_HA_LABEL) {
				fleet_box_call($box, 'DELETE', '/api/v1/management/commit-confirm/' . rawurlencode((string)$c['id']));
			}
		}
	} catch (Throwable $e) {
		$problems[] = "{$box['label']}: an open commit-confirm could not be cancelled (" . $e->getMessage() . '); it reverts by itself at its deadline';
	}
	try {
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/virtual-ips');
		$ids = array();
		foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $i => $v) {
			if (strpos((string)($v['descr'] ?? ''), FLEET_HA_MARK) === 0) {
				$ids[] = (int)($v['id'] ?? $i);
			}
		}
		rsort($ids);
		foreach ($ids as $id) {
			list($code, $json) = fleet_box_call($box, 'DELETE', "/api/v1/firewall/virtual-ips/{$id}?apply=true");
			if (($code < 200) || ($code >= 300)) {
				$problems[] = "{$box['label']}: address {$id}: " . fleet_box_error($code, $json);
			}
		}
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/rules');
		$rids = array();
		foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $i => $r) {
			if (strpos((string)($r['descr'] ?? ''), FLEET_HA_MARK) === 0) {
				$rids[] = (int)($r['id'] ?? $i);
			}
		}
		rsort($rids);
		foreach ($rids as $id) {
			list($code, $json) = fleet_box_call($box, 'DELETE', "/api/v1/firewall/rules/{$id}");
			if (($code < 200) || ($code >= 300)) {
				$problems[] = "{$box['label']}: rule {$id}: " . fleet_box_error($code, $json);
			}
		}
		if (!empty($rids)) {
			fleet_box_call($box, 'POST', '/api/v1/firewall/apply');
		}
		list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/system/hasync', $primary ?
		    array('synchronizetoip' => '', 'username' => '', 'pfsyncenabled' => false, 'pfsyncpeerip' => '') : array('pfsyncenabled' => false, 'pfsyncpeerip' => ''));
		if (($code < 200) || ($code >= 300)) {
			$problems[] = "{$box['label']}: HA sync settings: " . fleet_box_error($code, $json);
		}
		if (!$primary) {
			fleet_box_call($box, 'DELETE', '/api/v1/management/ha-sync-user');
		}
	} catch (Throwable $e) {
		$problems[] = "{$box['label']}: " . $e->getMessage();
	}
	return $problems;
}

/* The run (freesense-fleet-run ha-setup <op>). */
function fleet_ha_setup_run(int $op): void {
	$row = fleet_db()->prepare('SELECT data, who FROM ops WHERE id = ?');
	$row->execute(array($op));
	$r = $row->fetch();
	/* An open cursor keeps an SQLite read snapshot; the next write after another process wrote would fail at once. */
	$row->closeCursor();
	$plan = json_decode((string)($r['data'] ?? ''), true);
	$who = (string)($r['who'] ?? 'fleet');
	$tasks = array_column(fleet_op_tasks($op), null, 'node_id');
	$p = fleet_box_get((string)($plan['primary'] ?? ''));
	$s = fleet_box_get((string)($plan['secondary'] ?? ''));
	if (!is_array($plan) || ($p === null) || ($s === null)) {
		fleet_op_set($op, 'failed', 'The setup or a firewall is gone.');
		return;
	}
	$tp = (int)$tasks[$p['node_id']]['id'];
	$ts = (int)$tasks[$s['node_id']]['id'];
	/* Made for this run only; the firewalls keep them, Fleet does not. */
	$carp_pass = bin2hex(random_bytes(16));
	$sync_pass = bin2hex(random_bytes(24));
	$fail = function (string $why, int $task) use ($op, $p, $s, $tp, $ts, $who) {
		$undo = array_merge(fleet_ha_setup_undo($s, false), fleet_ha_setup_undo($p, true));
		fleet_op_set($task, 'failed', $why);
		foreach (array($tp, $ts) as $t) {
			if ($t !== $task) {
				fleet_op_set($t, 'failed', 'Undone: the setup did not finish.');
			}
		}
		$text = $why . (empty($undo) ? ' Everything Fleet set up was undone.' : ' Undo was incomplete: ' . implode('; ', $undo));
		fleet_op_set($op, 'failed', $text);
		fleet_audit($who, 'ha_setup', "{$p['label']} and {$s['label']}: failed: {$text}");
	};
	try {
		fleet_op_set($ts, 'running', 'Creating the HA sync user');
		list($code, $json) = fleet_box_call($s, 'PUT', '/api/v1/management/ha-sync-user', array('bcrypt_hash' => password_hash($sync_pass, PASSWORD_BCRYPT)));
		if (($code < 200) || ($code >= 300)) {
			throw new RuntimeException('HA sync user: ' . fleet_box_error($code, $json));
		}
		fleet_op_set($ts, 'queued', 'Waiting for the primary');
	} catch (Throwable $e) {
		$fail($e->getMessage(), $ts);
		return;
	}
	$steps = function (array $plan, bool $primary, string $carp_pass, string $sync_pass, int $gui_port): array {
		$out = array();
		/* The sync interface lets the peer's state and configuration sync in. */
		foreach (fleet_ha_rule_bodies($plan, $primary, $gui_port) as $rb) {
			$out[] = array('POST', '/api/v1/firewall/rules', $rb + array('after' => -1), 'Rule: ' . substr($rb['descr'], strlen(FLEET_HA_MARK) + 1),
			    function (array $box) use ($rb) { return fleet_ha_has_rule($box, $rb['descr']); });
		}
		foreach ($plan['vips'] as $v) {
			$out[] = array('POST', '/api/v1/firewall/virtual-ips?apply=true', fleet_ha_vip_body($v, $primary ? 0 : 100, $carp_pass), "Shared address {$v['address']} on {$v['name']}",
			    function (array $box) use ($v) {
				list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/virtual-ips');
				foreach ((($code === 200) ? (array)($json['data'] ?? array()) : array()) as $x) {
					if ((($x['mode'] ?? '') === 'carp') && ((int)($x['vhid'] ?? 0) === $v['vhid']) && (($x['subnet'] ?? '') === $v['address'])) {
						return true;
					}
				}
				return false;
			});
		}
		$out[] = array('PUT', '/api/v1/system/hasync', fleet_ha_sync_body($plan, $primary, $sync_pass), $primary ? 'HA sync to the secondary' : 'State sync (pfsync)',
		    function (array $box) use ($plan, $primary) {
			list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/system/hasync');
			$h = ($code === 200) ? (array)($json['data'] ?? array()) : array();
			return !empty($h['pfsyncenabled']) && (!$primary || (($h['synchronizetoip'] ?? '') === $plan['secondary_sync_ip']));
		});
		$out[] = array('POST', '/api/v1/firewall/apply', null, 'Reloading the filter', function (array $box) { return true; });
		return $out;
	};
	foreach (array(array($p, $tp, true), array($s, $ts, false)) as list($box, $task, $primary)) {
		try {
			fleet_op_set($task, 'running', 'Starting');
			fleet_ha_setup_box($box, $who, FLEET_HA_LABEL, $steps($plan, $primary, $carp_pass, $sync_pass, $primary ? 443 : fleet_ha_gui_port($box)), function (string $t) use ($task) {
				fleet_op_set($task, 'running', $t);
			});
			fleet_op_set($task, 'running', $primary ? 'Set up; waiting for the secondary' : 'Set up');
		} catch (Throwable $e) {
			$fail($e->getMessage(), $task);
			return;
		}
	}
	/* The pair must settle: found, one MASTER per address, and that is the primary. */
	fleet_op_set($op, 'running', 'Checking the pair', 90);
	$until = time() + FLEET_HA_SETTLE;
	$why = 'The pair did not show up.';
	do {
		sleep(10);
		fleet_poll_box(fleet_box_get($p['node_id']), time());
		fleet_poll_box(fleet_box_get($s['node_id']), time());
		list($pairs) = fleet_ha_now();
		$pair = fleet_ha_pair_of($pairs, $p['node_id']);
		if ($pair === null || !in_array($s['node_id'], $pair['nodes'], true)) {
			$why = 'Fleet does not see the two as a pair (the CARP addresses do not match).';
			continue;
		}
		if ($pair['problem'] !== null) {
			$why = ($pair['problem'][0] === 'split') ? 'Both became MASTER: the firewalls do not see each other on ' . fleet_ha_vip_text($pair['problem'][1]) . '.' :
			    'No firewall is MASTER for ' . fleet_ha_vip_text($pair['problem'][1]) . '.';
			continue;
		}
		if ($pair['masters'] !== array($p['node_id'])) {
			$why = 'The secondary is MASTER, not the primary.';
			continue;
		}
		$why = null;
	} while (($why !== null) && (time() < $until));
	if ($why !== null) {
		$fail("FLEET-E601: {$why}", $ts);
		return;
	}
	fleet_op_set($tp, 'done', 'MASTER');
	fleet_op_set($ts, 'done', 'BACKUP');
	fleet_op_set($op, 'done', sprintf('%s is MASTER and %s BACKUP for %s.', $p['label'], $s['label'], implode(', ', array_column($plan['vips'], 'address'))));
	fleet_audit($who, 'ha_setup', "{$p['label']} and {$s['label']}: pair set up");
}
