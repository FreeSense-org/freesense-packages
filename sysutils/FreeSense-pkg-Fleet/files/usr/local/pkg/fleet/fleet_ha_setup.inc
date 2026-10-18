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
/* The encrypted link between the pair: its default UDP port, how long the two get to see each other, the REST level it needs. */
define('FLEET_HA_LINK_PORT', 51831);
define('FLEET_HA_LINK_WAIT', 90);
define('FLEET_HA_LINK_API', 15);
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
		    'bits' => $bits, 'up' => in_array($i['status'] ?? '', array('up', 'associated'), true), 'dev' => (string)($i['hwif'] ?? ''), 'clash' => array());
	}
	/* Two assignments on one network card: their addresses cannot be told apart, so neither is offered. */
	foreach ($out as $k => $i) {
		foreach ($out as $k2 => $j) {
			if (($k !== $k2) && ($i['dev'] !== '') && ($i['dev'] === $j['dev'])) {
				$out[$k]['clash'][] = $j['name'];
			}
		}
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
		if (($b['busy'] ?? '') !== '') {
			$e[] = "{$name} is busy with another operation ({$b['busy']}): wait until it is done.";
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
	$tunnel = (($in['sync_mode'] ?? 'interface') === 'tunnel');
	$sync = (string)($in['sync_iface'] ?? '');
	$ps = $p['ifaces'][$sync] ?? null;
	$ss = $s['ifaces'][$sync] ?? null;
	$link = null;
	if ($tunnel) {
		/* The two firewalls get a WireGuard link of their own; the sync interface is made on them. */
		foreach (array('primary' => $p, 'secondary' => $s) as $which => $b) {
			if ((int)($b['api_level'] ?? 0) < FLEET_HA_LINK_API) {
				$e[] = ($b['label'] ?? $which) . ' needs FreeSense with REST API level ' . FLEET_HA_LINK_API . ' for the encrypted link (update it first).';
			}
		}
		$ends = array();
		foreach (array('p' => 'primary', 's' => 'secondary') as $k => $which) {
			$host = trim((string)($in["link_host_{$k}"] ?? ''));
			$port = (int)($in["link_port_{$k}"] ?? FLEET_HA_LINK_PORT);
			$name = (($which === 'primary') ? $p : $s)['label'] ?? $which;
			if (($port < 1) || ($port > 65535)) {
				$e[] = "{$name}: the link port must be 1-65535.";
			}
			if (($host !== '') && (fleet_halink_endpoint_of($host, $port) === null)) {
				$e[] = "{$name}: \"{$host}\" is not a host name or IPv4 address.";
			}
			$ends[$k] = array('host' => $host, 'port' => $port, 'endpoint' => ($host === '') ? '' : "{$host}:{$port}");
		}
		if (($ends['p']['endpoint'] === '') && ($ends['s']['endpoint'] === '')) {
			$e[] = 'At least one firewall needs an address the other can reach for the encrypted link (the other one then connects to it).';
		}
		$used = array();
		foreach (array($p, $s) as $b) {
			foreach ((array)($b['ifaces'] ?? array()) as $i) {
				if ((($i['ip'] ?? '') !== '') && (($i['bits'] ?? null) !== null)) {
					$used[] = array($i['ip'], (int)$i['bits']);
				}
			}
		}
		$net = fleet_ha_link_net($used);
		if ($net === null) {
			$e[] = 'No free private network is left for the encrypted link.';
		}
		$link = ($net === null) ? null : array('net' => $net[0], 'bits' => 30, 'primary_ip' => $net[1], 'secondary_ip' => $net[2],
		    'endpoint_p' => $ends['p']['endpoint'], 'endpoint_s' => $ends['s']['endpoint'], 'port_p' => $ends['p']['port'], 'port_s' => $ends['s']['port']);
	} elseif (($ps === null) || ($ss === null) || ($ps['ip'] === '') || ($ss['ip'] === '')) {
		$e[] = 'Choose a sync interface with an IPv4 address on both firewalls.';
	}
	$sections = array_values(array_intersect((array)($in['sections'] ?? array()), array_keys(FLEET_HA_SECTIONS)));
	if (!empty($sections) && !preg_match('/^[0-9a-f]{64}$/D', (string)($s['gui_cert'] ?? ''))) {
		$e[] = ($s['label'] ?? 'The secondary') . ' does not report its WebGUI certificate yet (it needs the System update); without it the primary cannot trust it for configuration sync. Update it, or choose no sync sections.';
	}
	if (!empty($e)) {
		return array(array_values(array_unique($e)), null);
	}
	$plan = array('primary' => $in['primary'], 'secondary' => $in['secondary'], 'vips' => $vips, 'sections' => $sections, 'secondary_cert' => (string)($s['gui_cert'] ?? ''));
	if ($tunnel) {
		return array(array(), $plan + array('sync_mode' => 'tunnel', 'sync_iface' => '', 'link' => $link, 'primary_sync_ip' => $link['primary_ip'], 'secondary_sync_ip' => $link['secondary_ip'],
		    'sync_bits' => 30, 'sync_net' => $link['net']));
	}
	return array(array(), $plan + array('sync_mode' => 'interface', 'sync_iface' => $sync, 'primary_sync_ip' => $ps['ip'], 'secondary_sync_ip' => $ss['ip'], 'sync_bits' => (int)$ps['bits'],
	    'sync_net' => long2ip(ip2long($ps['ip']) & ((0xffffffff << (32 - (int)$ps['bits'])) & 0xffffffff))));
}

/* pure: "host:port" when the host is an IPv4 address or a DNS name, else null. */
function fleet_halink_endpoint_of(string $host, int $port): ?string {
	$name = '/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/D';
	return (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || preg_match($name, $host)) ? "{$host}:{$port}" : null;
}

/*
 * pure: the first free /30 of 10.254.0.0/16 that overlaps none of the
 * networks in use ($used: [[address, bits], ...]), as array(network,
 * primary address, secondary address); null when none is left.
 */
function fleet_ha_link_net(array $used): ?array {
	$base = ip2long('10.254.0.0');
	for ($n = 0; $n < 16384; $n++) {
		$net = long2ip($base + $n * 4);
		$free = true;
		foreach ($used as list($ip, $bits)) {
			if (fleet_ha_in_net($net, (string)$ip, (int)$bits) || fleet_ha_in_net((string)$ip, $net, 30)) {
				$free = false;
				break;
			}
		}
		if ($free) {
			return array($net, long2ip($base + $n * 4 + 1), long2ip($base + $n * 4 + 2));
		}
	}
	return null;
}

/*
 * pure: the request that makes one firewall's end of the link ($primary:
 * which end). The firewall connects to the other one's endpoint when it has
 * one (with keepalive, which also keeps a NAT open); otherwise it waits.
 */
function fleet_ha_link_body(array $plan, bool $primary, string $peer_public_key): array {
	$l = $plan['link'];
	$peer_endpoint = $primary ? $l['endpoint_s'] : $l['endpoint_p'];
	return array('address' => $primary ? $l['primary_ip'] : $l['secondary_ip'], 'bits' => 30, 'peer_address' => $primary ? $l['secondary_ip'] : $l['primary_ip'],
	    'peer_public_key' => $peer_public_key, 'peer_endpoint' => $peer_endpoint, 'keepalive' => ($peer_endpoint !== '') ? 25 : 0);
}

/* pure: the UDP port a firewall listens on for the link. */
function fleet_ha_link_port(array $plan, bool $primary): int {
	return (int)($primary ? $plan['link']['port_p'] : $plan['link']['port_s']);
}

/*
 * pure: the rules for the link's own packets on the WAN, in (to this firewall's link port) and out (from it: WireGuard sends from its
 * listen port), both without state. With state, pfsync would sync the link's packets as states and every pfsync packet that crosses the
 * link would update one again: a storm of millions of packets after setup. A firewall that connects out needs the incoming rule too,
 * because nothing keeps a state for the answers.
 */
function fleet_ha_link_rule_bodies(array $plan, bool $primary): array {
	$port = (string)fleet_ha_link_port($plan, $primary);
	$base = array('type' => 'pass', 'ipprotocol' => 'inet', 'log' => false, 'quick' => true, 'proto' => 'udp', 'statetype' => 'none', 'srctype' => 'any', 'src' => '', 'srcmask' => '',
	    'dsttype' => 'any', 'dst' => '', 'dstmask' => '');
	return array(
		array('interface' => 'wan', 'dsttype' => 'wanip', 'dstbeginport' => $port, 'dstendport' => $port, 'descr' => FLEET_HA_MARK . ' Encrypted HA link in (WireGuard)') + $base,
		array('interface' => array('wan'), 'floating' => true, 'direction' => 'out', 'srcbeginport' => $port, 'srcendport' => $port, 'descr' => FLEET_HA_MARK . ' Encrypted HA link out (WireGuard)') + $base,
	);
}

/* pure: the network of an address, as "a.b.c.d/bits". */
function fleet_ha_net(string $ip, int $bits): string {
	return long2ip(ip2long($ip) & (($bits === 0) ? 0 : ((0xffffffff << (32 - $bits)) & 0xffffffff))) . '/' . $bits;
}

/*
 * pure: what two firewalls share: interface key => {name, net, bits, ips}
 * for interfaces with IPv4 on both in the same network. WAN is left out
 * (a shared address there is a choice for the admin, not a default).
 */
function fleet_ha_shared_nets(array $pi, array $si): array {
	$out = array();
	foreach ($pi as $k => $i) {
		$o = $si[$k] ?? null;
		if (($k === 'wan') || ($o === null) || ($i['ip'] === '') || ($o['ip'] === '') || ($i['bits'] === null) || ($i['bits'] > 30) ||
		    !fleet_ha_in_net($o['ip'], $i['ip'], (int)$i['bits'])) {
			continue;
		}
		$out[$k] = array('name' => $i['name'], 'net' => fleet_ha_net($i['ip'], (int)$i['bits']), 'bits' => (int)$i['bits'], 'ips' => array($i['ip'], $o['ip']));
	}
	return $out;
}

/*
 * pure: a suggested setup for two firewalls ($pi/$si: fleet_ha_ifaces()):
 * the sync interface (named like sync, HA, CARP or pfsync, else the
 * smallest shared network), and on every other shared network its first
 * address neither firewall uses as the shared address. Null when they
 * share no network.
 */
function fleet_ha_suggest(array $pi, array $si): ?array {
	$shared = fleet_ha_shared_nets($pi, $si);
	if (empty($shared)) {
		return null;
	}
	$sync = null;
	foreach ($shared as $k => $n) {
		if (preg_match('/sync|ha|^ha|carp/i', $n['name'] . ' ' . $k)) {
			$sync = $k;
			break;
		}
	}
	if ($sync === null) {
		uasort($shared, function ($a, $b) { return $b['bits'] <=> $a['bits']; });
		$sync = (string)array_key_first($shared);
	}
	/* Another interface on the sync network (two assignments of one port) is the same network. */
	$shared = array_filter($shared, function ($n, $k) use ($shared, $sync) {
		return ($k === $sync) || ($n['net'] !== $shared[$sync]['net']);
	}, ARRAY_FILTER_USE_BOTH);
	$vips = array();
	foreach ($shared as $k => $n) {
		if (($k === $sync) && (count($shared) > 1)) {
			continue;
		}
		$base = ip2long(explode('/', $n['net'])[0]);
		$size = 2 ** (32 - $n['bits']);
		for ($h = 1; $h < $size - 1; $h++) {
			$ip = long2ip($base + $h);
			if (!in_array($ip, $n['ips'], true)) {
				$vips[] = array('iface' => $k, 'address' => $ip);
				break;
			}
		}
	}
	return array('vips' => $vips, 'sync_iface' => $sync, 'sections' => array('rules', 'aliases', 'nat'));
}

/*
 * pure: pairs to set up among a group's firewalls ($facts: node =>
 * fleet_ha_setup_facts()): two managed firewalls, not in a pair, that
 * share an internal network. Each firewall is in at most one suggestion;
 * the lower name is the primary.
 */
function fleet_ha_candidates(array $facts): array {
	$nodes = array_keys(array_filter($facts, function ($f) {
		return (($f['role'] ?? '') === 'managed') && empty($f['in_pair']) && (($f['hasync_peer'] ?? '') === '') && !empty($f['ifaces']);
	}));
	usort($nodes, function ($a, $b) use ($facts) { return strnatcasecmp($facts[$a]['label'], $facts[$b]['label']); });
	$used = array();
	$out = array();
	foreach ($nodes as $i => $a) {
		foreach (array_slice($nodes, $i + 1) as $b) {
			if (isset($used[$a]) || isset($used[$b])) {
				continue;
			}
			$sg = fleet_ha_suggest($facts[$a]['ifaces'], $facts[$b]['ifaces']);
			if (($sg === null) || empty($sg['vips'])) {
				continue;
			}
			$out[] = array('primary' => $a, 'secondary' => $b) + $sg;
			$used[$a] = $used[$b] = true;
		}
	}
	return $out;
}

/*
 * pure: how exposed the state sync (pfsync, not encrypted) is on the sync
 * interface of a plan: 'wan' (crosses the internet), 'shared' (the same
 * interface carries a shared address, so other devices are on that network)
 * or null (a network of its own, as far as Fleet can tell).
 */
function fleet_ha_sync_risk(array $plan): ?string {
	if (($plan['sync_mode'] ?? 'interface') === 'tunnel') {
		return null;
	}
	if ($plan['sync_iface'] === 'wan') {
		return 'wan';
	}
	foreach ($plan['vips'] as $v) {
		if ($v['iface'] === $plan['sync_iface']) {
			return 'shared';
		}
	}
	return null;
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
		/* The secondary's WebGUI certificate is pinned: sync trusts exactly it (System > High Availability, peer certificate fingerprint). */
		$b += array('synchronizetoip' => $plan['secondary_sync_ip'], 'username' => 'fleet-hasync', 'password' => $password, 'syncpeerpin' => (string)($plan['secondary_cert'] ?? ''));
		foreach (array_keys(FLEET_HA_SECTIONS) as $sec) {
			$b['synchronize' . $sec] = in_array($sec, $plan['sections'], true);
		}
	}
	return $b;
}

/*
 * pure: the rules the sync interface needs. The same on both firewalls,
 * and right on either: HA sync copies the primary's rules to the
 * secondary, so they must not name "the other one". pfsync from the sync
 * network; the primary's configuration sync to this interface's address
 * on the secondary's WebGUI port ($gui_port).
 */
function fleet_ha_rule_bodies(array $plan, int $gui_port): array {
	/* The states of the sync traffic itself must not be synced: pfsync would send updates about its own packets, again and again. */
	$base = array('type' => 'pass', 'interface' => $plan['sync_iface'], 'ipprotocol' => 'inet', 'log' => false, 'nopfsync' => true);
	/*
	 * pfsync packets carry IP options (router alert), so a rule needs allow-opts to match them. They get no state: with one, pfsync would sync
	 * the state of its own packets, and every pfsync packet would update it again (a storm of millions of packets after setup). Outgoing is a
	 * floating rule on the sync interface.
	 */
	$out = array('type' => 'pass', 'interface' => array($plan['sync_iface']), 'floating' => true, 'direction' => 'out', 'quick' => true, 'ipprotocol' => 'inet', 'log' => false,
	    'statetype' => 'none', 'allowopts' => true, 'proto' => 'pfsync', 'srctype' => 'any', 'src' => '', 'srcmask' => '', 'dsttype' => 'any', 'dst' => '', 'dstmask' => '',
	    'dstbeginport' => '', 'dstendport' => '', 'descr' => FLEET_HA_MARK . ' State sync (pfsync) out');
	return array(
		$out,
		$base + array('allowopts' => true, 'statetype' => 'none', 'quick' => true, 'proto' => 'pfsync', 'srctype' => 'network', 'src' => $plan['sync_net'], 'srcmask' => (string)$plan['sync_bits'],
		    'dsttype' => 'any', 'dst' => '', 'dstmask' => '', 'dstbeginport' => '', 'dstendport' => '',
		    'descr' => FLEET_HA_MARK . ' State sync (pfsync) on the sync network'),
		$base + array('proto' => 'tcp', 'srctype' => 'single', 'src' => $plan['primary_sync_ip'], 'srcmask' => '',
		    'dsttype' => $plan['sync_iface'] . 'ip', 'dst' => '', 'dstmask' => '', 'dstbeginport' => (string)$gui_port, 'dstendport' => (string)$gui_port,
		    'descr' => FLEET_HA_MARK . ' Configuration sync from the HA primary'),
	);
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

/* The operation (reboot, update...) that is queued or running on a firewall, as words, or ''. A reboot in the middle of a setup undoes it. */
function fleet_ha_busy(string $node): string {
	$st = fleet_db()->prepare("SELECT kind FROM ops WHERE node_id = ? AND state IN ('queued', 'running') ORDER BY id DESC LIMIT 1");
	$st->execute(array($node));
	$kind = (string)$st->fetchColumn();
	return ($kind === '') ? '' : (defined('FLEET_OPS_KINDS') && isset(FLEET_OPS_KINDS[$kind]) ? strtolower(FLEET_OPS_KINDS[$kind]) : str_replace('_', ' ', $kind));
}

/* What setup needs to know about a firewall now (reads its interfaces and virtual IPs live). */
function fleet_ha_setup_facts(array $box): array {
	$st = json_decode((string)$box['status'], true) ?: array();
	list($pairs) = fleet_ha_now();
	$f = array('label' => $box['label'], 'role' => $box['role'], 'state' => $box['state'], 'api_level' => (int)($st['api_level'] ?? 0),
	    'in_pair' => fleet_ha_pair_of($pairs, $box['node_id']) !== null, 'hasync_peer' => (string)($st['hasync']['peer'] ?? ''),
	    'gui_cert' => (string)($st['webgui_cert_sha256'] ?? ''), 'busy' => fleet_ha_busy($box['node_id']),
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
		/* syncpeerpin only where the System knows it (it then reports its WebGUI certificate). */
		$knows_pin = isset((json_decode((string)$box['status'], true) ?: array())['webgui_cert_sha256']);
		list($code, $json) = fleet_box_call($box, 'PUT', '/api/v1/system/hasync', $primary ?
		    array('synchronizetoip' => '', 'username' => '', 'pfsyncenabled' => false, 'pfsyncpeerip' => '') + ($knows_pin ? array('syncpeerpin' => '') : array()) : array('pfsyncenabled' => false, 'pfsyncpeerip' => ''));
		if (($code < 200) || ($code >= 300)) {
			$problems[] = "{$box['label']}: HA sync settings: " . fleet_box_error($code, $json);
		}
		if (!$primary) {
			fleet_box_call($box, 'DELETE', '/api/v1/management/ha-sync-user');
		}
		/* The encrypted link, if Fleet made one (an older System does not know it: 404). */
		list($code, $json) = fleet_box_call($box, 'DELETE', '/api/v1/management/ha-link');
		if ((($code < 200) || ($code >= 300)) && ($code !== 404)) {
			$problems[] = "{$box['label']}: encrypted link: " . fleet_box_error($code, $json);
		}
	} catch (Throwable $e) {
		$problems[] = "{$box['label']}: " . $e->getMessage();
	}
	return $problems;
}

/*
 * The encrypted link of a plan in tunnel mode. Both firewalls make their key
 * first (a firewall without the WireGuard package installs it, which takes a
 * few minutes: it answers 202 until then). Each then makes its end under
 * commit-confirm, with the rule that lets the other connect to it, and the
 * two must see each other. Returns array(primary interface, secondary
 * interface); the keys stay inside this function. Throws RuntimeException.
 */
function fleet_ha_link_up(array $p, array $s, array $plan, string $who, callable $say): array {
	$keys = array();
	foreach (array(array($p, true), array($s, false)) as list($box, $primary)) {
		$say("{$box['label']}: making its key for the encrypted link");
		$until = time() + 420;
		$key = '';
		do {
			list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/ha-link/prepare', array('listen_port' => fleet_ha_link_port($plan, $primary)));
			if (($code === 202) || ($code === 0)) {
				$say("{$box['label']}: installing WireGuard");
				sleep(10);
				continue;
			}
			if ($code !== 200) {
				throw new RuntimeException("{$box['label']}: encrypted link: " . fleet_box_error($code, $json));
			}
			$key = (string)($json['data']['public_key'] ?? '');
			break;
		} while (time() < $until);
		if ($key === '') {
			throw new RuntimeException("{$box['label']}: WireGuard did not get installed in time. It needs internet and the FreeSense package repository.");
		}
		$keys[$box['node_id']] = $key;
	}
	$label = FLEET_HA_LABEL . ' (link)';
	foreach (array(array($p, $s, true), array($s, $p, false)) as list($box, $other, $primary)) {
		$bodies = array();
		foreach (fleet_ha_link_rule_bodies($plan, $primary) as $rule) {
			$bodies[] = array('POST', '/api/v1/firewall/rules', $rule + array('after' => -1), 'Rule: ' . substr($rule['descr'], strlen(FLEET_HA_MARK) + 1),
			    function (array $b) use ($rule) { return fleet_ha_has_rule($b, $rule['descr']); });
		}
		$bodies[] = array('POST', '/api/v1/firewall/apply', null, 'Reloading the filter', function (array $b) { return true; });
		$bodies[] = array('PUT', '/api/v1/management/ha-link', fleet_ha_link_body($plan, $primary, $keys[$other['node_id']]), 'Encrypted link',
		    function (array $b) {
			list($code, $json) = fleet_box_call($b, 'GET', '/api/v1/management/ha-link');
			return ($code === 200) && !empty($json['data']['present']);
		});
		fleet_ha_setup_box($box, $who, $label, $bodies, $say);
	}
	/* Each end must have seen the other. */
	$say('Waiting for the two firewalls to see each other over the link');
	$until = time() + FLEET_HA_LINK_WAIT;
	$ifs = array();
	do {
		sleep(5);
		$ifs = array();
		foreach (array($p, $s) as $box) {
			try {
				list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/management/ha-link');
			} catch (Throwable $e) {
				$code = 0;
				$json = array();
			}
			if (($code === 200) && !empty($json['data']['present']) && ((int)($json['data']['latest_handshake'] ?? 0) > 0) && (($json['data']['interface'] ?? '') !== '')) {
				$ifs[$box['node_id']] = (string)$json['data']['interface'];
			}
		}
	} while ((count($ifs) < 2) && (time() < $until));
	if (count($ifs) < 2) {
		throw new RuntimeException('FLEET-E602: The two firewalls did not see each other over the encrypted link. Check that ' .
		    (($plan['link']['endpoint_p'] !== '') ? "{$plan['link']['endpoint_p']}" : '') . (($plan['link']['endpoint_p'] !== '') && ($plan['link']['endpoint_s'] !== '') ? ' and ' : '') .
		    (($plan['link']['endpoint_s'] !== '') ? "{$plan['link']['endpoint_s']}" : '') . ' can be reached on UDP from the other firewall.');
	}
	return array($ifs[$p['node_id']], $ifs[$s['node_id']]);
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
		foreach (fleet_ha_rule_bodies($plan, $gui_port) as $rb) {
			$out[] = array('POST', '/api/v1/firewall/rules', $rb + array('after' => -1), 'Rule: ' . substr($rb['descr'], strlen(FLEET_HA_MARK) + 1),
			    function (array $box) use ($rb) { return fleet_ha_has_rule($box, $rb['descr']); });
		}
		/* The rules must be loaded before pfsync starts: a pfsync packet sent under the default rules makes a state that is synced, and the two firewalls then keep refreshing it for each other. */
		$out[] = array('POST', '/api/v1/firewall/apply', null, 'Loading the sync rules', function (array $box) { return true; });
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
	/* The secondary's WebGUI port, which the primary's configuration sync connects to (the same rule on both). */
	try {
		$gui_port = fleet_ha_gui_port($s);
	} catch (Throwable $e) {
		$fail('The WebGUI port of the secondary could not be read: ' . $e->getMessage(), $ts);
		return;
	}
	$ifaces = array();
	if (($plan['sync_mode'] ?? 'interface') === 'tunnel') {
		try {
			fleet_op_set($tp, 'running', 'Making the encrypted link');
			list($ifaces[$p['node_id']], $ifaces[$s['node_id']]) = fleet_ha_link_up($p, $s, $plan, $who, function (string $t) use ($tp) {
				fleet_op_set($tp, 'running', $t);
			});
			fleet_op_set($tp, 'queued', 'Waiting');
		} catch (Throwable $e) {
			$fail($e->getMessage(), $tp);
			return;
		}
	}
	foreach (array(array($p, $tp, true), array($s, $ts, false)) as list($box, $task, $primary)) {
		try {
			fleet_op_set($task, 'running', 'Starting');
			/* On the encrypted link the sync interface is the one that firewall made for it. */
			$boxplan = isset($ifaces[$box['node_id']]) ? array('sync_iface' => $ifaces[$box['node_id']]) + $plan : $plan;
			fleet_ha_setup_box($box, $who, FLEET_HA_LABEL, $steps($boxplan, $primary, $carp_pass, $sync_pass, $gui_port), function (string $t) use ($task) {
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
			$why = ($pair['problem'][0] === 'down') ? 'A firewall of the pair does not answer.' :
			    (($pair['problem'][0] === 'split') ? 'Both became MASTER: the firewalls do not see each other on ' . fleet_ha_vip_text($pair['problem'][1]) . '.' :
			    'No firewall is MASTER for ' . fleet_ha_vip_text($pair['problem'][1]) . '.');
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

/* ------------------------------------------------------------------ */
/* Remove a pair                                                       */
/* ------------------------------------------------------------------ */

/*
 * Start removing an HA pair in the background: the shared addresses, the
 * sync settings, the rules and the encrypted link Fleet made, on both
 * firewalls (the secondary first). $pair: a fleet_ha_pairs() entry.
 * Returns the operation id.
 */
function fleet_ha_remove_launch(array $pair, string $who): int {
	$primary = $pair['primary'] ?? null;
	$nodes = $pair['nodes'];
	/* The secondary goes first; without a known primary, the order of the list. */
	usort($nodes, function ($a, $b) use ($primary) { return (int)($a === $primary) <=> (int)($b === $primary); });
	$boxes = array_map('fleet_box_get', $nodes);
	$labels = array_map(function ($b) { return $b['label']; }, array_filter($boxes));
	$op = fleet_op_group_start('ha_remove', 'Remove HA pair ' . implode(' and ', $labels), $who);
	foreach ($nodes as $n) {
		fleet_op_start($n, 'ha_remove', 'Waiting', $who, $op, 'queued');
	}
	fleet_db()->prepare('UPDATE ops SET data = ? WHERE id = ?')->execute(array(json_encode(array('nodes' => $nodes, 'primary' => $primary)), $op));
	fleet_audit($who, 'ha_remove', implode(' and ', $labels));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run ha-remove ' . (int)$op);
	return $op;
}

/* The run (freesense-fleet-run ha-remove <op>). */
function fleet_ha_remove_run(int $op): void {
	$row = fleet_db()->prepare('SELECT data, who FROM ops WHERE id = ?');
	$row->execute(array($op));
	$r = $row->fetch();
	$row->closeCursor();
	$data = json_decode((string)($r['data'] ?? ''), true);
	$who = (string)($r['who'] ?? 'fleet');
	$tasks = array_column(fleet_op_tasks($op), null, 'node_id');
	if (!is_array($data) || empty($data['nodes'])) {
		fleet_op_set($op, 'failed', 'The pair is gone.');
		return;
	}
	$problems = array();
	foreach ($data['nodes'] as $node) {
		$box = fleet_box_get((string)$node);
		$task = (int)($tasks[$node]['id'] ?? 0);
		if ($box === null) {
			$problems[] = "{$node}: the firewall is gone";
			fleet_op_set($task, 'failed', 'The firewall is gone.');
			continue;
		}
		fleet_op_set($task, 'running', 'Removing the pair settings');
		$undo = fleet_ha_setup_undo($box, ($data['primary'] ?? null) === $node);
		if (empty($undo)) {
			fleet_op_set($task, 'done', 'Removed');
		} else {
			fleet_op_set($task, 'failed', implode('; ', $undo));
			$problems = array_merge($problems, $undo);
		}
	}
	/* So the pair list is right at once, not at the next check. */
	foreach ($data['nodes'] as $node) {
		$box = fleet_box_get((string)$node);
		if ($box !== null) {
			fleet_poll_box($box, time());
		}
	}
	if (!empty($problems)) {
		fleet_op_set($op, 'failed', 'Not everything could be removed: ' . implode('; ', $problems));
		fleet_audit($who, 'ha_remove', 'failed: ' . implode('; ', $problems));
		return;
	}
	fleet_op_set($op, 'done', 'The pair is removed: the shared addresses, the sync settings and the encrypted link are gone from both firewalls.');
	fleet_audit($who, 'ha_remove', 'pair removed');
}
