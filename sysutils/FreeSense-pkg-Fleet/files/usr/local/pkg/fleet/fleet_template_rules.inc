<?php
/*
 * fleet_template_rules.inc
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
 * Rule and port forward templates. Each entry the template pushes is
 * marked in its description, "[Fleet:T<template>:<key>] text", so Fleet
 * finds it again and never touches an entry it did not push. A template's
 * filter rules come first on their interface, in the template's order;
 * the firewall's own rules keep their order after them.
 *
 * Applying is guarded: a safety backup, then a commit-confirm window on
 * the firewall, the changes and one filter reload, then Fleet checks it
 * still reaches the firewall. Only then is the change confirmed. A rule
 * that cuts Fleet off is reverted by the firewall itself at the deadline
 * (FLEET-E310). Functions marked "pure" touch neither the network nor the
 * database.
 */

require_once('fleet/fleet_store.inc');

/* kind => array(name, icon, what it holds, the list route, API level). */
define('FLEET_TLIST_KINDS', array(
	'rules' => array('Firewall rules', 'fa-shield-halved', 'Pass and block rules, first on their interface', '/api/v1/firewall/rules', 11),
	'nat' => array('Port forwards', 'fa-right-left', 'NAT port forwards with their firewall rule', '/api/v1/firewall/nat/port-forwards', 11),
));
define('FLEET_TRULE_ACTIONS', array('pass' => 'Pass', 'block' => 'Block', 'reject' => 'Reject'));
define('FLEET_TRULE_PROTOS', array('any' => 'Any', 'tcp' => 'TCP', 'udp' => 'UDP', 'tcp/udp' => 'TCP and UDP', 'icmp' => 'ICMP'));
/* Commit-confirm window for a rule or NAT change, and how long Fleet tries to reach the firewall after it. */
define('FLEET_TLIST_CONFIRM', 300);
define('FLEET_TLIST_VERIFY', 45);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: the description marker of one entry. */
function fleet_tlist_marker(int $tid, string $key): string {
	return "[Fleet:T{$tid}:{$key}]";
}

/* pure: array(template id, key) of a marked description, or null. */
function fleet_tlist_owner(string $descr): ?array {
	return preg_match('/^\[Fleet:T(\d+):([a-z0-9_-]{1,24})\]/', $descr, $m) ? array((int)$m[1], $m[2]) : null;
}

/* pure: an interface key (wan, lan, opt3). */
function fleet_tlist_iface_ok(string $i): bool {
	return (bool)preg_match('/^(wan|lan|opt\d{1,3})$/D', $i);
}

/*
 * pure: a source or destination: "any", an interface's network ("lan")
 * or address ("lanip"), an address, a network (CIDR) or an alias name.
 */
function fleet_tlist_addr_ok(string $a): bool {
	if (($a === 'any') || preg_match('/^(wan|lan|opt\d{1,3})(ip)?$/D', $a) || (filter_var($a, FILTER_VALIDATE_IP) !== false)) {
		return true;
	}
	if (strpos($a, '/') !== false) {
		list($ip, $bits) = explode('/', $a, 2);
		$max = (strpos($ip, ':') !== false) ? 128 : 32;
		return (filter_var($ip, FILTER_VALIDATE_IP) !== false) && ctype_digit($bits) && ((int)$bits <= $max);
	}
	return (bool)preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,30}$/D', $a);
}

/* pure: a port: 443, a range 8000-8080, or an alias name. */
function fleet_tlist_port_ok(string $p): bool {
	if (preg_match('/^(\d{1,5})(-(\d{1,5}))?$/D', $p, $m)) {
		return ((int)$m[1] >= 1) && ((int)$m[1] <= 65535) && (!isset($m[3]) || (((int)$m[3] >= (int)$m[1]) && ((int)$m[3] <= 65535)));
	}
	return (bool)preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,30}$/D', $p);
}

/* pure: one entry of a rule or NAT template from its form, checked. Throws InvalidArgumentException. */
function fleet_tlist_item_from(string $kind, array $in): array {
	$key = strtolower(trim((string)($in['key'] ?? '')));
	$descr = mb_substr(trim(preg_replace('/[\x00-\x1f\x7f]/u', ' ', (string)($in['descr'] ?? ''))), 0, 120);
	$what = ($key !== '') ? $key : 'an entry';
	if (!preg_match('/^[a-z0-9_-]{1,24}$/D', $key)) {
		throw new InvalidArgumentException("Give {$what} a short name: 1 to 24 letters, digits, - or _.");
	}
	$iface = strtolower(trim((string)($in['iface'] ?? '')));
	if (!fleet_tlist_iface_ok($iface)) {
		throw new InvalidArgumentException("{$key}: the interface is wan, lan or optN.");
	}
	$proto = (string)($in['proto'] ?? 'any');
	$port = trim((string)($in['port'] ?? ''));
	if ($kind === 'rules') {
		$action = (string)($in['action'] ?? 'pass');
		if (!isset(FLEET_TRULE_ACTIONS[$action]) || !isset(FLEET_TRULE_PROTOS[$proto])) {
			throw new InvalidArgumentException("{$key}: choose an action and a protocol.");
		}
		$src = trim((string)($in['src'] ?? 'any')) ?: 'any';
		$dst = trim((string)($in['dst'] ?? 'any')) ?: 'any';
		foreach (array('source' => $src, 'destination' => $dst) as $label => $a) {
			if (!fleet_tlist_addr_ok($a)) {
				throw new InvalidArgumentException("{$key}: the {$label} is any, an interface network (lan) or address (lanip), an address, a CIDR network or an alias.");
			}
		}
		if (($port !== '') && (!in_array($proto, array('tcp', 'udp', 'tcp/udp'), true) || !fleet_tlist_port_ok($port))) {
			throw new InvalidArgumentException("{$key}: a port needs TCP or UDP, and is 443, 8000-8080 or an alias.");
		}
		return array('key' => $key, 'action' => $action, 'iface' => $iface, 'proto' => $proto, 'src' => $src, 'dst' => $dst, 'port' => $port,
		    'log' => !empty($in['log']), 'descr' => $descr);
	}
	if (!in_array($proto, array('tcp', 'udp', 'tcp/udp'), true)) {
		throw new InvalidArgumentException("{$key}: a port forward is TCP, UDP or both.");
	}
	$target = trim((string)($in['target'] ?? ''));
	$local = trim((string)($in['local'] ?? ''));
	if (!fleet_tlist_port_ok($port) || (($local !== '') && !fleet_tlist_port_ok($local))) {
		throw new InvalidArgumentException("{$key}: the ports are 443, 8000-8080 or an alias.");
	}
	if (($target === '') || !fleet_tlist_addr_ok($target) || ($target === 'any') || (strpos($target, '/') !== false)) {
		throw new InvalidArgumentException("{$key}: forward to one address or a host alias.");
	}
	return array('key' => $key, 'iface' => $iface, 'proto' => $proto, 'port' => $port, 'target' => $target, 'local' => ($local !== '') ? $local : $port, 'descr' => $descr);
}

/* pure: all entries of a template's form; keys are unique. Throws InvalidArgumentException. */
function fleet_tlist_items_from(string $kind, array $rows): array {
	$items = array();
	$seen = array();
	foreach ($rows as $row) {
		if (!is_array($row) || (trim(implode('', array_map('strval', array_diff_key($row, array('action' => 1, 'proto' => 1, 'iface' => 1, 'log' => 1))))) === '')) {
			continue;
		}
		$item = fleet_tlist_item_from($kind, $row);
		if (isset($seen[$item['key']])) {
			throw new InvalidArgumentException("The name {$item['key']} is in the template twice.");
		}
		$seen[$item['key']] = true;
		$items[] = $item;
	}
	if (empty($items) || (count($items) > FLEET_TEMPLATE_MAX_ITEMS)) {
		throw new InvalidArgumentException('Add 1 to ' . FLEET_TEMPLATE_MAX_ITEMS . (($kind === 'rules') ? ' rules.' : ' port forwards.'));
	}
	return $items;
}

/* pure: an address the REST API's rule form takes: array(type, address, mask). */
function fleet_tlist_addr_fields(string $a): array {
	if ($a === 'any') {
		return array('any', '', '');
	}
	if (preg_match('/^(wan|lan|opt\d{1,3})(ip)?$/D', $a)) {
		return array($a, '', '');
	}
	if (strpos($a, '/') !== false) {
		list($ip, $bits) = explode('/', $a, 2);
		return array('network', $ip, $bits);
	}
	return array('single', $a, '');
}

/* pure: a port as begin and end. */
function fleet_tlist_port_fields(string $p): array {
	if ($p === '') {
		return array('', '');
	}
	$r = explode('-', $p, 2);
	return array($r[0], $r[1] ?? $r[0]);
}

/* pure: the REST body of an entry (the edit page's fields). */
function fleet_tlist_body(string $kind, int $tid, array $item): array {
	$descr = trim(fleet_tlist_marker($tid, $item['key']) . ' ' . $item['descr']);
	list($pb, $pe) = fleet_tlist_port_fields($item['port']);
	if ($kind === 'rules') {
		list($st, $s, $sm) = fleet_tlist_addr_fields($item['src']);
		list($dt, $d, $dm) = fleet_tlist_addr_fields($item['dst']);
		$body = array('type' => $item['action'], 'interface' => $item['iface'], 'ipprotocol' => 'inet', 'proto' => $item['proto'],
		    'srctype' => $st, 'src' => $s, 'srcmask' => $sm, 'dsttype' => $dt, 'dst' => $d, 'dstmask' => $dm,
		    'dstbeginport' => $pb, 'dstendport' => $pe, 'descr' => $descr, 'log' => $item['log']);
		return $body;
	}
	list($lb) = fleet_tlist_port_fields($item['local']);
	return array('interface' => $item['iface'], 'ipprotocol' => 'inet', 'proto' => $item['proto'], 'srctype' => 'any', 'dsttype' => $item['iface'] . 'ip',
	    'dstbeginport' => $pb, 'dstendport' => $pe, 'localip' => $item['target'], 'localbeginport' => $lb, 'descr' => $descr,
	    'filter-rule-association' => 'add-associated');
}

/* pure: an address as the configuration stores it, in the template's words. */
function fleet_tlist_addr_raw($a): string {
	$a = is_array($a) ? $a : array();
	if (isset($a['any'])) {
		return 'any';
	}
	return (string)($a['network'] ?? $a['address'] ?? 'any');
}

/* pure: what decides whether an entry on a firewall matches (the stored form, as GET or config.xml has it). */
function fleet_tlist_norm_raw(string $kind, array $r): array {
	if ($kind === 'rules') {
		return array((string)($r['type'] ?? 'pass'), (string)($r['interface'] ?? ''), (string)($r['protocol'] ?? 'any'),
		    fleet_tlist_addr_raw($r['source'] ?? null), fleet_tlist_addr_raw($r['destination'] ?? null),
		    (string)($r['destination']['port'] ?? ''), isset($r['log']), (string)($r['descr'] ?? ''));
	}
	return array((string)($r['interface'] ?? ''), (string)($r['protocol'] ?? ''), (string)($r['destination']['port'] ?? ''),
	    (string)($r['target'] ?? ''), (string)($r['local-port'] ?? ''), (string)($r['descr'] ?? ''));
}

/* pure: the same for a template entry. */
function fleet_tlist_norm_item(string $kind, int $tid, array $item): array {
	$descr = trim(fleet_tlist_marker($tid, $item['key']) . ' ' . $item['descr']);
	if ($kind === 'rules') {
		return array($item['action'], $item['iface'], $item['proto'], $item['src'], $item['dst'], $item['port'], $item['log'], $descr);
	}
	return array($item['iface'], $item['proto'], $item['port'], $item['target'], fleet_tlist_port_fields($item['local'])[0], $descr);
}

/*
 * pure: what applying template $tid takes on a firewall whose entries are
 * $remote (each with its "id": the position the REST API uses). Returns
 * {action: create | update | delete | same, name, detail, id}. Entries
 * the template did not push are never in it.
 */
function fleet_tlist_plan(string $kind, int $tid, array $items, array $remote): array {
	$mine = array();
	foreach ($remote as $r) {
		$o = is_array($r) ? fleet_tlist_owner((string)($r['descr'] ?? '')) : null;
		if (($o !== null) && ($o[0] === $tid)) {
			$mine[$o[1]] = $r;
		}
	}
	$out = array();
	$names = array('tcp/udp' => 'TCP/UDP');
	foreach ($items as $item) {
		$cur = $mine[$item['key']] ?? null;
		unset($mine[$item['key']]);
		$what = ($kind === 'rules') ? sprintf('%s %s on %s', ucfirst($item['action']), $names[$item['proto']] ?? strtoupper($item['proto']), $item['iface']) :
		    sprintf('%s %s to %s:%s', $item['iface'], $item['port'], $item['target'], $item['local']);
		if ($cur === null) {
			$out[] = array('action' => 'create', 'name' => $item['key'], 'detail' => $what, 'id' => null);
		} elseif (($have = fleet_tlist_norm_raw($kind, $cur)) !== ($want = fleet_tlist_norm_item($kind, $tid, $item))) {
			/* Say what differs: "port 5353, template 53". */
			$labels = ($kind === 'rules') ? array('action', 'interface', 'protocol', 'source', 'destination', 'port', 'logging', 'description') :
			    array('interface', 'protocol', 'port', 'target', 'local port', 'description');
			$diff = array();
			foreach ($labels as $i => $label) {
				if ($have[$i] !== $want[$i]) {
					$show = function ($v) { return is_bool($v) ? ($v ? 'on' : 'off') : (($v === '') ? 'none' : (string)$v); };
					$diff[] = sprintf('%s %s, template %s', $label, $show($have[$i]), $show($want[$i]));
				}
			}
			$out[] = array('action' => 'update', 'name' => $item['key'], 'detail' => 'On the firewall: ' . implode('; ', $diff), 'id' => (int)$cur['id']);
		} else {
			$out[] = array('action' => 'same', 'name' => $item['key'], 'detail' => '', 'id' => (int)$cur['id']);
		}
	}
	foreach ($mine as $key => $cur) {
		$out[] = array('action' => 'delete', 'name' => (string)$key, 'detail' => 'No longer in the template', 'id' => (int)$cur['id']);
	}
	return $out;
}

/*
 * pure: the new rule order of each interface the template has rules on:
 * its rules first, in its order, then the others as they were. Only
 * interfaces whose order changes. $remote: the rules with ids.
 */
function fleet_tlist_rule_order(int $tid, array $items, array $remote): array {
	$want = array();
	foreach ($items as $i => $item) {
		$want[$item['iface']][$item['key']] = $i;
	}
	$out = array();
	foreach ($want as $iface => $keys) {
		$mine = array();
		$others = array();
		$now = array();
		foreach ($remote as $r) {
			if (!empty($r['floating']) || ((string)($r['interface'] ?? '') !== $iface)) {
				continue;
			}
			$now[] = (int)$r['id'];
			$o = fleet_tlist_owner((string)($r['descr'] ?? ''));
			if (($o !== null) && ($o[0] === $tid) && isset($keys[$o[1]])) {
				$mine[$keys[$o[1]]] = (int)$r['id'];
			} else {
				$others[] = (int)$r['id'];
			}
		}
		ksort($mine);
		$order = array_merge(array_values($mine), $others);
		if ($order !== $now) {
			$out[$iface] = $order;
		}
	}
	return $out;
}

/* pure: the entries of a configuration backup, as the REST list has them (with ids), or null. */
function fleet_tlist_from_config(string $kind, string $xml): ?array {
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml);
	libxml_use_internal_errors($prev);
	if ($doc === false) {
		return null;
	}
	$out = array();
	$nodes = ($kind === 'rules') ? $doc->filter->rule : $doc->nat->rule;
	foreach ($nodes ?? array() as $i => $node) {
		$r = json_decode(json_encode($node), true) ?: array();
		/* An empty element (<any/>, <log/>) reads as an empty array: keep it as present. */
		foreach (array('source', 'destination') as $side) {
			if (isset($r[$side]['any'])) {
				$r[$side]['any'] = '';
			}
		}
		$out[] = array('id' => count($out)) + $r;
	}
	return $out;
}

/* pure: a firewall's entry in the template's words (adopting it), or null when it is not one the form can say. */
function fleet_tlist_item_from_raw(string $kind, string $key, array $r): ?array {
	$descr = trim((string)preg_replace('/^\[Fleet:T\d+:[a-z0-9_-]+\]\s*/', '', (string)($r['descr'] ?? '')));
	try {
		if ($kind === 'rules') {
			return fleet_tlist_item_from('rules', array('key' => $key, 'action' => (string)($r['type'] ?? 'pass'), 'iface' => (string)($r['interface'] ?? ''),
			    'proto' => (string)($r['protocol'] ?? 'any'), 'src' => fleet_tlist_addr_raw($r['source'] ?? null), 'dst' => fleet_tlist_addr_raw($r['destination'] ?? null),
			    'port' => (string)($r['destination']['port'] ?? ''), 'log' => isset($r['log']), 'descr' => $descr));
		}
		return fleet_tlist_item_from('nat', array('key' => $key, 'iface' => (string)($r['interface'] ?? ''), 'proto' => (string)($r['protocol'] ?? ''),
		    'port' => (string)($r['destination']['port'] ?? ''), 'target' => (string)($r['target'] ?? ''), 'local' => (string)($r['local-port'] ?? ''), 'descr' => $descr));
	} catch (InvalidArgumentException $e) {
		return null;
	}
}

/* ------------------------------------------------------------------ */
/* Reading and applying                                                */
/* ------------------------------------------------------------------ */

/* A firewall's entries of a kind now, over its connection. */
function fleet_tlist_remote(string $kind, array $box): array {
	$st = json_decode((string)($box['status'] ?? ''), true) ?: array();
	if ((int)($st['api_level'] ?? 0) < FLEET_TLIST_KINDS[$kind][4]) {
		throw new RuntimeException(sprintf('FLEET-E401: This firewall is too old for %s templates (it needs the System update with API level %d).',
		    strtolower(FLEET_TLIST_KINDS[$kind][0]), FLEET_TLIST_KINDS[$kind][4]));
	}
	list($code, $json) = fleet_box_call($box, 'GET', FLEET_TLIST_KINDS[$kind][3]);
	if (($code !== 200) || !is_array($json['data'] ?? null)) {
		throw new RuntimeException('The ' . strtolower(FLEET_TLIST_KINDS[$kind][0]) . ' could not be read: ' . fleet_box_error($code, $json));
	}
	return $json['data'];
}

/*
 * Apply a rule or NAT template to one firewall under commit-confirm.
 * Returns the words for the result; throws RuntimeException.
 */
function fleet_tlist_apply_box(array $t, array $box, string $who, ?callable $progress = null): string {
	$say = $progress ?? function () {};
	$kind = $t['kind'];
	$route = FLEET_TLIST_KINDS[$kind][3];
	$say('Reading the ' . strtolower(FLEET_TLIST_KINDS[$kind][0]), 10);
	$remote = fleet_tlist_remote($kind, $box);
	$plan = fleet_tlist_plan($kind, (int)$t['id'], $t['items'], $remote);
	$c = fleet_template_plan_counts($plan);
	$order = ($kind === 'rules') ? fleet_tlist_rule_order((int)$t['id'], $t['items'], $remote) : array();
	$hash = fleet_template_hash($t);
	if (($c['create'] + $c['update'] + $c['delete'] === 0) && empty($order)) {
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', 'In sync');
		return 'Already in sync.';
	}
	/* Every interface the template names must exist there; otherwise nothing is changed. */
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/firewall/rules/tabs');
	$have = array_map('strtolower', array_column((array)($json['data'] ?? array()), 'id'));
	$missing = array_values(array_unique(array_diff(array_column($t['items'], 'iface'), $have)));
	if (($code === 200) && !empty($missing)) {
		throw new RuntimeException('This firewall has no interface ' . implode(', ', $missing) . '; nothing was changed. Leave it out of the template, or set up the interface first.');
	}
	$say('Safety backup', 15);
	fleet_backup_box($box, 'template', $who);
	$say('Starting commit-confirm', 20);
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/commit-confirm', array('seconds' => FLEET_TLIST_CONFIRM,
	    'label' => mb_substr("Fleet template {$t['name']}", 0, 120)));
	$cid = (string)($json['data']['id'] ?? '');
	if ((($code !== 200) && ($code !== 201)) || ($cid === '')) {
		throw new RuntimeException('Commit-confirm could not start, so nothing was changed: ' . fleet_box_error($code, $json));
	}
	$items = array();
	foreach ($t['items'] as $item) {
		$items[$item['key']] = $item;
	}
	$errors = array();
	/* Changes first and removals from the end, so the positions the API uses stay right; new entries last. */
	$steps = array_values(array_filter($plan, function ($p) { return $p['action'] !== 'same'; }));
	usort($steps, function ($a, $b) {
		$rank = array('update' => 0, 'delete' => 1, 'create' => 2);
		return ($rank[$a['action']] <=> $rank[$b['action']]) ?: (($a['action'] === 'delete') ? ((int)$b['id'] <=> (int)$a['id']) : 0);
	});
	$n = 0;
	foreach ($steps as $p) {
		$n++;
		$say(ucfirst($p['action']) . ' ' . $p['name'], 20 + (int)(45 * $n / max(1, count($steps))));
		if ($p['action'] === 'delete') {
			list($code, $json) = fleet_box_call($box, 'DELETE', "{$route}/" . (int)$p['id']);
		} elseif ($p['action'] === 'update') {
			list($code, $json) = fleet_box_call($box, 'PUT', "{$route}/" . (int)$p['id'], fleet_tlist_body($kind, (int)$t['id'], $items[$p['name']]));
		} else {
			list($code, $json) = fleet_box_call($box, 'POST', $route, fleet_tlist_body($kind, (int)$t['id'], $items[$p['name']]) + (($kind === 'rules') ? array('after' => -1) : array()));
		}
		if (($code < 200) || ($code >= 300)) {
			$errors[] = $p['name'] . ': ' . fleet_box_error($code, $json);
			break;
		}
	}
	if (empty($errors) && ($kind === 'rules')) {
		try {
			$after = fleet_tlist_remote($kind, $box);
			foreach (fleet_tlist_rule_order((int)$t['id'], $t['items'], $after) as $iface => $ids) {
				$say("Ordering the rules on {$iface}", 70);
				list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/firewall/rules/order', array('interface' => $iface, 'order' => $ids));
				if (($code < 200) || ($code >= 300)) {
					$errors[] = "Order on {$iface}: " . fleet_box_error($code, $json);
				}
			}
		} catch (RuntimeException $e) {
			$errors[] = $e->getMessage();
		}
	}
	if (empty($errors)) {
		$say('Reloading the filter', 75);
		list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/firewall/apply');
		if (($code < 200) || ($code >= 300)) {
			$errors[] = 'Reload: ' . fleet_box_error($code, $json);
		}
	}
	if (!empty($errors)) {
		/* Put the snapshot back at once; if even that fails, the firewall does it at the deadline. */
		try {
			fleet_box_call($box, 'DELETE', '/api/v1/management/commit-confirm/' . rawurlencode($cid));
		} catch (Throwable $e) {
		}
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'failed', implode('; ', $errors) . ' (rolled back)');
		fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: " . implode('; ', $errors) . '; rolled back');
		throw new RuntimeException(rtrim(implode('; ', $errors), '.') . '. Rolled back: the firewall has its previous rules.');
	}
	$say('Checking Fleet still reaches the firewall', 85);
	$ok = false;
	$until = time() + FLEET_TLIST_VERIFY;
	do {
		sleep(3);
		try {
			list($code) = fleet_box_call(fleet_box_get($box['node_id']) ?? $box, 'GET', '/api/v1/management/status');
			$ok = ($code === 200);
		} catch (Throwable $e) {
			$ok = false;
		}
	} while (!$ok && (time() < $until));
	if (!$ok) {
		$back = date('H:i', time() + FLEET_TLIST_CONFIRM - FLEET_TLIST_VERIFY);
		fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'failed', "FLEET-E310: Fleet lost the firewall after the change; it reverts by itself by {$back}");
		fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: FLEET-E310 not reachable after the change; the firewall reverts it by {$back}");
		throw new RuntimeException("FLEET-E310: After the change Fleet could not reach the firewall, so it was not confirmed. The firewall puts its previous configuration back by itself by {$back}. Check the template does not block the Fleet tunnel or path.");
	}
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/commit-confirm/' . rawurlencode($cid) . '/confirm');
	if (($code < 200) || ($code >= 300)) {
		throw new RuntimeException('The change worked but could not be confirmed (' . fleet_box_error($code, $json) . '); the firewall will revert it at the deadline. Apply again.');
	}
	try {
		fleet_backup_box($box, 'change', $who);
	} catch (RuntimeException $e) {
	}
	$words = sprintf('%d created, %d changed, %d removed', $c['create'], $c['update'], $c['delete']) . (empty($order) ? '' : ', reordered') . '; confirmed';
	fleet_template_state_set((int)$t['id'], $box['node_id'], $hash, 'done', $words);
	fleet_audit($who, 'template', "{$t['name']} on {$box['label']}: {$words}");
	return $words . '.';
}
