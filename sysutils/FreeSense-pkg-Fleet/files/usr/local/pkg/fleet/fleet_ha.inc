<?php
/*
 * fleet_ha.inc
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
 * HA pairs. Firewalls that share a CARP address (same VHID and address)
 * are one pair (or cluster). Fleet shows them together, alerts on
 * split-brain (two MASTERs for one address) and on no MASTER, and never
 * works on both at once: the BACKUP goes first, the MASTER only when its
 * partner is back and the pair is healthy. When HA config sync is on, the
 * primary pushes aliases, rules, NAT and users to its peer, so Fleet
 * applies those to the primary only. Fleet never changes CARP itself.
 */

require_once('fleet/fleet_store.inc');

/* Template kinds and the HA sync section that carries them. */
define('FLEET_HA_SYNC_SECTIONS', array('aliases' => 'aliases', 'rules' => 'rules', 'nat' => 'nat', 'users' => 'users'));
/* How long a group operation waits for a pair to be ready before giving up on a firewall. */
define('FLEET_HA_WAIT', 600);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/*
 * pure: the HA pairs among these firewalls (box rows with their status
 * JSON). Returns a list of clusters:
 *   nodes   => node ids (sorted)
 *   vips    => "vhid@address" => node id => state
 *   masters => node ids that are MASTER of an address
 *   primary => the node that pushes HA config sync to the others, or null
 *   problem => null, array('split'|'nomaster', "vhid@address"), or
 *              array('down', node id) when a member does not answer
 * Only firewalls that answered their last check count for split-brain and
 * no MASTER: a silent one's CARP state is old (it may have lost power while
 * its partner took over). A pair with a silent member is never healthy.
 */
function fleet_ha_pairs(array $boxes): array {
	$owner = array();
	$parent = array();
	$find = function (string $n) use (&$parent, &$find): string {
		return ($parent[$n] === $n) ? $n : ($parent[$n] = $find($parent[$n]));
	};
	$info = array();
	foreach ($boxes as $b) {
		$st = is_array($b['status'] ?? null) ? $b['status'] : (json_decode((string)($b['status'] ?? ''), true) ?: array());
		$node = (string)$b['node_id'];
		$vips = array();
		foreach ((array)($st['carp_vips'] ?? array()) as $v) {
			if (is_array($v) && ((int)($v['vhid'] ?? 0) > 0) && (($v['address'] ?? '') !== '')) {
				$vips[(int)$v['vhid'] . '@' . $v['address']] = (string)($v['state'] ?? 'UNKNOWN');
			}
		}
		if (empty($vips)) {
			continue;
		}
		$info[$node] = array('vips' => $vips, 'online' => ((($b['state'] ?? '') === 'online') && ((int)($b['misses'] ?? 0) === 0)), 'peer' => (string)($st['hasync']['peer'] ?? ''));
		$parent[$node] = $node;
		foreach (array_keys($vips) as $k) {
			if (isset($owner[$k])) {
				$parent[$find($node)] = $find($owner[$k]);
			} else {
				$owner[$k] = $node;
			}
		}
	}
	$groups = array();
	foreach (array_keys($info) as $node) {
		$groups[$find($node)][] = $node;
	}
	$out = array();
	foreach ($groups as $nodes) {
		if (count($nodes) < 2) {
			continue;
		}
		sort($nodes);
		$vips = array();
		$masters = array();
		$primary = null;
		foreach ($nodes as $n) {
			foreach ($info[$n]['vips'] as $k => $state) {
				$vips[$k][$n] = $state;
				if ($state === 'MASTER') {
					$masters[$n] = true;
				}
			}
			if ($info[$n]['peer'] !== '') {
				$primary = $n;
			}
		}
		ksort($vips);
		$problem = null;
		foreach ($vips as $k => $states) {
			if (count($states) < 2) {
				continue;
			}
			$live = array_filter($states, function ($n) use ($info) { return $info[$n]['online']; }, ARRAY_FILTER_USE_KEY);
			$m = count(array_keys($live, 'MASTER', true));
			if ($m > 1) {
				$problem = array('split', $k);
				break;
			}
			if (!empty($live) && ($m === 0)) {
				$problem = $problem ?? array('nomaster', $k);
			}
		}
		if ($problem === null) {
			foreach ($nodes as $n) {
				if (!$info[$n]['online']) {
					$problem = array('down', $n);
					break;
				}
			}
		}
		$out[] = array('nodes' => $nodes, 'vips' => $vips, 'masters' => array_keys($masters), 'primary' => $primary, 'problem' => $problem);
	}
	return $out;
}

/* pure: "211@10.0.0.1/24" as people read it. */
function fleet_ha_vip_text(string $key): string {
	list($vhid, $addr) = explode('@', $key, 2) + array('', '');
	return sprintf('%s (VHID %s)', $addr, $vhid);
}

/* pure: the pair a firewall is in, or null. */
function fleet_ha_pair_of(array $pairs, string $node): ?array {
	foreach ($pairs as $p) {
		if (in_array($node, $p['nodes'], true)) {
			return $p;
		}
	}
	return null;
}

/* pure: these boxes in working order: every MASTER of a pair after the rest, otherwise as given. Keys are kept. */
function fleet_ha_order(array $boxes, array $pairs): array {
	$masters = array();
	foreach ($pairs as $p) {
		foreach ($p['masters'] as $n) {
			$masters[$n] = true;
		}
	}
	$first = array();
	$last = array();
	foreach ($boxes as $k => $b) {
		if (isset($masters[(string)(is_array($b) ? $b['node_id'] : $b)])) {
			$last[$k] = $b;
		} else {
			$first[$k] = $b;
		}
	}
	return $first + $last;
}

/*
 * pure: rollout rings ($rings: ring => node ids) with each pair's MASTER in
 * the latest ring of its partners and after them, so a pair is never
 * updated MASTER first.
 */
function fleet_ha_rings(array $rings, array $pairs): array {
	$ring_of = array();
	foreach ($rings as $r => $nodes) {
		foreach ($nodes as $n) {
			$ring_of[$n] = $r;
		}
	}
	foreach ($pairs as $p) {
		$others = array_diff(array_intersect($p['nodes'], array_keys($ring_of)), $p['masters']);
		if (empty($others)) {
			continue;
		}
		$late = max(array_map(function ($n) use ($ring_of) { return $ring_of[$n]; }, $others));
		foreach ($p['masters'] as $m) {
			if (isset($ring_of[$m]) && ($ring_of[$m] < $late)) {
				$rings[$ring_of[$m]] = array_values(array_diff($rings[$ring_of[$m]], array($m)));
				$rings[$late][] = $m;
				$ring_of[$m] = $late;
			}
		}
	}
	return array_map(function ($nodes) use ($pairs) { return array_values(fleet_ha_order($nodes, $pairs)); }, $rings);
}

/*
 * pure: why Fleet must not start work on this firewall of a pair now, or
 * null. $states: node id => box state. The rest of the pair must be online
 * and the pair healthy (one MASTER per address), so the partner carries
 * the traffic while this one is changed.
 */
function fleet_ha_wait_reason(?array $pair, string $node, array $states, array $labels): ?string {
	if ($pair === null) {
		return null;
	}
	foreach ($pair['nodes'] as $n) {
		if (($n !== $node) && (($states[$n] ?? '') !== 'online')) {
			return sprintf('Waiting for its HA partner %s to be online', $labels[$n] ?? $n);
		}
	}
	if ($pair['problem'] !== null) {
		if ($pair['problem'][0] === 'down') {
			return sprintf('Waiting: %s in the HA pair does not answer', $labels[$pair['problem'][1]] ?? $pair['problem'][1]);
		}
		return ($pair['problem'][0] === 'split') ? sprintf('Waiting: the HA pair has two MASTERs for %s', fleet_ha_vip_text($pair['problem'][1])) :
		    sprintf('Waiting: the HA pair has no MASTER for %s', fleet_ha_vip_text($pair['problem'][1]));
	}
	return null;
}

/* pure: the primary that gives this firewall a template kind by HA config sync, or null. */
function fleet_ha_synced_from(?array $pair, string $node, string $kind, array $statuses): ?string {
	if (($pair === null) || ($pair['primary'] === null) || ($pair['primary'] === $node) || !isset(FLEET_HA_SYNC_SECTIONS[$kind])) {
		return null;
	}
	$sections = (array)($statuses[$pair['primary']]['hasync']['sections'] ?? array());
	return in_array(FLEET_HA_SYNC_SECTIONS[$kind], $sections, true) ? $pair['primary'] : null;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

/* The HA pairs of the fleet now, with the box rows by node id. */
function fleet_ha_now(): array {
	$boxes = fleet_db()->query('SELECT node_id, label, state, misses, status FROM boxes')->fetchAll();
	return array(fleet_ha_pairs($boxes), array_column($boxes, null, 'node_id'));
}

/* Why Fleet must wait before working on this firewall, or null. */
function fleet_ha_wait(string $node): ?string {
	list($pairs, $boxes) = fleet_ha_now();
	return fleet_ha_wait_reason(fleet_ha_pair_of($pairs, $node), $node, array_column($boxes, 'state', 'node_id'), array_column($boxes, 'label', 'node_id'));
}

/* These boxes (rows or node ids) in working order for HA pairs. */
function fleet_ha_sort(array $boxes): array {
	return fleet_ha_order($boxes, fleet_ha_now()[0]);
}

/* The label of the primary that gives this firewall a template kind by HA sync, or null. */
function fleet_ha_sync_source(string $node, string $kind): ?string {
	list($pairs, $boxes) = fleet_ha_now();
	$statuses = array_map(function ($b) { return json_decode((string)$b['status'], true) ?: array(); }, $boxes);
	$from = fleet_ha_synced_from(fleet_ha_pair_of($pairs, $node), $node, $kind, $statuses);
	return ($from === null) ? null : (string)$boxes[$from]['label'];
}

/* pure: one sentence for a pair's problem. $boxes: node id => row with label. */
function fleet_ha_problem_text(array $p, array $boxes, string $names): string {
	if ($p['problem'][0] === 'down') {
		$down = $p['problem'][1];
		$others = array_values(array_diff($p['nodes'], array($down)));
		$carry = array_values(array_filter($others, function ($n) use ($p) { return in_array($n, $p['masters'], true); }));
		return sprintf('HA pair %s: %s does not answer.', $names, $boxes[$down]['label'] ?? $down) .
		    (empty($carry) ? '' : sprintf(' %s carries the shared addresses.', implode(', ', array_map(function ($n) use ($boxes) { return $boxes[$n]['label'] ?? $n; }, $carry))));
	}
	return ($p['problem'][0] === 'split') ?
	    sprintf('HA pair %s: both are MASTER for %s (split-brain). Check the link between them.', $names, fleet_ha_vip_text($p['problem'][1])) :
	    sprintf('HA pair %s: no firewall is MASTER for %s.', $names, fleet_ha_vip_text($p['problem'][1]));
}

/* pure: the short badge text for a pair's problem. */
function fleet_ha_problem_badge(array $problem): string {
	return array('split' => 'Split-brain', 'nomaster' => 'No MASTER', 'down' => 'Member down')[$problem[0]] ?? 'Problem';
}

/* The minute poll: alert when a pair goes into or out of split-brain, no MASTER or a member down. */
function fleet_ha_tick(): void {
	list($pairs, $boxes) = fleet_ha_now();
	$was = json_decode((string)fleet_setting('ha_problems', '{}'), true) ?: array();
	$now = array();
	foreach ($pairs as $p) {
		$key = implode(',', $p['nodes']);
		$labels = array_map(function ($n) use ($boxes) { return $boxes[$n]['label']; }, $p['nodes']);
		natcasesort($labels);
		$names = implode(' and ', $labels);
		$prob = ($p['problem'] === null) ? '' : implode(' ', $p['problem']);
		if ($prob !== '') {
			$now[$key] = $prob;
		}
		if ($prob === ($was[$key] ?? '')) {
			continue;
		}
		if ($prob !== '') {
			fleet_alert('ha_problem', $p['nodes'][0], fleet_ha_problem_text($p, $boxes, $names));
		} else {
			fleet_alert('ha_ok', $p['nodes'][0], sprintf('HA pair %s is healthy again.', $names));
		}
	}
	fleet_setting_set('ha_problems', json_encode($now, JSON_FORCE_OBJECT));
}
