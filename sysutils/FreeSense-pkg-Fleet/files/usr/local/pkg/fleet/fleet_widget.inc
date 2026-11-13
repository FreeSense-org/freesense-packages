<?php
/*
 * fleet_widget.inc
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
 * The "FreeSense Fleet" dashboard widget (www/widgets/fleet.js, data from
 * GET /api/v1/packages/fleet/widget through the plugin_restapi hook):
 * health tiles, the firewalls that need attention, availability over 24
 * hours, and the controller with its standby. Each part can be turned off
 * and the widget can focus on one group.
 */

define('FLEET_WIDGET_PARTS', array('health' => 'Health tiles', 'problems' => 'Firewalls that need attention',
    'availability' => 'Availability (24 hours)', 'controller' => 'Controller and standby'));
define('FLEET_WIDGET_ROWS', array(3, 5, 10));

/* pure: the widget settings with defaults: {parts, group, rows}. */
function fleet_widget_cfg(array $w): array {
	$parts = array_key_exists('fleet_parts', $w) ? array_values(array_intersect(array_keys(FLEET_WIDGET_PARTS), explode(',', (string)$w['fleet_parts']))) :
	    array_keys(FLEET_WIDGET_PARTS);
	return array('parts' => $parts, 'group' => max(0, (int)($w['fleet_group'] ?? 0)),
	    'rows' => in_array((int)($w['fleet_rows'] ?? 0), FLEET_WIDGET_ROWS, true) ? (int)$w['fleet_rows'] : 5);
}

/*
 * pure: the firewalls that need attention, worst first, at most $rows:
 * offline, HA pair problems, degraded, policy problems, no rollback,
 * update available. Each {label, link, badge: [state, text], text}.
 */
function fleet_widget_problems(array $boxes, array $ha_pairs, array $labels, int $rows): array {
	$items = array();
	$link = function (string $id) { return '/fleet/fleet_box.php?id=' . urlencode($id); };
	/* The first sentence of an error, without its code: enough for a widget line. */
	$short = function (string $t, string $none) {
		$t = trim(preg_replace('/^FLEET-E\d+:\s*/', '', $t));
		$p = strpos($t, '. ');
		return ($t === '') ? $none : rtrim(($p === false) ? $t : substr($t, 0, $p), '.');
	};
	foreach ($boxes as $b) {
		if ($b['state'] === 'offline') {
			$items[] = array(0, $b['label'], $link($b['id']), array('block', 'Offline'), $short($b['problem'], 'Does not answer'));
		}
	}
	foreach ($ha_pairs as $p) {
		if ($p['problem'] === null) {
			continue;
		}
		$names = array_map(function ($n) use ($labels) { return $labels[$n] ?? $n; }, $p['nodes']);
		natcasesort($names);
		$items[] = array(1, implode(' + ', $names), '/fleet/fleet_ha.php', array(($p['problem'][0] === 'down') ? 'warn' : 'block', fleet_ha_problem_badge($p['problem'])),
		    array('split' => 'Both are MASTER: check the link between them', 'nomaster' => 'No firewall is MASTER',
		    'down' => 'A member does not answer; its partner carries the shared addresses')[$p['problem'][0]] ?? '');
	}
	foreach ($boxes as $b) {
		if ($b['state'] === 'degraded') {
			$items[] = array(2, $b['label'], $link($b['id']), array('warn', 'Degraded'), $short($b['problem'], 'Answers slowly or misses checks'));
		} elseif (($b['state'] === 'online') && ((int)$b['policy'] > 0)) {
			$items[] = array(3, $b['label'], $link($b['id']), array('warn', 'Policy'), sprintf(((int)$b['policy'] === 1) ? '%d policy rule fails' : '%d policy rules fail', (int)$b['policy']));
		} elseif (($b['state'] === 'online') && empty($b['rollback'])) {
			$items[] = array(4, $b['label'], $link($b['id']), array('warn', 'No rollback'), 'A failed update cannot roll back (UFS)');
		} elseif (($b['state'] === 'online') && !empty($b['update'])) {
			$items[] = array(5, $b['label'], '/fleet/fleet_updates.php', array('info', 'Update'), (string)($b['update'][1] ?? 'Update available'));
		}
	}
	usort($items, function ($a, $b) { return array($a[0], strtolower($a[1])) <=> array($b[0], strtolower($b[1])); });
	return array_map(function ($i) { return array('label' => $i[1], 'link' => $i[2], 'badge' => $i[3], 'text' => $i[4]); }, array_slice($items, 0, $rows));
}


/* What the enabled parts show, for the group when one is chosen. */
function fleet_widget_data(array $cfg): array {
	$s = fleet_ctl_settings();
	if (!$s['enable'] || !is_file(FLEET_DATA . '/fleet.db')) {
		$sb = fleet_standby_role() === 'standby' ? fleet_standby_state() : null;
		return array('ready' => false, 'standby' => $sb);
	}
	$now = time();
	$groups = fleet_groups_by_box();
	$rows = fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, ' .
	    '(SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll();
	$group_name = '';
	if ($cfg['group'] > 0) {
		$rows = array_values(array_filter($rows, function ($r) use ($groups, $cfg) {
			return in_array($cfg['group'], array_column($groups[$r['node_id']] ?? array(), 'id'), true);
		}));
		foreach (fleet_groups_all() as $g) {
			$group_name = ((int)$g['id'] === $cfg['group']) ? (string)$g['name'] : $group_name;
		}
	}
	$pending = (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn();
	$d = fleet_dashboard_data($rows, $pending, $now, $groups);
	$nodes = array_column($rows, 'node_id');
	$out = array('ready' => true, 'group' => $group_name, 'headline' => $d['headline'], 'total' => $d['total'], 'counts' => $d['counts']);
	$out['updates'] = count(array_filter($d['boxes'], function ($b) { return !empty($b['update']); }));
	if (in_array('problems', $cfg['parts'], true)) {
		list($pairs) = fleet_ha_now();
		$pairs = array_values(array_filter($pairs, function ($p) use ($nodes) { return !empty(array_intersect($p['nodes'], $nodes)); }));
		$labels = array_column($rows, 'label', 'node_id');
		$out['problems'] = fleet_widget_problems($d['boxes'], $pairs, $labels, $cfg['rows']);
		$out['problem_count'] = count(fleet_widget_problems($d['boxes'], $pairs, $labels, PHP_INT_MAX));
	}
	if (in_array('availability', $cfg['parts'], true)) {
		$out['stats'] = fleet_stats('24h', ($cfg['group'] > 0) ? $nodes : null);
		$out['pulse'] = fleet_widget_pulse_cols(fleet_trends_pulse($cfg['group'], $now));
	}
	if (in_array('controller', $cfg['parts'], true)) {
		$out['controller'] = fleet_controller_row();
		$out['standby'] = fleet_standby_overview();
		$out['blocked'] = count(array_filter(fleet_access_json('access_blocked'), function ($u) use ($now) { return (int)$u > $now; }));
		$out['alerts'] = (int)(fleet_alert_report_counts($now)['alerts'] ?? 0);
	}
	return $out;
}

/* pure: per half hour of a fleet pulse, how many firewalls were online, degraded and offline: {t, cols: [[online, degraded, offline], ...]}. */
function fleet_widget_pulse_cols(array $pulse): array {
	$cols = array();
	foreach ($pulse['t'] as $i => $t) {
		$c = array('online' => 0, 'degraded' => 0, 'offline' => 0);
		foreach ($pulse['rows'] as $r) {
			$st = (string)($r['cells'][$i] ?? '');
			if (isset($c[$st])) {
				$c[$st]++;
			} elseif ($st === 'new') {
				$c['online']++;
			}
		}
		$cols[] = array_values($c);
	}
	return array('t' => $pulse['t'], 'cols' => $cols);
}

/* REST API routes for the dashboard widget (core collects them through the plugin_restapi hook). */
function fleet_plugin_restapi($params) {
	return array(
		restapi_route('GET', '/v1/packages/fleet/widget', 'fleet_restapi_widget', array(
			'page' => 'fleet/fleet_dashboard.php', 'area' => 'packages',
			'query' => array('parts' => 'Comma list of health, problems, availability, controller (all when omitted)',
			    'group' => 'Group id (0: every firewall)', 'rows' => '3, 5 or 10'),
			'summary' => 'FreeSense Fleet at a glance: health counts, firewalls that need attention, availability (24 h), controller and standby')),
	);
}

function fleet_restapi_widget($req) {
	$q = (array)($req['query'] ?? array());
	$w = array('fleet_group' => $q['group'] ?? 0, 'fleet_rows' => $q['rows'] ?? 5);
	if (isset($q['parts'])) {
		$w['fleet_parts'] = (string)$q['parts'];
	}
	$cfg = fleet_widget_cfg($w);
	$data = fleet_widget_data($cfg);
	$data['parts'] = $cfg['parts'];
	$data['groups'] = (fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db')) ?
	    array_map(function ($g) { return array('id' => (int)$g['id'], 'name' => (string)$g['name']); }, fleet_groups_all()) : array();
	if (isset($data['controller']['uptime']) && ($data['controller']['uptime'] !== null)) {
		$data['controller']['uptime_text'] = fleet_uptime_text((int)$data['controller']['uptime']);
	}
	$data['standby_late'] = isset($data['standby']['seen']) && ($data['standby']['seen'] > 0) && ((time() - $data['standby']['seen']) > FLEET_STANDBY_LATE);
	return array('data' => $data);
}
