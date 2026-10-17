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
 * The "FreeSense Fleet" dashboard widget (widgets/widgets/fleet.widget.php):
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

/* pure: the mini pulse as SVG: one column per half hour, stacked online, degraded, offline. */
function fleet_widget_pulse_svg(array $p): string {
	$n = count($p['cols']);
	$max = 1;
	foreach ($p['cols'] as $c) {
		$max = max($max, array_sum($c));
	}
	$w = 4;
	$h = 40;
	$out = '<svg class="fs-fleet-widget-pulse" viewBox="0 0 ' . ($n * $w) . ' ' . $h . '" preserveAspectRatio="none" role="img" aria-label="' .
	    htmlspecialchars(gettext('Firewalls online, degraded and offline per half hour, last 24 hours')) . '">';
	foreach ($p['cols'] as $i => $c) {
		$y = $h;
		foreach (array('online', 'degraded', 'offline') as $k => $cls) {
			$bh = $h * $c[$k] / $max;
			if ($bh > 0) {
				$y -= $bh;
				$out .= '<rect class="s-' . $cls . '" x="' . ($i * $w + .5) . '" y="' . round($y, 2) . '" width="' . ($w - 1) . '" height="' . round($bh, 2) . '"><title>' .
				    htmlspecialchars(date('H:i', $p['t'][$i]) . ': ' . sprintf(gettext('%1$d online, %2$d degraded, %3$d offline'), $c[0], $c[1], $c[2])) . '</title></rect>';
			}
		}
	}
	return $out . '</svg>';
}

/* The widget body (also what the refresh fetches). */
function fleet_widget_html(array $d, array $cfg): string {
	$h = function ($s) { return htmlspecialchars((string)$s); };
	if (!$d['ready']) {
		if ($d['standby'] !== null) {
			$ok = (int)($d['standby']['last_ok'] ?? 0);
			return '<p class="fs-fleet-widget-note">' . $h(gettext('This server is the Fleet standby.')) . ' ' .
			    $h(($ok > 0) ? sprintf(gettext('Last copy %s.'), date('Y-m-d H:i', $ok)) : gettext('No copy yet.')) .
			    ' <a href="/fleet/fleet.php?tab=settings&amp;view=standby">' . $h(gettext('Standby status')) . '</a></p>';
		}
		return '<p class="fs-fleet-widget-note">' . $h(gettext('FreeSense Fleet is not set up on this firewall.')) .
		    ' <a href="/fleet/fleet.php?tab=settings">' . $h(gettext('Settings')) . '</a></p>';
	}
	$c = $d['counts'];
	$out = '';
	if (in_array('health', $cfg['parts'], true)) {
		$tone = ($c['offline'] > 0) ? 'block' : (($c['degraded'] > 0) ? 'warn' : 'pass');
		$out .= '<a class="fs-fleet-widget-head" href="/fleet/fleet_dashboard.php"><span class="fs-fleet-ov-state fs-fc-' . $tone . '"><i class="fa-solid ' .
		    (($tone === 'pass') ? 'fa-circle-check' : 'fa-triangle-exclamation') . '" aria-hidden="true"></i></span><span><strong>' . $h(gettext($d['headline'])) . '</strong>' .
		    (empty($d['group']) ? '' : '<span class="fs-muted">' . $h(sprintf(gettext('in %s'), $d['group'])) . '</span>') . '</span></a>';
		$wall = '/fleet/fleet_dashboard.php?view=firewalls';
		$tiles = array(
			array('fa-server', gettext('Firewalls'), $d['total'], $wall, 'c1'),
			array('fa-circle-check', gettext('Online'), $c['online'], $wall, 'pass'),
			array('fa-triangle-exclamation', gettext('Degraded'), $c['degraded'], $wall, ($c['degraded'] > 0) ? 'warn' : 'neutral'),
			array('fa-plug-circle-xmark', gettext('Offline'), $c['offline'], $wall, ($c['offline'] > 0) ? 'block' : 'neutral'),
			array('fa-circle-up', gettext('Updates'), $d['updates'], '/fleet/fleet_updates.php', ($d['updates'] > 0) ? 'info' : 'neutral'),
			array('fa-hourglass-half', gettext('Waiting'), $c['pending'], '/fleet/fleet.php', ($c['pending'] > 0) ? 'warn' : 'neutral'),
		);
		$out .= '<div class="fs-fleet-widget-tiles">';
		foreach ($tiles as list($icon, $label, $n, $href, $t)) {
			$out .= '<a class="fs-fleet-widget-tile fs-fc-' . $t . ((((int)$n > 0) && in_array($t, array('warn', 'block'), true)) ? ' is-hot' : '') . '" href="' . $h($href) . '">' .
			    '<i class="fa-solid ' . $icon . '" aria-hidden="true"></i><span class="fs-fleet-widget-n">' . (int)$n . '</span><span class="fs-fleet-widget-l">' . $h($label) . '</span></a>';
		}
		$out .= '</div>';
	}
	if (in_array('problems', $cfg['parts'], true)) {
		$out .= '<div class="fs-fleet-widget-part">';
		if (empty($d['problems'])) {
			$out .= '<p class="fs-fleet-widget-ok"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ' .
			    $h(($d['total'] === 0) ? gettext('No firewalls yet.') : sprintf(($d['total'] === 1) ? gettext('The firewall is fine.') : gettext('All %d firewalls are fine.'), $d['total'])) . '</p>';
		} else {
			$out .= '<h4 class="fs-fleet-widget-sub"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>' . $h(gettext('Needs attention')) . '</h4><ul class="fs-fleet-widget-list">';
			foreach ($d['problems'] as $p) {
				$out .= '<li>' . fs_badge($p['badge'][0], gettext($p['badge'][1])) . '<a href="' . $h($p['link']) . '">' . $h($p['label']) . '</a><span class="fs-fleet-widget-why" title="' .
				    $h(gettext($p['text'])) . '">' . $h(gettext($p['text'])) . '</span></li>';
			}
			$out .= '</ul>';
			if ($d['problem_count'] > count($d['problems'])) {
				$out .= '<a class="fs-fleet-widget-more" href="/fleet/fleet_dashboard.php">' . $h(sprintf(gettext('and %d more'), $d['problem_count'] - count($d['problems']))) . '</a>';
			}
		}
		$out .= '</div>';
	}
	if (in_array('availability', $cfg['parts'], true) && isset($d['stats'])) {
		$st = $d['stats'];
		$pct = ($st['percent'] === null) ? '-' : rtrim(rtrim(number_format((float)$st['percent'], 2, '.', ''), '0'), '.') . ' %';
		$out .= '<a class="fs-fleet-widget-part fs-fleet-widget-avail" href="/fleet/fleet_dashboard.php?view=trends">' .
		    '<span class="fs-fleet-widget-sub"><i class="fa-solid fa-wave-square" aria-hidden="true"></i>' . $h(gettext('Last 24 hours')) . '<span class="fs-fleet-widget-sum"><strong>' .
		    $h($pct) . '</strong> ' . $h(gettext('available')) . ', ' . $h(sprintf(((int)$st['outages'] === 1) ? gettext('%d outage') : gettext('%d outages'), (int)$st['outages'])) .
		    '</span></span>' . (isset($d['pulse']) ? fleet_widget_pulse_svg($d['pulse']) : '') .
		    '<span class="fs-fleet-widget-axis"><span>' . $h(date('H:i', (int)($d['pulse']['t'][0] ?? (time() - 86400)))) . '</span><span>' . $h(gettext('Now')) . '</span></span></a>';
	}
	if (in_array('controller', $cfg['parts'], true) && isset($d['controller'])) {
		$ctl = $d['controller'];
		$sb = $d['standby'];
		$out .= '<dl class="fs-fleet-widget-part fs-fleet-widget-facts"><dt><i class="fa-solid fa-tower-broadcast" aria-hidden="true"></i>' . $h(gettext('Controller')) . '</dt><dd>' . $h($ctl['version']) .
		    (($ctl['uptime'] !== null) ? ', ' . $h(sprintf(gettext('up %s'), fleet_uptime_text((int)$ctl['uptime']))) : '') . '</dd>';
		if (($sb['role'] ?? '') === 'primary') {
			$late = ($sb['seen'] > 0) && ((time() - $sb['seen']) > FLEET_STANDBY_LATE);
			$out .= '<dt><i class="fa-solid fa-clone" aria-hidden="true"></i>' . $h(gettext('Standby')) . '</dt><dd>' . (($sb['addr'] !== '') ? fs_badge($late ? 'warn' : 'pass', $late ? gettext('Late') : gettext('Up to date')) . ' ' . $h($sb['addr']) :
			    '<span class="fs-muted">' . $h(gettext('waiting for it to connect')) . '</span>') . '</dd>';
		}
		$out .= '<dt><i class="fa-solid fa-bell" aria-hidden="true"></i>' . $h(gettext('Alerts (24 h)')) . '</dt><dd><a href="/fleet/fleet_alerts.php">' . (int)$d['alerts'] . '</a></dd>';
		if ($d['blocked'] > 0) {
			$out .= '<dt><i class="fa-solid fa-ban" aria-hidden="true"></i>' . $h(gettext('Blocked')) . '</dt><dd><a href="/fleet/fleet.php?tab=settings&amp;view=access&amp;section=allowed">' . $h(sprintf(gettext('%d addresses (wrong keys)'), $d['blocked'])) . '</a></dd>';
		}
		$out .= '</dl>';
	}
	return ($out === '') ? '<p class="fs-fleet-widget-note">' . $h(gettext('Every part is turned off. Open the widget settings to choose what it shows.')) . '</p>' : $out;
}
