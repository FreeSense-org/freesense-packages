<?php
/*
 * fleet_kiosk.inc
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
 * NOC screens: a full-screen, read-only view of the fleet for a wall
 * screen that never logs in. Each screen has its own kiosk key (shown
 * once, kept only as a hash) and the networks it may be used from; a
 * key can be revoked at any time. A screen in a public place can hide
 * names and addresses. The kiosk page (www/fleet/kiosk.php) carries the
 * key in the URL fragment, which browsers never send or log, and asks
 * kiosk_data.php with it in a header; that answer is read-only and
 * holds no secrets.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_KIOSK_PREFIX', 'fkk_');

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: the networks a screen may use, one per line or comma separated; returns array(list, problem or null). */
function fleet_kiosk_networks(string $text): array {
	$out = array();
	foreach (preg_split('/[\s,]+/', trim($text), -1, PREG_SPLIT_NO_EMPTY) as $n) {
		if (strpos($n, '/') === false) {
			$n .= (strpos($n, ':') !== false) ? '/128' : '/32';
		}
		list($ip, $bits) = explode('/', $n, 2);
		$v6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
		if (((filter_var($ip, FILTER_VALIDATE_IP) === false)) || !ctype_digit($bits) || ((int)$bits > ($v6 ? 128 : 32))) {
			return array(array(), sprintf('"%s" is not an address or network (like 10.0.5.0/24).', $n));
		}
		if ((int)$bits === 0) {
			return array(array(), 'A screen cannot be allowed from everywhere: give the network the screen is on.');
		}
		$out[] = $ip . '/' . (int)$bits;
	}
	if (empty($out)) {
		return array(array(), 'Give the network or address the screen is on.');
	}
	return array(array_values(array_unique($out)), null);
}

/* pure: is $ip in one of the networks? */
function fleet_kiosk_ip_allowed(string $ip, array $networks): bool {
	$bin = @inet_pton($ip);
	if ($bin === false) {
		return false;
	}
	foreach ($networks as $n) {
		list($net, $bits) = explode('/', $n, 2);
		$nb = @inet_pton($net);
		if (($nb === false) || (strlen($nb) !== strlen($bin))) {
			continue;
		}
		$bits = (int)$bits;
		$bytes = intdiv($bits, 8);
		if (strncmp($bin, $nb, $bytes) !== 0) {
			continue;
		}
		$rest = $bits % 8;
		if (($rest === 0) || (((ord($bin[$bytes]) ^ ord($nb[$bytes])) >> (8 - $rest)) === 0)) {
			return true;
		}
	}
	return false;
}

/* The looks of a NOC screen (fleet-kiosk.css): key => array(name, what it is for). */
define('FLEET_KIOSK_STYLES', array(
	'freesense' => array('FreeSense', 'The FreeSense colours; calm until something breaks.'),
	'pro' => array('Pro', 'Flat and compact: the most firewalls on one screen.'),
	'hacker' => array('Hacker', 'A green terminal with scanlines.'),
	'control' => array('Control room', 'Amber and very large type, readable from across a room.'),
	'blueprint' => array('Blueprint', 'A technical drawing on grid paper.'),
));
define('FLEET_KIOSK_THEMES', array('auto' => 'Follow the screen', 'dark' => 'Dark', 'light' => 'Light'));

/* pure: a style and theme as given (URL, form), or the defaults. */
function fleet_kiosk_look(string $style, string $theme): array {
	return array(isset(FLEET_KIOSK_STYLES[$style]) ? $style : 'freesense', isset(FLEET_KIOSK_THEMES[$theme]) ? $theme : 'auto');
}

/*
 * What a screen shows: the left side holds panels (general fleet
 * information and charts), the right side the firewall list. Every
 * panel: key => array(title, size), size 1 = one row, 2 = two rows.
 */
define('FLEET_KIOSK_PANELS', array(
	'health' => array('Fleet health', 1),
	'groups' => array('Groups', 3),
	'ha' => array('HA pairs', 2),
	'controller' => array('Fleet server', 2),
	'pulse' => array('Availability', 2),
	'load' => array('CPU and memory', 1),
	'traffic' => array('Traffic', 1),
	'states' => array('State tables', 1),
	'temp' => array('Temperature', 1),
	'alerts' => array('Alerts', 2),
	'ops' => array('Operations', 1),
	'backups' => array('Backups', 1),
	'compliance' => array('Policy compliance', 1),
	'versions' => array('Versions', 1),
	'busiest' => array('Busiest firewalls', 1),
	'outages' => array('Outages', 1),
	/* Internet connectivity (shown while the option is on). */
	'inet' => array('Internet now', 1),
	'inet_quality' => array('Internet quality', 2),
	'inet_worst' => array('Worst internet connections', 1),
	'inet_score' => array('Connection quality', 1),
	'inet_pulse' => array('Internet availability', 2),
	'inet_events' => array('Failovers and internet outages', 1),
));
/* The firewall list's columns: key => heading. */
define('FLEET_KIOSK_COLUMNS', array(
	'state' => 'State', 'name' => 'Firewall', 'host' => 'Hostname', 'groups' => 'Groups', 'version' => 'Version', 'seen' => 'Last seen',
	'cpu' => 'CPU', 'mem' => 'Memory', 'states' => 'States', 'traffic' => 'Traffic', 'uptime' => 'Up (24 h)', 'inet' => 'Internet', 'ha' => 'HA', 'flags' => 'Notes',
));
define('FLEET_KIOSK_SORTS', array('problems' => 'Problems first', 'name' => 'Name', 'group' => 'Group'));
define('FLEET_KIOSK_LAYOUTS', array('split' => 'Panels and firewall list', 'list' => 'Firewall list only', 'panels' => 'Panels only'));
define('FLEET_KIOSK_RANGES', array('24h' => 'Last 24 hours', '7d' => 'Last 7 days', '30d' => 'Last 30 days'));
define('FLEET_KIOSK_BEEPS', array('offline' => 'A firewall goes offline', 'degraded' => 'A firewall answers late', 'ha' => 'An HA pair has a problem', 'inet' => 'A firewall loses its internet'));

/* pure: a screen's settings with every value present and in range. */
function fleet_kiosk_config_defaults(): array {
	return array(
		'layout' => 'split', 'left' => 40, 'side' => 'left', 'view' => 'list',
		'columns' => array('state', 'name', 'groups', 'version', 'cpu', 'mem', 'traffic', 'uptime', 'inet', 'ha', 'flags'),
		'sort' => 'problems', 'groups' => array(), 'rows' => 0, 'flip' => 12, 'hold' => true, 'group_rows' => false,
		'panels' => array_keys(FLEET_KIOSK_PANELS), 'panel_flip' => 20, 'range' => '24h',
		'sound' => false, 'beep' => array('offline', 'ha'),
		'heading' => '', 'subheading' => '',
	);
}

/* pure: one line of header text: no markup or control characters, at most $max characters. */
function fleet_kiosk_text($v, int $max): string {
	$v = preg_replace('/\s+/u', ' ', preg_replace('/[\x00-\x1f\x7f<>]+/u', ' ', (string)$v) ?? '') ?? '';
	return mb_substr(trim($v), 0, $max);
}

/*
 * pure: a screen's settings from a form ($form: unticked boxes are off)
 * or from stored JSON (a missing value is the default); unknown values
 * fall back to the defaults and numbers are clamped. Panels come in the
 * order given ($in['order'][key] numbers, when a form sends them).
 */
function fleet_kiosk_config_parse(array $in, bool $form = false): array {
	$d = fleet_kiosk_config_defaults();
	$pick = function (string $k, array $allowed) use ($in, $d) {
		$v = (string)($in[$k] ?? '');
		return isset($allowed[$v]) ? $v : $d[$k];
	};
	$clamp = function (string $k, int $lo, int $hi) use ($in, $d) {
		return (isset($in[$k]) && is_numeric($in[$k])) ? max($lo, min($hi, (int)$in[$k])) : $d[$k];
	};
	$list = function (string $k, array $allowed) use ($in, $d, $form) {
		if (!isset($in[$k])) {
			return $form ? array() : $d[$k];
		}
		return array_values(array_unique(array_filter(array_map('strval', (array)$in[$k]), function ($v) use ($allowed) { return isset($allowed[$v]); })));
	};
	$flag = function (string $k) use ($in, $d, $form) {
		return array_key_exists($k, $in) ? !empty($in[$k]) : ($form ? false : $d[$k]);
	};
	$c = array(
		'layout' => $pick('layout', FLEET_KIOSK_LAYOUTS),
		'left' => (int)(round($clamp('left', 25, 75) / 5) * 5),
		'side' => (($in['side'] ?? '') === 'right') ? 'right' : 'left',
		'view' => (($in['view'] ?? '') === 'tiles') ? 'tiles' : 'list',
		'columns' => $list('columns', FLEET_KIOSK_COLUMNS),
		'sort' => $pick('sort', FLEET_KIOSK_SORTS),
		'groups' => array_values(array_unique(array_filter(array_map('intval', (array)($in['groups'] ?? array())), function ($g) { return $g > 0; }))),
		'rows' => (isset($in['rows']) && is_numeric($in['rows']) && ((int)$in['rows'] > 0)) ? max(3, min(50, (int)$in['rows'])) : 0,
		'flip' => $clamp('flip', 5, 120),
		'hold' => $flag('hold'),
		'group_rows' => $flag('group_rows'),
		'panels' => $list('panels', FLEET_KIOSK_PANELS),
		'panel_flip' => $clamp('panel_flip', 5, 300),
		'range' => $pick('range', FLEET_KIOSK_RANGES),
		'sound' => $flag('sound'),
		'beep' => $list('beep', FLEET_KIOSK_BEEPS),
		'heading' => fleet_kiosk_text($in['heading'] ?? $d['heading'], 60),
		'subheading' => fleet_kiosk_text($in['subheading'] ?? $d['subheading'], 100),
	);
	/* Every list shows what a firewall is and how it is; the columns keep the catalogue's order. */
	$c['columns'] = array_values(array_intersect(array_keys(FLEET_KIOSK_COLUMNS), array_merge(array('state', 'name'), $c['columns'])));
	if (isset($in['order']) && is_array($in['order'])) {
		$order = $in['order'];
		$pos = array_flip($c['panels']);
		usort($c['panels'], function ($a, $b) use ($order, $pos) {
			return array((int)($order[$a] ?? 99), $pos[$a]) <=> array((int)($order[$b] ?? 99), $pos[$b]);
		});
	}
	if (($c['layout'] === 'panels') && empty($c['panels'])) {
		$c['layout'] = 'list';
	}
	return $c;
}

/* pure: stored JSON as settings (a screen saved before settings existed gets the defaults). */
function fleet_kiosk_config_json(string $json): array {
	$a = json_decode($json, true);
	return fleet_kiosk_config_parse(is_array($a) ? $a : array());
}

/*
 * pure: the boxes a screen shows: its groups only, in its order. $boxes:
 * fleet_dashboard_data() boxes; $inet: node_id => internet state (down,
 * degraded, ...). Offline, late, then no internet, then poor internet come
 * first in every order.
 */
function fleet_kiosk_boxes(array $boxes, array $cfg, array $inet = array()): array {
	if (!empty($cfg['groups'])) {
		$boxes = array_values(array_filter($boxes, function ($b) use ($cfg) {
			return !empty(array_intersect($cfg['groups'], array_map('intval', array_column($b['groups'], 'id'))));
		}));
	}
	$rank = function (array $b) use ($inet) {
		$n = (string)($b['id'] ?? ($b['node_id'] ?? ''));
		$i = array('down' => 2, 'degraded' => 3)[$inet[$n] ?? ''] ?? 4;
		return array('offline' => 0, 'degraded' => 1)[$b['state']] ?? $i;
	};
	$pos = array_flip(array_keys($boxes));
	$keys = array_keys($boxes);
	usort($keys, function ($x, $y) use ($boxes, $cfg, $rank, $pos) {
		$a = $boxes[$x];
		$b = $boxes[$y];
		$ka = ($cfg['sort'] === 'problems') ? $pos[$x] : (($cfg['sort'] === 'group') ? strtolower((string)($a['groups'][0]['name'] ?? '~')) . '|' . strtolower($a['label']) : strtolower($a['label']));
		$kb = ($cfg['sort'] === 'problems') ? $pos[$y] : (($cfg['sort'] === 'group') ? strtolower((string)($b['groups'][0]['name'] ?? '~')) . '|' . strtolower($b['label']) : strtolower($b['label']));
		/* A problem is never hidden on page two, whatever the order. */
		return array($rank($a), $ka) <=> array($rank($b), $kb);
	});
	return array_map(function ($k) use ($boxes) { return $boxes[$k]; }, $keys);
}

/*
 * pure: panels as a screen that hides names may show them: firewall
 * names become the numbers the list uses ($anon: node id => "Firewall
 * N"), links, alert texts and the server's own name are left out.
 */
function fleet_kiosk_panels_hide(array $panels, array $anon): array {
	$name = function ($node) use ($anon) {
		return $anon[(string)$node] ?? 'Firewall';
	};
	foreach ($panels as $k => $p) {
		/* The Groups panel is numbered by the view itself. */
		if ($k === 'groups') {
			continue;
		}
		foreach (array('rows', 'top', 'busiest') as $list) {
			if (isset($p[$list])) {
				foreach ($p[$list] as $i => $r) {
					$p[$list][$i]['label'] = $name($r['node'] ?? '');
					unset($p[$list][$i]['link'], $p[$list][$i]['node']);
				}
			}
		}
		if (isset($p['latest'])) {
			foreach ($p['latest'] as $i => $a) {
				$p['latest'][$i]['box'] = ($a['node'] ?? '') === '' ? '' : $name($a['node']);
				$p['latest'][$i]['text'] = '';
				unset($p['latest'][$i]['node']);
			}
		}
		if (isset($p['pairs'])) {
			foreach ($p['pairs'] as $i => $pair) {
				$p['pairs'][$i]['name'] = sprintf('Pair %d', $i + 1);
				foreach ($pair['members'] as $j => $m) {
					$p['pairs'][$i]['members'][$j]['label'] = $name($m['node']);
					unset($p['pairs'][$i]['members'][$j]['node']);
				}
			}
		}
		if (isset($p['rules'])) {
			$p['rules'] = array_map(function ($r) { return array('label' => $r['label'], 'value' => $r['value']); }, $p['rules']);
		}
		if ($k === 'controller') {
			$p['host'] = '';
			$p['standby_addr'] = '';
		}
		$panels[$k] = $p;
	}
	return $panels;
}

/*
 * pure: the NOC page. $live: the WebUI's own live view (session, a style
 * picker, links to the firewalls) rather than a wall screen with a key.
 * $fixed: the style came from the URL, so the screen's saved style does
 * not replace it. No inline script or style (the kiosk page's CSP).
 */
function fleet_kiosk_page(bool $live, string $style, string $theme, bool $fixed, array $versions): string {
	$h = function ($s) {
		return htmlspecialchars((string)$s, ENT_QUOTES);
	};
	$opts = '';
	foreach (FLEET_KIOSK_STYLES as $k => list($name)) {
		$opts .= '<option value="' . $k . '"' . (($k === $style) ? ' selected' : '') . '>' . $h($name) . '</option>';
	}
	$picker = $live ? '<label class="k-pick"><span>Style</span><select id="k-style">' . $opts . '</select></label>' .
	    '<button type="button" id="k-theme" aria-label="Light or dark">' . (($theme === 'light') ? 'Light' : (($theme === 'dark') ? 'Dark' : 'Auto')) . '</button>' .
	    '<a class="k-btn" id="k-config" href="/fleet/fleet_kiosks.php?config=live">Configure</a>' : '';
	return '<!doctype html>
<html lang="en" class="k--' . $h($style) . '"' . (($theme !== 'auto') ? ' data-theme="' . $h($theme) . '"' : '') . ' data-theme-choice="' . $h($theme) . '">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>FreeSense Fleet</title>
<link rel="stylesheet" href="/fleet/assets/fleet-kiosk.css?v=' . (int)($versions['css'] ?? 0) . '">
</head>
<body data-mode="' . ($live ? 'live' : 'kiosk') . '" data-fixed="' . ($fixed ? '1' : '0') . '">
<div class="k-fx" aria-hidden="true"></div>
<header class="k-top">
	<div class="k-brand"><span class="k-mark" aria-hidden="true">FS</span>
		<div class="k-titles"><h1 class="k-heading" id="k-title">FreeSense Fleet</h1><p class="k-sub" id="k-sub" hidden></p></div></div>
	<ul class="k-counts k-rings" id="k-counts" aria-label="Firewalls by state"></ul>
	<p class="k-sr" id="k-headline" aria-live="polite">Connecting...</p>
	<div class="k-side">
		<time class="k-clock" id="k-clock"></time>
		<span class="k-fresh" id="k-fresh"></span>
		<span class="k-tools">' . $picker . '
			<button type="button" id="k-sound" aria-pressed="false">Turn sound on</button>
			<button type="button" id="k-full">Full screen</button>
		</span>
	</div>
</header>
<div class="k-ops" id="k-ops" hidden></div>
<main class="k-body" id="k-body">
	<section class="k-panels" id="k-panels" aria-label="Fleet"></section>
	<section class="k-right" aria-label="Firewalls">
		<div class="k-list" id="k-list" role="table" aria-label="Firewalls"></div>
		<div class="k-grid" id="k-grid"></div>
		<div class="k-pager" id="k-pager" aria-live="off"></div>
	</section>
</main>
<footer class="k-foot"><span id="k-ppager"></span><span id="k-page"></span></footer>
<div class="k-blocked" id="k-blocked" hidden>
	<h1>This screen is not connected</h1>
	<p id="k-blocked-text">' . ($live ? 'Your WebUI session ended. Log in again and reopen the live view.' :
	    'The kiosk link is missing its key, or the key was revoked, or this screen is on a network the key is not allowed from.') . '</p>
	<p>' . ($live ? '<a href="/fleet/fleet_dashboard.php">Open FreeSense Fleet</a>' : 'An administrator makes a new link in FreeSense Fleet under Dashboard, NOC screens.') . '</p>
</div>
<script src="/fleet/assets/fleet-charts.js?v=' . (int)($versions['charts'] ?? 0) . '"></script>
<script src="/fleet/assets/fleet-kiosk.js?v=' . (int)($versions['js'] ?? 0) . '"></script>
</body>
</html>
';
}

/*
 * pure: one row per firewall group for the Groups panel and the list's
 * group headings. $boxes: fleet_dashboard_data() boxes; $inet: node_id =>
 * internet state; $ha_bad: node_id => true for a member of an HA pair with
 * a problem; $only: the screen's groups (none: every group, plus "No
 * group" for firewalls in none). Problem groups come first. A firewall in
 * two groups counts in both.
 */
function fleet_kiosk_group_rows(array $boxes, array $inet, array $ha_bad, array $only = array()): array {
	$rows = array();
	$rank = array('offline' => 0, 'degraded' => 1, 'inet' => 2, 'ha' => 3, 'policy' => 4, 'ok' => 5);
	foreach ($boxes as $b) {
		$node = (string)($b['id'] ?? ($b['node_id'] ?? ''));
		$groups = $b['groups'] ?? array();
		if (empty($groups) && empty($only)) {
			$groups = array(array('id' => 0, 'name' => 'No group', 'color' => ''));
		}
		foreach ($groups as $g) {
			$id = (int)$g['id'];
			if (!empty($only) && !in_array($id, $only, true)) {
				continue;
			}
			$r = &$rows[$id];
			$r = $r ?? array('id' => $id, 'name' => (string)$g['name'], 'color' => ($id === 0) ? '' : fleet_group_color((string)($g['color'] ?? '')),
			    'total' => 0, 'online' => 0, 'degraded' => 0, 'offline' => 0, 'new' => 0, 'inet' => 0, 'ha' => 0, 'policy' => 0);
			$r['total']++;
			$r[$b['state']] = ($r[$b['state']] ?? 0) + 1;
			$r['inet'] += in_array($inet[$node] ?? '', array('down', 'degraded'), true) ? 1 : 0;
			$r['ha'] += empty($ha_bad[$node]) ? 0 : 1;
			$r['policy'] += ((int)($b['policy'] ?? 0) > 0) ? 1 : 0;
			unset($r);
		}
	}
	foreach ($rows as &$r) {
		$r['worst'] = ($r['offline'] > 0) ? 'offline' : (($r['degraded'] > 0) ? 'degraded' : (($r['inet'] > 0) ? 'inet' : (($r['ha'] > 0) ? 'ha' : (($r['policy'] > 0) ? 'policy' : 'ok'))));
	}
	unset($r);
	$rows = array_values($rows);
	usort($rows, function ($a, $b) use ($rank) {
		/* "No group" last among equals. */
		return array($rank[$a['worst']], ($a['id'] === 0) ? 1 : 0, strtolower($a['name'])) <=> array($rank[$b['worst']], ($b['id'] === 0) ? 1 : 0, strtolower($b['name']));
	});
	return $rows;
}

/*
 * pure: the list grouped: each firewall under its first group that the
 * screen shows (0: no group), groups in $rows order, the firewalls of a
 * group in the order they came. Returns the boxes with 'g' set.
 */
function fleet_kiosk_group_list(array $boxes, array $rows): array {
	$pos = array_flip(array_column($rows, 'id'));
	$keyed = array();
	foreach ($boxes as $i => $b) {
		$keyed[] = array($pos[$b['g']] ?? PHP_INT_MAX, $i, $b);
	}
	usort($keyed, function ($a, $b) { return array($a[0], $a[1]) <=> array($b[0], $b[1]); });
	return array_column($keyed, 2);
}

/*
 * pure: what a screen is sent, from fleet_dashboard_data() and the
 * running group operations. With $hide, names, hostnames, addresses and
 * error texts are left out and firewalls are numbered.
 */
function fleet_kiosk_view(array $data, array $running, bool $hide, string $title, array $look = array('freesense', 'auto'), ?array $cfg = null, array $extra = array(),
    array $panels = array()): array {
	$cfg = $cfg ?? fleet_kiosk_config_defaults();
	$shown = fleet_kiosk_boxes($data['boxes'], $cfg, array_map(function ($x) { return (string)($x['inet']['state'] ?? ''); }, $extra));
	$boxes = array();
	$anon = array();
	foreach ($shown as $i => $b) {
		$node = (string)($b['id'] ?? ($b['node_id'] ?? ''));
		$x = $extra[$node] ?? array();
		$in = empty($cfg['groups']) ? $b['groups'] : array_values(array_filter($b['groups'], function ($g) use ($cfg) { return in_array((int)$g['id'], $cfg['groups'], true); }));
		$box = array('state' => $b['state'], 'groups' => array_column($b['groups'], 'name'), 'version' => $b['version'], 'seen' => $b['seen'],
		    'gc' => array_map(function ($g) { return fleet_group_color((string)($g['color'] ?? '')); }, $b['groups']), 'g' => (int)($in[0]['id'] ?? 0),
		    'policy' => $b['policy'], 'breakglass' => $b['breakglass'], 'update' => ($b['update'] !== null),
		    'op' => (($b['op'] !== null) && in_array($b['op']['state'] ?? '', array('running', 'queued'), true)) ? array('text' => (string)($b['op']['text'] ?? ''), 'progress' => $b['op']['progress'] ?? null) : null,
		    'cpu' => $x['cpu'] ?? null, 'mem' => $x['mem'] ?? null, 'states' => $x['states'] ?? null, 'states_max' => $x['states_max'] ?? null,
		    'rx' => $x['rx'] ?? null, 'tx' => $x['tx'] ?? null, 'up' => $x['up'] ?? null, 'ha' => (string)($x['ha'] ?? ''), 'inet' => $x['inet'] ?? null);
		$anon[$node] = sprintf('Firewall %d', $i + 1);
		if ($hide) {
			$box['name'] = sprintf('Firewall %d', $i + 1);
			$box['host'] = '';
			/* A group is often named after a customer or site. */
			$box['groups'] = array();
			$box['gc'] = array();
			/* The state line says it; an error text could name a host or an address. */
			$box['problem'] = '';
			if ($box['inet'] !== null) {
				$box['inet']['gw'] = '';
				$box['inet']['text'] = ($box['inet']['state'] === 'down') ? 'down' : $box['inet']['numbers'];
			}
			if ($box['op'] !== null) {
				$box['op']['text'] = 'Working';
			}
		} else {
			$box['name'] = $b['label'];
			$box['host'] = $b['host'];
			$box['problem'] = mb_strimwidth((string)$b['problem'], 0, 90, '...');
		}
		if (!$hide) {
			$box['id'] = $node;
		}
		$boxes[] = $box;
	}
	/* A screen for some groups counts and heads only those. */
	if (!empty($cfg['groups'])) {
		$data['counts'] = array_merge($data['counts'], array('online' => 0, 'degraded' => 0, 'offline' => 0, 'new' => 0));
		foreach ($boxes as $b) {
			$data['counts'][$b['state']] = ($data['counts'][$b['state']] ?? 0) + 1;
		}
		$data['total'] = count($boxes);
		$bad = $data['counts']['offline'] + $data['counts']['degraded'];
		$data['headline'] = ($data['total'] === 0) ? 'No firewalls in these groups' : (($bad === 0) ? sprintf('All %d firewalls are online', $data['total']) :
		    sprintf('%d of %d %s attention', $bad, $data['total'], ($data['total'] === 1) ? 'firewall needs' : 'firewalls need'));
	}
	$inet_now = array_map(function ($x) { return (string)($x['inet']['state'] ?? ''); }, $extra);
	$ha_bad = array_map(function ($x) { return !empty($x['ha_bad']); }, $extra);
	$grows = fleet_kiosk_group_rows($shown, $inet_now, $ha_bad, $cfg['groups']);
	if ($hide) {
		foreach ($grows as $i => &$g) {
			$g['name'] = sprintf('Group %d', $i + 1);
		}
		unset($g);
	}
	if ($cfg['group_rows']) {
		$boxes = fleet_kiosk_group_list($boxes, $grows);
	}
	$panels['groups'] = array('rows' => $grows);
	$ops = array();
	foreach ($running as $o) {
		$ops[] = array('title' => $hide ? 'Fleet operation' : (string)$o['title'], 'done' => (int)($o['done'] ?? 0), 'total' => (int)($o['total'] ?? 0),
		    'percent' => (int)($o['percent'] ?? 0));
	}
	$panels = array_intersect_key($panels, array_flip($cfg['panels']));
	return array('title' => $title, 'headline' => $data['headline'], 'total' => $data['total'], 'counts' => $data['counts'], 'boxes' => $boxes, 'ops' => $ops,
	    'checked' => $data['checked'], 'now' => $data['now'], 'style' => $look[0], 'theme' => $look[1], 'group_rows' => $grows,
	    'layout' => array_diff_key($cfg, array('groups' => 1)), 'panels' => $hide ? fleet_kiosk_panels_hide($panels, $anon) : $panels);
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

function fleet_kiosk_row(array $r): array {
	$r['networks'] = json_decode((string)$r['networks'], true) ?: array();
	return $r;
}

function fleet_kiosks_all(): array {
	return array_map('fleet_kiosk_row', fleet_db()->query('SELECT * FROM kiosk_keys WHERE revoked IS NULL ORDER BY name COLLATE NOCASE')->fetchAll());
}

/* A screen's name from its form, or InvalidArgumentException. */
function fleet_kiosk_name(array $in): string {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (mb_strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/u', $name)) {
		throw new InvalidArgumentException('Give the screen a name of 1 to 60 characters.');
	}
	return $name;
}

/* A new screen: returns array(id, key). The key is shown once. */
function fleet_kiosk_create(array $in, string $who): array {
	$name = fleet_kiosk_name($in);
	list($nets, $problem) = fleet_kiosk_networks((string)($in['networks'] ?? ''));
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	$key = FLEET_KIOSK_PREFIX . rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
	list($style, $theme) = fleet_kiosk_look((string)($in['style'] ?? ''), (string)($in['theme'] ?? ''));
	fleet_db()->prepare('INSERT INTO kiosk_keys (name, hash, networks, hide, created, who, style, theme) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
	    ->execute(array($name, hash('sha256', $key), json_encode($nets), empty($in['hide']) ? 0 : 1, time(), $who, $style, $theme));
	$id = (int)fleet_db()->lastInsertId();
	fleet_audit($who, 'kiosk', sprintf('Screen %s: key made, from %s%s', $name, implode(', ', $nets), empty($in['hide']) ? '' : ', names hidden'));
	return array($id, $key);
}

/* Change a screen's name, networks or hiding (the key stays). */
function fleet_kiosk_update(int $id, array $in, string $who): void {
	$name = fleet_kiosk_name($in);
	list($nets, $problem) = fleet_kiosk_networks((string)($in['networks'] ?? ''));
	if ($problem !== null) {
		throw new InvalidArgumentException($problem);
	}
	list($style, $theme) = fleet_kiosk_look((string)($in['style'] ?? ''), (string)($in['theme'] ?? ''));
	fleet_db()->prepare('UPDATE kiosk_keys SET name = ?, networks = ?, hide = ?, style = ?, theme = ? WHERE id = ? AND revoked IS NULL')
	    ->execute(array($name, json_encode($nets), empty($in['hide']) ? 0 : 1, $style, $theme, $id));
	fleet_audit($who, 'kiosk', sprintf('Screen %s: from %s%s', $name, implode(', ', $nets), empty($in['hide']) ? '' : ', names hidden'));
}

function fleet_kiosk_revoke(int $id, string $who): void {
	fleet_db()->prepare('UPDATE kiosk_keys SET revoked = ? WHERE id = ?')->execute(array(time(), $id));
	fleet_audit($who, 'kiosk', "Screen {$id}: key revoked");
}

/*
 * The screen a key and address belong to, or array(null, reason). The
 * reason is for the audit log, never for the caller.
 */
function fleet_kiosk_check(string $key, string $ip, int $now): array {
	if ((strncmp($key, FLEET_KIOSK_PREFIX, strlen(FLEET_KIOSK_PREFIX)) !== 0) || (strlen($key) > 80)) {
		return array(null, 'not a kiosk key');
	}
	$q = fleet_db()->prepare('SELECT * FROM kiosk_keys WHERE hash = ? AND revoked IS NULL');
	$q->execute(array(hash('sha256', $key)));
	$row = $q->fetch();
	if (!is_array($row)) {
		return array(null, 'unknown or revoked key');
	}
	$row = fleet_kiosk_row($row);
	if (!fleet_kiosk_ip_allowed($ip, $row['networks'])) {
		return array(null, "screen {$row['name']} used from {$ip}");
	}
	if ($now - (int)$row['last_used'] > 60) {
		fleet_db()->prepare('UPDATE kiosk_keys SET last_used = ?, last_ip = ? WHERE id = ?')->execute(array($now, $ip, (int)$row['id']));
	}
	return array($row, null);
}

/* ------------------------------------------------------------------ */
/* Settings and data                                                   */
/* ------------------------------------------------------------------ */

/* The settings of a screen (its id) or of the WebUI's live view ('live'). */
function fleet_kiosk_config_get(string $target): array {
	if ($target === 'live') {
		return fleet_kiosk_config_json((string)fleet_setting('noc_config', '{}'));
	}
	$q = fleet_db()->prepare('SELECT config FROM kiosk_keys WHERE id = ? AND revoked IS NULL');
	$q->execute(array((int)$target));
	$v = $q->fetchColumn();
	if ($v === false) {
		throw new InvalidArgumentException('That screen does not exist or its link was revoked.');
	}
	return fleet_kiosk_config_json((string)$v);
}

function fleet_kiosk_config_set(string $target, array $cfg, string $who): void {
	$json = json_encode($cfg);
	if ($target === 'live') {
		fleet_setting_set('noc_config', $json);
		fleet_audit($who, 'kiosk', 'Live view layout changed');
		return;
	}
	fleet_kiosk_config_get($target);
	fleet_db()->prepare('UPDATE kiosk_keys SET config = ? WHERE id = ? AND revoked IS NULL')->execute(array($json, (int)$target));
	fleet_audit($who, 'kiosk', "Screen {$target}: layout changed");
}

/* A value kept for $ttl seconds in the data folder, so many screens do not each work it out. */
function fleet_kiosk_cached(string $name, int $ttl, callable $make) {
	$f = FLEET_DATA . '/kiosk-cache-' . preg_replace('/[^a-z0-9_-]/', '', $name) . '.json';
	$st = @stat($f);
	if (($st !== false) && (time() - $st['mtime'] < $ttl)) {
		$v = json_decode((string)@file_get_contents($f), true);
		if (is_array($v)) {
			return $v;
		}
	}
	$v = $make();
	@file_put_contents($f . '.tmp', json_encode($v));
	@rename($f . '.tmp', $f);
	return $v;
}

/* node id => the list's live values: the newest load sample, availability over 24 hours and the HA role. */
function fleet_kiosk_extra(): array {
	return fleet_kiosk_cached('extra', 30, function () {
		$out = array();
		$q = fleet_db()->query('SELECT s.node_id, s.cpu, s.mem, s.states, s.states_max, s.rx_bps, s.tx_bps FROM samples s
		    JOIN (SELECT node_id, MAX(time) AS t FROM samples GROUP BY node_id) m ON m.node_id = s.node_id AND m.t = s.time WHERE s.time > ' . (time() - 1800));
		foreach ($q->fetchAll() as $r) {
			$out[$r['node_id']] = array('cpu' => ($r['cpu'] === null) ? null : round((float)$r['cpu'], 1), 'mem' => ($r['mem'] === null) ? null : round((float)$r['mem'], 1),
			    'states' => ($r['states'] === null) ? null : (int)$r['states'], 'states_max' => ($r['states_max'] === null) ? null : (int)$r['states_max'],
			    'rx' => ($r['rx_bps'] === null) ? null : (int)$r['rx_bps'], 'tx' => ($r['tx_bps'] === null) ? null : (int)$r['tx_bps']);
		}
		foreach (fleet_stats('24h', null, 2)['boxes'] as $b) {
			$out[$b['node']]['up'] = $b['percent'];
		}
		list($pairs) = fleet_ha_now();
		foreach ($pairs as $p) {
			foreach ($p['nodes'] as $n) {
				$out[$n]['ha'] = in_array($n, $p['masters'], true) ? 'MASTER' : 'BACKUP';
				$out[$n]['ha_bad'] = $p['problem'] !== null;
			}
		}
		$q24 = fleet_inet_enabled() ? fleet_inet_stats(86400, time()) : array();
		foreach (fleet_inet_now() as $n => $r) {
			$out[$n]['inet'] = array('state' => $r['state'], 'text' => fleet_inet_text($r), 'gw' => $r['gw'],
			    'numbers' => ($r['delay_ms'] === null) ? '' : fleet_inet_text(array('state' => 'up') + $r), 'since' => (int)$r['since'],
			    'score' => $q24[$n]['score'] ?? null, 'loss24' => $q24[$n]['loss'] ?? null, 'flaps24' => $q24[$n]['flaps'] ?? null,
			    'loss' => ($r['loss_pct'] === null) ? null : round((float)$r['loss_pct'], 1), 'delay' => ($r['delay_ms'] === null) ? null : round((float)$r['delay_ms'], 1));
		}
		return $out;
	});
}

/* The fleet server itself: host, load, memory, disk, database, the poll, the tunnel and the standby. */
function fleet_kiosk_controller(): array {
	$sys = function (string $name) {
		return (int)trim((string)@shell_exec('/sbin/sysctl -n ' . escapeshellarg($name) . ' 2>/dev/null'));
	};
	$load = function_exists('sys_getloadavg') ? (sys_getloadavg() ?: array()) : array();
	$page = $sys('hw.pagesize');
	$total = $sys('hw.physmem');
	$free = $page * ($sys('vm.stats.vm.v_free_count') + $sys('vm.stats.vm.v_inactive_count') + $sys('vm.stats.vm.v_cache_count'));
	$db = FLEET_DATA . '/fleet.db';
	$round = json_decode((string)fleet_setting('poll_round', '{}'), true) ?: array();
	list(, $hs) = fleet_ctl_exec(array('/usr/bin/wg', 'show', FLEET_CTL_IF, 'latest-handshakes'));
	$peers = 0;
	$recent = 0;
	foreach (explode("\n", trim((string)$hs)) as $l) {
		$f = preg_split('/\s+/', trim($l));
		if (count($f) === 2) {
			$peers++;
			$recent += ((int)$f[1] > 0) && ((time() - (int)$f[1]) < 300) ? 1 : 0;
		}
	}
	$sb = fleet_standby_overview();
	$row = fleet_controller_row();
	$disk_total = @disk_total_space(FLEET_DATA) ?: 0;
	return array(
		'host' => $row['label'], 'version' => $row['version'], 'uptime' => $row['uptime'],
		'load' => array_map(function ($v) { return round((float)$v, 2); }, array_slice($load, 0, 3)), 'cpus' => max(1, $sys('hw.ncpu')),
		'mem_pct' => ($total > 0) ? round(100 * (1 - min($free, $total) / $total), 1) : null, 'mem_total' => $total,
		'disk_pct' => ($disk_total > 0) ? round(100 * (1 - (@disk_free_space(FLEET_DATA) ?: 0) / $disk_total), 1) : null,
		'disk_free' => ($disk_total > 0) ? (int)(@disk_free_space(FLEET_DATA) ?: 0) : null,
		'db_bytes' => (int)@filesize($db) + (int)@filesize($db . '-wal'),
		'poll_at' => (int)($round['at'] ?? 0), 'poll_secs' => (int)($round['secs'] ?? 0), 'poll_boxes' => (int)($round['boxes'] ?? 0),
		'poll_interval' => (int)fleet_ctl_settings()['poll_interval'],
		'tunnel_peers' => $peers, 'tunnel_recent' => $recent,
		'pending' => (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(),
		'standby_role' => $sb['role'], 'standby_addr' => $sb['addr'], 'standby_seen' => $sb['seen'], 'standby_version' => $sb['version'],
		'fleet_version' => trim((string)@shell_exec("/usr/sbin/pkg query '%v' FreeSense-pkg-Fleet 2>/dev/null")),
	);
}

/* The HA pairs as the NOC draws them: members with their role and state, the problem, and the last HA alert. */
function fleet_kiosk_ha(): array {
	list($pairs, $boxes) = fleet_ha_now();
	$out = array();
	foreach ($pairs as $p) {
		$members = array();
		foreach ($p['nodes'] as $n) {
			$up = (($boxes[$n]['state'] ?? '') === 'online') && ((int)($boxes[$n]['misses'] ?? 0) === 0);
			$members[] = array('node' => $n, 'label' => (string)($boxes[$n]['label'] ?? $n), 'state' => (string)($boxes[$n]['state'] ?? 'new'),
			    'role' => !$up ? 'down' : (in_array($n, $p['masters'], true) ? 'MASTER' : 'BACKUP'), 'primary' => $p['primary'] === $n);
		}
		$last = fleet_db()->prepare("SELECT MAX(time) FROM alerts WHERE event IN ('ha_problem', 'ha_ok') AND node_id IN (" . implode(',', array_fill(0, count($p['nodes']), '?')) . ')');
		$last->execute(array_values($p['nodes']));
		$labels = array_column($members, 'label');
		natcasesort($labels);
		$out[] = array('name' => implode(' + ', $labels), 'members' => $members, 'vips' => count($p['vips']),
		    'problem' => ($p['problem'] === null) ? '' : fleet_ha_problem_badge($p['problem']), 'last' => (int)$last->fetchColumn() ?: null);
	}
	return $out;
}

/* pure: " AND <col> IN (...)" for a group screen's firewalls, or "" for the whole fleet. */
function fleet_kiosk_in(string $col, ?array $nodes): string {
	if ($nodes === null) {
		return '';
	}
	return " AND {$col} IN (" . (empty($nodes) ? "''" : implode(',', array_map(array(fleet_db(), 'quote'), $nodes))) . ')';
}

/*
 * Every panel's data for a range and the screen's groups (none: the whole
 * fleet), kept 30 seconds. With names: the hide pass
 * (fleet_kiosk_panels_hide) is done per screen.
 */
function fleet_kiosk_panels(array $cfg, int $now): array {
	$group = fleet_trends_group_ids($cfg['groups']);
	sort($group);
	return fleet_kiosk_cached("panels-{$cfg['range']}-" . (empty($group) ? '0' : implode('_', $group)), 30, function () use ($cfg, $group, $now) {
		$tr = fleet_trends($cfg['range'], $group, $now);
		$nodes = empty($group) ? null : array_column(fleet_trends_boxes($group), 'node_id');
		$st = fleet_stats('24h', $nodes, 2);
		$days = $tr['days'];
		$p = array();
		$p['health'] = array('up' => $st['percent'], 'outages' => $st['outages'], 'longest' => $st['longest'], 't' => $tr['up']['t'], 'avail' => $tr['up']['up']);
		$p['pulse'] = fleet_trends_pulse($group, $now);
		$p['load'] = array('t' => $tr['t'], 'cpu' => $tr['load']['cpu_med'], 'cpu_p90' => $tr['load']['cpu_p90'], 'mem' => $tr['load']['mem_med'], 'mem_p90' => $tr['load']['mem_p90'],
		    'sampled' => $tr['sampled']);
		$p['traffic'] = array('t' => $tr['t'], 'rx' => $tr['load']['rx'], 'tx' => $tr['load']['tx']);
		$p['states'] = array('t' => $tr['t'], 'top' => array_map(function ($r) { return array('label' => $r['label'], 'node' => $r['node'], 'data' => $r['data'], 'peak' => round($r['peak'], 1)); }, $tr['states_top']));
		$p['temp'] = array('t' => $tr['t'], 'top' => array_map(function ($r) { return array('label' => $r['label'], 'node' => $r['node'], 'data' => $r['data'], 'peak' => round($r['peak'], 1)); }, $tr['temp_top']));
		$latest = array();
		/* A group screen shows its firewalls' alerts and the fleet-wide ones (no firewall). */
		foreach (fleet_db()->query('SELECT time, event, severity, node_id FROM alerts WHERE 1' . (($nodes === null) ? '' : " AND (node_id = '' OR 1" . fleet_kiosk_in('node_id', $nodes) . ')') .
		    ' ORDER BY id DESC LIMIT 6')->fetchAll() as $a) {
			$latest[] = array('time' => (int)$a['time'], 'severity' => (string)$a['severity'], 'title' => (string)(FLEET_ALERT_EVENTS[$a['event']][0] ?? $a['event']),
			    'node' => (string)$a['node_id'], 'box' => (string)(fleet_box_get((string)$a['node_id'])['label'] ?? ''), 'text' => '');
		}
		$p['alerts'] = array('days' => $days, 'day' => $tr['alerts_day'], 'latest' => $latest);
		$p['ops'] = array('days' => $days, 'day' => $tr['ops_day'],
		    'failed_24h' => (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE state = 'failed' AND started > " . ($now - 86400) .
		    (($nodes === null) ? ' AND parent IS NULL' : fleet_kiosk_in('node_id', $nodes)))->fetchColumn());
		$newest = fleet_db()->query('SELECT MIN(t) AS oldest, COUNT(*) AS n FROM (SELECT MAX(time) AS t FROM backups WHERE 1' . fleet_kiosk_in('node_id', $nodes) . ' GROUP BY node_id)')->fetch();
		$p['backups'] = array('days' => $days, 'day' => $tr['backups_day'], 'oldest' => ($newest['oldest'] === null) ? null : (int)$newest['oldest'],
		    'with' => (int)$newest['n'], 'total' => $tr['total'],
		    'ok_24h' => (int)fleet_db()->query('SELECT COUNT(*) FROM backups WHERE time > ' . ($now - 86400) . fleet_kiosk_in('node_id', $nodes))->fetchColumn());
		$rules = array();
		$cat = fleet_policy_catalog();
		foreach (fleet_db()->query("SELECT rule_id, COUNT(DISTINCT node_id) AS n FROM compliance WHERE state = 'fail'" . fleet_kiosk_in('node_id', $nodes) .
		    ' GROUP BY rule_id ORDER BY n DESC LIMIT 5')->fetchAll() as $r) {
			$base = preg_replace('/:\d+$/', '', (string)$r['rule_id']);
			$rules[] = array('label' => (string)($cat[$base]['title'] ?? $base) . ' ' . $base, 'value' => (int)$r['n']);
		}
		$p['compliance'] = $tr['compliance'] + array('rules' => $rules, 'checked' => (int)fleet_setting('compliance_checked', '0'));
		$updates = 0;
		foreach (fleet_db()->query('SELECT update_info FROM boxes WHERE 1' . fleet_kiosk_in('node_id', $nodes))->fetchAll(PDO::FETCH_COLUMN) as $u) {
			$updates += (fleet_update_verdict(json_decode((string)$u, true) ?: null) !== null) ? 1 : 0;
		}
		$p['versions'] = array('versions' => $tr['versions'], 'updates' => $updates);
		$p['busiest'] = array('busiest' => array_map(function ($r) {
			return array('label' => $r['label'], 'node' => $r['node'], 'cpu' => $r['cpu_now'], 'mem' => $r['mem_now'], 'peak' => $r['peak']);
		}, array_slice($tr['busiest'], 0, 5)));
		$p['outages'] = array('days' => $days, 'day' => $tr['outages_day']);
		/* A pair is shown when one of its firewalls is in the screen's groups. */
		$p['ha'] = array('pairs' => array_values(array_filter(fleet_kiosk_ha(), function ($pair) use ($nodes) {
			return ($nodes === null) || !empty(array_intersect(array_column($pair['members'], 'node'), $nodes));
		})));
		$p['controller'] = fleet_kiosk_controller();
		if (fleet_inet_enabled()) {
			$p += fleet_kiosk_inet_panels($cfg['range'], $group, $now);
		}
		return $p;
	});
}

/* The internet panels for a range and groups (none: all): now, quality, worst connections, availability and the latest events. */
function fleet_kiosk_inet_panels(string $range, int|array $group, int $now): array {
	$grouped = !empty(fleet_trends_group_ids($group));
	$boxes = fleet_trends_boxes($group);
	$nodes = array_column($boxes, 'node_id');
	$labels = array_column($boxes, 'label', 'node_id');
	$cur = array_intersect_key(fleet_inet_now(), array_flip($nodes));
	$counts = fleet_inet_counts($cur);
	$backup = count(array_filter($cur, function ($r) { return strpos((string)$r['reason'], 'default gateway') === 0; }));
	$avail = fleet_inet_availability(86400, $now);
	$mine = array_intersect_key($avail, array_flip($nodes));
	$worst = array();
	foreach ($cur as $n => $r) {
		$score = (($r['state'] === 'down') ? 1000 : 0) + (float)($r['loss_pct'] ?? 0) * 10 + (float)($r['delay_ms'] ?? 0) / 10;
		$worst[] = array('label' => (string)($labels[$n] ?? $n), 'node' => $n, 'state' => $r['state'], 'value' => round($score, 1), 'text' => fleet_inet_text($r));
	}
	usort($worst, function ($a, $b) { return $b['value'] <=> $a['value']; });
	$events = array();
	foreach (fleet_inet_events(6) as $e) {
		if (($e['node'] !== '') && !isset($labels[$e['node']]) && $grouped) {
			continue;
		}
		$events[] = array('time' => $e['time'], 'severity' => $e['severity'], 'title' => $e['title'], 'node' => $e['node'],
		    'box' => (string)($labels[$e['node']] ?? ''), 'text' => '');
	}
	$span = FLEET_STATS_RANGES[$range] ?? 86400;
	$qs = array_intersect_key(fleet_inet_stats($span, $now), array_flip($nodes));
	$ranked = array();
	foreach ($qs as $n => $s) {
		if ($s['score'] !== null) {
			$ranked[] = array('label' => (string)($labels[$n] ?? $n), 'node' => $n, 'score' => $s['score'], 'loss' => $s['loss'], 'flaps' => $s['flaps'], 'loss_min' => $s['loss_min']);
		}
	}
	usort($ranked, function ($a, $b) { return array($a['score'], $a['label']) <=> array($b['score'], $b['label']); });
	return array(
		'inet' => $counts + array('backup' => $backup, 'total' => count($cur), 'avail' => empty($mine) ? null : round(array_sum($mine) / count($mine), 1)),
		'inet_score' => array('fleet' => fleet_inet_fleet_stats($qs), 'top' => array_slice($ranked, 0, 6)),
		'inet_quality' => fleet_inet_series($range, $grouped ? $nodes : null, $now),
		/* Only connections with a problem now: a clean fleet leaves the panel out. */
		'inet_worst' => array('top' => array_slice(array_values(array_filter($worst, function ($w) use ($cur) {
			return ($w['state'] !== 'up') || ((float)($cur[$w['node']]['loss_pct'] ?? 0) > 0);
		})), 0, 5)),
		'inet_pulse' => fleet_inet_pulse($boxes, $now),
		'inet_events' => array('latest' => $events),
	);
}

/*
 * What noc_data.php and kiosk_data.php answer: the fleet now, a screen's
 * list and panels. $cfg: the screen's settings.
 */
function fleet_kiosk_payload(bool $hide, string $title, array $look, array $cfg): array {
	$now = time();
	$data = fleet_dashboard_data(
	    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
	    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), $now, fleet_groups_by_box(), fleet_ops_for_tiles($now), array());
	$panels = (($cfg['layout'] === 'list') || empty($cfg['panels'])) ? array() : fleet_kiosk_panels($cfg, $now);
	$view = fleet_kiosk_view($data, fleet_ops_groups_running(), $hide, $title, $look, $cfg, fleet_kiosk_extra(), $panels);
	$view['ha_problems'] = count(array_filter($panels['ha']['pairs'] ?? fleet_kiosk_ha(), function ($p) { return $p['problem'] !== ''; }));
	$view['inet_on'] = fleet_inet_enabled();
	return $view;
}
