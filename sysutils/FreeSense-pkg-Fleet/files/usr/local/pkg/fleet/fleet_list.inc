<?php
/*
 * fleet_list.inc
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
 * Lists that grow: filters, search and paging shared by every Fleet list
 * (Activity, a firewall's Events, later backups and the audit log). A
 * fleet has hundreds of firewalls and thousands of operations, so no list
 * shows "the last N" only. Filters live in the URL, so a link or a reload
 * keeps them. The WHERE builders are pure and return SQL with ? params.
 */

require_once('fleet/fleet_store.inc');


/* What the Activity filters offer: value => label. */
define('FLEET_OPS_STATES', array('running' => 'Running', 'done' => 'Done', 'failed' => 'Failed'));
define('FLEET_OPS_KINDS', array('backup_all' => 'Group backups', 'reboot_group' => 'Group reboots', 'update_group' => 'Group updates', 'rollout' => 'Rollouts', 'update' => 'Updates', 'backup' => 'Backups', 'reboot' => 'Reboots', 'restore' => 'Restores', 'template' => 'Templates', 'users' => 'User syncs', 'connections' => 'Connection changes', 'ha_setup' => 'HA pair setups', 'ha_remove' => 'HA pair removals', 'replica' => 'Backup copies', 'replica_sync' => 'Backup copy syncs'));
define('FLEET_OPS_SINCE', array('1' => 'Last 24 hours', '7' => 'Last 7 days', '30' => 'Last 30 days'));

/* A firewall's events by type: value => array(label, audit actions). */
define('FLEET_EVENT_TYPES', array(
	'state' => array('Status changes', array('state', 'joined', 'pending')),
	'backup' => array('Backups', array('backup', 'backup_all', 'backup_failed', 'backup_download')),
	'restore' => array('Restores', array('restore', 'restore_failed')),
	'manage' => array('Reboots and services', array('reboot', 'reboot_done', 'reboot_failed', 'service', 'states_reset')),
	'access' => array('Sign-ins', array('handoff')),
	'groups' => array('Groups', array('groups')),
));

/* pure: the filters from the query string, only known values; anything else is dropped. */
function fleet_list_filters(array $get, array $allowed): array {
	$out = array();
	foreach ($allowed as $key => $values) {
		$v = trim((string)($get[$key] ?? ''));
		if ($v === '') {
			continue;
		}
		if ($values === null) {
			/* Free text (search): at most 80 characters, no control characters. */
			$v = preg_replace('/[\x00-\x1f\x7f]/', '', substr($v, 0, 80));
			if ($v !== '') {
				$out[$key] = $v;
			}
		} elseif (array_key_exists($v, $values)) {
			$out[$key] = $v;
		}
	}
	return $out;
}

/* pure: which page to show; a page past the end shows the last one. */
function fleet_list_page(int $total, int $page, int $per = 0): array {
	$per = ($per > 0) ? $per : fleet_opt('per_page');
	$pages = max(1, (int)ceil($total / $per));
	$page = min(max(1, $page), $pages);
	return array('page' => $page, 'pages' => $pages, 'per' => $per, 'offset' => ($page - 1) * $per, 'total' => $total,
	    'first' => ($total === 0) ? 0 : ($page - 1) * $per + 1, 'last' => min($total, $page * $per));
}

/* pure: page numbers to show around the current one; 0 is a gap ("..."). */
function fleet_list_page_links(int $page, int $pages): array {
	$keep = array_unique(array_filter(array(1, $page - 1, $page, $page + 1, $pages), function ($n) use ($pages) {
		return $n >= 1 && $n <= $pages;
	}));
	sort($keep);
	$out = array();
	$prev = 0;
	foreach ($keep as $n) {
		if ($n > $prev + 1) {
			$out[] = 0;
		}
		$out[] = $n;
		$prev = $n;
	}
	return $out;
}

/* pure: LIKE with the user's % and _ taken literally. */
function fleet_list_like(string $q): string {
	return '%' . strtr($q, array('\\' => '\\\\', '%' => '\\%', '_' => '\\_')) . '%';
}

/* pure: the Activity filters as SQL on ops o LEFT JOIN boxes b. Group tasks never show on their own. */
function fleet_ops_where(array $f, int $now): array {
	$where = array('o.parent IS NULL');
	$params = array();
	if (isset($f['state'])) {
		$where[] = ($f['state'] === 'running') ? "o.state IN ('running', 'queued')" : 'o.state = ?';
		if ($f['state'] !== 'running') {
			$params[] = $f['state'];
		}
	}
	if (isset($f['kind'])) {
		$where[] = 'o.kind = ?';
		$params[] = $f['kind'];
		if (in_array($f['kind'], array('backup', 'reboot', 'restore', 'update'), true)) {
			$where[] = "o.node_id != ''";
		}
	}
	if (isset($f['since'])) {
		$where[] = 'o.started >= ?';
		$params[] = $now - 86400 * (int)$f['since'];
	}
	if (isset($f['q'])) {
		/* A group operation matches when one of its firewalls does too. */
		$like = fleet_list_like($f['q']);
		$where[] = "(o.title LIKE ? ESCAPE '\\' OR o.text LIKE ? ESCAPE '\\' OR o.who LIKE ? ESCAPE '\\' OR b.label LIKE ? ESCAPE '\\' OR o.node_id LIKE ? ESCAPE '\\'" .
		    " OR o.id IN (SELECT t.parent FROM ops t LEFT JOIN boxes tb ON tb.node_id = t.node_id WHERE t.parent IS NOT NULL AND (tb.label LIKE ? ESCAPE '\\' OR t.node_id LIKE ? ESCAPE '\\' OR t.text LIKE ? ESCAPE '\\')))";
		array_push($params, $like, $like, $like, $like, $like, $like, $like, $like);
	}
	return array(implode(' AND ', $where), $params);
}

/* One page of operations and how many match. */
function fleet_ops_find(array $f, int $page, int $now): array {
	list($where, $params) = fleet_ops_where($f, $now);
	$count = fleet_db()->prepare("SELECT COUNT(*) FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE {$where}");
	$count->execute($params);
	$p = fleet_list_page((int)$count->fetchColumn(), $page);
	$q = fleet_db()->prepare("SELECT o.*, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE {$where} ORDER BY o.started DESC, o.id DESC LIMIT ? OFFSET ?");
	$q->execute(array_merge($params, array($p['per'], $p['offset'])));
	return array($q->fetchAll(), $p);
}

/* pure: a firewall's event filters as SQL on audit. */
function fleet_events_where(string $node_id, array $f, int $now): array {
	$where = array('detail LIKE ?');
	$params = array($node_id . '%');
	if (isset($f['type'])) {
		$actions = FLEET_EVENT_TYPES[$f['type']][1];
		$where[] = 'action IN (' . implode(', ', array_fill(0, count($actions), '?')) . ')';
		$params = array_merge($params, $actions);
	}
	if (isset($f['since'])) {
		$where[] = 'time >= ?';
		$params[] = $now - 86400 * (int)$f['since'];
	}
	if (isset($f['q'])) {
		$like = fleet_list_like($f['q']);
		$where[] = "(detail LIKE ? ESCAPE '\\' OR who LIKE ? ESCAPE '\\')";
		array_push($params, $like, $like);
	}
	return array(implode(' AND ', $where), $params);
}

function fleet_events_find(string $node_id, array $f, int $page, int $now): array {
	list($where, $params) = fleet_events_where($node_id, $f, $now);
	$count = fleet_db()->prepare("SELECT COUNT(*) FROM audit WHERE {$where}");
	$count->execute($params);
	$p = fleet_list_page((int)$count->fetchColumn(), $page);
	$q = fleet_db()->prepare("SELECT time, who, action, detail FROM audit WHERE {$where} ORDER BY time DESC, id DESC LIMIT ? OFFSET ?");
	$q->execute(array_merge($params, array($p['per'], $p['offset'])));
	return array($q->fetchAll(), $p);
}

/* ------------------------------------------------------------------ */
/* Markup shared by the list pages                                     */
/* ------------------------------------------------------------------ */

/* The URL of this list with some filters changed (null removes one); page goes back to 1 unless given. */
function fleet_list_url(array $base, array $f, array $change): string {
	$all = array_merge($base, $f, array('page' => null), $change);
	return '?' . http_build_query(array_filter($all, function ($v) { return $v !== null && $v !== ''; }));
}

/* A filter bar: selects and a search box in a GET form; fleet-list.js submits on change. */
function fleet_list_filterbar(array $base, array $f, array $selects, string $search_label, string $search_hint): string {
	$h = '<form method="get" class="fs-fleet-filterbar" role="search" data-fleet-filters>';
	foreach ($base as $k => $v) {
		$h .= '<input type="hidden" name="' . htmlspecialchars($k) . '" value="' . htmlspecialchars((string)$v) . '"/>';
	}
	$h .= '<div class="fs-fleet-search"><i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>' .
	    '<input type="search" class="form-control form-control-sm" name="q" value="' . htmlspecialchars($f['q'] ?? '') . '" placeholder="' . htmlspecialchars($search_hint) .
	    '" aria-label="' . htmlspecialchars($search_label) . '"/></div>';
	foreach ($selects as $name => list($label, $options)) {
		$h .= '<select class="form-select form-select-sm" name="' . htmlspecialchars($name) . '" aria-label="' . htmlspecialchars($label) . '">';
		$h .= '<option value="">' . htmlspecialchars($label) . '</option>';
		foreach ($options as $value => $text) {
			$h .= '<option value="' . htmlspecialchars((string)$value) . '"' . ((($f[$name] ?? '') === (string)$value) ? ' selected' : '') . '>' . htmlspecialchars(gettext($text)) . '</option>';
		}
		$h .= '</select>';
	}
	$h .= '<button class="btn btn-sm btn-outline-secondary" type="submit">' . gettext('Filter') . '</button>';
	if (!empty($f)) {
		$h .= '<a class="btn btn-sm btn-link" href="' . htmlspecialchars(fleet_list_url($base, array(), array())) . '">' . gettext('Clear filters') . '</a>';
	}
	/* The bar needs fleet-list.js; bring it along once so no page forgets it. */
	static $script = false;
	if (!$script) {
		$script = true;
		$h .= '<script src="/fleet/assets/fleet-list.js?v=' . (int)@filemtime('/usr/local/www/fleet/assets/fleet-list.js') . '" defer></script>';
	}
	return $h . '</form>';
}

/* "26-50 of 340" and page links (Bootstrap pagination, styled by the WebUI). */
function fleet_list_pager(array $p, array $base, array $f): string {
	$h = '<div class="fs-fleet-pager"><span class="fs-muted">' . (($p['total'] === 0) ? '' : sprintf(gettext('%1$d-%2$d of %3$d'), $p['first'], $p['last'], $p['total'])) . '</span>';
	if ($p['pages'] > 1) {
		$h .= '<nav aria-label="' . gettext('Pages') . '"><ul class="pagination pagination-sm mb-0">';
		$link = function ($n, $label, $disabled = false, $current = false) use ($base, $f) {
			$cls = 'page-item' . ($disabled ? ' disabled' : '') . ($current ? ' active' : '');
			$inner = $disabled ? '<span class="page-link">' . $label . '</span>'
			    : '<a class="page-link" href="' . htmlspecialchars(fleet_list_url($base, $f, array('page' => $n))) . '"' . ($current ? ' aria-current="page"' : '') . '>' . $label . '</a>';
			return '<li class="' . $cls . '">' . $inner . '</li>';
		};
		$h .= $link($p['page'] - 1, '<span aria-hidden="true">&lsaquo;</span><span class="visually-hidden">' . gettext('Previous') . '</span>', $p['page'] <= 1);
		foreach (fleet_list_page_links($p['page'], $p['pages']) as $n) {
			$h .= ($n === 0) ? '<li class="page-item disabled"><span class="page-link">&hellip;</span></li>' : $link($n, (string)$n, false, $n === $p['page']);
		}
		$h .= $link($p['page'] + 1, '<span aria-hidden="true">&rsaquo;</span><span class="visually-hidden">' . gettext('Next') . '</span>', $p['page'] >= $p['pages']);
		$h .= '</ul></nav>';
	}
	return $h . '</div>';
}

/*
 * The progress bar every action uses: fills to $progress, with moving
 * stripes while it runs; slides when the progress is unknown (null);
 * green when done, red when failed. The same markup as fleet.js draws.
 */
function fleet_progress_bar(string $state, ?int $progress, string $label, string $size = ''): string {
	$running = in_array($state, array('running', 'queued'), true);
	$known = !$running || ($progress !== null);
	$value = $running ? (int)$progress : 100;
	$aria = 'role="progressbar" aria-label="' . htmlspecialchars($label) . '" aria-valuemin="0" aria-valuemax="100"' . ($known ? ' aria-valuenow="' . $value . '"' : '');
	return '<span class="fs-fleet-bar' . ($size !== '' ? ' fs-fleet-bar--' . $size : '') . '" data-state="' . htmlspecialchars($state) . '"' .
	    ($known ? '' : ' data-indeterminate') . ' ' . $aria . '><span class="fs-fleet-bar-fill" style="width: ' . ($known ? $value : 100) . '%"></span></span>';
}

/* ------------------------------------------------------------------ */
/* The Firewalls tab                                                   */
/* ------------------------------------------------------------------ */

define('FLEET_FW_STATES', array('online' => 'Online', 'degraded' => 'Degraded', 'offline' => 'Offline', 'new' => 'Not seen yet'));
define('FLEET_FW_SORTS', array('state' => 'Needs attention first', 'name' => 'Name', 'seen' => 'Last seen', 'version' => 'Version'));

/*
 * pure: the firewalls (fleet_dashboard_data()['boxes']) that match the
 * filters q (label, hostname, overlay, version), state, group (id),
 * version and problem (attention / unprotected / policy / update), in
 * the chosen order.
 */
function fleet_firewalls_filter(array $boxes, array $f): array {
	$q = strtolower($f['q'] ?? '');
	$out = array_values(array_filter($boxes, function ($b) use ($f, $q) {
		if (($q !== '') && (strpos(strtolower($b['label'] . ' ' . $b['host'] . ' ' . $b['overlay'] . ' ' . $b['version']), $q) === false)) {
			return false;
		}
		if (isset($f['state']) && ($b['state'] !== $f['state'])) {
			return false;
		}
		if (isset($f['group']) && !in_array((int)$f['group'], array_column($b['groups'], 'id'), true)) {
			return false;
		}
		if (isset($f['version']) && ($b['version'] !== $f['version'])) {
			return false;
		}
		switch ($f['problem'] ?? '') {
		case 'attention':
			return in_array($b['state'], array('offline', 'degraded'), true) || $b['breakglass'];
		case 'unprotected':
			return $b['rollback'] === false;
		case 'policy':
			return $b['policy'] > 0;
		case 'update':
			return ($b['update'][0] ?? '') === 'info';
		case 'waiting':
			return false;
		}
		return true;
	}));
	$sort = $f['sort'] ?? 'state';
	if ($sort === 'name') {
		usort($out, function ($a, $b) { return strcasecmp($a['label'], $b['label']); });
	} elseif ($sort === 'seen') {
		usort($out, function ($a, $b) { return (int)$b['seen'] <=> (int)$a['seen']; });
	} elseif ($sort === 'version') {
		usort($out, function ($a, $b) { return array(version_compare($b['version'], $a['version']), strcasecmp($a['label'], $b['label'])) <=> array(0, 0); });
	}
	return $out;
}

/* pure: the versions in the fleet, newest first, for the filter. */
function fleet_firewalls_versions(array $boxes): array {
	$v = array_values(array_unique(array_filter(array_column($boxes, 'version'))));
	usort($v, function ($a, $b) { return version_compare($b, $a); });
	return array_combine($v, $v) ?: array();
}

/*
 * Firewalls that are on their way in: joined and waiting for approval,
 * open invitations, and Deployment Factory rows not joined yet. Newest
 * first; $q narrows by label.
 */
function fleet_waiting_list(?string $q = null): array {
	$out = array();
	$now = time();
	foreach (fleet_db()->query("SELECT e.id, e.code, e.created, e.source_ip, i.label FROM enrollments e JOIN invitations i ON i.token_id = e.token_id
	    WHERE e.state = 'pending' ORDER BY e.created DESC")->fetchAll() as $e) {
		$out[] = array('kind' => 'approval', 'label' => (string)$e['label'], 'time' => (int)$e['created'],
		    'detail' => sprintf(gettext('Joined from %1$s; code %2$s'), $e['source_ip'] ?: '-', $e['code']), 'url' => '/fleet/fleet.php?view=invite');
	}
	$q1 = fleet_db()->prepare("SELECT i.token_id, i.label, i.created, i.expires, i.via, i.batch_id, b.name AS batch FROM invitations i LEFT JOIN batches b ON b.id = i.batch_id
	    WHERE i.state = 'open' AND i.expires > ? AND NOT EXISTS (SELECT 1 FROM enrollments e WHERE e.token_id = i.token_id AND e.state = 'pending')
	    ORDER BY i.created DESC");
	$q1->execute(array($now));
	foreach ($q1->fetchAll() as $i) {
		$factory = ($i['batch_id'] !== null);
		$out[] = array('kind' => $factory ? 'factory' : 'invite', 'label' => (string)$i['label'], 'time' => (int)$i['created'],
		    'detail' => trim(($factory ? sprintf(gettext('Deployment Factory: %s.'), $i['batch']) : gettext('Invitation not used yet.')) . ' ' .
		    sprintf(gettext('Valid until %s'), date('Y-m-d H:i', (int)$i['expires'])) . (($i['via'] === 'tailscale') ? ', ' . gettext('over Tailscale') : '')),
		    'url' => $factory ? '/fleet/fleet_factory.php?view=batch&id=' . (int)$i['batch_id'] : '/fleet/fleet.php?view=invite');
	}
	if (($q !== null) && ($q !== '')) {
		$out = array_values(array_filter($out, function ($w) use ($q) { return stripos($w['label'], $q) !== false; }));
	}
	return $out;
}

/* The controller itself, for the firewall list (read-only there). */
function fleet_controller_row(): array {
	$boot = fleet_boottime_seconds();
	return array(
		'label' => (string)config_get_path('system/hostname') . '.' . (string)config_get_path('system/domain'),
		'version' => trim((string)@file_get_contents('/etc/version')),
		'uptime' => ($boot > 0) ? time() - $boot : null,
		'addresses' => fleet_ctl_settings()['public_host'] ?? '',
	);
}

/* Seconds since the epoch this system booted, or 0. */
function fleet_boottime_seconds(): int {
	return preg_match('/sec = (\d+)/', (string)@shell_exec('/sbin/sysctl -n kern.boottime'), $m) ? (int)$m[1] : 0;
}

/*
 * A button that asks first (assets/fleet-confirm.js): the attributes that make a submit button or link open a confirmation
 * dialog. $tone: 'danger' (deletes, cannot be undone), 'warning' (changes firewalls, stops a service, ends access) or 'info'.
 * $icon: a Font Awesome name without "fa-". $items: what will happen, one line each. $type: text the admin has to type first,
 * for the most serious actions. The text must already be translated. Returns an attribute string for the tag.
 */
function fleet_confirm(string $title, string $text, string $action, string $tone = 'danger', string $icon = '', array $items = array(), string $type = ''): string {
	$cfg = array('title' => $title, 'text' => $text, 'action' => $action, 'tone' => $tone, 'cancel' => gettext('Cancel'));
	if ($icon !== '') {
		$cfg['icon'] = $icon;
	}
	if (!empty($items)) {
		$cfg['items'] = array_values($items);
	}
	if ($type !== '') {
		$cfg['type'] = $type;
		$cfg['typeLabel'] = sprintf(gettext('To confirm, type: %s'), $type);
	}
	return ' data-fleet-confirm="' . htmlspecialchars(json_encode($cfg, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), ENT_QUOTES) . '"';
}

/* The script tag of the confirmation dialog, for the foot of a page with buttons that ask first. */
function fleet_confirm_script(): string {
	return '<script src="/fleet/assets/fleet-confirm.js?v=' . (int)@filemtime('/usr/local/www/fleet/assets/fleet-confirm.js') . '"></script>' . "
";
}

/* The views of the Firewalls tab, as the WebUI's segmented control. */
function fleet_firewalls_nav(string $current, int $pending = 0): string {
	$views = array(
		'list' => array(gettext('All firewalls'), '/fleet/fleet.php'),
		'invite' => array(gettext('Add and approve'), '/fleet/fleet.php?view=invite'),
		'factory' => array(gettext('Deployment Factory'), '/fleet/fleet_factory.php'),
		'connections' => array(gettext('Connections'), '/fleet/fleet_connections.php'),
		'ha' => array(gettext('HA pairs'), '/fleet/fleet_ha.php'),
		'internet' => array(gettext('Internet'), '/fleet/fleet_internet.php'),
		'groups' => array(gettext('Groups'), '/fleet/fleet.php?view=groups'),
	);
	$h = '<nav class="fs-viewswitch" aria-label="' . htmlspecialchars(gettext('Firewalls')) . '">';
	foreach ($views as $k => list($label, $url)) {
		$badge = (($k === 'invite') && ($pending > 0)) ? ' <span class="fs-fleet-count" title="' . htmlspecialchars(gettext('Waiting for approval')) . '">' . $pending . '</span>' : '';
		$h .= '<a href="' . $url . '"' . (($k === $current) ? ' aria-current="page"' : '') . '>' . htmlspecialchars($label) . $badge . '</a>';
	}
	return $h . '</nav>';
}

/* The views of the Dashboard tab. */
function fleet_dashboard_nav(string $current, bool $manage = true): string {
	$views = array('overview' => array(gettext('Overview'), '/fleet/fleet_dashboard.php'), 'trends' => array(gettext('Trends'), '/fleet/fleet_dashboard.php?view=trends'),
	    'firewalls' => array(gettext('Firewalls'), '/fleet/fleet_dashboard.php?view=firewalls'));
	if ($manage) {
		$views['kiosks'] = array(gettext('NOC screens'), '/fleet/fleet_kiosks.php');
	}
	$h = '<nav class="fs-viewswitch" aria-label="' . htmlspecialchars(gettext('Dashboard')) . '">';
	foreach ($views as $k => list($label, $url)) {
		$h .= '<a href="' . $url . '"' . (($k === $current) ? ' aria-current="page"' : '') . '>' . htmlspecialchars($label) . '</a>';
	}
	return $h . '</nav>';
}
