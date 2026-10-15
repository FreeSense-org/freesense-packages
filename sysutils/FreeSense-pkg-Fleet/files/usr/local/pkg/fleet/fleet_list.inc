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

define('FLEET_LIST_PER_PAGE', 25);

/* What the Activity filters offer: value => label. */
define('FLEET_OPS_STATES', array('running' => 'Running', 'done' => 'Done', 'failed' => 'Failed'));
define('FLEET_OPS_KINDS', array('backup_all' => 'Group backups', 'reboot_group' => 'Group reboots', 'backup' => 'Backups', 'reboot' => 'Reboots'));
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
function fleet_list_page(int $total, int $page, int $per = FLEET_LIST_PER_PAGE): array {
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
		if (in_array($f['kind'], array('backup', 'reboot'), true)) {
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
