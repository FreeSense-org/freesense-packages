<?php
/*
 * fleet_ops.inc
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
 * Every action reports its progress the same way, whatever it is (a
 * reboot, an update, a policy change, a rule pushed to a router): a
 * percentage when it knows one, NULL when it cannot, and one progress bar
 * draws both (filling, or sliding while it cannot tell).
 *
 * Operations: one record per action on a firewall (a reboot, a backup)
 * with its current step in words, so the dashboard can show a spinner and
 * "Restarting..." on the tile until the action is over, and any page or
 * browser shows the same. The status poll moves a reboot along; the
 * Activity Center builds on the same table.
 */

require_once('fleet/fleet_store.inc');


/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/*
 * pure: where a reboot stands after a status check. $status is the box's
 * answer (null: no answer). Returns null (no change) or array(state, text).
 * Done only when the box answers with a boot time after the request, so a
 * box that merely missed a check is never "back".
 */
function fleet_op_reboot_step(array $op, ?array $status, int $now): ?array {
	if ($status !== null) {
		if ((int)($status['boot_time'] ?? 0) > (int)$op['started']) {
			return array('done', sprintf('Back online after %s', fleet_op_duration($now - (int)$op['started'])), 100);
		}
		return ($op['text'] === 'Waiting for it to go down') ? null : array('running', 'Waiting for it to go down', 25);
	}
	$timeout = 60 * fleet_opt('reboot_timeout');
	if (($now - (int)$op['started']) > $timeout) {
		return array('failed', 'Not back after ' . fleet_op_duration($timeout) . '. Check its console.', 100);
	}
	return ($op['text'] === 'Restarting') ? null : array('running', 'Restarting', 50);
}

/* pure: "1 min 10 s", "45 s". */
function fleet_op_duration(int $seconds): string {
	$seconds = max(0, $seconds);
	if ($seconds < 60) {
		return "{$seconds} s";
	}
	$m = intdiv($seconds, 60);
	$s = $seconds % 60;
	return ($s === 0) ? "{$m} min" : "{$m} min {$s} s";
}

/* pure: a long time span in words: "3 days 4 h", "5 h 12 min", "8 min". */
function fleet_uptime_text(int $seconds): string {
	$seconds = max(0, $seconds);
	$d = intdiv($seconds, 86400);
	$h = intdiv($seconds % 86400, 3600);
	$m = intdiv($seconds % 3600, 60);
	if ($d > 0) {
		return (($d === 1) ? '1 day' : "{$d} days") . (($h > 0) ? " {$h} h" : '');
	}
	return ($h > 0) ? "{$h} h {$m} min" : "{$m} min";
}

/* pure: what a tile shows for an operation, or null when there is nothing to show. */
function fleet_op_view(?array $op, int $now): ?array {
	if ($op === null) {
		return null;
	}
	if (!in_array($op['state'], array('running', 'queued'), true) && (($now - (int)$op['finished']) > fleet_opt('show_done'))) {
		return null;
	}
	return array('id' => (int)$op['id'], 'kind' => (string)$op['kind'], 'state' => (string)$op['state'], 'text' => (string)$op['text'],
	    'progress' => isset($op['progress']) ? (int)$op['progress'] : null,
	    'started' => (int)$op['started'], 'by' => (string)$op['who']);
}

/*
 * pure: a group operation's progress from its tasks' states; $partial (the
 * running tasks' own 0-100) moves the bar while a firewall is half way.
 */
function fleet_op_progress(array $states, array $partial = array()): array {
	$n = count($states);
	$done = count(array_filter($states, function ($s) { return $s !== 'running' && $s !== 'queued'; }));
	$failed = count(array_keys($states, 'failed', true));
	return array('total' => $n, 'finished' => $done, 'failed' => $failed, 'skipped' => count(array_keys($states, 'skipped', true)),
	    'percent' => ($n === 0) ? 100 : (int)floor((100 * $done + array_sum(array_map('intval', $partial))) / $n));
}

/*
 * pure: the next step of a rolling operation (one firewall at a time) from
 * its tasks' states in order: 'start' the task at index, 'wait' for the
 * one running, 'stop' after a failure, or 'done'.
 */
function fleet_rolling_next(array $states): array {
	$states = array_values($states);
	if (in_array('failed', $states, true)) {
		return array('do' => in_array('running', $states, true) ? 'wait' : 'stop');
	}
	if (in_array('running', $states, true)) {
		return array('do' => 'wait');
	}
	$next = array_search('queued', $states, true);
	return ($next === false) ? array('do' => 'done') : array('do' => 'start', 'index' => $next);
}

/*
 * pure: which firewalls a group update touches, in order, and which it
 * leaves out and why: like a reboot, and also those without an update and
 * (unless allowed) those without rollback. $info: node_id => update info.
 */
function fleet_group_update_plan(array $boxes, array $busy, array $info, bool $ufs_ok, array $blocked = array()): array {
	$plan = fleet_group_reboot_plan($boxes, $busy);
	$go = array();
	foreach ($plan['go'] as $b) {
		$i = $info[$b['node_id']] ?? null;
		$st = json_decode((string)($b['status'] ?? ''), true) ?: array();
		if (isset($blocked[$b['node_id']])) {
			$plan['skip'][] = array($b, $blocked[$b['node_id']]);
		} elseif (($i === null) || ($i['error'] !== null)) {
			$plan['skip'][] = array($b, ($i === null) ? 'Not checked for updates yet' : 'Its update check failed');
		} elseif (!$i['available']) {
			$plan['skip'][] = array($b, 'Up to date (' . fleet_version_number($i['installed']) . ')');
		} elseif (!$ufs_ok && (($st['rollback_protection'] ?? null) === false)) {
			$plan['skip'][] = array($b, 'No rollback (UFS): update it by itself');
		} else {
			$go[] = $b;
		}
	}
	$plan['go'] = $go;
	return $plan;
}

/*
 * pure: which firewalls a group reboot touches, in order, and which it
 * leaves out and why. $busy: node_id => what is running on it.
 */
function fleet_group_reboot_plan(array $boxes, array $busy): array {
	$go = array();
	$skip = array();
	usort($boxes, function ($a, $b) {
		return strcasecmp((string)$a['label'], (string)$b['label']);
	});
	foreach ($boxes as $b) {
		if (($b['role'] ?? '') !== 'managed') {
			$skip[] = array($b, 'Monitor only: the controller may not change it');
		} elseif (in_array($b['state'] ?? '', array('offline', 'new'), true)) {
			$skip[] = array($b, 'Offline');
		} elseif (isset($busy[$b['node_id']])) {
			$skip[] = array($b, 'Busy: ' . lcfirst($busy[$b['node_id']]));
		} else {
			$go[] = $b;
		}
	}
	return array('go' => $go, 'skip' => $skip);
}

/* pure: the words for a group operation's state. */
function fleet_op_summary(array $p, bool $over): string {
	if (!$over) {
		return sprintf('%d of %d done', $p['finished'], $p['total']);
	}
	if ($p['failed'] === 0) {
		return ($p['total'] === 1) ? 'Done' : sprintf('All %d done', $p['total']);
	}
	if (($p['skipped'] ?? 0) > 0) {
		return sprintf('%d of %d failed, %d left alone', $p['failed'], $p['total'], $p['skipped']);
	}
	return sprintf('%d of %d failed', $p['failed'], $p['total']);
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_op_start(string $node_id, string $kind, string $text, string $who, ?int $parent = null, string $state = 'running'): int {
	fleet_db()->prepare('INSERT INTO ops (node_id, kind, state, text, who, started, updated, parent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
	    ->execute(array($node_id, $kind, $state, $text, $who, time(), time(), $parent));
	return (int)fleet_db()->lastInsertId();
}

/* A group operation: no firewall of its own, a title, its tasks point at it. */
function fleet_op_group_start(string $kind, string $title, string $who): int {
	fleet_db()->prepare("INSERT INTO ops (node_id, kind, state, text, who, started, updated, title) VALUES ('', ?, 'running', 'Starting', ?, ?, ?, ?)")
	    ->execute(array($kind, $who, time(), time(), $title));
	return (int)fleet_db()->lastInsertId();
}

/* Recount a group operation from its tasks; it is over when none is waiting or running. */
function fleet_op_group_update(int $id): array {
	$p = fleet_op_group_progress($id);
	$over = $p['finished'] === $p['total'];
	fleet_op_set($id, $over ? (($p['failed'] > 0) ? 'failed' : 'done') : 'running', fleet_op_summary($p, $over), $p['percent']);
	return $p;
}

function fleet_op_group_progress(int $id): array {
	$q = fleet_db()->prepare('SELECT state, progress FROM ops WHERE parent = ?');
	$q->execute(array($id));
	$rows = $q->fetchAll();
	$partial = array_map(function ($r) { return (int)$r['progress']; }, array_filter($rows, function ($r) { return $r['state'] === 'running'; }));
	return fleet_op_progress(array_column($rows, 'state'), $partial);
}

/* Running group operations with their progress, for the dashboard strip. */
function fleet_ops_groups_running(): array {
	$out = array();
	foreach (fleet_db()->query("SELECT * FROM ops WHERE node_id = '' AND state = 'running' ORDER BY id")->fetchAll() as $op) {
		$out[] = array('id' => (int)$op['id'], 'title' => (string)$op['title'], 'text' => (string)$op['text'], 'started' => (int)$op['started'],
		    'by' => (string)$op['who']) + fleet_op_group_progress((int)$op['id']);
	}
	return $out;
}

/* The Activity list: operations started on their own or as a group (not the group's tasks), newest first. */
function fleet_ops_history(int $limit = 50): array {
	$q = fleet_db()->prepare('SELECT o.*, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE o.parent IS NULL ORDER BY o.id DESC LIMIT ?');
	$q->execute(array($limit));
	return $q->fetchAll();
}

function fleet_op_tasks(int $parent): array {
	$q = fleet_db()->prepare('SELECT o.*, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE o.parent = ? ORDER BY (o.state = \'failed\') DESC, o.id');
	$q->execute(array($parent));
	return $q->fetchAll();
}

/* $progress: 0-100, or null to keep the last one; a finished operation is at 100. */
function fleet_op_set(int $id, string $state, string $text, ?int $progress = null): void {
	$over = !in_array($state, array('running', 'queued'), true);
	$finished = $over ? time() : null;
	if ($over) {
		$progress = 100;
	}
	$was = fleet_db()->prepare('SELECT state FROM ops WHERE id = ?');
	$was->execute(array($id));
	$was = (string)$was->fetchColumn();
	fleet_db()->prepare('UPDATE ops SET state = ?, text = ?, updated = ?, finished = COALESCE(finished, ?), progress = COALESCE(?, progress) WHERE id = ?')
	    ->execute(array($state, $text, time(), $finished, ($progress === null) ? null : max(0, min(100, $progress)), $id));
	/* An operation that just failed raises an alert (a task inside a group operation does not: the group reports once). */
	if (($state === 'failed') && ($was !== 'failed') && function_exists('fleet_alert')) {
		$q = fleet_db()->prepare('SELECT o.kind, o.node_id, o.title, o.parent, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE o.id = ?');
		$q->execute(array($id));
		$o = $q->fetch();
		if (is_array($o) && ($o['parent'] === null)) {
			try {
				fleet_alert('op_failed', (string)$o['node_id'], trim((string)($o['label'] ?? $o['title'] ?? '') . ' (' . $o['kind'] . '): ' . $text));
			} catch (Throwable $e) {
				/* An alert must never break the operation. */
			}
		}
	}
}

/* The newest operation of each firewall (running, or finished a moment ago), as node_id => view. */
function fleet_ops_for_tiles(int $now): array {
	$out = array();
	$q = fleet_db()->prepare("SELECT * FROM ops WHERE node_id != '' AND (state IN ('running', 'queued') OR finished >= ?) ORDER BY id");
	$q->execute(array($now - fleet_opt('show_done')));
	foreach ($q->fetchAll() as $op) {
		$view = fleet_op_view($op, $now);
		if ($view !== null) {
			$out[$op['node_id']] = $view;
		}
	}
	return $out;
}

/*
 * The running operation of a firewall, or null. A task still waiting its
 * turn (a rollout ring can wait days for its window) does not make the
 * firewall busy: it can still be backed up or rebooted meanwhile.
 */
function fleet_op_running(string $node_id): ?array {
	$q = fleet_db()->prepare("SELECT * FROM ops WHERE node_id = ? AND state = 'running' ORDER BY id DESC LIMIT 1");
	$q->execute(array($node_id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

/* Called by the status poll for every firewall: moves its running reboot along. */
function fleet_ops_follow(array $box, ?array $status, int $now): void {
	$op = fleet_op_running($box['node_id']);
	if (($op === null) || ($op['kind'] !== 'reboot')) {
		return;
	}
	$step = fleet_op_reboot_step($op, $status, $now);
	if ($step !== null) {
		fleet_op_set((int)$op['id'], $step[0], $step[1], $step[2] ?? null);
		if ($step[0] !== 'running') {
			fleet_audit('poll', ($step[0] === 'done') ? 'reboot_done' : 'reboot_failed', "{$box['node_id']} ({$box['label']}): {$step[1]}");
		}
	}
}

/* ------------------------------------------------------------------ */
/* The top-bar item (plugin_navbar)                                    */
/* ------------------------------------------------------------------ */


/*
 * pure: the top-bar item: always there while Fleet runs, its icon showing
 * the state at a glance. Worst first: actions that failed lately (red
 * count), firewalls offline (red), degraded (yellow), actions running
 * (spinner and count), else a green icon. Opens a short summary panel.
 */
function fleet_nav_item(int $running, int $failed, int $offline = 0, int $degraded = 0, int $policy = 0): array {
	$item = array('id' => 'activity', 'icon' => 'fa-tower-broadcast', 'href' => '/fleet/fleet_dashboard.php', 'poll' => '/fleet/fleet_nav.php',
	    'panel' => '/fleet/fleet_nav.php?panel=1', 'busy' => $running > 0, 'hidden' => false);
	$n = function (int $c, string $one, string $many) { return ($c === 1) ? $one : sprintf($many, $c); };
	if ($failed > 0) {
		return $item + array('badge' => $failed, 'kind' => 'block', 'label' => 'FreeSense Fleet: ' . $n($failed, '1 action failed', '%d actions failed'));
	}
	if ($offline > 0) {
		return $item + array('badge' => $offline, 'kind' => 'block', 'label' => 'FreeSense Fleet: ' . $n($offline, '1 firewall offline', '%d firewalls offline'));
	}
	if ($degraded > 0) {
		return $item + array('badge' => $degraded, 'kind' => 'warn', 'label' => 'FreeSense Fleet: ' . $n($degraded, '1 firewall degraded', '%d firewalls degraded'));
	}
	if ($policy > 0) {
		return $item + array('badge' => $policy, 'kind' => 'warn', 'label' => 'FreeSense Fleet: ' . $n($policy, '1 firewall fails a policy rule', '%d firewalls fail a policy rule'));
	}
	if ($running > 0) {
		return $item + array('badge' => $running, 'kind' => 'info', 'label' => 'FreeSense Fleet: ' . $n($running, '1 action running', '%d actions running'));
	}
	return $item + array('badge' => 0, 'kind' => 'pass', 'label' => 'FreeSense Fleet: all fine');
}

/* The item now: running operations (a group counts once), recent failures and firewalls in trouble. */
function fleet_nav_now(int $now): array {
	$running = (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state IN ('running', 'queued')")->fetchColumn();
	$q = fleet_db()->prepare("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state = 'failed' AND finished >= ?");
	$q->execute(array($now - 60 * fleet_opt('nav_failed')));
	$st = array_column(fleet_db()->query('SELECT state, COUNT(*) AS n FROM boxes GROUP BY state')->fetchAll(), 'n', 'state');
	$policy = (int)fleet_db()->query("SELECT COUNT(DISTINCT node_id) FROM compliance WHERE state = 'fail'")->fetchColumn();
	return fleet_nav_item($running, (int)$q->fetchColumn(), (int)($st['offline'] ?? 0), (int)($st['degraded'] ?? 0), $policy);
}

/*
 * The summary panel under the item: the state of the fleet, what runs,
 * what failed in the last 24 hours, with links into Fleet. HTML.
 */
function fleet_nav_panel_html(int $now): string {
	$h = function ($s) { return htmlspecialchars((string)$s); };
	$st = array_column(fleet_db()->query('SELECT state, COUNT(*) AS n FROM boxes GROUP BY state')->fetchAll(), 'n', 'state');
	$total = array_sum($st);
	$bad = (int)($st['offline'] ?? 0) + (int)($st['degraded'] ?? 0);
	$policy = (int)fleet_db()->query("SELECT COUNT(DISTINCT node_id) FROM compliance WHERE state = 'fail'")->fetchColumn();
	$kinds = array('reboot' => 'Reboot', 'backup' => 'Back up', 'restore' => 'Restore', 'update' => 'Update', 'template' => 'Apply template to', 'users' => 'Sync users to');
	$name = function ($op) use ($kinds) {
		return ($op['node_id'] === '') ? (string)$op['title'] : (($kinds[$op['kind']] ?? ucfirst((string)$op['kind'])) . ' ' . ($op['label'] ?? $op['node_id']));
	};
	$ago = function (int $t) use ($now) {
		$d = max(0, $now - $t);
		return ($d < 60) ? gettext('just now') : (($d < 3600) ? sprintf(gettext('%d min ago'), intdiv($d, 60)) : sprintf(gettext('%d h ago'), intdiv($d, 3600)));
	};
	$running = fleet_db()->query("SELECT o.*, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE o.parent IS NULL AND o.state IN ('running', 'queued')
	    ORDER BY o.started DESC LIMIT 5")->fetchAll();
	$q = fleet_db()->prepare("SELECT o.*, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id WHERE o.parent IS NULL AND o.state = 'failed' AND o.finished >= ?
	    ORDER BY o.finished DESC LIMIT 5");
	$q->execute(array($now - 86400));
	$failed = $q->fetchAll();

	$out = '<div class="fs-navpanel-head"><span class="fs-navpanel-state fs-tone-' . (($st['offline'] ?? 0) ? 'block' : ($bad ? 'warn' : 'pass')) . '"><i class="fa-solid ' .
	    ($bad ? 'fa-triangle-exclamation' : 'fa-circle-check') . '" aria-hidden="true"></i></span><div><strong>' . $h(gettext('FreeSense Fleet')) . '</strong><span>' .
	    $h($bad ? sprintf(gettext('%1$d of %2$d need attention'), $bad, $total) : (($policy > 0) ?
	    sprintf(gettext('All %1$d firewalls are online; %2$d fail a policy rule'), $total, $policy) : sprintf(gettext('All %d firewalls are fine'), $total))) . '</span></div></div>';
	$out .= '<div class="fs-navpanel-counts">';
	foreach (array('online' => array(gettext('Online'), 'pass'), 'degraded' => array(gettext('Degraded'), 'warn'), 'offline' => array(gettext('Offline'), 'block')) as $k => list($l, $tone)) {
		$c = (int)($st[$k] ?? 0);
		$out .= '<a href="/fleet/fleet_dashboard.php?view=firewalls" class="fs-tone-' . (($c > 0) ? $tone : 'neutral') . '"><strong>' . $c . '</strong><span>' . $h($l) . '</span></a>';
	}
	$out .= '</div>';
	$section = function (string $icon, string $title, array $rows, string $empty, callable $line) use ($h) {
		$s = '<div class="fs-navpanel-sec"><div class="fs-navpanel-sec-title"><i class="fa-solid ' . $icon . '" aria-hidden="true"></i>' . $h($title) . '</div>';
		if (empty($rows)) {
			return $s . '<p class="fs-navpanel-none">' . $h($empty) . '</p></div>';
		}
		return $s . '<ul>' . implode('', array_map($line, $rows)) . '</ul></div>';
	};
	$out .= $section('fa-spinner', gettext('Running'), $running, gettext('Nothing running.'), function ($op) use ($h, $name, $ago) {
		return '<li><a href="/fleet/fleet_activity.php?op=' . (int)$op['id'] . '"><span>' . $h($name($op)) . '</span><time>' . $h($ago((int)$op['started'])) . '</time></a></li>';
	});
	$out .= $section('fa-circle-xmark', gettext('Failed, last 24 hours'), $failed, gettext('No failures.'), function ($op) use ($h, $name, $ago) {
		return '<li class="is-failed"><a href="/fleet/fleet_activity.php?op=' . (int)$op['id'] . '"><span>' . $h($name($op)) . '<small>' . $h((string)$op['text']) . '</small></span><time>' .
		    $h($ago((int)$op['finished'])) . '</time></a></li>';
	});
	return $out . '<div class="fs-navpanel-foot"><a href="/fleet/fleet_dashboard.php"><i class="fa-solid fa-gauge-high" aria-hidden="true"></i>' . $h(gettext('Dashboard')) .
	    '</a><a href="/fleet/fleet_activity.php"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i>' . $h(gettext('Activity')) . '</a></div>';
}

/*
 * pure: the notices for operations that finished after $since (a time),
 * newest last, as the WebUI shows them (System's plugin_navbar toasts).
 * $titles: what each operation is called ("Reboot Lab", "Back up Aarhus").
 */
function fleet_nav_toasts(array $finished, bool $done_on, bool $failed_on): array {
	$out = array();
	foreach ($finished as $op) {
		$failed = ($op['state'] === 'failed');
		if (($failed && !$failed_on) || (!$failed && !$done_on) || !in_array($op['state'], array('done', 'failed'), true)) {
			continue;
		}
		$text = $op['name'] . ': ' . $op['text'];
		$out[] = array('text' => (strlen($text) > 200) ? substr($text, 0, 197) . '...' : $text, 'kind' => $failed ? 'block' : 'pass',
		    'href' => '/fleet/fleet_activity.php?op=' . (int)$op['id'], 'sticky' => $failed);
	}
	return array_slice($out, -5);
}

/* Operations that finished after $since, with a name for the notice. */
function fleet_ops_finished_since(int $since, int $now): array {
	$q = fleet_db()->prepare("SELECT o.id, o.kind, o.state, o.text, o.title, o.node_id, b.label FROM ops o LEFT JOIN boxes b ON b.node_id = o.node_id
	    WHERE o.parent IS NULL AND o.finished > ? AND o.finished <= ? ORDER BY o.finished, o.id");
	$q->execute(array($since, $now));
	$kinds = array('reboot' => 'Reboot', 'backup' => 'Back up', 'restore' => 'Restore', 'update' => 'Update', 'template' => 'Apply template to', 'users' => 'Sync users to');
	return array_map(function ($op) use ($kinds) {
		$op['name'] = ($op['node_id'] === '') ? (string)$op['title'] : (($kinds[$op['kind']] ?? ucfirst((string)$op['kind'])) . ' ' . ($op['label'] ?? $op['node_id']));
		return $op;
	}, $q->fetchAll());
}

/*
 * What a group reboot or update would do now: array(boxes, plan, update
 * infos). $group null: every firewall. Used by the review page and by
 * schedules.
 */
function fleet_group_plan(?array $group, string $action): array {
	$boxes = fleet_db()->query('SELECT * FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	if ($group !== null) {
		$q = fleet_db()->prepare('SELECT node_id FROM box_groups WHERE group_id = ?');
		$q->execute(array((int)$group['id']));
		$members = $q->fetchAll(PDO::FETCH_COLUMN);
		$boxes = array_values(array_filter($boxes, function ($b) use ($members) { return in_array($b['node_id'], $members, true); }));
	}
	$infos = array();
	foreach ($boxes as $b) {
		$infos[$b['node_id']] = fleet_update_info($b);
	}
	return array($boxes, fleet_boxes_plan($boxes, $action), $infos);
}

/* What a reboot or update of these firewalls would do now (one at a time, who is left out and why). */
function fleet_boxes_plan(array $boxes, string $action): array {
	$busy = array();
	$infos = array();
	foreach ($boxes as $b) {
		$running = fleet_op_running($b['node_id']);
		if ($running !== null) {
			$busy[$b['node_id']] = (string)$running['text'];
		}
		$infos[$b['node_id']] = fleet_update_info($b);
	}
	$plan = ($action === 'update') ? fleet_group_update_plan($boxes, $busy, $infos, fleet_opt('update_ufs_in_groups'), fleet_policy_update_blocks($boxes, $infos)) :
	    fleet_group_reboot_plan($boxes, $busy);
	/* An HA pair: the BACKUP first, the MASTER when its partner is back. */
	$plan['go'] = array_values(fleet_ha_sort($plan['go']));
	return $plan;
}

/* Start a reviewed (or scheduled) group reboot or update in the background. $group: a group, a name, or null (all). Returns the operation id. */
function fleet_group_op_launch($group, string $action, array $plan, string $who): int {
	$name = is_array($group) ? $group['name'] : (is_string($group) ? $group : 'all firewalls');
	$op = fleet_op_group_start($action . '_group', sprintf(($action === 'update') ? 'Update %s' : 'Reboot %s', $name), $who);
	foreach ($plan['go'] as $b) {
		fleet_op_start($b['node_id'], $action, 'Waiting', $who, $op, 'queued');
	}
	foreach ($plan['skip'] as list($b, $why)) {
		fleet_op_set(fleet_op_start($b['node_id'], $action, $why, $who, $op, 'skipped'), 'skipped', 'Skipped: ' . lcfirst($why));
	}
	fleet_op_group_update($op);
	fleet_audit($who, $action . '_group', sprintf('%s: %d firewalls, one at a time', $name, count($plan['go'])));
	mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-run ' . $action . '-group ' . (int)$op);
	return $op;
}

