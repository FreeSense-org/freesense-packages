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
function fleet_group_update_plan(array $boxes, array $busy, array $info, bool $ufs_ok): array {
	$plan = fleet_group_reboot_plan($boxes, $busy);
	$go = array();
	foreach ($plan['go'] as $b) {
		$i = $info[$b['node_id']] ?? null;
		$st = json_decode((string)($b['status'] ?? ''), true) ?: array();
		if (($i === null) || ($i['error'] !== null)) {
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
	fleet_db()->prepare('UPDATE ops SET state = ?, text = ?, updated = ?, finished = COALESCE(finished, ?), progress = COALESCE(?, progress) WHERE id = ?')
	    ->execute(array($state, $text, time(), $finished, ($progress === null) ? null : max(0, min(100, $progress)), $id));
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
 * pure: the top-bar item from what runs and what failed lately. Out of
 * sight when the fleet is quiet; a spinner and a count while actions run;
 * a red count for a while after one failed.
 */
function fleet_nav_item(int $running, int $failed): array {
	$item = array('id' => 'activity', 'icon' => 'fa-server', 'href' => '/fleet/fleet_activity.php', 'poll' => '/fleet/fleet_nav.php',
	    'busy' => $running > 0, 'hidden' => ($running === 0) && ($failed === 0));
	if ($running > 0) {
		return $item + array('badge' => $running, 'kind' => 'info',
		    'label' => ($running === 1) ? 'FreeSense Fleet: 1 action running' : "FreeSense Fleet: {$running} actions running");
	}
	if ($failed > 0) {
		return $item + array('badge' => $failed, 'kind' => 'block',
		    'label' => ($failed === 1) ? 'FreeSense Fleet: 1 action failed' : "FreeSense Fleet: {$failed} actions failed");
	}
	return $item + array('badge' => 0, 'kind' => 'info', 'label' => 'FreeSense Fleet activity');
}

/* The item now: running operations (a group counts once) and recent failures. */
function fleet_nav_now(int $now): array {
	$running = (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state IN ('running', 'queued')")->fetchColumn();
	$q = fleet_db()->prepare("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state = 'failed' AND finished >= ?");
	$q->execute(array($now - 60 * fleet_opt('nav_failed')));
	return fleet_nav_item($running, (int)$q->fetchColumn());
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
	$kinds = array('reboot' => 'Reboot', 'backup' => 'Back up', 'restore' => 'Restore', 'update' => 'Update');
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
	return ($action === 'update') ? fleet_group_update_plan($boxes, $busy, $infos, fleet_opt('update_ufs_in_groups')) : fleet_group_reboot_plan($boxes, $busy);
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

