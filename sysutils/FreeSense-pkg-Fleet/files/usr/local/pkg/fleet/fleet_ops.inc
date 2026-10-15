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
 * Operations: one record per action on a firewall (a reboot, a backup)
 * with its current step in words, so the dashboard can show a spinner and
 * "Restarting..." on the tile until the action is over, and any page or
 * browser shows the same. The status poll moves a reboot along; the
 * Activity Center builds on the same table.
 */

require_once('fleet/fleet_store.inc');

/* A reboot that is not back after this long has failed. */
define('FLEET_OP_REBOOT_TIMEOUT', 600);
/* A finished operation stays on the tile this long, so its result can be read. */
define('FLEET_OP_SHOW_DONE', 90);

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
			return array('done', sprintf('Back online after %s', fleet_op_duration($now - (int)$op['started'])));
		}
		return ($op['text'] === 'Waiting for it to go down') ? null : array('running', 'Waiting for it to go down');
	}
	if (($now - (int)$op['started']) > FLEET_OP_REBOOT_TIMEOUT) {
		return array('failed', 'Not back after ' . fleet_op_duration(FLEET_OP_REBOOT_TIMEOUT) . '. Check its console.');
	}
	return ($op['text'] === 'Restarting') ? null : array('running', 'Restarting');
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
	if (!in_array($op['state'], array('running', 'queued'), true) && (($now - (int)$op['finished']) > FLEET_OP_SHOW_DONE)) {
		return null;
	}
	return array('id' => (int)$op['id'], 'kind' => (string)$op['kind'], 'state' => (string)$op['state'], 'text' => (string)$op['text'],
	    'started' => (int)$op['started'], 'by' => (string)$op['who']);
}

/* pure: a group operation's progress from its tasks' states. */
function fleet_op_progress(array $states): array {
	$n = count($states);
	$done = count(array_filter($states, function ($s) { return $s !== 'running' && $s !== 'queued'; }));
	$failed = count(array_keys($states, 'failed', true));
	return array('total' => $n, 'finished' => $done, 'failed' => $failed, 'skipped' => count(array_keys($states, 'skipped', true)),
	    'percent' => ($n === 0) ? 100 : (int)floor(100 * $done / $n));
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
			$skip[] = array($b, 'Monitor only: the controller may not reboot it');
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
	$q = fleet_db()->prepare('SELECT state FROM ops WHERE parent = ?');
	$q->execute(array($id));
	$p = fleet_op_progress($q->fetchAll(PDO::FETCH_COLUMN));
	$over = $p['finished'] === $p['total'];
	fleet_op_set($id, $over ? (($p['failed'] > 0) ? 'failed' : 'done') : 'running', fleet_op_summary($p, $over));
	return $p;
}

/* Running group operations with their progress, for the dashboard strip. */
function fleet_ops_groups_running(): array {
	$out = array();
	foreach (fleet_db()->query("SELECT * FROM ops WHERE node_id = '' AND state = 'running' ORDER BY id")->fetchAll() as $op) {
		$q = fleet_db()->prepare('SELECT state FROM ops WHERE parent = ?');
		$q->execute(array($op['id']));
		$out[] = array('id' => (int)$op['id'], 'title' => (string)$op['title'], 'text' => (string)$op['text'], 'started' => (int)$op['started'],
		    'by' => (string)$op['who']) + fleet_op_progress($q->fetchAll(PDO::FETCH_COLUMN));
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

function fleet_op_set(int $id, string $state, string $text): void {
	$finished = in_array($state, array('running', 'queued'), true) ? null : time();
	fleet_db()->prepare('UPDATE ops SET state = ?, text = ?, updated = ?, finished = COALESCE(finished, ?) WHERE id = ?')
	    ->execute(array($state, $text, time(), $finished, $id));
}

/* The newest operation of each firewall (running, or finished a moment ago), as node_id => view. */
function fleet_ops_for_tiles(int $now): array {
	$out = array();
	$q = fleet_db()->prepare("SELECT * FROM ops WHERE node_id != '' AND (state IN ('running', 'queued') OR finished >= ?) ORDER BY id");
	$q->execute(array($now - FLEET_OP_SHOW_DONE));
	foreach ($q->fetchAll() as $op) {
		$view = fleet_op_view($op, $now);
		if ($view !== null) {
			$out[$op['node_id']] = $view;
		}
	}
	return $out;
}

/* The running operation of a firewall, or null. */
function fleet_op_running(string $node_id): ?array {
	$q = fleet_db()->prepare("SELECT * FROM ops WHERE node_id = ? AND state IN ('running', 'queued') ORDER BY id DESC LIMIT 1");
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
		fleet_op_set((int)$op['id'], $step[0], $step[1]);
		if ($step[0] !== 'running') {
			fleet_audit('poll', ($step[0] === 'done') ? 'reboot_done' : 'reboot_failed', "{$box['node_id']} ({$box['label']}): {$step[1]}");
		}
	}
}
