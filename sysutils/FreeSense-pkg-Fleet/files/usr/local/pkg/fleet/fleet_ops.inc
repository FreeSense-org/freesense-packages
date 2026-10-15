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
	if (($op['state'] !== 'running') && (($now - (int)$op['finished']) > FLEET_OP_SHOW_DONE)) {
		return null;
	}
	return array('id' => (int)$op['id'], 'kind' => (string)$op['kind'], 'state' => (string)$op['state'], 'text' => (string)$op['text'],
	    'started' => (int)$op['started'], 'by' => (string)$op['who']);
}

/* ------------------------------------------------------------------ */
/* Storage                                                             */
/* ------------------------------------------------------------------ */

function fleet_op_start(string $node_id, string $kind, string $text, string $who): int {
	fleet_db()->prepare("INSERT INTO ops (node_id, kind, state, text, who, started, updated) VALUES (?, ?, 'running', ?, ?, ?, ?)")
	    ->execute(array($node_id, $kind, $text, $who, time(), time()));
	return (int)fleet_db()->lastInsertId();
}

function fleet_op_set(int $id, string $state, string $text): void {
	$finished = ($state === 'running') ? null : time();
	fleet_db()->prepare('UPDATE ops SET state = ?, text = ?, updated = ?, finished = COALESCE(finished, ?) WHERE id = ?')
	    ->execute(array($state, $text, time(), $finished, $id));
}

/* The newest operation of each firewall (running, or finished a moment ago), as node_id => view. */
function fleet_ops_for_tiles(int $now): array {
	$out = array();
	$q = fleet_db()->prepare('SELECT * FROM ops WHERE state = \'running\' OR finished >= ? ORDER BY id');
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
		fleet_op_set((int)$op['id'], $step[0], $step[1]);
		if ($step[0] !== 'running') {
			fleet_audit('poll', ($step[0] === 'done') ? 'reboot_done' : 'reboot_failed', "{$box['node_id']} ({$box['label']}): {$step[1]}");
		}
	}
}
