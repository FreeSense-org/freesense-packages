<?php
/*
 * fleet_rollouts.inc
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
 * Maintenance windows and rollouts.
 *
 * A window is a weekly time slot in the controller's time zone: days of
 * the week (1 = Monday ... 7 = Sunday), a start time and a length; it may
 * run past midnight. A group may have a window.
 *
 * A rollout brings firewalls to the newest version ring by ring: each ring
 * is a group (Canary, then Denmark...), the last ring may be "everyone
 * else". Inside a ring the firewalls update one at a time, and only while
 * the ring's window is open with enough time left (update_timeout). The
 * next ring starts when the one before is done and the gap has passed
 * (rollout_gap_hours). A rollback or failure pauses the rollout; it goes
 * on only when someone resumes it. The rollout is a group operation (one
 * task per firewall, kind update), so Activity, the tiles, the progress
 * bar and the notices follow it like any other operation. The poll calls
 * fleet_rollouts_tick() every minute.
 */

require_once('fleet/fleet_store.inc');

/* ------------------------------------------------------------------ */
/* Pure: windows                                                       */
/* ------------------------------------------------------------------ */

/* pure: a window from what a form sends, or an InvalidArgumentException that says what is wrong. */
function fleet_window_from(array $in): array {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (strlen($name) > 40) || preg_match('/[<>\x00-\x1f\x7f]/', $name)) {
		throw new InvalidArgumentException('Give the window a name of 1 to 40 characters.');
	}
	$days = array_values(array_unique(array_filter(array_map('intval', (array)($in['days'] ?? array())), function ($d) {
		return $d >= 1 && $d <= 7;
	})));
	sort($days);
	if (empty($days)) {
		throw new InvalidArgumentException('Choose at least one day.');
	}
	if (!preg_match('/^([01]\d|2[0-3]):([0-5]\d)$/', (string)($in['start'] ?? ''), $m)) {
		throw new InvalidArgumentException('The start is a time like 01:30.');
	}
	$length = (int)($in['length'] ?? 0);
	if (($length < 30) || ($length > 1440) || ((string)$length !== trim((string)($in['length'] ?? '')))) {
		throw new InvalidArgumentException('The length is 30 to 1440 minutes.');
	}
	return array('name' => $name, 'days' => $days, 'start' => 60 * (int)$m[1] + (int)$m[2], 'length' => $length);
}

/*
 * pure: is the window open at $now, and how many seconds are left in it?
 * array(open, seconds left). A window that starts late on a chosen day
 * and runs past midnight is open early the next day too. $tz: the time
 * zone the window is written in.
 */
function fleet_window_state(array $w, int $now, string $tz = 'UTC'): array {
	$zone = new DateTimeZone($tz);
	$t = (new DateTimeImmutable('@' . $now))->setTimezone($zone);
	/* Today's and yesterday's start (yesterday's may still be running past midnight). */
	foreach (array(0, 1) as $back) {
		$day = $t->modify("-{$back} day");
		if (!in_array((int)$day->format('N'), $w['days'], true)) {
			continue;
		}
		$start = $day->setTime(intdiv($w['start'], 60), $w['start'] % 60)->getTimestamp();
		$end = $start + 60 * $w['length'];
		if (($now >= $start) && ($now < $end)) {
			return array(true, $end - $now);
		}
	}
	return array(false, 0);
}

/* pure: when the window opens next (now when it is open), as a time; null when it never opens. */
function fleet_window_next(array $w, int $now, string $tz = 'UTC'): ?int {
	if (fleet_window_state($w, $now, $tz)[0]) {
		return $now;
	}
	$t = (new DateTimeImmutable('@' . $now))->setTimezone(new DateTimeZone($tz));
	for ($i = 0; $i <= 7; $i++) {
		$day = $t->modify("+{$i} day");
		if (in_array((int)$day->format('N'), $w['days'], true)) {
			$start = $day->setTime(intdiv($w['start'], 60), $w['start'] % 60)->getTimestamp();
			if ($start > $now) {
				return $start;
			}
		}
	}
	return null;
}

/* pure: "Mon-Fri 01:00, 3 h" */
function fleet_window_text(array $w): string {
	$names = array(1 => 'Mon', 2 => 'Tue', 3 => 'Wed', 4 => 'Thu', 5 => 'Fri', 6 => 'Sat', 7 => 'Sun');
	$d = $w['days'];
	if ($d === array(1, 2, 3, 4, 5, 6, 7)) {
		$days = 'Every day';
	} elseif ($d === array(1, 2, 3, 4, 5)) {
		$days = 'Mon-Fri';
	} elseif ($d === array(6, 7)) {
		$days = 'Sat-Sun';
	} else {
		$days = implode(', ', array_map(function ($x) use ($names) { return $names[$x]; }, $d));
	}
	$len = ($w['length'] % 60 === 0) ? ($w['length'] / 60) . ' h' : fleet_op_duration(60 * $w['length']);
	return sprintf('%s %02d:%02d, %s', $days, intdiv($w['start'], 60), $w['start'] % 60, $len);
}

/* ------------------------------------------------------------------ */
/* Pure: rollouts                                                      */
/* ------------------------------------------------------------------ */

/*
 * pure: what a rollout does now. $rings: the rings in order, each
 * array(window or null, task states in order). $ring_done: when each
 * finished ring ended (index => time). Returns one of
 *   array('do' => 'start', 'ring' => r, 'task' => i)   update that firewall
 *   array('do' => 'wait', 'why' => text, 'until' => time|null)
 *   array('do' => 'pause', 'ring' => r)                a task failed
 *   array('do' => 'done')
 * $margin: seconds a window must still have to start an update in it.
 */
function fleet_rollout_next(array $rings, array $ring_done, int $now, int $gap, int $margin, string $tz = 'UTC'): array {
	foreach ($rings as $r => list($window, $states)) {
		if (in_array('failed', $states, true)) {
			return in_array('running', $states, true) ? array('do' => 'wait', 'why' => 'Waiting for the update in progress', 'until' => null)
			    : array('do' => 'pause', 'ring' => $r);
		}
		if (in_array('running', $states, true)) {
			return array('do' => 'wait', 'why' => 'Updating', 'until' => null);
		}
		$next = array_search('queued', $states, true);
		if ($next === false) {
			continue;
		}
		/* The ring before must be done for long enough. */
		if (($r > 0) && isset($ring_done[$r - 1]) && ($now < $ring_done[$r - 1] + $gap)) {
			return array('do' => 'wait', 'why' => 'Waiting before the next ring', 'until' => $ring_done[$r - 1] + $gap);
		}
		if ($window !== null) {
			list($open, $left) = fleet_window_state($window, $now, $tz);
			if (!$open || ($left < $margin)) {
				$from = $open ? $now + $left : $now;
				return array('do' => 'wait', 'why' => 'Waiting for the maintenance window', 'until' => fleet_window_next($window, $from, $tz));
			}
		}
		return array('do' => 'start', 'ring' => $r, 'task' => $next);
	}
	return array('do' => 'done');
}

/*
 * pure: which firewalls go into which ring. $groups: ring group ids in
 * order (0 = everyone not in an earlier ring); $members: group id =>
 * node ids; $eligible: node ids that can be updated (managed, an update
 * available, not UFS unless allowed). A firewall is in the first ring
 * that has it.
 */
function fleet_rollout_rings(array $groups, array $members, array $eligible): array {
	$taken = array();
	$rings = array();
	foreach ($groups as $gid) {
		$ring = array();
		$pool = ($gid === 0) ? $eligible : array_values(array_intersect($members[$gid] ?? array(), $eligible));
		foreach ($pool as $node) {
			if (!isset($taken[$node])) {
				$taken[$node] = true;
				$ring[] = $node;
			}
		}
		$rings[] = $ring;
	}
	return $rings;
}

/* ------------------------------------------------------------------ */
/* Storage: windows                                                    */
/* ------------------------------------------------------------------ */

/* The controller's time zone, which windows are written in. */
function fleet_tz(): string {
	return date_default_timezone_get() ?: 'UTC';
}

function fleet_window_row(array $row): array {
	return array('id' => (int)$row['id'], 'name' => (string)$row['name'], 'days' => array_map('intval', json_decode((string)$row['days'], true) ?: array()),
	    'start' => (int)$row['start'], 'length' => (int)$row['length']);
}

function fleet_windows_all(): array {
	return array_map('fleet_window_row', fleet_db()->query('SELECT * FROM windows ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_window_get(?int $id): ?array {
	if (!$id) {
		return null;
	}
	$q = fleet_db()->prepare('SELECT * FROM windows WHERE id = ?');
	$q->execute(array($id));
	$row = $q->fetch();
	return is_array($row) ? fleet_window_row($row) : null;
}

/* Create or change a window from a form. Returns its id; InvalidArgumentException says what is wrong. */
function fleet_window_save(?int $id, array $in, string $who): int {
	$w = fleet_window_from($in);
	$q = fleet_db()->prepare('SELECT COUNT(*) FROM windows WHERE name = ? COLLATE NOCASE AND id != ?');
	$q->execute(array($w['name'], $id ?? 0));
	if ((int)$q->fetchColumn() > 0) {
		throw new InvalidArgumentException('There is already a window with that name.');
	}
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO windows (name, days, start, length) VALUES (?, ?, ?, ?)')->execute(array($w['name'], json_encode($w['days']), $w['start'], $w['length']));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		fleet_db()->prepare('UPDATE windows SET name = ?, days = ?, start = ?, length = ? WHERE id = ?')->execute(array($w['name'], json_encode($w['days']), $w['start'], $w['length'], $id));
	}
	fleet_audit($who, 'window', $w['name'] . ': ' . fleet_window_text($w));
	return $id;
}

/* The groups that use a window (it cannot be deleted while any does). */
function fleet_window_users(int $id): array {
	$q = fleet_db()->prepare('SELECT name FROM fleet_groups WHERE window_id = ? ORDER BY name COLLATE NOCASE');
	$q->execute(array($id));
	return $q->fetchAll(PDO::FETCH_COLUMN);
}

function fleet_window_delete(int $id, string $who): void {
	$users = fleet_window_users($id);
	if (!empty($users)) {
		throw new InvalidArgumentException('This window is used by ' . implode(', ', $users) . '. Choose another window for them first.');
	}
	$w = fleet_window_get($id);
	fleet_db()->prepare('DELETE FROM windows WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'window', ($w['name'] ?? (string)$id) . ': deleted');
}

function fleet_group_set_window(int $group, ?int $window, string $who): void {
	fleet_db()->prepare('UPDATE fleet_groups SET window_id = ? WHERE id = ?')->execute(array($window ?: null, $group));
}

/* ------------------------------------------------------------------ */
/* Storage: rollouts                                                   */
/* ------------------------------------------------------------------ */

/* The newest version any firewall can update to (the one most of them report). */
function fleet_rollout_target(): ?string {
	$count = array();
	foreach (fleet_db()->query('SELECT update_info FROM boxes')->fetchAll(PDO::FETCH_COLUMN) as $raw) {
		$i = json_decode((string)$raw, true);
		if (is_array($i) && !empty($i['available']) && ($i['latest'] ?? '') !== '') {
			$v = fleet_version_number($i['latest']);
			$count[$v] = ($count[$v] ?? 0) + 1;
		}
	}
	if (empty($count)) {
		return null;
	}
	uksort($count, 'version_compare');
	return array_key_last($count);
}

/*
 * The plan for a rollout: $ring_groups in order (0 = everyone else).
 * array('rings' => [array(group id, name, window, [boxes])], 'skip' => [array(box, why)]).
 */
function fleet_rollout_plan(array $ring_groups, string $target): array {
	$boxes = fleet_db()->query('SELECT * FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	$busy = array();
	$infos = array();
	foreach ($boxes as $b) {
		$running = fleet_op_running($b['node_id']);
		if ($running !== null) {
			$busy[$b['node_id']] = (string)$running['text'];
		}
		$infos[$b['node_id']] = fleet_update_info($b);
		if (($infos[$b['node_id']] !== null) && $infos[$b['node_id']]['available'] && !fleet_version_same($infos[$b['node_id']]['latest'], $target)) {
			/* Its channel offers another version: not this rollout. */
			$infos[$b['node_id']]['available'] = false;
			$infos[$b['node_id']]['installed'] = $infos[$b['node_id']]['latest'] . ' offered';
		}
	}
	$plan = fleet_group_update_plan($boxes, $busy, $infos, fleet_opt('update_ufs_in_groups'), fleet_policy_update_blocks($boxes, $infos, $target));
	$members = array();
	foreach (fleet_db()->query('SELECT group_id, node_id FROM box_groups')->fetchAll() as $m) {
		$members[(int)$m['group_id']][] = $m['node_id'];
	}
	$byid = array_column($boxes, null, 'node_id');
	$nodes = fleet_rollout_rings($ring_groups, $members, array_column($plan['go'], 'node_id'));
	$rings = array();
	$placed = array();
	foreach ($ring_groups as $r => $gid) {
		$g = ($gid === 0) ? null : fleet_group_get($gid);
		$rings[] = array($gid, ($g === null) ? 'Everyone else' : $g['name'], ($g === null) ? null : fleet_window_get((int)$g['window_id']),
		    array_map(function ($n) use ($byid) { return $byid[$n]; }, $nodes[$r]));
		foreach ($nodes[$r] as $n) {
			$placed[$n] = true;
		}
	}
	foreach ($plan['go'] as $b) {
		if (!isset($placed[$b['node_id']])) {
			$plan['skip'][] = array($b, 'In no ring of this rollout');
		}
	}
	return array('rings' => $rings, 'skip' => $plan['skip']);
}

/* Start a rollout from a reviewed plan. Returns the operation id. */
function fleet_rollout_start(array $plan, string $target, int $gap, string $who): int {
	$op = fleet_op_group_start('rollout', sprintf('Roll out %s', $target), $who);
	$rings = array();
	foreach ($plan['rings'] as $r => list($gid, $name, $window, $boxes)) {
		$rings[] = array('group' => $gid, 'name' => $name, 'window' => ($window === null) ? null : $window['id']);
		foreach ($boxes as $b) {
			$t = fleet_op_start($b['node_id'], 'update', 'Waiting for its ring', $who, $op, 'queued');
			fleet_db()->prepare('UPDATE ops SET data = ? WHERE id = ?')->execute(array(json_encode(array('ring' => $r)), $t));
		}
	}
	foreach ($plan['skip'] as list($b, $why)) {
		fleet_op_set(fleet_op_start($b['node_id'], 'update', $why, $who, $op, 'skipped'), 'skipped', 'Skipped: ' . lcfirst($why));
	}
	fleet_db()->prepare("INSERT INTO rollouts (op_id, target, rings, state, gap, who, created) VALUES (?, ?, ?, 'running', ?, ?, ?)")
	    ->execute(array($op, $target, json_encode($rings), $gap, $who, time()));
	fleet_audit($who, 'rollout', sprintf('%s: %s', $target, implode(' > ', array_column($rings, 'name'))));
	fleet_op_group_update($op);
	return $op;
}

function fleet_rollout_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM rollouts WHERE id = ?');
	$q->execute(array($id));
	$row = $q->fetch();
	return is_array($row) ? $row : null;
}

function fleet_rollouts_all(int $limit = 20): array {
	$q = fleet_db()->prepare('SELECT r.*, o.text AS op_text, o.progress AS op_progress, o.state AS op_state FROM rollouts r LEFT JOIN ops o ON o.id = r.op_id ORDER BY r.id DESC LIMIT ?');
	$q->execute(array($limit));
	return $q->fetchAll();
}

/* The rings of a rollout as fleet_rollout_next() wants them, plus the tasks of each ring. */
function fleet_rollout_rings_now(array $ro): array {
	$acked = array_map('intval', json_decode((string)$ro['acked'], true) ?: array());
	$tasks = array();
	foreach (fleet_op_tasks((int)$ro['op_id']) as $t) {
		$d = json_decode((string)($t['data'] ?? ''), true) ?: array();
		if (isset($d['ring'])) {
			$tasks[(int)$d['ring']][] = $t;
		}
	}
	$out = array();
	foreach (json_decode((string)$ro['rings'], true) ?: array() as $r => $ring) {
		$list = $tasks[$r] ?? array();
		usort($list, function ($a, $b) { return (int)$a['id'] <=> (int)$b['id']; });
		/* A failure someone resumed past counts as finished. */
		$states = array_map(function ($t) use ($acked) {
			return (($t['state'] === 'failed') && in_array((int)$t['id'], $acked, true)) ? 'skipped' : (string)$t['state'];
		}, $list);
		/* states: for deciding what comes next; shown: what really happened, for the page. */
		$out[] = array('ring' => $ring, 'window' => fleet_window_get($ring['window'] ?? null), 'tasks' => $list, 'states' => $states,
		    'shown' => array_map(function ($t) { return (string)$t['state']; }, $list));
	}
	return $out;
}

/* One rollout one step further (the poll calls this every minute). */
function fleet_rollout_tick(array $ro, int $now): void {
	if ($ro['state'] !== 'running') {
		return;
	}
	$rings = fleet_rollout_rings_now($ro);
	$done = json_decode((string)$ro['ring_done'], true) ?: array();
	foreach ($rings as $r => $ring) {
		$over = !empty($ring['states']) ? !array_intersect(array('queued', 'running', 'failed'), $ring['states']) : true;
		if ($over && !isset($done[$r])) {
			$done[$r] = $now;
		}
	}
	fleet_db()->prepare('UPDATE rollouts SET ring_done = ? WHERE id = ?')->execute(array(json_encode($done, JSON_FORCE_OBJECT), $ro['id']));
	$next = fleet_rollout_next(array_map(function ($x) { return array($x['window'], $x['states']); }, $rings),
	    array_map('intval', $done), $now, (int)$ro['gap'], 60 * fleet_opt('update_timeout'), fleet_tz());
	$op = (int)$ro['op_id'];
	switch ($next['do']) {
	case 'start':
		$t = $rings[$next['ring']]['tasks'][$next['task']];
		$box = fleet_box_get((string)$t['node_id']);
		try {
			if ($box === null) {
				throw new RuntimeException('Not in the fleet any more.');
			}
			fleet_box_update($box, (string)$ro['who'], (int)$t['id']);
		} catch (RuntimeException $e) {
			fleet_op_set((int)$t['id'], 'failed', 'Update refused: ' . $e->getMessage());
		}
		fleet_op_group_update($op);
		break;
	case 'pause':
		fleet_db()->prepare("UPDATE rollouts SET state = 'paused' WHERE id = ?")->execute(array($ro['id']));
		fleet_op_set($op, 'running', sprintf('Paused in %s: a firewall failed. Resume or cancel.', $rings[$next['ring']]['ring']['name']));
		fleet_audit('rollout', 'rollout', sprintf('%s: paused in %s after a failure', $ro['target'], $rings[$next['ring']]['ring']['name']));
		break;
	case 'wait':
		/* Count only the firewalls in the rings, not those left out at the start. */
		$all = array_merge(...array_map(function ($x) { return $x['states']; }, $rings));
		$fin = count(array_filter($all, function ($st) { return !in_array($st, array('queued', 'running'), true); }));
		$p = array('percent' => empty($all) ? 100 : (int)floor(100 * $fin / count($all)));
		$text = sprintf('%d of %d updated. %s', $fin, count($all), $next['why']) . (($next['until'] !== null) ? ' (' . date('D H:i', (int)$next['until']) . ')' : '');
		fleet_op_set($op, 'running', $text, $p['percent']);
		break;
	case 'done':
		fleet_db()->prepare("UPDATE rollouts SET state = 'done' WHERE id = ?")->execute(array($ro['id']));
		fleet_op_group_update($op);
		break;
	}
}

function fleet_rollouts_tick(int $now): void {
	foreach (fleet_db()->query("SELECT * FROM rollouts WHERE state = 'running'")->fetchAll() as $ro) {
		try {
			fleet_rollout_tick($ro, $now);
		} catch (Throwable $e) {
			fleet_audit('rollout', 'rollout', "{$ro['target']}: " . $e->getMessage());
		}
	}
}

/* Resume a paused rollout: the failures so far are passed over (they stay failed in Activity). */
function fleet_rollout_resume(int $id, string $who): void {
	$ro = fleet_rollout_get($id);
	if (($ro === null) || ($ro['state'] !== 'paused')) {
		throw new RuntimeException('This rollout is not paused.');
	}
	$acked = json_decode((string)$ro['acked'], true) ?: array();
	foreach (fleet_op_tasks((int)$ro['op_id']) as $t) {
		if ($t['state'] === 'failed') {
			$acked[] = (int)$t['id'];
		}
	}
	fleet_db()->prepare("UPDATE rollouts SET state = 'running', acked = ? WHERE id = ?")->execute(array(json_encode(array_values(array_unique($acked))), $id));
	fleet_op_set((int)$ro['op_id'], 'running', 'Resumed by ' . $who . '. The next firewall starts in its window.');
	fleet_audit($who, 'rollout', "{$ro['target']}: resumed");
}

/* Cancel: firewalls not started yet are left alone; one updating now finishes. */
function fleet_rollout_cancel(int $id, string $who): void {
	$ro = fleet_rollout_get($id);
	if (($ro === null) || !in_array($ro['state'], array('running', 'paused'), true)) {
		throw new RuntimeException('This rollout has ended already.');
	}
	foreach (fleet_op_tasks((int)$ro['op_id']) as $t) {
		if ($t['state'] === 'queued') {
			fleet_op_set((int)$t['id'], 'skipped', 'Skipped: the rollout was cancelled by ' . $who);
		}
	}
	fleet_db()->prepare("UPDATE rollouts SET state = 'cancelled' WHERE id = ?")->execute(array($id));
	fleet_op_group_update((int)$ro['op_id']);
	fleet_audit($who, 'rollout', "{$ro['target']}: cancelled");
}

