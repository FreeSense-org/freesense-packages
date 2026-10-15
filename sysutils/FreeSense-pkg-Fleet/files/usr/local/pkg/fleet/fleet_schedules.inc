<?php
/*
 * fleet_schedules.inc
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
 * Schedules: recurring jobs on one firewall, a group or every firewall at a time of
 * day on chosen weekdays, in the controller's time zone. A job is the same
 * operation the dashboard starts (back up, reboot one at a time, update
 * one at a time), so Activity and the notices follow it. The poll checks
 * every minute; a run the controller missed by more than
 * schedule_grace minutes (it was off) is recorded as missed, not run
 * late. Timed firewall rules come with templates (phase 3).
 */

require_once('fleet/fleet_store.inc');

define('FLEET_SCHEDULE_KINDS', array('backup' => 'Back up', 'reboot' => 'Reboot one at a time', 'update' => 'Update one at a time'));

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: a schedule from what a form sends, or an InvalidArgumentException that says what is wrong. */
function fleet_schedule_from(array $in): array {
	$name = trim((string)($in['name'] ?? ''));
	if (($name === '') || (strlen($name) > 60) || preg_match('/[<>\x00-\x1f\x7f]/', $name)) {
		throw new InvalidArgumentException('Give the schedule a name of 1 to 60 characters.');
	}
	$kind = (string)($in['kind'] ?? '');
	if (!isset(FLEET_SCHEDULE_KINDS[$kind])) {
		throw new InvalidArgumentException('Choose what the schedule does.');
	}
	$days = array_values(array_unique(array_filter(array_map('intval', (array)($in['days'] ?? array())), function ($d) {
		return $d >= 1 && $d <= 7;
	})));
	sort($days);
	if (empty($days)) {
		throw new InvalidArgumentException('Choose at least one day.');
	}
	if (!preg_match('/^([01]\d|2[0-3]):([0-5]\d)$/', (string)($in['time'] ?? ''), $m)) {
		throw new InvalidArgumentException('The time is like 02:30.');
	}
	return array('name' => $name, 'kind' => $kind, 'targets' => fleet_targets_from($in['targets'] ?? ($in['target'] ?? 'all')), 'days' => $days,
	    'time' => 60 * (int)$m[1] + (int)$m[2], 'enabled' => !empty($in['enabled']));
}

/*
 * pure: which firewalls a job is for, from a form: ["all"], or any mix of
 * "g:<group id>" and "n:<node id>" (sorted, no repeats). "all" wins over
 * the rest. Shared by everything that targets firewalls.
 */
function fleet_targets_from($in): array {
	$out = array();
	foreach ((array)$in as $t) {
		$t = (string)$t;
		if ($t === 'all') {
			return array('all');
		}
		if (!preg_match('/^(g:\d+|n:[A-Za-z0-9-]{1,64})$/', $t)) {
			throw new InvalidArgumentException('Choose which firewalls it is for.');
		}
		$out[$t] = true;
	}
	if (empty($out)) {
		throw new InvalidArgumentException('Choose which firewalls it is for.');
	}
	$out = array_keys($out);
	sort($out);
	return $out;
}

/*
 * pure: the firewalls targets mean, in label order, plus what no longer
 * exists. $boxes: rows; $members: group id => node ids.
 */
function fleet_targets_resolve(array $targets, array $boxes, array $members): array {
	$byid = array_column($boxes, null, 'node_id');
	$want = array();
	$gone = array();
	foreach ($targets as $t) {
		if ($t === 'all') {
			$want += array_fill_keys(array_keys($byid), true);
		} elseif (strncmp($t, 'g:', 2) === 0) {
			if (!isset($members[(int)substr($t, 2)])) {
				$gone[] = $t;
				continue;
			}
			$want += array_fill_keys(array_intersect($members[(int)substr($t, 2)], array_keys($byid)), true);
		} elseif (isset($byid[substr($t, 2)])) {
			$want[substr($t, 2)] = true;
		} else {
			$gone[] = $t;
		}
	}
	$list = array_values(array_filter($boxes, function ($b) use ($want) { return isset($want[$b['node_id']]); }));
	return array($list, $gone);
}

/* pure: "Canary, Retail, VMware lab box" (names: target => label). */
function fleet_targets_text(array $targets, array $names): string {
	return implode(', ', array_map(function ($t) use ($names) {
		return ($t === 'all') ? 'All firewalls' : ($names[$t] ?? (($t[0] === 'g') ? 'deleted group' : 'removed firewall'));
	}, $targets));
}

/* pure: the times the schedule fires on the day of $day (a DateTimeImmutable in the right zone), or null. */
function fleet_schedule_at(array $s, DateTimeImmutable $day): ?int {
	return in_array((int)$day->format('N'), $s['days'], true) ? $day->setTime(intdiv($s['time'], 60), $s['time'] % 60)->getTimestamp() : null;
}

/*
 * pure: what to do now. $since: the last run (or when it was made). Returns
 * null (nothing), array('run', time) or array('missed', time) for the
 * newest time it should have fired after $since.
 */
function fleet_schedule_due(array $s, int $since, int $now, int $grace, string $tz = 'UTC'): ?array {
	$t = (new DateTimeImmutable('@' . $now))->setTimezone(new DateTimeZone($tz));
	for ($back = 0; $back <= 7; $back++) {
		$at = fleet_schedule_at($s, $t->modify("-{$back} day"));
		if (($at === null) || ($at > $now)) {
			continue;
		}
		if ($at <= $since) {
			return null;
		}
		return array(($now - $at <= $grace) ? 'run' : 'missed', $at);
	}
	return null;
}

/* pure: when it fires next after $now. */
function fleet_schedule_next(array $s, int $now, string $tz = 'UTC'): ?int {
	$t = (new DateTimeImmutable('@' . $now))->setTimezone(new DateTimeZone($tz));
	for ($i = 0; $i <= 8; $i++) {
		$at = fleet_schedule_at($s, $t->modify("+{$i} day"));
		if (($at !== null) && ($at > $now)) {
			return $at;
		}
	}
	return null;
}

/* pure: "Mon-Fri 02:30" */
function fleet_schedule_text(array $s): string {
	return preg_replace('/, .*$/', '', fleet_window_text(array('days' => $s['days'], 'start' => $s['time'], 'length' => 60)));
}

/* ------------------------------------------------------------------ */
/* Storage and running                                                 */
/* ------------------------------------------------------------------ */

function fleet_schedule_row(array $r): array {
	$r['days'] = array_map('intval', json_decode((string)$r['days'], true) ?: array());
	$r['time'] = (int)$r['time'];
	$r['targets'] = json_decode((string)($r['targets'] ?? ''), true) ?: array('all');
	$r['enabled'] = (bool)$r['enabled'];
	return $r;
}

function fleet_schedules_all(): array {
	return array_map('fleet_schedule_row', fleet_db()->query('SELECT * FROM schedules ORDER BY name COLLATE NOCASE')->fetchAll());
}

function fleet_schedule_get(int $id): ?array {
	$q = fleet_db()->prepare('SELECT * FROM schedules WHERE id = ?');
	$q->execute(array($id));
	$r = $q->fetch();
	return is_array($r) ? fleet_schedule_row($r) : null;
}

function fleet_schedule_save(?int $id, array $in, string $who): int {
	$s = fleet_schedule_from($in);
	list(, $gone) = fleet_targets_now($s['targets']);
	if (!empty($gone)) {
		throw new InvalidArgumentException('A chosen group or firewall does not exist any more. Choose again.');
	}
	$args = array($s['name'], $s['kind'], json_encode($s['targets']), json_encode($s['days']), $s['time'], (int)$s['enabled']);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO schedules (name, kind, targets, days, time, enabled, last_run, who, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time(), $who, time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		/* Changing the time must not fire a run that "was due" under the old time. */
		fleet_db()->prepare('UPDATE schedules SET name = ?, kind = ?, targets = ?, days = ?, time = ?, enabled = ?, last_run = MAX(last_run, ?) WHERE id = ?')
		    ->execute(array_merge($args, array(time(), $id)));
	}
	fleet_audit($who, 'schedule', sprintf('%s: %s %s, %s%s', $s['name'], FLEET_SCHEDULE_KINDS[$s['kind']], fleet_targets_text($s['targets'], fleet_target_names()),
	    fleet_schedule_text($s), $s['enabled'] ? '' : ' (paused)'));
	return $id;
}

function fleet_schedule_delete(int $id, string $who): void {
	$s = fleet_schedule_get($id);
	fleet_db()->prepare('DELETE FROM schedules WHERE id = ?')->execute(array($id));
	fleet_audit($who, 'schedule', ($s['name'] ?? (string)$id) . ': deleted');
}

function fleet_schedule_set_enabled(int $id, bool $on, string $who): void {
	fleet_db()->prepare('UPDATE schedules SET enabled = ?, last_run = MAX(last_run, ?) WHERE id = ?')->execute(array((int)$on, time(), $id));
	$s = fleet_schedule_get($id);
	fleet_audit($who, 'schedule', ($s['name'] ?? (string)$id) . ($on ? ': resumed' : ': paused'));
}

/* What targets mean right now: array(firewall rows, targets that no longer exist). */
function fleet_targets_now(array $targets): array {
	$members = array();
	foreach (fleet_groups_all() as $g) {
		$members[(int)$g['id']] = array();
	}
	foreach (fleet_db()->query('SELECT group_id, node_id FROM box_groups')->fetchAll() as $m) {
		$members[(int)$m['group_id']][] = $m['node_id'];
	}
	return fleet_targets_resolve($targets, fleet_db()->query('SELECT * FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll(), $members);
}

/* target => label for every group and firewall (for lists and the audit log). */
function fleet_target_names(): array {
	$names = array();
	foreach (fleet_groups_all() as $g) {
		$names['g:' . $g['id']] = $g['name'];
	}
	foreach (fleet_db()->query('SELECT node_id, label FROM boxes')->fetchAll() as $b) {
		$names['n:' . $b['node_id']] = $b['label'];
	}
	return $names;
}

/* Run a schedule's job now. Returns the words for its last result. */
function fleet_schedule_run(array $s, string $who): string {
	list($boxes, $gone) = fleet_targets_now($s['targets']);
	$note = empty($gone) ? '' : ' (' . count($gone) . ' chosen groups or firewalls no longer exist)';
	if ((count($s['targets']) === 1) && (strncmp($s['targets'][0], 'n:', 2) === 0)) {
		/* One firewall: exactly what its own page does. */
		$result = fleet_schedule_run_one($s, substr($s['targets'][0], 2), $who);
	} elseif (empty($boxes)) {
		$result = 'Not run: no firewalls' . $note . '.';
	} elseif ($s['kind'] === 'backup') {
		mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup nodes ' . escapeshellarg($who) . ' ' .
		    escapeshellarg('Back up ' . fleet_targets_text($s['targets'], fleet_target_names())) . ' ' . escapeshellarg(implode(',', array_column($boxes, 'node_id'))));
		$result = sprintf('Backup of %d firewalls started%s.', count($boxes), $note);
	} else {
		$plan = fleet_boxes_plan($boxes, $s['kind']);
		if (empty($plan['go'])) {
			$result = 'Nothing to do: ' . (empty($plan['skip']) ? 'no firewalls.' : 'every firewall was left out (' . lcfirst($plan['skip'][0][1]) . (count($plan['skip']) > 1 ? ', ...' : '') . ').');
		} else {
			$op = fleet_group_op_launch(fleet_targets_text($s['targets'], fleet_target_names()), $s['kind'], $plan, $who);
			fleet_db()->prepare('UPDATE schedules SET last_op = ? WHERE id = ?')->execute(array($op, $s['id']));
			$result = sprintf('Started for %d firewalls%s.', count($plan['go']), $note);
		}
	}
	fleet_db()->prepare('UPDATE schedules SET last_result = ?, ran_at = ? WHERE id = ?')->execute(array($result, time(), $s['id']));
	return $result;
}

/* Called by the poll every minute. */
function fleet_schedules_tick(int $now): void {
	foreach (fleet_schedules_all() as $s) {
		if (!$s['enabled']) {
			continue;
		}
		$due = fleet_schedule_due($s, (int)$s['last_run'], $now, 60 * fleet_opt('schedule_grace'), fleet_tz());
		if ($due === null) {
			continue;
		}
		fleet_db()->prepare('UPDATE schedules SET last_run = ? WHERE id = ?')->execute(array($due[1], $s['id']));
		if ($due[0] === 'missed') {
			$text = sprintf('Missed %s: the controller was not running then.', date('D H:i', $due[1]));
			fleet_db()->prepare('UPDATE schedules SET last_result = ?, ran_at = ? WHERE id = ?')->execute(array($text, $due[1], $s['id']));
			fleet_audit('schedule', 'schedule', "{$s['name']}: {$text}");
			continue;
		}
		try {
			fleet_schedule_run($s, 'schedule: ' . $s['name']);
		} catch (Throwable $e) {
			fleet_db()->prepare('UPDATE schedules SET last_result = ?, ran_at = ? WHERE id = ?')->execute(array('Failed: ' . $e->getMessage(), time(), $s['id']));
		}
	}
}

/* A schedule on one firewall: the same actions as its own page. */
function fleet_schedule_run_one(array $s, string $node, string $who): string {
	$box = fleet_box_get($node);
	if ($box === null) {
		return 'Not run: the firewall left the fleet.';
	}
	if ($s['kind'] === 'backup') {
		mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup one ' . escapeshellarg($box['node_id']) . ' schedule ' . escapeshellarg($who));
		return 'Backup started.';
	}
	if ($box['state'] === 'offline') {
		return 'Not run: the firewall was offline.';
	}
	if ($s['kind'] === 'update') {
		$info = fleet_update_info($box);
		if (($info === null) || !$info['available']) {
			return 'Nothing to do: ' . (($info === null) ? 'not checked for updates yet.' : (($info['error'] !== null) ? 'its update check failed.' : 'up to date.'));
		}
	}
	try {
		$text = ($s['kind'] === 'update') ? fleet_box_update($box, $who) : fleet_box_reboot($box, $who);
	} catch (RuntimeException $e) {
		return 'Not run: ' . $e->getMessage();
	}
	$op = fleet_op_running($box['node_id']);
	if ($op !== null) {
		fleet_db()->prepare('UPDATE schedules SET last_op = ? WHERE id = ?')->execute(array($op['id'], $s['id']));
	}
	return $text;
}

