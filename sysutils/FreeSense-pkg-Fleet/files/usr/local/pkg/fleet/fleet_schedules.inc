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
	/* Target: "all", "g:<group id>" or "n:<node id>" (the form), or group_id alone. */
	list($group, $node) = array(max(0, (int)($in['group_id'] ?? 0)), null);
	$target = (string)($in['target'] ?? '');
	if (preg_match('/^g:(\d+)$/', $target, $t)) {
		$group = (int)$t[1];
	} elseif (preg_match('/^n:([A-Za-z0-9-]{1,64})$/', $target, $t)) {
		list($group, $node) = array(0, $t[1]);
	} elseif (($target !== '') && ($target !== 'all')) {
		throw new InvalidArgumentException('Choose which firewalls the schedule is for.');
	}
	return array('name' => $name, 'kind' => $kind, 'group_id' => $group, 'node_id' => $node, 'days' => $days,
	    'time' => 60 * (int)$m[1] + (int)$m[2], 'enabled' => !empty($in['enabled']));
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
	$r['group_id'] = (int)$r['group_id'];
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
	if (($s['group_id'] > 0) && (fleet_group_get($s['group_id']) === null)) {
		throw new InvalidArgumentException('That group does not exist any more.');
	}
	if (($s['node_id'] !== null) && (fleet_box_get($s['node_id']) === null)) {
		throw new InvalidArgumentException('That firewall is not in the fleet any more.');
	}
	$args = array($s['name'], $s['kind'], $s['group_id'], $s['node_id'], json_encode($s['days']), $s['time'], (int)$s['enabled']);
	if ($id === null) {
		fleet_db()->prepare('INSERT INTO schedules (name, kind, group_id, node_id, days, time, enabled, last_run, who, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array_merge($args, array(time(), $who, time())));
		$id = (int)fleet_db()->lastInsertId();
	} else {
		/* Changing the time must not fire a run that "was due" under the old time. */
		fleet_db()->prepare('UPDATE schedules SET name = ?, kind = ?, group_id = ?, node_id = ?, days = ?, time = ?, enabled = ?, last_run = MAX(last_run, ?) WHERE id = ?')
		    ->execute(array_merge($args, array(time(), $id)));
	}
	fleet_audit($who, 'schedule', sprintf('%s: %s, %s%s', $s['name'], FLEET_SCHEDULE_KINDS[$s['kind']], fleet_schedule_text($s), $s['enabled'] ? '' : ' (paused)'));
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

/* Run a schedule's job now. Returns the words for its last result. */
function fleet_schedule_run(array $s, string $who): string {
	$group = ($s['group_id'] > 0) ? fleet_group_get($s['group_id']) : null;
	if (!empty($s['node_id'])) {
		$result = fleet_schedule_run_one($s, $who);
	} elseif (($s['group_id'] > 0) && ($group === null)) {
		$result = 'Not run: its group was deleted.';
	} elseif ($s['kind'] === 'backup') {
		mwexec_bg('/usr/local/bin/php /usr/local/sbin/freesense-fleet-backup all ' . escapeshellarg($who) . ' ' . (int)$s['group_id']);
		$result = 'Backup started.';
	} else {
		list(, $plan) = fleet_group_plan($group, $s['kind']);
		if (empty($plan['go'])) {
			$result = 'Nothing to do: ' . (empty($plan['skip']) ? 'no firewalls.' : 'every firewall was left out (' . lcfirst($plan['skip'][0][1]) . (count($plan['skip']) > 1 ? ', ...' : '') . ').');
		} else {
			$op = fleet_group_op_launch($group, $s['kind'], $plan, $who);
			fleet_db()->prepare('UPDATE schedules SET last_op = ? WHERE id = ?')->execute(array($op, $s['id']));
			$result = sprintf('Started for %d firewalls.', count($plan['go']));
		}
	}
	fleet_db()->prepare('UPDATE schedules SET last_result = ? WHERE id = ?')->execute(array($result, $s['id']));
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
			fleet_db()->prepare('UPDATE schedules SET last_result = ? WHERE id = ?')->execute(array($text, $s['id']));
			fleet_audit('schedule', 'schedule', "{$s['name']}: {$text}");
			continue;
		}
		try {
			fleet_schedule_run($s, 'schedule: ' . $s['name']);
		} catch (Throwable $e) {
			fleet_db()->prepare('UPDATE schedules SET last_result = ? WHERE id = ?')->execute(array('Failed: ' . $e->getMessage(), $s['id']));
		}
	}
}

/* A schedule on one firewall: the same actions as its own page. */
function fleet_schedule_run_one(array $s, string $who): string {
	$box = fleet_box_get((string)$s['node_id']);
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

