<?php
/*
 * fleet_updates.inc
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
 * System updates of firewalls. The box does the update itself (the same
 * update as System > Update, with its boot environment and its own health
 * check that rolls back by itself); the controller starts it, follows it
 * from the outside and says how it ended:
 *   installing      the box answers, same version, not rebooted
 *   restarting      no answer
 *   staying healthy back on the new version, waiting out the box's own
 *                   rollback window (update_healthy setting)
 *   done            still on the new version after that window
 *   failed          back on the old version after a reboot (it rolled
 *                   back), or no result within update_timeout
 * Each box's last update check (installed, latest, channel) is kept on the
 * box row, refreshed every update_check_hours by the poll. Later the
 * Policy Manager adds version rules (minimum, pinned, allowed versions,
 * channel) per group or firewall; fleet_update_verdict() is where they go.
 */

require_once('fleet/fleet_store.inc');

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: "1.1.5-RELEASE", "1.1.5_1", "1.2.0.20261016" -> the numbers that name the version ("1.1.5"). */
function fleet_version_number(string $v): string {
	return preg_match('/^\d+(?:\.\d+)*/', trim($v), $m) ? $m[0] : '';
}

/* pure: the same version, whatever the spelling. */
function fleet_version_same(string $a, string $b): bool {
	return (fleet_version_number($a) !== '') && (fleet_version_number($a) === fleet_version_number($b));
}

/* pure: what the box said about updates (GET /v1/system/version), kept on the box row. */
function fleet_update_info_from(int $code, array $json, int $now): array {
	if ($code === 200) {
		$d = (array)($json['data'] ?? array());
		return array('checked' => $now, 'installed' => (string)($d['installed_version'] ?? ''), 'latest' => (string)($d['latest_version'] ?? ''),
		    'available' => !empty($d['update_available']), 'channel' => (string)($d['channel'] ?? ''), 'error' => null);
	}
	$msgs = array_filter((array)($json['error']['details']['messages'] ?? array()), 'is_string');
	$why = !empty($msgs) ? implode(' ', $msgs) : (string)($json['error']['message'] ?? "HTTP {$code}");
	return array('checked' => $now, 'installed' => '', 'latest' => '', 'available' => false, 'channel' => '',
	    'error' => 'The firewall could not check for updates: ' . $why);
}

/*
 * pure: what a tile or page says about a firewall's version: array(kind,
 * words) or null when there is nothing to say. Policy version rules join
 * here later.
 */
function fleet_update_verdict(?array $info): ?array {
	if ($info === null) {
		return null;
	}
	if ($info['error'] !== null) {
		return array('neutral', 'Update check failed');
	}
	return $info['available'] ? array('info', 'Update: ' . fleet_version_number($info['latest'])) : null;
}

/*
 * pure: where an update stands after a status check. $op has started and
 * data {from, to, reached}; $status is the box's answer (null: none).
 * Returns null (no change) or array(state, text, progress, data).
 */
function fleet_op_update_step(array $op, ?array $status, int $now, int $healthy, int $timeout): ?array {
	$d = json_decode((string)($op['data'] ?? ''), true) ?: array();
	$from = (string)($d['from'] ?? '');
	$to = (string)($d['to'] ?? '');
	$started = (int)$op['started'];
	$set = function (string $state, string $text, int $progress) use ($op, $d) {
		/* No change only when both the words and the bar stay the same. */
		return (($op['text'] === $text) && ($state === 'running') && ((int)($op['progress'] ?? -1) === $progress)) ? null : array($state, $text, $progress, $d);
	};
	if ($status !== null) {
		$version = (string)($status['version'] ?? '');
		$rebooted = (int)($status['boot_time'] ?? 0) > $started;
		if (fleet_version_same($version, $to)) {
			if (!isset($d['reached'])) {
				$d['reached'] = $now;
				return array('running', 'Checking that it stays healthy', 85, $d);
			}
			if (($now - (int)$d['reached']) >= $healthy) {
				return array('done', sprintf('Updated to %s in %s', fleet_version_number($to), fleet_op_duration($now - $started)), 100, $d);
			}
			return $set('running', 'Checking that it stays healthy', 85 + (int)floor(14 * ($now - (int)$d['reached']) / max(1, $healthy)));
		}
		if ($rebooted && fleet_version_same($version, $from)) {
			return array('failed', sprintf('Rolled back to %s: the new version did not pass the firewall\'s own health check', fleet_version_number($from)), 100, $d);
		}
		if (!$rebooted && (($now - $started) <= $timeout)) {
			/* Downloading and installing takes most of the time; the bar creeps so it never looks stuck. */
			return $set('running', 'Downloading and installing', 10 + (int)min(40, floor(40 * ($now - $started) / max(1, $timeout / 2))));
		}
	}
	if (($now - $started) > $timeout) {
		return array('failed', 'No result after ' . fleet_op_duration($timeout) . '. Check the firewall\'s console and System > Update.', 100, $d);
	}
	return ($status === null) ? $set('running', 'Restarting', 60) : null;
}

/* ------------------------------------------------------------------ */
/* Storage and calls                                                   */
/* ------------------------------------------------------------------ */

function fleet_update_info(array $box): ?array {
	$info = json_decode((string)($box['update_info'] ?? ''), true);
	return is_array($info) ? $info : null;
}

/* Ask the box about updates now (refresh: make it check its repository again) and keep the answer. */
function fleet_update_check(array $box, bool $refresh = false): array {
	try {
		list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/system/version' . ($refresh ? '?refresh=true' : ''));
	} catch (RuntimeException $e) {
		$code = 0;
		$json = array('error' => array('message' => $e->getMessage()));
	}
	$info = fleet_update_info_from((int)$code, (array)$json, time());
	fleet_db()->prepare('UPDATE boxes SET update_info = ? WHERE node_id = ?')->execute(array(json_encode($info), $box['node_id']));
	return $info;
}

/* Checks before updating, as the box runs them (update available, disk space, boot environment, repository...). */
function fleet_update_preflight(array $box): array {
	list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/system/update/preflight');
	if ($code !== 200) {
		throw new RuntimeException('The firewall did not run its update checks: ' . fleet_box_error($code, $json));
	}
	return array_values(array_filter((array)($json['data'] ?? array()), function ($c) {
		return is_array($c) && isset($c['label'], $c['state']);
	}));
}

/* Start the update of one firewall. $task: its group operation's task, if any. Returns the words for the result. */
function fleet_box_update(array $box, string $who, ?int $task = null): string {
	fleet_manage_require($box);
	if (($task === null) && (fleet_op_running($box['node_id']) !== null)) {
		throw new RuntimeException('Something is already running on this firewall. Wait until it is done.');
	}
	list($code, $json) = fleet_box_call($box, 'POST', '/api/v1/management/update', array('confirm' => true, 'operator' => fleet_operator($who)));
	if ($code !== 202) {
		throw new RuntimeException('The firewall did not start the update: ' . fleet_box_error($code, $json));
	}
	$from = (string)($json['data']['from'] ?? '');
	$to = (string)($json['data']['to'] ?? '');
	$data = json_encode(array('from' => $from, 'to' => $to));
	if ($task === null) {
		$task = fleet_op_start($box['node_id'], 'update', 'Downloading and installing', $who);
	}
	fleet_db()->prepare("UPDATE ops SET state = 'running', text = 'Downloading and installing', started = ?, updated = ?, progress = 10, data = ? WHERE id = ?")
	    ->execute(array(time(), time(), $data, $task));
	fleet_audit($who, 'update', "{$box['node_id']} ({$box['label']}): from {$from} to {$to}");
	return sprintf('Updating from %s to %s. It reboots on the way; this page follows it.', fleet_version_number($from), fleet_version_number($to));
}

/* Called by the status poll for every firewall: moves its running update along. */
function fleet_update_follow(array $box, ?array $status, int $now): void {
	$op = fleet_op_running($box['node_id']);
	if (($op === null) || ($op['kind'] !== 'update') || ($op['state'] !== 'running') || empty($op['data'])) {
		return;
	}
	$step = fleet_op_update_step($op, $status, $now, 60 * fleet_opt('update_healthy'), 60 * fleet_opt('update_timeout'));
	if ($step === null) {
		return;
	}
	fleet_db()->prepare('UPDATE ops SET data = ? WHERE id = ?')->execute(array(json_encode($step[3]), $op['id']));
	fleet_op_set((int)$op['id'], $step[0], $step[1], $step[2]);
	if ($step[0] !== 'running') {
		fleet_audit('poll', ($step[0] === 'done') ? 'update_done' : 'update_failed', "{$box['node_id']} ({$box['label']}): {$step[1]}");
		/* The new version changes what is available: ask again at once. */
		fleet_update_check(fleet_box_get($box['node_id']), true);
		if ($op['parent'] !== null) {
			fleet_op_group_update((int)$op['parent']);
		}
	}
}
