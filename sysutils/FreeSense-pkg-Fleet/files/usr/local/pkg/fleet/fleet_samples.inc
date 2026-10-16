<?php
/*
 * fleet_samples.inc
 *
 * part of FreeSense (https://freesense.org)
 * Copyright (c) 2025-2026 FreeSense
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
 * Load samples for the fleet charts: every 5 minutes the poll asks each
 * online firewall for CPU and memory (its RRD, last 10 minutes), states
 * and temperature (live) and WAN traffic (its RRD). Five-minute rows are
 * kept for 48 hours, then folded into hourly rows kept for 30 days.
 */

define('FLEET_SAMPLES_EVERY', 300);
/* The poll spends at most this long on samples per run; the rest follow next minute. */
define('FLEET_SAMPLES_BUDGET', 20);
define('FLEET_SAMPLES_DETAIL', 172800);
define('FLEET_SAMPLES_KEEP', 2592000);
define('FLEET_SAMPLES_LEVEL', 11);
define('FLEET_SAMPLES_COLS', array('cpu', 'mem', 'states', 'states_max', 'temp', 'rx_bps', 'tx_bps'));

/* pure: the last number in a series (RRD series end in nulls while the step fills), or null. */
function fleet_samples_last($series): ?float {
	foreach (array_reverse(is_array($series) ? $series : array()) as $v) {
		if (is_numeric($v)) {
			return (float)$v;
		}
	}
	return null;
}

/*
 * pure: one sample from the firewall's answers: system (live), its
 * CPU/memory history and its WAN traffic history (each may be null).
 */
function fleet_samples_from(?array $sys, ?array $hist, ?array $traffic): array {
	$temp = null;
	foreach ((array)($sys['temperatures'] ?? array()) as $t) {
		if (is_numeric($t['celsius'] ?? null)) {
			$temp = max($temp ?? -INF, (float)$t['celsius']);
		}
	}
	$mem = fleet_samples_last($hist['mem'] ?? null);
	if (($mem === null) && ((int)($sys['memory']['total_bytes'] ?? 0) > 0)) {
		$mem = 100 * (float)$sys['memory']['used_bytes'] / (float)$sys['memory']['total_bytes'];
	}
	$round = function ($v, $d) { return ($v === null) ? null : round($v, $d); };
	return array(
		'cpu' => $round(fleet_samples_last($hist['cpu'] ?? null) ?? (is_numeric($sys['cpu']['usage'] ?? null) ? (float)$sys['cpu']['usage'] : null), 1),
		'mem' => $round($mem, 1),
		'states' => is_numeric($sys['states']['current'] ?? null) ? (int)$sys['states']['current'] : null,
		'states_max' => is_numeric($sys['states']['max'] ?? null) ? (int)$sys['states']['max'] : null,
		'temp' => $round($temp, 1),
		'rx_bps' => $round(fleet_samples_last($traffic['in_bps'] ?? null), 0),
		'tx_bps' => $round(fleet_samples_last($traffic['out_bps'] ?? null), 0),
	);
}

/* pure: hourly rows from five-minute rows: averages per node and hour, the CPU peak and the count. */
function fleet_samples_hourly(array $rows): array {
	$acc = array();
	foreach ($rows as $r) {
		$k = $r['node_id'] . '|' . (intdiv((int)$r['time'], 3600) * 3600);
		$a = $acc[$k] ?? array('node_id' => $r['node_id'], 'time' => intdiv((int)$r['time'], 3600) * 3600, 'n' => 0, 'cpu_max' => null, 'sum' => array(), 'cnt' => array());
		$a['n']++;
		foreach (FLEET_SAMPLES_COLS as $c) {
			if ($r[$c] !== null) {
				$a['sum'][$c] = ($a['sum'][$c] ?? 0) + (float)$r[$c];
				$a['cnt'][$c] = ($a['cnt'][$c] ?? 0) + 1;
			}
		}
		if ($r['cpu'] !== null) {
			$a['cpu_max'] = max($a['cpu_max'] ?? 0, (float)$r['cpu']);
		}
		$acc[$k] = $a;
	}
	$out = array();
	foreach ($acc as $a) {
		$row = array('node_id' => $a['node_id'], 'time' => $a['time'], 'n' => $a['n'], 'cpu_max' => $a['cpu_max']);
		foreach (FLEET_SAMPLES_COLS as $c) {
			$row[$c] = isset($a['cnt'][$c]) ? round($a['sum'][$c] / $a['cnt'][$c], 1) : null;
		}
		$out[] = $row;
	}
	return $out;
}

/* Sample the firewalls that are due, within the time budget. Returns how many were sampled. */
function fleet_samples_tick(int $now): int {
	$last = array();
	foreach (fleet_db()->query('SELECT node_id, MAX(time) AS t FROM samples GROUP BY node_id')->fetchAll() as $r) {
		$last[$r['node_id']] = (int)$r['t'];
	}
	$start = microtime(true);
	$n = 0;
	foreach (fleet_db()->query("SELECT * FROM boxes WHERE state = 'online' ORDER BY host_no")->fetchAll() as $box) {
		if ((microtime(true) - $start) > FLEET_SAMPLES_BUDGET) {
			break;
		}
		$st = json_decode((string)$box['status'], true) ?: array();
		if (((int)($st['api_level'] ?? 0) < FLEET_SAMPLES_LEVEL) || (($now - ($last[$box['node_id']] ?? 0)) < FLEET_SAMPLES_EVERY - 20)) {
			continue;
		}
		$get = function (string $path) use ($box) {
			try {
				list($code, $json) = fleet_box_call($box, 'GET', $path);
				return ($code === 200) ? (array)($json['data'] ?? array()) : null;
			} catch (Throwable $e) {
				return null;
			}
		};
		$sys = $get('/api/v1/status/system');
		if ($sys === null) {
			continue;
		}
		$s = fleet_samples_from($sys, $get('/api/v1/status/system/history?range=10m'), $get('/api/v1/status/traffic/history?if=wan&range=10m'));
		fleet_db()->prepare('INSERT INTO samples (node_id, time, cpu, mem, states, states_max, temp, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
		    ->execute(array($box['node_id'], $now, $s['cpu'], $s['mem'], $s['states'], $s['states_max'], $s['temp'], $s['rx_bps'], $s['tx_bps']));
		$n++;
	}
	return $n;
}

/* Once an hour: fold five-minute rows older than 48 hours into hourly rows; drop hourly rows older than 30 days. */
function fleet_samples_rollup(int $now): void {
	if (($now - (int)fleet_setting('samples_rolled', '0')) < 3600) {
		return;
	}
	fleet_setting_set('samples_rolled', (string)$now);
	$cut = intdiv($now - FLEET_SAMPLES_DETAIL, 3600) * 3600;
	$db = fleet_db();
	$q = $db->prepare('SELECT * FROM samples WHERE time < ?');
	$q->execute(array($cut));
	$rows = $q->fetchAll();
	$q->closeCursor();
	$db->exec('BEGIN IMMEDIATE');
	$ins = $db->prepare('INSERT INTO samples_hourly (node_id, time, n, cpu, cpu_max, mem, states, states_max, temp, rx_bps, tx_bps) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	foreach (fleet_samples_hourly($rows) as $h) {
		$ins->execute(array($h['node_id'], $h['time'], $h['n'], $h['cpu'], $h['cpu_max'], $h['mem'], $h['states'], $h['states_max'], $h['temp'], $h['rx_bps'], $h['tx_bps']));
	}
	$db->prepare('DELETE FROM samples WHERE time < ?')->execute(array($cut));
	$db->prepare('DELETE FROM samples_hourly WHERE time < ?')->execute(array($now - FLEET_SAMPLES_KEEP));
	$db->exec('COMMIT');
}

/*
 * The samples between $from and $to for some firewalls (null = all):
 * five-minute rows where they exist, hourly rows before that. Each row
 * {node_id, time, cpu, cpu_max, mem, states, states_max, temp, rx_bps, tx_bps}.
 */
function fleet_samples_rows(?array $nodes, int $from, int $to): array {
	$in = ($nodes === null) ? '' : (empty($nodes) ? ' AND 0' : ' AND node_id IN (' . implode(',', array_fill(0, count($nodes), '?')) . ')');
	$args = array_merge(array($from, $to), $nodes ?? array());
	$q = fleet_db()->prepare('SELECT node_id, time, cpu, cpu AS cpu_max, mem, states, states_max, temp, rx_bps, tx_bps FROM samples WHERE time >= ? AND time <= ?' . $in .
	    ' UNION ALL SELECT node_id, time, cpu, cpu_max, mem, states, states_max, temp, rx_bps, tx_bps FROM samples_hourly WHERE time >= ? AND time <= ?' . $in . ' ORDER BY time');
	$q->execute(array_merge($args, $args));
	return $q->fetchAll(PDO::FETCH_ASSOC);
}
