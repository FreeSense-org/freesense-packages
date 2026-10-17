<?php
/*
 * fleet_trends.inc
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
 * What the dashboard charts show: the fleet pulse (each firewall's state
 * per half hour), load from the samples (fleet_samples.inc), outages,
 * alerts, operations and backups per day, versions and compliance. The
 * data is gathered here and drawn by assets/fleet-charts.js.
 */

/* Buckets per range: the step of the charts. */
define('FLEET_TRENDS_POINTS', array('24h' => 96, '7d' => 84, '30d' => 90));
define('FLEET_TRENDS_RANK', array('offline' => 4, 'degraded' => 3, 'new' => 2, 'online' => 1));

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/*
 * pure: one firewall's state in each of $n buckets of $size from $from:
 * the worst state it had in the bucket, or null before it joined.
 * $before: its state at $from (null if not in the fleet yet); $log:
 * [time, state] changes, oldest first.
 */
function fleet_trends_cells(?string $before, array $log, int $from, int $size, int $n): array {
	$out = array();
	$st = $before;
	$k = 0;
	for ($i = 0; $i < $n; $i++) {
		$end = $from + ($i + 1) * $size;
		$seen = ($st === null) ? array() : array($st);
		while (($k < count($log)) && ($log[$k][0] < $end)) {
			$st = $log[$k][1];
			$seen[] = $st;
			$k++;
		}
		$worst = null;
		foreach ($seen as $s) {
			if (($worst === null) || ((FLEET_TRENDS_RANK[$s] ?? 0) > (FLEET_TRENDS_RANK[$worst] ?? 0))) {
				$worst = $s;
			}
		}
		$out[] = $worst;
	}
	return $out;
}

/* pure: how bad a row of cells was (for sorting: offline cells weigh most). */
function fleet_trends_badness(array $cells): int {
	$w = array('offline' => 100, 'degraded' => 10);
	$s = 0;
	foreach ($cells as $c) {
		$s += $w[(string)$c] ?? 0;
	}
	return $s;
}

/* pure: day labels (local Y-m-d) for $days days ending today at $now. */
function fleet_trends_days(int $now, int $days): array {
	$out = array();
	for ($i = $days - 1; $i >= 0; $i--) {
		$out[] = date('Y-m-d', $now - $i * 86400);
	}
	return $out;
}

/* pure: counts per day of $times (each [time, kind]) for $days, one series per kind in $kinds. */
function fleet_trends_per_day(array $items, array $days, array $kinds): array {
	$idx = array_flip($days);
	$out = array_fill_keys($kinds, array_fill(0, count($days), 0));
	foreach ($items as list($t, $kind)) {
		$d = date('Y-m-d', (int)$t);
		if (isset($idx[$d], $out[$kind])) {
			$out[$kind][$idx[$d]]++;
		}
	}
	return $out;
}

/* pure: the q-quantile (0..1) of numbers, or null. */
function fleet_trends_quantile(array $v, float $q): ?float {
	$v = array_values(array_filter($v, function ($x) { return $x !== null; }));
	if (empty($v)) {
		return null;
	}
	sort($v);
	$pos = ($q * (count($v) - 1));
	$lo = (int)floor($pos);
	$hi = (int)ceil($pos);
	return round($v[$lo] + ($v[$hi] - $v[$lo]) * ($pos - $lo), 1);
}

/*
 * pure: the samples in $n buckets of $size from $from: per bucket and
 * firewall the average of each column. Returns node => col => [values].
 */
function fleet_trends_buckets(array $rows, int $from, int $size, int $n): array {
	$acc = array();
	foreach ($rows as $r) {
		$i = intdiv((int)$r['time'] - $from, $size);
		if (($i < 0) || ($i >= $n)) {
			continue;
		}
		foreach (array('cpu', 'cpu_max', 'mem', 'states', 'states_max', 'temp', 'rx_bps', 'tx_bps') as $c) {
			if ($r[$c] !== null) {
				$acc[$r['node_id']][$c][$i][] = (float)$r[$c];
			}
		}
	}
	$out = array();
	foreach ($acc as $node => $cols) {
		foreach ($cols as $c => $byi) {
			$out[$node][$c] = array_fill(0, $n, null);
			foreach ($byi as $i => $vals) {
				$out[$node][$c][$i] = ($c === 'cpu_max') ? max($vals) : array_sum($vals) / count($vals);
			}
		}
	}
	return $out;
}

/*
 * pure: the fleet's load per bucket from fleet_trends_buckets(): CPU and
 * memory median and 90th percentile across firewalls, WAN traffic summed.
 */
function fleet_trends_load(array $buckets, int $n): array {
	$out = array('cpu_med' => array(), 'cpu_p90' => array(), 'mem_med' => array(), 'mem_p90' => array(), 'rx' => array(), 'tx' => array());
	for ($i = 0; $i < $n; $i++) {
		$col = function (string $c) use ($buckets, $i) {
			return array_values(array_filter(array_map(function ($b) use ($c, $i) { return $b[$c][$i] ?? null; }, $buckets), function ($x) { return $x !== null; }));
		};
		$cpu = $col('cpu');
		$mem = $col('mem');
		$rx = $col('rx_bps');
		$tx = $col('tx_bps');
		$out['cpu_med'][] = fleet_trends_quantile($cpu, .5);
		$out['cpu_p90'][] = fleet_trends_quantile($cpu, .9);
		$out['mem_med'][] = fleet_trends_quantile($mem, .5);
		$out['mem_p90'][] = fleet_trends_quantile($mem, .9);
		$out['rx'][] = empty($rx) ? null : round(array_sum($rx));
		$out['tx'][] = empty($tx) ? null : round(array_sum($tx));
	}
	return $out;
}

/*
 * pure: the $k firewalls with the highest peak of $metric(node buckets)
 * as series [label, node, data]; $metric returns the per-bucket values.
 */
function fleet_trends_top(array $buckets, array $labels, callable $metric, int $k): array {
	$all = array();
	foreach ($buckets as $node => $b) {
		$data = $metric($b);
		$vals = array_filter($data, function ($x) { return $x !== null; });
		if (!empty($vals)) {
			$all[] = array('label' => $labels[$node] ?? $node, 'node' => $node, 'peak' => max($vals), 'data' => array_map(function ($x) {
				return ($x === null) ? null : round($x, 1);
			}, $data));
		}
	}
	usort($all, function ($a, $b) { return $b['peak'] <=> $a['peak']; });
	return array_slice($all, 0, $k);
}

/* pure: firewalls per System version, most first. */
function fleet_trends_versions(array $statuses): array {
	$c = array();
	foreach ($statuses as $st) {
		$v = trim((string)($st['version'] ?? ''));
		$c[($v === '') ? 'Unknown' : $v] = ($c[($v === '') ? 'Unknown' : $v] ?? 0) + 1;
	}
	arsort($c);
	$out = array();
	foreach ($c as $v => $n) {
		$out[] = array('label' => $v, 'value' => $n);
	}
	return $out;
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

/* pure: group ids from one id (0 = all) or a list of ids (empty = all). */
function fleet_trends_group_ids(int|array $group): array {
	$ids = is_array($group) ? $group : array($group);
	return array_values(array_unique(array_filter(array_map('intval', $ids), function ($g) { return $g > 0; })));
}

/* pure: the boxes in any of these groups ($by: fleet_groups_by_box()); all of them for no groups. */
function fleet_trends_in_groups(array $boxes, array $by, array $groups): array {
	if (empty($groups)) {
		return $boxes;
	}
	return array_values(array_filter($boxes, function ($b) use ($by, $groups) {
		return !empty(array_intersect($groups, array_column($by[$b['node_id']] ?? array(), 'id')));
	}));
}

/* The firewalls (node_id, label, joined, status) of one group or several (0 or none: all). */
function fleet_trends_boxes(int|array $group): array {
	$boxes = fleet_db()->query('SELECT node_id, label, state, status FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	$ids = fleet_trends_group_ids($group);
	return empty($ids) ? $boxes : fleet_trends_in_groups($boxes, fleet_groups_by_box(), $ids);
}

/* Each firewall's state changes over [$from, $to): node => array(before, log). */
function fleet_trends_logs(array $boxes, int $from, int $to): array {
	$before = fleet_db()->prepare('SELECT state FROM state_log WHERE node_id = ? AND time < ? ORDER BY time DESC, id DESC LIMIT 1');
	$inside = fleet_db()->prepare('SELECT time, state FROM state_log WHERE node_id = ? AND time >= ? AND time < ? ORDER BY time, id');
	$out = array();
	foreach ($boxes as $b) {
		$before->execute(array($b['node_id'], $from));
		$st = $before->fetchColumn();
		$before->closeCursor();
		$inside->execute(array($b['node_id'], $from, $to));
		$out[$b['node_id']] = array(($st === false) ? null : (string)$st, array_map(function ($r) { return array((int)$r['time'], (string)$r['state']); }, $inside->fetchAll()));
	}
	return $out;
}

/*
 * The fleet pulse: the last 24 hours in half hours, one row per firewall,
 * worst first. {t, rows: [{label, link, node, cells, bad}], healthy}.
 */
function fleet_trends_pulse(int|array $group, int $now): array {
	$n = 48;
	$size = 1800;
	$to = intdiv($now, $size) * $size + $size;
	$from = $to - $n * $size;
	$boxes = fleet_trends_boxes($group);
	$logs = fleet_trends_logs($boxes, $from, $to);
	$rows = array();
	foreach ($boxes as $b) {
		list($before, $log) = $logs[$b['node_id']];
		$cells = fleet_trends_cells($before, $log, $from, $size, $n);
		/* The current half hour shows the state now. */
		$cells[$n - 1] = $cells[$n - 1] ?? $b['state'];
		$rows[] = array('label' => $b['label'], 'node' => $b['node_id'], 'link' => '/fleet/fleet_box.php?id=' . urlencode($b['node_id']), 'cells' => $cells,
		    'bad' => fleet_trends_badness($cells) + ((FLEET_TRENDS_RANK[$b['state']] ?? 1) - 1) * 1000);
	}
	usort($rows, function ($a, $b) { return array($b['bad'], strtolower($a['label'])) <=> array($a['bad'], strtolower($b['label'])); });
	$t = array();
	for ($i = 0; $i < $n; $i++) {
		$t[] = $from + $i * $size;
	}
	return array('t' => $t, 'rows' => $rows, 'healthy' => count(array_filter($rows, function ($r) { return $r['bad'] === 0; })));
}

/* Everything the Trends view draws for a range (24h, 7d, 30d) and a group (0 = all). */
function fleet_trends(string $range, int|array $group, int $now): array {
	$span = FLEET_STATS_RANGES[$range] ?? 86400;
	$n = FLEET_TRENDS_POINTS[$range] ?? 96;
	$size = max(300, intdiv($span, $n));
	$from = $now - $n * $size;
	$boxes = fleet_trends_boxes($group);
	$grouped = !empty(fleet_trends_group_ids($group));
	$nodes = array_column($boxes, 'node_id');
	$labels = array_column($boxes, 'label', 'node_id');
	$t = array();
	for ($i = 0; $i < $n; $i++) {
		$t[] = $from + $i * $size;
	}
	$out = array('range' => $range, 'from' => $from, 'to' => $now, 't' => $t, 'total' => count($boxes));

	/* Availability over time (as on the availability panel). */
	$logs = fleet_trends_logs($boxes, $from, $now);
	$tl = fleet_stats_timeline($logs, $from, $now, min($n, 96));
	$out['up'] = array('t' => array_map(function ($i) use ($from, $tl) { return $from + $i * $tl['size']; }, array_keys($tl['up'])), 'up' => $tl['up'], 'in' => $tl['in']);

	/* Per day: outages, alerts, operations, backups. */
	$days = fleet_trends_days($now, ($range === '24h') ? 7 : intdiv($span, 86400));
	$dfrom = strtotime($days[0] . ' 00:00:00');
	$outs = array();
	foreach ($logs as $node => list($before, $log)) {
		foreach (fleet_stats_box($before, $log, $from, $now)['outages'] as list($a)) {
			$outs[] = array($a, 'outages');
		}
	}
	/* Outages per day need the whole day range, not only the chart range. */
	if ($dfrom < $from) {
		foreach (fleet_trends_logs($boxes, $dfrom, $from) as list($before, $log)) {
			foreach (fleet_stats_box($before, $log, $dfrom, $from)['outages'] as list($a)) {
				$outs[] = array($a, 'outages');
			}
		}
	}
	$out['days'] = $days;
	$out['outages_day'] = fleet_trends_per_day($outs, $days, array('outages'))['outages'];
	$in = empty($nodes) ? '' : implode(',', array_map(array(fleet_db(), 'quote'), $nodes));
	$q = fleet_db()->prepare('SELECT time, severity FROM alerts WHERE time >= ?' . ($grouped ? " AND node_id IN ({$in})" : ''));
	$q->execute(array($dfrom));
	$out['alerts_day'] = fleet_trends_per_day(array_map(function ($r) { return array($r['time'], $r['severity']); }, ($grouped && $in === '') ? array() : $q->fetchAll()),
	    $days, array('critical', 'warning', 'info'));
	$q = fleet_db()->prepare('SELECT started, kind, state FROM ops WHERE parent IS NULL AND started >= ?');
	$q->execute(array($dfrom));
	$ops = $q->fetchAll();
	$out['ops_day'] = fleet_trends_per_day(array_map(function ($r) { return array($r['started'], ($r['state'] === 'failed') ? 'failed' : (($r['state'] === 'done') ? 'done' : 'other')); }, $ops),
	    $days, array('done', 'failed'));
	$q = fleet_db()->prepare('SELECT time FROM backups WHERE time >= ?' . ($grouped ? " AND node_id IN ({$in})" : ''));
	$q->execute(array($dfrom));
	$bk = fleet_trends_per_day(array_map(function ($r) { return array($r['time'], 'ok'); }, ($grouped && $in === '') ? array() : $q->fetchAll()), $days, array('ok'));
	$bf = fleet_trends_per_day(array_map(function ($r) { return array($r['started'], 'failed'); }, array_filter($ops, function ($r) {
		return (strpos((string)$r['kind'], 'backup') === 0) && ($r['state'] === 'failed');
	})), $days, array('failed'));
	$out['backups_day'] = array('ok' => $bk['ok'], 'failed' => $bf['failed']);

	/* Load from the samples. */
	$b = fleet_trends_buckets(fleet_samples_rows($grouped ? $nodes : null, $from, $now), $from, $size, $n);
	$b = array_intersect_key($b, array_flip($nodes));
	$out['load'] = fleet_trends_load($b, $n);
	$out['sampled'] = count($b);
	$heat = fleet_trends_top($b, $labels, function ($x) use ($n) { return $x['cpu'] ?? array_fill(0, $n, null); }, 15);
	usort($heat, function ($a, $c) { return strcasecmp($a['label'], $c['label']); });
	$out['heat'] = $heat;
	$out['states_top'] = fleet_trends_top($b, $labels, function ($x) use ($n) {
		$o = array();
		for ($i = 0; $i < $n; $i++) {
			$s = $x['states'][$i] ?? null;
			$m = $x['states_max'][$i] ?? null;
			$o[] = (($s !== null) && ($m > 0)) ? 100 * $s / $m : null;
		}
		return $o;
	}, 5);
	$out['temp_top'] = fleet_trends_top($b, $labels, function ($x) use ($n) { return $x['temp'] ?? array_fill(0, $n, null); }, 5);
	$busy = fleet_trends_top($b, $labels, function ($x) use ($n) { return $x['cpu'] ?? array_fill(0, $n, null); }, 10);
	$out['busiest'] = array_map(function ($r) use ($b, $n) {
		$cur = function ($a) { foreach (array_reverse($a) as $v) { if ($v !== null) { return round($v, 1); } } return null; };
		$mem = $b[$r['node']]['mem'] ?? array_fill(0, $n, null);
		$st = $b[$r['node']]['states'] ?? array_fill(0, $n, null);
		return array('label' => $r['label'], 'node' => $r['node'], 'link' => '/fleet/fleet_box.php?id=' . urlencode($r['node']) . '&view=stats', 'cpu' => $r['data'], 'mem' => array_map(function ($v) {
			return ($v === null) ? null : round($v, 1);
		}, $mem), 'states' => $st, 'cpu_now' => $cur($r['data']), 'mem_now' => $cur($mem), 'peak' => round($r['peak'], 1));
	}, $busy);

	/* Now: versions and policy compliance. */
	$out['versions'] = fleet_trends_versions(array_map(function ($x) { return json_decode((string)$x['status'], true) ?: array(); }, $boxes));
	$cc = array('pass' => 0, 'fail' => 0, 'unknown' => 0);
	foreach (array_intersect_key(fleet_compliance_counts(), array_flip($nodes)) as $c) {
		foreach ($cc as $k => $v) {
			$cc[$k] += (int)($c[$k] ?? 0);
		}
	}
	$out['compliance'] = $cc;
	return $out;
}

/*
 * One firewall's stats kept on the controller, for its Stats view over a
 * range (1h, 24h, 7d, 30d): availability for 24 hours, 7 and 30 days, its
 * last 30 days by day, outages, load samples (states, temperature),
 * alerts and backups.
 */
function fleet_trends_box(string $node, string $range, int $now): array {
	$span = array('1h' => 3600, '24h' => 86400, '7d' => 604800, '30d' => 2592000)[$range] ?? 86400;
	$out = array('range' => $range);
	foreach (FLEET_STATS_RANGES as $rk => $sec) {
		$out['avail'][$rk] = fleet_stats($rk, array($node), 2)['percent'];
	}
	$dto = strtotime(date('Y-m-d', $now) . ' 00:00:00') + 86400;
	list($before, $log) = fleet_trends_logs(array(array('node_id' => $node)), $dto - 30 * 86400, $dto)[$node];
	$out['days'] = fleet_trends_days($now, 30);
	$out['day_cells'] = fleet_trends_cells($before, $log, $dto - 30 * 86400, 86400, 30);
	$out['outages'] = array_reverse(array_map(function ($o) { return array('from' => $o[0], 'to' => $o[1]); },
	    fleet_stats_box($before, $log, $dto - 30 * 86400, min($dto, $now))['outages']));
	$n = ($range === '1h') ? 12 : 96;
	$size = max(300, intdiv($span, $n));
	$from = $now - $n * $size;
	$b = fleet_trends_buckets(fleet_samples_rows(array($node), $from, $now), $from, $size, $n)[$node] ?? array();
	$out['t'] = array_map(function ($i) use ($from, $size) { return $from + $i * $size; }, range(0, $n - 1));
	$out['states'] = $b['states'] ?? array_fill(0, $n, null);
	$out['states_max'] = max(array_merge(array(0), array_filter($b['states_max'] ?? array())));
	$out['temp'] = $b['temp'] ?? array_fill(0, $n, null);
	$q = fleet_db()->prepare('SELECT time, event, severity, repeats FROM alerts WHERE node_id = ? AND time >= ? ORDER BY time DESC');
	$q->execute(array($node, $now - 30 * 86400));
	$alerts = $q->fetchAll(PDO::FETCH_ASSOC);
	$out['alerts_day'] = fleet_trends_per_day(array_map(function ($r) { return array($r['time'], $r['severity']); }, $alerts), $out['days'], array('critical', 'warning', 'info'));
	$out['alerts'] = array_slice($alerts, 0, 8);
	$q = fleet_db()->prepare('SELECT time FROM backups WHERE node_id = ? AND time >= ?');
	$q->execute(array($node, $now - 30 * 86400));
	$out['backups_day'] = fleet_trends_per_day(array_map(function ($r) { return array($r['time'], 'ok'); }, $q->fetchAll()), $out['days'], array('ok'))['ok'];
	return $out;
}
