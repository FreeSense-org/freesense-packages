<?php
/*
 * fleet_stats.inc
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
 * Fleet availability. Every state change of a firewall is kept in
 * state_log (the poll writes it; the schema migration fills it from the
 * audit log), and the dashboard works out from it, per firewall and for
 * the fleet: availability (online or degraded counts as up), outages
 * (offline periods), the longest one, and how many firewalls were up over
 * time.
 */

require_once('fleet/fleet_store.inc');

define('FLEET_STATS_RANGES', array('24h' => 86400, '7d' => 604800, '30d' => 2592000));
/* State changes kept, at most this long. */
define('FLEET_STATS_KEEP', 90 * 86400);

/* ------------------------------------------------------------------ */
/* Pure                                                                */
/* ------------------------------------------------------------------ */

/* pure: does a state count as up? */
function fleet_stats_up(?string $state): bool {
	return in_array($state, array('online', 'degraded'), true);
}

/*
 * pure: one firewall over [$from, $to). $before: its state at $from (or
 * null when it was not in the fleet yet); $log: [time, state] changes in
 * the range, oldest first. Returns up seconds, known seconds (time it was
 * in the fleet), and outages as [start, end].
 */
function fleet_stats_box(?string $before, array $log, int $from, int $to): array {
	$up = 0;
	$known = 0;
	$outages = array();
	$state = $before;
	$t = $from;
	$down_since = (($state !== null) && !fleet_stats_up($state)) ? $from : null;
	foreach (array_merge($log, array(array($to, null))) as list($when, $next)) {
		$when = max($from, min($to, (int)$when));
		if ($state !== null) {
			$known += $when - $t;
			if (fleet_stats_up($state)) {
				$up += $when - $t;
			}
		}
		if ($next === null) {
			break;
		}
		if (($state === null || fleet_stats_up($state)) && !fleet_stats_up($next)) {
			$down_since = $when;
		} elseif (($down_since !== null) && fleet_stats_up($next)) {
			$outages[] = array($down_since, $when);
			$down_since = null;
		}
		$state = $next;
		$t = $when;
	}
	if ($down_since !== null) {
		$outages[] = array($down_since, $to);
	}
	return array('up' => $up, 'known' => $known, 'outages' => $outages);
}

/* pure: availability as a percentage with one decimal, or null when nothing is known. */
function fleet_stats_percent(int $up, int $known): ?float {
	return ($known > 0) ? floor(1000 * $up / $known) / 10 : null;
}

/*
 * pure: how many firewalls were up in each of $n buckets of [$from, $to).
 * $boxes: node => array(before, log). A bucket counts a firewall as up
 * when it was up for most of it.
 */
function fleet_stats_timeline(array $boxes, int $from, int $to, int $n): array {
	$size = max(1, intdiv($to - $from, $n));
	$out = array_fill(0, $n, 0);
	$in = array_fill(0, $n, 0);
	foreach ($boxes as list($before, $log)) {
		for ($i = 0; $i < $n; $i++) {
			$a = $from + $i * $size;
			$b = $a + $size;
			$st = $before;
			foreach ($log as list($when, $s)) {
				if ($when < $a) {
					$st = $s;
				}
			}
			$inside = array_values(array_filter($log, function ($x) use ($a, $b) { return ($x[0] >= $a) && ($x[0] < $b); }));
			$r = fleet_stats_box($st, $inside, $a, $b);
			if ($r['known'] * 2 >= $size) {
				$in[$i]++;
			}
			if (($r['known'] > 0) && ($r['up'] * 2 >= $r['known'])) {
				$out[$i]++;
			}
		}
	}
	return array('size' => $size, 'up' => $out, 'in' => $in);
}

/* pure: the parts of one audit "state" line: array(node id, from, to), or null. */
function fleet_stats_audit_line(string $detail): ?array {
	return preg_match('/^(\S+) \(.*\): ([a-z]+) -> ([a-z]+)/', $detail, $m) ? array($m[1], $m[2], $m[3]) : null;
}

/*
 * pure: the timeline as an SVG area chart (firewalls up out of $total),
 * $w x $h, with the time labels from $label(time).
 */
function fleet_stats_svg(array $tl, int $total, int $from, int $w, int $h, callable $label, string $title): string {
	$n = count($tl['up']);
	if (($n < 2) || ($total < 1)) {
		return '';
	}
	$l = 34;
	$b = 20;
	$x = function ($i) use ($n, $w, $l) { return round($l + ($w - $l - 6) * $i / ($n - 1), 1); };
	$y = function ($v) use ($total, $h, $b) { return round(6 + ($h - 6 - $b) * (1 - $v / $total), 1); };
	$pts = array();
	foreach ($tl['up'] as $i => $v) {
		$pts[] = $x($i) . ',' . $y($v);
	}
	$svg = '<svg class="fs-fleet-chart" width="' . $w . '" height="' . $h . '" viewBox="0 0 ' . $w . ' ' . $h . '" role="img" aria-label="' . htmlspecialchars($title) . '">';
	foreach (array(0, $total) as $g) {
		$svg .= '<line class="fs-fleet-chart-grid" x1="' . $l . '" x2="' . ($w - 6) . '" y1="' . $y($g) . '" y2="' . $y($g) . '"/>' .
		    '<text class="fs-fleet-chart-axis" x="' . ($l - 6) . '" y="' . ($y($g) + 4) . '" text-anchor="end">' . $g . '</text>';
	}
	foreach (array(0 => 'start', intdiv($n - 1, 2) => 'middle', $n - 1 => 'end') as $i => $anchor) {
		$svg .= '<text class="fs-fleet-chart-axis" x="' . $x($i) . '" y="' . ($h - 5) . '" text-anchor="' . $anchor . '">' . htmlspecialchars($label($from + $i * $tl['size'])) . '</text>';
	}
	$svg .= '<polygon class="fs-fleet-chart-area" points="' . $x(0) . ',' . $y(0) . ' ' . implode(' ', $pts) . ' ' . $x($n - 1) . ',' . $y(0) . '"/>';
	$svg .= '<polyline class="fs-fleet-chart-line fs-fleet-chart-s1" points="' . implode(' ', $pts) . '"/>';
	/* How many were in the fleet then: a gap below it is an outage, not a firewall that had not joined yet. */
	$ins = array();
	foreach (($tl['in'] ?? array()) as $i => $v) {
		$ins[] = $x($i) . ',' . $y($v);
	}
	if (!empty($ins)) {
		$svg .= '<polyline class="fs-fleet-chart-line fs-fleet-chart-in" points="' . implode(' ', $ins) . '"/>';
	}
	return $svg . '</svg>';
}

/* ------------------------------------------------------------------ */
/* Store                                                               */
/* ------------------------------------------------------------------ */

/* The poll: a firewall changed state. */
function fleet_stats_record(string $node, string $state, int $now): void {
	try {
		fleet_db()->prepare('INSERT INTO state_log (node_id, time, state) VALUES (?, ?, ?)')->execute(array($node, $now, $state));
	} catch (PDOException $e) {
		/* Availability is a report: it never stops the poll. The minute tick repairs it. */
	}
}

/* Fill state_log from the audit log (the schema migration, once). */
function fleet_stats_backfill(PDO $db): void {
	$ins = $db->prepare('INSERT INTO state_log (node_id, time, state) VALUES (?, ?, ?)');
	$seen = array();
	foreach ($db->query("SELECT time, detail FROM audit WHERE who = 'poll' AND action = 'state' ORDER BY id")->fetchAll() as $a) {
		$p = fleet_stats_audit_line((string)$a['detail']);
		if ($p === null) {
			continue;
		}
		if (!isset($seen[$p[0]])) {
			/* Its state before the first change, from just before it. */
			$ins->execute(array($p[0], (int)$a['time'] - 1, $p[1]));
			$seen[$p[0]] = true;
		}
		$ins->execute(array($p[0], (int)$a['time'], $p[2]));
	}
	/* Firewalls that never changed state: their state since they joined. */
	foreach ($db->query('SELECT node_id, joined, state FROM boxes')->fetchAll() as $b) {
		if (!isset($seen[$b['node_id']])) {
			$ins->execute(array($b['node_id'], (int)$b['joined'], (string)$b['state']));
		}
	}
}

/*
 * The fleet's availability over a range: per firewall (label, percent,
 * outages, longest, last outage) and for the fleet, plus the timeline.
 * $nodes: limit to these (a group), or null for all.
 */
function fleet_stats(string $range, ?array $nodes = null, int $points = 48): array {
	$to = time();
	$from = $to - (FLEET_STATS_RANGES[$range] ?? 604800);
	$boxes = fleet_db()->query('SELECT node_id, label, joined FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
	if ($nodes !== null) {
		$boxes = array_values(array_filter($boxes, function ($b) use ($nodes) { return in_array($b['node_id'], $nodes, true); }));
	}
	$before = fleet_db()->prepare('SELECT state FROM state_log WHERE node_id = ? AND time < ? ORDER BY time DESC, id DESC LIMIT 1');
	$inside = fleet_db()->prepare('SELECT time, state FROM state_log WHERE node_id = ? AND time >= ? AND time < ? ORDER BY time, id');
	$rows = array();
	$all = array();
	$up = 0;
	$known = 0;
	$outages = 0;
	foreach ($boxes as $b) {
		$before->execute(array($b['node_id'], $from));
		$st = $before->fetchColumn();
		$inside->execute(array($b['node_id'], $from, $to));
		$log = array_map(function ($r) { return array((int)$r['time'], (string)$r['state']); }, $inside->fetchAll());
		$r = fleet_stats_box(($st === false) ? null : (string)$st, $log, $from, $to);
		$all[$b['node_id']] = array(($st === false) ? null : (string)$st, $log);
		$longest = 0;
		foreach ($r['outages'] as list($a, $z)) {
			$longest = max($longest, $z - $a);
		}
		$rows[] = array('node' => $b['node_id'], 'label' => $b['label'], 'percent' => fleet_stats_percent($r['up'], $r['known']),
		    'outages' => count($r['outages']), 'longest' => $longest, 'down_now' => !empty($r['outages']) && (end($r['outages'])[1] === $to),
		    'last' => empty($r['outages']) ? null : end($r['outages'])[0]);
		$up += $r['up'];
		$known += $r['known'];
		$outages += count($r['outages']);
	}
	return array('range' => $range, 'from' => $from, 'to' => $to, 'percent' => fleet_stats_percent($up, $known), 'outages' => $outages,
	    'longest' => empty($rows) ? 0 : max(array_column($rows, 'longest')), 'boxes' => $rows, 'total' => count($boxes),
	    'timeline' => fleet_stats_timeline($all, $from, $to, $points));
}

/* The minute poll: record any firewall whose state differs from its last logged one, and drop old changes. */
function fleet_stats_prune(int $now): void {
	foreach (fleet_db()->query('SELECT node_id, state FROM boxes b WHERE state IS NOT (SELECT s.state FROM state_log s WHERE s.node_id = b.node_id ORDER BY s.time DESC, s.id DESC LIMIT 1)')->fetchAll() as $b) {
		fleet_stats_record((string)$b['node_id'], (string)$b['state'], $now);
	}
	/* Each firewall keeps its last change before the cut: its state when the kept time starts. */
	fleet_db()->prepare('DELETE FROM state_log WHERE time < ? AND id NOT IN (SELECT MAX(id) FROM state_log WHERE time < ? GROUP BY node_id)')
	    ->execute(array($now - FLEET_STATS_KEEP, $now - FLEET_STATS_KEEP));
}
