<?php
/*
 * fleet_inet.inc
 *
 * part of FreeSense (https://www.freesense.org)
 * Copyright (c) 2025-2026 The FreeSense Project
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
 * Internet connectivity (an option under Settings > Monitoring): every
 * firewall already measures its gateways (dpinger: latency, jitter,
 * loss). When the option is on, the controller reads them with the load
 * samples, keeps five-minute rows for 48 hours and hourly rows for 30
 * days, works out whether each firewall's internet is up, poor or down,
 * and raises alerts after a few bad checks in a row. Many firewalls
 * losing their internet at once is one alert (an upstream outage).
 */

define('FLEET_INET_STATES', array('up' => 'Up', 'degraded' => 'Poor', 'down' => 'Down', 'unknown' => 'Unknown'));
/* The availability charts draw internet states with the firewall states' colours. */
define('FLEET_INET_PULSE', array('up' => 'online', 'degraded' => 'degraded', 'down' => 'offline', 'unknown' => null));

/* The thresholds from the settings, for fleet_inet_classify(). */
function fleet_inet_thresholds(): array {
	return array('loss_warn' => (float)fleet_opt('inet_loss_warn'), 'loss_bad' => (float)fleet_opt('inet_loss_bad'),
	    'latency_warn' => (float)fleet_opt('inet_latency_warn'),
	    'jitter_warn' => (float)fleet_opt('inet_jitter_warn'));
}

/*
 * pure: one gateway as the firewall reports it (GET /status/gateways):
 * array(state, reason). Down: dpinger says down, or the loss reaches the
 * bad threshold. Poor: loss, latency or jitter over a warning threshold.
 * Unknown: the gateway is not monitored.
 */
function fleet_inet_classify(array $gw, array $thr): array {
	$status = strtolower((string)($gw['status'] ?? ''));
	$sub = strtolower((string)($gw['substatus'] ?? ''));
	$delay = is_numeric($gw['delay_ms'] ?? null) ? (float)$gw['delay_ms'] : null;
	$jitter = is_numeric($gw['stddev_ms'] ?? null) ? (float)$gw['stddev_ms'] : null;
	$loss = is_numeric($gw['loss_pct'] ?? null) ? (float)$gw['loss_pct'] : null;
	if (($status === 'down') || ($sub === 'down') || (($loss !== null) && ($loss >= $thr['loss_bad']))) {
		return array('down', ($loss !== null) && ($loss > 0) ? sprintf('%s%% loss', fleet_inet_num($loss)) : 'gateway down');
	}
	if (in_array($status, array('none', ''), true) && ($delay === null)) {
		return array('unknown', 'not monitored');
	}
	$why = array();
	if (($loss !== null) && ($loss >= $thr['loss_warn'])) {
		$why[] = sprintf('%s%% loss', fleet_inet_num($loss));
	}
	if (($delay !== null) && ($delay >= $thr['latency_warn'])) {
		$why[] = sprintf('%s ms latency', fleet_inet_num($delay));
	}
	if (($jitter !== null) && ($jitter >= $thr['jitter_warn'])) {
		$why[] = sprintf('%s ms jitter', fleet_inet_num($jitter));
	}
	if (in_array($sub, array('highloss', 'loss', 'highdelay', 'delay'), true) && empty($why)) {
		$why[] = ($sub === 'highloss' || $sub === 'loss') ? 'loss' : 'latency';
	}
	return empty($why) ? array('up', '') : array('degraded', implode(', ', $why));
}

/* pure: a number for a text, without needless decimals. */
function fleet_inet_num(float $v): string {
	return ($v >= 10) ? (string)round($v) : rtrim(rtrim(number_format($v, 1, '.', ''), '0'), '.');
}

/*
 * pure: a firewall's internet from its gateways, each
 * {name, iface, descr, default, state, reason, delay_ms, stddev_ms,
 * loss_pct}: the default gateway decides. With the default down and
 * another gateway up, the firewall still reaches the internet the other
 * way (poor, "default gateway down"). No default gateway: the best one.
 * Returns {state, gw, iface, reason, delay_ms, stddev_ms, loss_pct}.
 */
function fleet_inet_box_state(array $gws): array {
	$rank = array('up' => 0, 'degraded' => 1, 'down' => 2, 'unknown' => 3);
	$none = array('state' => 'unknown', 'gw' => '', 'iface' => '', 'reason' => 'no gateways', 'delay_ms' => null, 'stddev_ms' => null, 'loss_pct' => null);
	if (empty($gws)) {
		return $none;
	}
	$pick = function (array $g, string $state, string $reason) {
		return array('state' => $state, 'gw' => (string)$g['name'], 'iface' => (string)($g['iface'] ?? ''), 'reason' => $reason,
		    'delay_ms' => $g['delay_ms'] ?? null, 'stddev_ms' => $g['stddev_ms'] ?? null, 'loss_pct' => $g['loss_pct'] ?? null);
	};
	usort($gws, function ($a, $b) use ($rank) { return array($rank[$a['state']] ?? 3, (string)$a['name']) <=> array($rank[$b['state']] ?? 3, (string)$b['name']); });
	$def = array_values(array_filter($gws, function ($g) { return !empty($g['default']); }));
	if (empty($def)) {
		return $pick($gws[0], $gws[0]['state'], (string)$gws[0]['reason']);
	}
	$d = $def[0];
	if (($d['state'] === 'down') && (($gws[0]['state'] ?? '') === 'up')) {
		return $pick($gws[0], 'degraded', sprintf('default gateway %s down, %s up', $d['name'], $gws[0]['name']));
	}
	return $pick($d, $d['state'], (string)$d['reason']);
}

/*
 * pure: the next state of one firewall's internet and the alerts it
 * raises. $prev: {state, bad_count, alerted, default_gw} (empty: first
 * check); $box: fleet_inet_box_state() plus 'default_gw'. A problem is
 * told after $grace checks in a row; "back" only after a problem was
 * told. Returns array(next, events), events: array(event, text).
 */
function fleet_inet_step(array $prev, array $box, int $grace): array {
	$next = array('state' => $box['state'], 'bad_count' => (int)($prev['bad_count'] ?? 0), 'alerted' => (string)($prev['alerted'] ?? ''),
	    'default_gw' => (string)($prev['default_gw'] ?? ''));
	$events = array();
	$was_gw = (string)($prev['default_gw'] ?? '');
	$gw = (string)($box['default_gw'] ?? '');
	if (($was_gw !== '') && ($gw !== '') && ($gw !== $was_gw)) {
		$events[] = array('inet_failover', sprintf('moved from %s to %s', $was_gw, $gw));
	}
	if ($gw !== '') {
		$next['default_gw'] = $gw;
	}
	if ($box['state'] === 'unknown') {
		$next['state'] = (string)($prev['state'] ?? 'unknown');
		return array($next, $events);
	}
	if ($box['state'] === 'up') {
		$next['bad_count'] = 0;
		if ($next['alerted'] !== '') {
			$events[] = array('inet_up', 'internet works again');
			$next['alerted'] = '';
		}
		return array($next, $events);
	}
	$next['bad_count']++;
	if (($next['bad_count'] >= max(1, $grace)) && ($next['alerted'] !== $box['state'])) {
		$events[] = array(($box['state'] === 'down') ? 'inet_down' : 'inet_degraded', (string)$box['reason']);
		$next['alerted'] = $box['state'];
	}
	return array($next, $events);
}

/*
 * pure: is this an outage upstream (many firewalls without internet at
 * once)? $states: node => state. At least $min firewalls and $pct % of
 * those whose state is known.
 */
function fleet_inet_wide(array $states, int $pct, int $min = 3): bool {
	$known = count(array_filter($states, function ($s) { return $s !== 'unknown'; }));
	$down = count(array_keys($states, 'down', true));
	return ($known > 0) && ($down >= max(1, $min)) && ((100 * $down / $known) >= $pct);
}

/*
 * pure: a connection's quality, 0-100 (100: no loss, low latency and
 * jitter, steady). Loss weighs most, then flaps (the gateway changing
 * between up, poor and down), latency and jitter against the warning
 * thresholds. Null without measurements.
 */
function fleet_inet_score(?float $loss, ?float $latency, ?float $jitter, int $flaps, array $thr): ?int {
	if (($loss === null) && ($latency === null)) {
		return null;
	}
	$p = min(60.0, 4.0 * max(0.0, (float)$loss));
	$p += min(20.0, 5.0 * max(0, $flaps));
	$lw = max(1.0, (float)$thr['latency_warn']);
	$p += min(15.0, 15.0 * max(0.0, (float)$latency - 0.2 * $lw) / $lw);
	$p += min(10.0, 10.0 * max(0.0, (float)$jitter) / max(1.0, (float)$thr['jitter_warn']));
	return (int)max(0, min(100, round(100 - $p)));
}

/* pure: the score as words. */
function fleet_inet_score_word(?int $score): string {
	if ($score === null) {
		return '-';
	}
	return ($score >= 90) ? 'Excellent' : (($score >= 75) ? 'Good' : (($score >= 50) ? 'Unstable' : 'Bad'));
}

/* The score as a badge for WebUI lists: "Quality 94" coloured by its word. */
function fleet_inet_score_badge(?int $score): string {
	if ($score === null) {
		return '<span class="fs-muted">-</span>';
	}
	$tone = ($score >= 90) ? 'pass' : (($score >= 75) ? 'info' : (($score >= 50) ? 'warn' : 'block'));
	return fs_badge($tone, (string)$score, sprintf(gettext('Quality %1$d of 100: %2$s'), $score, gettext(fleet_inet_score_word($score))));
}

/* pure: how often a connection changed between up, poor and down, from its states in time order (unknown ones left out). */
function fleet_inet_flaps(array $states): int {
	$n = 0;
	$prev = null;
	foreach ($states as $s) {
		if (($s === null) || ($s === 'unknown')) {
			continue;
		}
		if (($prev !== null) && ($s !== $prev)) {
			$n++;
		}
		$prev = $s;
	}
	return $n;
}

/* pure: a connection that changes state more than $warn times an hour is unstable. */
function fleet_inet_unstable(int $flaps_hour, int $warn): bool {
	return ($warn > 0) && ($flaps_hour > $warn);
}

/* pure: how long ago, short. */
function fleet_inet_ago(int $t, int $now): string {
	$d = max(0, $now - $t);
	return ($d < 60) ? gettext('just now') : (($d < 3600) ? sprintf(gettext('%d min ago'), intdiv($d, 60)) :
	    (($d < 172800) ? sprintf(gettext('%d h ago'), intdiv($d, 3600)) : sprintf(gettext('%d days ago'), intdiv($d, 86400))));
}

/* pure: the 'Internet' text for a list: "12 ms · 0 % loss", or the reason. */
function fleet_inet_text(array $s): string {
	if (($s['state'] ?? 'unknown') === 'unknown') {
		return '-';
	}
	if (($s['state'] === 'down') || ($s['delay_ms'] === null)) {
		return (string)($s['reason'] ?? '');
	}
	return sprintf('%s ms · %s %% loss', fleet_inet_num((float)$s['delay_ms']), fleet_inet_num((float)($s['loss_pct'] ?? 0)));
}

/* ------------------------------------------------------------------ */
/* Collection (the poll's minute tick)                                 */
/* ------------------------------------------------------------------ */

function fleet_inet_enabled(): bool {
	return (bool)fleet_opt('inet_enable');
}

/* Read every online firewall's gateways when they are due, keep them, and raise alerts. Returns how many firewalls were read. */
function fleet_inet_tick(int $now): int {
	if (!fleet_inet_enabled() || (($now - (int)fleet_setting('inet_checked', '0')) < 60 * (int)fleet_opt('inet_interval') - 10)) {
		return 0;
	}
	fleet_setting_set('inet_checked', (string)$now);
	$thr = fleet_inet_thresholds();
	$all = (bool)fleet_opt('inet_all');
	$prev = array();
	foreach (fleet_db()->query('SELECT * FROM inet_state')->fetchAll() as $r) {
		$prev[$r['node_id']] = $r;
	}
	$start = microtime(true);
	$n = 0;
	$checked = array();
	$db = fleet_db();
	$ins = $db->prepare('INSERT INTO gw_samples (node_id, time, gw, iface, descr, is_default, status, state, delay_ms, stddev_ms, loss_pct) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	foreach ($db->query("SELECT * FROM boxes WHERE state = 'online' ORDER BY host_no")->fetchAll() as $box) {
		if ((microtime(true) - $start) > FLEET_SAMPLES_BUDGET) {
			break;
		}
		$st = json_decode((string)$box['status'], true) ?: array();
		if ((int)($st['api_level'] ?? 0) < FLEET_SAMPLES_LEVEL) {
			continue;
		}
		try {
			list($code, $json) = fleet_box_call($box, 'GET', '/api/v1/status/gateways');
		} catch (Throwable $e) {
			continue;
		}
		if ($code !== 200) {
			continue;
		}
		$gws = array();
		$default = '';
		foreach ((array)($json['data'] ?? array()) as $g) {
			if (!is_array($g) || (($g['name'] ?? '') === '')) {
				continue;
			}
			list($state, $reason) = fleet_inet_classify($g, $thr);
			$row = array('name' => (string)$g['name'], 'iface' => (string)($g['interface'] ?? ''), 'descr' => (string)($g['description'] ?? ''),
			    'default' => !empty($g['default']), 'state' => $state, 'reason' => $reason, 'status' => (string)($g['status'] ?? ''),
			    'delay_ms' => is_numeric($g['delay_ms'] ?? null) ? (float)$g['delay_ms'] : null, 'stddev_ms' => is_numeric($g['stddev_ms'] ?? null) ? (float)$g['stddev_ms'] : null,
			    'loss_pct' => is_numeric($g['loss_pct'] ?? null) ? (float)$g['loss_pct'] : null);
			if ($row['default'] && ($default === '')) {
				$default = $row['name'];
			}
			$gws[] = $row;
		}
		foreach ($gws as $g) {
			if ($all || $g['default'] || (count($gws) === 1)) {
				$ins->execute(array($box['node_id'], $now, $g['name'], $g['iface'], $g['descr'], $g['default'] ? 1 : 0, $g['status'], $g['state'], $g['delay_ms'], $g['stddev_ms'], $g['loss_pct']));
			}
		}
		$checked[$box['node_id']] = array('box' => $box, 'state' => fleet_inet_box_state($gws) + array('default_gw' => $default), 'gws' => $gws);
		$n++;
	}
	/* Firewalls the controller cannot reach keep their last known internet state. */
	$states = array();
	foreach ($prev as $node => $r) {
		$states[$node] = (string)$r['state'];
	}
	foreach ($checked as $node => $c) {
		if ($c['state']['state'] !== 'unknown') {
			$states[$node] = $c['state']['state'];
		}
	}
	$wide = fleet_inet_wide($states, (int)fleet_opt('inet_wide_pct'));
	$was_wide = (fleet_setting('inet_wide', '0') === '1');
	$up = $db->prepare('INSERT OR REPLACE INTO inet_state (node_id, state, since, bad_count, alerted, default_gw, gw, iface, reason, delay_ms, stddev_ms, loss_pct, gateways, checked)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	foreach ($checked as $node => $c) {
		$p = $prev[$node] ?? array();
		list($next, $events) = fleet_inet_step($p, $c['state'], (int)fleet_opt('inet_grace'));
		$since = (($p['state'] ?? '') === $next['state']) ? (int)$p['since'] : $now;
		if (($p['state'] ?? '') !== $next['state']) {
			$db->prepare('INSERT INTO inet_log (node_id, time, state) VALUES (?, ?, ?)')->execute(array($node, $now, $next['state']));
		}
		$s = $c['state'];
		$up->execute(array($node, $next['state'], $since, $next['bad_count'], $next['alerted'], $next['default_gw'], $s['gw'], $s['iface'], $s['reason'],
		    $s['delay_ms'], $s['stddev_ms'], $s['loss_pct'], json_encode($c['gws']), $now));
		foreach ($events as list($event, $text)) {
			/* An upstream outage is one alert, not one per firewall. */
			if ($wide && ($event === 'inet_down')) {
				continue;
			}
			fleet_alert($event, $node, sprintf('%s: %s', $c['box']['label'], $text));
		}
	}
	/* Unstable: the default gateway changed state too often in the last hour. */
	$warn = (int)fleet_opt('inet_flaps_warn');
	if (($warn > 0) && !empty($checked)) {
		$hour = fleet_inet_stats(3600, $now);
		foreach ($checked as $node => $c) {
			$fl = (int)($hour[$node]['flaps'] ?? 0);
			if (fleet_inet_unstable($fl, $warn)) {
				fleet_alert('inet_unstable', $node, sprintf('%s: the connection changed state %d times in the last hour', $c['box']['label'], $fl));
			}
		}
	}
	if ($wide && !$was_wide) {
		$down = count(array_keys($states, 'down', true));
		fleet_alert('inet_wide', '', sprintf('%d of %d firewalls lost their internet at the same time (an outage upstream?)', $down, count($states)));
	}
	if ($wide !== $was_wide) {
		fleet_setting_set('inet_wide', $wide ? '1' : '0');
	}
	return $n;
}

/* Once an hour: fold gateway rows older than 48 hours into hourly rows; drop hourly rows older than 30 days. */
function fleet_inet_rollup(int $now): void {
	if (($now - (int)fleet_setting('inet_rolled', '0')) < 3600) {
		return;
	}
	fleet_setting_set('inet_rolled', (string)$now);
	$cut = intdiv($now - FLEET_SAMPLES_DETAIL, 3600) * 3600;
	$db = fleet_db();
	$q = $db->prepare('SELECT * FROM gw_samples WHERE time < ? ORDER BY node_id, gw, time');
	$q->execute(array($cut));
	$hours = array();
	foreach ($q->fetchAll() as $r) {
		$k = $r['node_id'] . "\n" . $r['gw'] . "\n" . (intdiv((int)$r['time'], 3600) * 3600);
		$hours[$k][] = $r;
	}
	$db->exec('BEGIN IMMEDIATE');
	$ins = $db->prepare('INSERT INTO gw_hourly (node_id, time, gw, is_default, n, delay_ms, delay_max, stddev_ms, loss_pct, loss_max, down_n, flaps, loss_n)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
	$avg = function (array $v) { $v = array_filter($v, 'is_numeric'); return empty($v) ? null : array_sum($v) / count($v); };
	foreach ($hours as $k => $rows) {
		list($node, $gw, $t) = explode("\n", $k);
		$ins->execute(array($node, (int)$t, $gw, max(array_column($rows, 'is_default')), count($rows), $avg(array_column($rows, 'delay_ms')),
		    max(array_map('floatval', array_column($rows, 'delay_ms'))), $avg(array_column($rows, 'stddev_ms')), $avg(array_column($rows, 'loss_pct')),
		    max(array_map('floatval', array_column($rows, 'loss_pct'))), count(array_keys(array_column($rows, 'state'), 'down', true)),
		    fleet_inet_flaps(array_column($rows, 'state')), count(array_filter(array_column($rows, 'loss_pct'), function ($l) { return (float)$l > 0; }))));
	}
	$db->prepare('DELETE FROM gw_samples WHERE time < ?')->execute(array($cut));
	$db->prepare('DELETE FROM gw_hourly WHERE time < ?')->execute(array($now - FLEET_SAMPLES_KEEP));
	$db->prepare('DELETE FROM inet_log WHERE time < ?')->execute(array($now - FLEET_SAMPLES_KEEP));
	$db->exec('COMMIT');
}

/* ------------------------------------------------------------------ */
/* Reading                                                             */
/* ------------------------------------------------------------------ */

/* node id => the firewall's internet now (inet_state row with 'gateways' decoded). Only while the option is on. */
function fleet_inet_now(): array {
	if (!fleet_inet_enabled()) {
		return array();
	}
	$out = array();
	foreach (fleet_db()->query('SELECT * FROM inet_state')->fetchAll() as $r) {
		$r['gateways'] = json_decode((string)$r['gateways'], true) ?: array();
		foreach (array('delay_ms', 'stddev_ms', 'loss_pct') as $k) {
			$r[$k] = ($r[$k] === null) ? null : (float)$r[$k];
		}
		$out[$r['node_id']] = $r;
	}
	return $out;
}

/* pure: counts of firewalls per internet state. */
function fleet_inet_counts(array $now): array {
	$c = array('up' => 0, 'degraded' => 0, 'down' => 0, 'unknown' => 0);
	foreach ($now as $r) {
		$c[$r['state']] = ($c[$r['state']] ?? 0) + 1;
	}
	return $c;
}

/* pure: the median and the 90th percentile of some numbers (nulls left out), or nulls. */
function fleet_inet_med_p90(array $v): array {
	$v = array_values(array_filter($v, 'is_numeric'));
	if (empty($v)) {
		return array(null, null);
	}
	sort($v);
	$at = function (float $q) use ($v) { return round((float)$v[(int)min(count($v) - 1, floor($q * (count($v) - 1) + 0.5))], 1); };
	return array($at(0.5), $at(0.9));
}

/*
 * Fleet internet quality over a range: buckets with the median and 90th
 * percentile of latency and loss over the default gateways. $nodes: null
 * for every firewall.
 */
function fleet_inet_series(string $range, ?array $nodes, int $now): array {
	$span = FLEET_STATS_RANGES[$range] ?? 86400;
	$n = FLEET_TRENDS_POINTS[$range] ?? 96;
	$size = max(300, intdiv($span, $n));
	$from = $now - $n * $size;
	$in = ($nodes === null) ? '' : (empty($nodes) ? ' AND 0' : ' AND node_id IN (' . implode(',', array_fill(0, count($nodes), '?')) . ')');
	$args = array_merge(array($from), $nodes ?? array());
	$q = fleet_db()->prepare('SELECT time, delay_ms, loss_pct FROM gw_samples WHERE is_default = 1 AND time >= ?' . $in .
	    ' UNION ALL SELECT time, delay_ms, loss_pct FROM gw_hourly WHERE is_default = 1 AND time >= ?' . $in);
	$q->execute(array_merge($args, $args));
	$b = array();
	foreach ($q->fetchAll(PDO::FETCH_NUM) as list($t, $d, $l)) {
		$i = (int)floor(((int)$t - $from) / $size);
		if (($i >= 0) && ($i < $n)) {
			$b[$i][0][] = $d;
			$b[$i][1][] = $l;
		}
	}
	$out = array('t' => array(), 'delay' => array(), 'delay_p90' => array(), 'loss' => array(), 'loss_p90' => array());
	for ($i = 0; $i < $n; $i++) {
		$out['t'][] = $from + $i * $size;
		list($dm, $d9) = fleet_inet_med_p90($b[$i][0] ?? array());
		list($lm, $l9) = fleet_inet_med_p90($b[$i][1] ?? array());
		$out['delay'][] = $dm;
		$out['delay_p90'][] = $d9;
		$out['loss'][] = $lm;
		$out['loss_p90'][] = $l9;
	}
	return $out;
}

/* Firewalls × half hours of their internet over 24 hours (the availability chart's rows). */
function fleet_inet_pulse(array $boxes, int $now): array {
	$n = 48;
	$size = 1800;
	$to = intdiv($now, $size) * $size + $size;
	$from = $to - $n * $size;
	$cur = fleet_inet_now();
	$rows = array();
	$map = FLEET_INET_PULSE;
	foreach ($boxes as $b) {
		$q = fleet_db()->prepare('SELECT time, state FROM inet_log WHERE node_id = ? AND time < ? ORDER BY time');
		$q->execute(array($b['node_id'], $to));
		$before = null;
		$log = array();
		foreach ($q->fetchAll(PDO::FETCH_NUM) as list($t, $s)) {
			$s = $map[$s] ?? null;
			if ((int)$t < $from) {
				$before = $s;
			} elseif ($s !== null) {
				$log[] = array((int)$t, $s);
			}
		}
		if (($before === null) && empty($log) && !isset($cur[$b['node_id']])) {
			continue;
		}
		$cells = fleet_trends_cells($before, $log, $from, $size, $n);
		$cells[$n - 1] = $cells[$n - 1] ?? ($map[$cur[$b['node_id']]['state'] ?? 'unknown'] ?? null);
		$rows[] = array('label' => $b['label'], 'node' => $b['node_id'], 'link' => '/fleet/fleet_box.php?id=' . urlencode($b['node_id']), 'cells' => $cells,
		    'bad' => fleet_trends_badness($cells));
	}
	usort($rows, function ($a, $b) { return array($b['bad'], strtolower($a['label'])) <=> array($a['bad'], strtolower($b['label'])); });
	$t = array();
	for ($i = 0; $i < $n; $i++) {
		$t[] = $from + $i * $size;
	}
	return array('t' => $t, 'rows' => $rows);
}

/* node id => the share (%) of checks in the last $secs with internet (not down), or nothing without checks. */
function fleet_inet_availability(int $secs, int $now): array {
	$q = fleet_db()->prepare("SELECT node_id, SUM(n) AS n, SUM(down_n) AS down FROM (
	    SELECT node_id, 1 AS n, CASE WHEN state = 'down' THEN 1 ELSE 0 END AS down_n FROM gw_samples WHERE is_default = 1 AND time >= ?
	    UNION ALL SELECT node_id, n, down_n FROM gw_hourly WHERE is_default = 1 AND time >= ?) GROUP BY node_id");
	$q->execute(array($now - $secs, $now - $secs));
	$out = array();
	foreach ($q->fetchAll() as $r) {
		if ((int)$r['n'] > 0) {
			$out[$r['node_id']] = round(100 * (1 - (int)$r['down'] / (int)$r['n']), 1);
		}
	}
	return $out;
}

/*
 * Per firewall over the last $secs (default gateways): average loss,
 * latency and jitter, flaps, minutes with loss, checks, and the quality
 * score. node id => {loss, latency, jitter, flaps, loss_min, n, score}.
 */
function fleet_inet_stats(int $secs, int $now): array {
	$from = $now - $secs;
	$every = 60 * (int)fleet_opt('inet_interval');
	$acc = array();
	$q = fleet_db()->prepare('SELECT node_id, state, delay_ms, stddev_ms, loss_pct FROM gw_samples WHERE is_default = 1 AND time >= ? ORDER BY node_id, time');
	$q->execute(array($from));
	$seq = array();
	foreach ($q->fetchAll() as $r) {
		$a = &$acc[$r['node_id']];
		$a['n'] = ($a['n'] ?? 0) + 1;
		foreach (array('loss' => 'loss_pct', 'latency' => 'delay_ms', 'jitter' => 'stddev_ms') as $k => $col) {
			if (is_numeric($r[$col])) {
				$a[$k . '_s'] = ($a[$k . '_s'] ?? 0) + (float)$r[$col];
				$a[$k . '_n'] = ($a[$k . '_n'] ?? 0) + 1;
			}
		}
		$a['loss_min'] = ($a['loss_min'] ?? 0) + (((float)$r['loss_pct'] > 0) ? $every / 60 : 0);
		$seq[$r['node_id']][] = $r['state'];
		unset($a);
	}
	foreach ($seq as $node => $states) {
		$acc[$node]['flaps'] = fleet_inet_flaps($states);
	}
	$q = fleet_db()->prepare('SELECT node_id, n, delay_ms, stddev_ms, loss_pct, flaps, loss_n FROM gw_hourly WHERE is_default = 1 AND time >= ?');
	$q->execute(array($from));
	foreach ($q->fetchAll() as $r) {
		$a = &$acc[$r['node_id']];
		$n = (int)$r['n'];
		$a['n'] = ($a['n'] ?? 0) + $n;
		foreach (array('loss' => 'loss_pct', 'latency' => 'delay_ms', 'jitter' => 'stddev_ms') as $k => $col) {
			if (is_numeric($r[$col])) {
				$a[$k . '_s'] = ($a[$k . '_s'] ?? 0) + $n * (float)$r[$col];
				$a[$k . '_n'] = ($a[$k . '_n'] ?? 0) + $n;
			}
		}
		$a['flaps'] = ($a['flaps'] ?? 0) + (int)$r['flaps'];
		$a['loss_min'] = ($a['loss_min'] ?? 0) + (int)$r['loss_n'] * $every / 60;
		unset($a);
	}
	$thr = fleet_inet_thresholds();
	$out = array();
	foreach ($acc as $node => $a) {
		$avg = function (string $k) use ($a) { return empty($a[$k . '_n']) ? null : round($a[$k . '_s'] / $a[$k . '_n'], 2); };
		$s = array('loss' => $avg('loss'), 'latency' => $avg('latency'), 'jitter' => $avg('jitter'), 'flaps' => (int)($a['flaps'] ?? 0),
		    'loss_min' => (int)round($a['loss_min'] ?? 0), 'n' => (int)($a['n'] ?? 0));
		/* Flaps count per day for the score, so a long range is not punished for its length. */
		$per_day = $s['flaps'] / max(1.0, $secs / 86400);
		$s['score'] = fleet_inet_score($s['loss'], $s['latency'], $s['jitter'], (int)round($per_day), $thr);
		$out[$node] = $s;
	}
	return $out;
}

/* pure: the fleet's figures from fleet_inet_stats(): averages over the firewalls, flaps summed. */
function fleet_inet_fleet_stats(array $stats): array {
	$m = function (string $k) use ($stats) {
		$v = array_values(array_filter(array_column($stats, $k), 'is_numeric'));
		return empty($v) ? null : round(array_sum($v) / count($v), 1);
	};
	return array('loss' => $m('loss'), 'latency' => $m('latency'), 'jitter' => $m('jitter'), 'score' => ($m('score') === null) ? null : (int)round($m('score')),
	    'flaps' => array_sum(array_column($stats, 'flaps')), 'loss_min' => array_sum(array_column($stats, 'loss_min')), 'firewalls' => count($stats));
}

/* One firewall's gateway history for a range: per gateway {t, delay, loss}. */
function fleet_inet_box_history(string $node, string $range, int $now): array {
	$span = FLEET_STATS_RANGES[$range] ?? 86400;
	$q = fleet_db()->prepare('SELECT time, gw, delay_ms, loss_pct FROM gw_samples WHERE node_id = ? AND time >= ?
	    UNION ALL SELECT time, gw, delay_ms, loss_pct FROM gw_hourly WHERE node_id = ? AND time >= ? ORDER BY time');
	$q->execute(array($node, $now - $span, $node, $now - $span));
	$out = array();
	foreach ($q->fetchAll() as $r) {
		$out[$r['gw']]['t'][] = (int)$r['time'];
		$out[$r['gw']]['delay'][] = ($r['delay_ms'] === null) ? null : round((float)$r['delay_ms'], 1);
		$out[$r['gw']]['loss'][] = ($r['loss_pct'] === null) ? null : round((float)$r['loss_pct'], 1);
	}
	return $out;
}

/* The latest internet alerts (failovers, outages, back): {time, event, severity, title, node}. */
function fleet_inet_events(int $limit = 6): array {
	$out = array();
	$q = fleet_db()->prepare("SELECT time, event, severity, node_id, text FROM alerts WHERE event LIKE 'inet_%' ORDER BY id DESC LIMIT ?");
	$q->execute(array($limit));
	foreach ($q->fetchAll() as $a) {
		$out[] = array('time' => (int)$a['time'], 'event' => (string)$a['event'], 'severity' => (string)$a['severity'],
		    'title' => (string)(FLEET_ALERT_EVENTS[$a['event']][0] ?? $a['event']), 'node' => (string)$a['node_id'], 'text' => (string)$a['text']);
	}
	return $out;
}
