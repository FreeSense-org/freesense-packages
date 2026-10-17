<?php
/*
 * fleet_dashboard.php
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
 * The fleet at a glance, in three views:
 *   overview   the fleet pulse (every firewall over 24 hours), what needs
 *              attention, states, the controller and the HA pairs
 *   trends     availability, load, activity and make-up over 24 hours,
 *              7 or 30 days, drawn by assets/fleet-charts.js
 *   firewalls  one tile per firewall, refreshed by assets/fleet.js
 * Overview and Trends refresh by fetching their own part (?part=1):
 * every minute and every five minutes, while the tab is visible.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'));
$s = fleet_ctl_settings();
$ready = $s['enable'] && is_file(FLEET_DATA . '/fleet.db');
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
$manage = isAllowedPage('fleet/fleet.php');
$h = function ($v) { return htmlspecialchars((string)$v); };

/* The view, the group and the range are kept in the URL. */
$views = array('overview' => gettext('Overview'), 'trends' => gettext('Trends'), 'firewalls' => gettext('Firewalls'));
$view = array_key_exists($_GET['view'] ?? '', $views) ? (string)$_GET['view'] : 'overview';
$all_groups = $ready ? fleet_groups_all() : array();
$group_names = array_column($all_groups, 'name', 'id');
$group = isset($group_names[(int)($_GET['group'] ?? 0)]) ? (int)$_GET['group'] : 0;
$range = array_key_exists($_GET['range'] ?? '', FLEET_STATS_RANGES) ? (string)$_GET['range'] : '24h';
$s_sort = in_array($_GET['s_sort'] ?? '', array('avail', 'outages', 'name'), true) ? (string)$_GET['s_sort'] : 'avail';
$show_all = !empty($_GET['all']);
$url = function (array $change = array(), string $anchor = '') use ($view, $group, $range, $s_sort, $show_all) {
	$q = array_filter(array_merge(array('view' => $view, 'group' => $group ?: null, 'range' => ($view === 'trends') ? $range : null,
	    's_sort' => (($view === 'trends') && ($s_sort !== 'avail')) ? $s_sort : null, 'all' => $show_all ? 1 : null), $change), function ($v) { return $v !== null; });
	return '?' . htmlspecialchars(http_build_query($q)) . $anchor;
};
$range_labels = array('24h' => gettext('24 hours'), '7d' => gettext('7 days'), '30d' => gettext('30 days'));
$dur = function (int $sec) {
	return ($sec <= 0) ? '-' : (($sec < 3600) ? sprintf(gettext('%d min'), max(1, round($sec / 60))) : fleet_uptime_text($sec));
};

/* A panel head: the icon in a tinted square (tone c1..c8 or a state), the title, and room for a summary. */
$head = function (string $icon, string $tone, string $title, string $sum = '', string $id = '') use ($h) {
	return '<header class="fs-fleet-cp-head"><span class="fs-fleet-cp-icon fs-fc-' . $tone . '"><i class="fa-solid ' . $icon . '" aria-hidden="true"></i></span>' .
	    '<h3' . (($id !== '') ? ' id="' . $id . '"' : '') . '>' . $h($title) . '</h3><span class="fs-fleet-cp-sum"' . (($sum === '') ? '' : ' data-sum="' . $sum . '"') . '></span></header>';
};

/* Text the charts need, translated in one place. */
$cstrings = array(
	'online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'), 'none' => gettext('Not in the fleet'),
	'now' => gettext('Now'), 'up' => gettext('Up'), 'in' => gettext('In the fleet'), 'outages' => gettext('Outages'), 'median' => gettext('Median'),
	'p90' => gettext('Busiest 10 %'), 'rx' => gettext('In'), 'tx' => gettext('Out'), 'critical' => gettext('Critical'), 'warning' => gettext('Warning'),
	'info' => gettext('Info'), 'done' => gettext('Done'), 'failed' => gettext('Failed'), 'backed_up' => gettext('Backed up'), 'pass' => gettext('Pass'),
	'fail' => gettext('Fail'), 'unknown' => gettext('Not checked'), 'warn_temp' => gettext('80 °C'), 'nothing' => gettext('Nothing in this range.'),
	'no_samples' => gettext('No samples in this range yet.'), 'no_temp' => gettext('No firewall reports a temperature sensor.'),
	'no_states' => gettext('No firewall reports its state table yet.'), 'sum_now' => gettext('%s now'), 'sum_peak' => gettext('peak %s'),
	'sum_total' => gettext('%s in all'), 'sum_firewalls' => gettext('%d firewalls'), 'sum_rules' => gettext('%d checks'), 'firewall' => gettext('Firewall'),
	'cpu' => gettext('CPU'), 'memory' => gettext('Memory'), 'states' => gettext('States'), 'peak' => gettext('Peak'), 'none_busy' => gettext('No samples yet.'),
	'in_use' => gettext('%s of the limit'),
);

/* ------------------------------------------------------------------ overview */
$overview = function () use ($h, $head, $url, $group, $group_names, $manage, $show_all) {
	$wd = fleet_widget_data(array('parts' => array_keys(FLEET_WIDGET_PARTS), 'group' => $group, 'rows' => 8));
	$pulse = fleet_trends_pulse($group, time());
	$more = 0;
	if (!$show_all && (count($pulse['rows']) > 40)) {
		$more = count($pulse['rows']) - 30;
		$pulse['rows'] = array_slice($pulse['rows'], 0, 30);
	}
	$c = $wd['counts'];
	$problems = (int)($wd['problem_count'] ?? 0);
	$tone = ($c['offline'] > 0) ? 'block' : ((($c['degraded'] > 0) || ($problems > 0)) ? 'warn' : 'pass');
	$pct = $wd['stats']['percent'] ?? null;
	$strip = array(
		array('fa-server', 'c1', (int)$wd['total'], ($wd['total'] === 1) ? gettext('firewall') : gettext('firewalls'), $url(array('view' => 'firewalls')), ''),
		array('fa-heart-pulse', ($pct !== null && $pct < 99.5) ? 'warn' : 'pass', ($pct === null) ? '-' : $pct . ' %', gettext('available, 24 hours'), $url(array('view' => 'trends', 'range' => '24h')),
		    sprintf(gettext('%d outages'), (int)($wd['stats']['outages'] ?? 0))),
		array('fa-circle-up', 'info', (int)$wd['updates'], gettext('with an update'), '/fleet/fleet_updates.php', ''),
		array('fa-bell', ((int)($wd['alerts'] ?? 0) > 0) ? 'warn' : 'neutral', (int)($wd['alerts'] ?? 0), gettext('alerts, 24 hours'), '/fleet/fleet_alerts.php', ''),
	);
	if ($manage) {
		$strip[] = array('fa-hourglass-half', ($c['pending'] > 0) ? 'warn' : 'neutral', (int)$c['pending'], gettext('waiting for approval'), '/fleet/fleet.php', '');
	}
?>
	<div class="fs-fleet-ov-head">
		<span class="fs-fleet-ov-state fs-fc-<?=$tone?>"><i class="fa-solid <?=($tone === 'pass') ? 'fa-circle-check' : 'fa-triangle-exclamation'?>" aria-hidden="true"></i></span>
		<div>
			<h2 class="fs-fleet-headline" aria-live="polite"><?=$h(gettext($wd['headline']))?><?=($group > 0) ? ' <span class="fs-fleet-ov-group">' . $h(sprintf(gettext('in %s'), $group_names[$group])) . '</span>' : ''?></h2>
			<p class="fs-fleet-checked mb-0"><?=$h(sprintf(gettext('Updated %s'), date('H:i')))?></p>
		</div>
	</div>
	<ul class="fs-fleet-strip">
<?php foreach ($strip as list($icon, $stone, $value, $label, $link, $sub)): ?>
		<li><a href="<?=$link?>"><span class="fs-fleet-cp-icon fs-fc-<?=$stone?>"><i class="fa-solid <?=$icon?>" aria-hidden="true"></i></span>
			<span class="fs-fleet-strip-v"><?=$h($value)?></span><span class="fs-fleet-strip-l"><?=$h($label)?><?=($sub !== '') ? '<br><span class="fs-muted">' . $h($sub) . '</span>' : ''?></span></a></li>
<?php endforeach; ?>
	</ul>

	<section class="fs-fleet-cp fs-fleet-pulse" aria-labelledby="fs-pulse-title">
		<?=$head('fa-wave-square', 'pass', gettext('Fleet pulse'), '', 'fs-pulse-title')?>
		<p class="fs-fleet-lead small"><?=gettext('Every firewall over the last 24 hours, half an hour per cell. The ones that had trouble come first; select a name to open it.')?></p>
		<div class="fs-fleet-cp-body" data-chart="pulse"></div>
		<p class="fs-fleet-chart-legend small mb-0">
<?php foreach (array('online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'), 'none' => gettext('Not in the fleet')) as $sk => $sl): ?>
			<span class="fs-fleet-pulse-key s-<?=$sk?>"></span><?=$h($sl)?>
<?php endforeach; ?>
		</p>
<?php if ($more > 0): ?>
		<p class="small mb-0 mt-2"><a href="<?=$url(array('all' => 1))?>"><?=$h(sprintf(gettext('Show all %d firewalls'), $more + 30))?></a> <span class="fs-muted"><?=$h(sprintf(gettext('(%d more not shown)'), $more))?></span></p>
<?php elseif ($show_all && (count($pulse['rows']) > 40)): ?>
		<p class="small mb-0 mt-2"><a href="<?=$url(array('all' => null))?>"><?=gettext('Show the first 30')?></a></p>
<?php endif; ?>
	</section>

	<div class="fs-fleet-ov-grid">
		<section class="fs-fleet-cp fs-fleet-attention" aria-labelledby="fs-att-title">
			<?=$head('fa-triangle-exclamation', ($problems > 0) ? 'warn' : 'pass', gettext('Needs attention'), '', 'fs-att-title')?>
<?php if (empty($wd['problems'])): ?>
			<p class="fs-fleet-quiet mb-0"><i class="fa-solid fa-circle-check" aria-hidden="true"></i><?=$h(sprintf(gettext('All %d firewalls are fine.'), $wd['total']))?></p>
<?php else: ?>
			<ul class="fs-fleet-attn-list">
<?php foreach ($wd['problems'] as $p): ?>
				<li><?=fs_badge($p['badge'][0], $p['badge'][1])?> <a href="<?=$h($p['link'])?>"><?=$h($p['label'])?></a><span class="fs-muted small"><?=$h($p['text'])?></span></li>
<?php endforeach; ?>
			</ul>
<?php if ($problems > count($wd['problems'])): ?>
			<p class="small mb-0 mt-2"><a href="<?=$url(array('view' => 'firewalls'))?>"><?=$h(sprintf(gettext('%d more on the Firewalls view'), $problems - count($wd['problems'])))?></a></p>
<?php endif; ?>
<?php endif; ?>
		</section>
		<section class="fs-fleet-cp" aria-labelledby="fs-states-title">
			<?=$head('fa-chart-pie', 'c1', gettext('States now'), '', 'fs-states-title')?>
			<div class="fs-fleet-cp-body" data-chart="states"></div>
		</section>
		<section class="fs-fleet-cp" aria-labelledby="fs-ctl-title">
			<?=$head('fa-tower-broadcast', 'c7', gettext('Controller'), '', 'fs-ctl-title')?>
			<dl class="fs-fleet-facts">
				<dt><i class="fa-solid fa-code-branch" aria-hidden="true"></i><?=gettext('Version')?></dt><dd><?=$h($wd['controller']['version'])?></dd>
				<dt><i class="fa-solid fa-clock" aria-hidden="true"></i><?=gettext('Up')?></dt><dd><?=($wd['controller']['uptime'] !== null) ? $h(fleet_uptime_text((int)$wd['controller']['uptime'])) : '-'?></dd>
<?php $sb = $wd['standby']; if (($sb['role'] ?? '') === 'primary'): $late = ($sb['seen'] > 0) && ((time() - $sb['seen']) > FLEET_STANDBY_LATE); ?>
				<dt><i class="fa-solid fa-clone" aria-hidden="true"></i><?=gettext('Standby')?></dt><dd><?=($sb['addr'] !== '') ? fs_badge($late ? 'warn' : 'pass', $late ? gettext('Late') : gettext('Up to date')) . ' ' . $h($sb['addr']) :
				    '<span class="fs-muted">' . gettext('waiting for it to connect') . '</span>'?></dd>
<?php endif; ?>
				<dt><i class="fa-solid fa-bell" aria-hidden="true"></i><?=gettext('Alerts')?></dt><dd><a href="/fleet/fleet_alerts.php"><?=$h(sprintf(gettext('%d in 24 hours'), (int)$wd['alerts']))?></a></dd>
<?php if ($wd['blocked'] > 0): ?>
				<dt><i class="fa-solid fa-ban" aria-hidden="true"></i><?=gettext('Blocked')?></dt><dd><a href="/fleet/fleet.php?tab=settings&amp;view=access"><?=$h(sprintf(gettext('%d addresses'), $wd['blocked']))?></a></dd>
<?php endif; ?>
			</dl>
		</section>
<?php
	list($ha_pairs, $ha_boxes) = fleet_ha_now();
	if ($group > 0) {
		$gn = array_column(array_filter(fleet_db()->query('SELECT node_id, group_id FROM box_groups')->fetchAll(), function ($r) use ($group) { return (int)$r['group_id'] === $group; }), 'node_id');
		$ha_pairs = array_values(array_filter($ha_pairs, function ($p) use ($gn) { return !empty(array_intersect($p['nodes'], $gn)); }));
	}
	if (!empty($ha_pairs)):
?>
		<section class="fs-fleet-cp" aria-labelledby="fs-ha-title">
			<?=$head('fa-clone', 'c3', gettext('HA pairs'), '', 'fs-ha-title')?>
			<ul class="fs-fleet-attn-list">
<?php foreach ($ha_pairs as $hp): $names = array_map(function ($n) use ($ha_boxes, $hp) { return $ha_boxes[$n]['label'] . (in_array($n, $hp['masters'], true) ? ' (MASTER)' : ''); }, $hp['nodes']); sort($names, SORT_NATURAL | SORT_FLAG_CASE); ?>
				<li><?=($hp['problem'] === null) ? fs_badge('pass', gettext('Healthy')) : fs_badge('down', gettext(fleet_ha_problem_badge($hp['problem'])))?>
					<a href="/fleet/fleet_box.php?id=<?=urlencode($hp['nodes'][0])?>"><?=$h(implode(' + ', $names))?></a></li>
<?php endforeach; ?>
			</ul>
		</section>
<?php endif; ?>
	</div>
	<script type="application/json" data-fleet-json><?=json_encode(array('pulse' => $pulse, 'counts' => $c, 'total' => $wd['total']), JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES)?></script>
<?php
};

/* ------------------------------------------------------------------ trends */
$trends = function () use ($h, $head, $url, $group, $range, $s_sort, $show_all, $dur) {
	$t = fleet_trends($range, $group, time());
	$nodes = ($group > 0) ? array_column(fleet_trends_boxes($group), 'node_id') : null;
	$stats = fleet_stats($range, $nodes);
	$rows = $stats['boxes'];
	usort($rows, function ($a, $b) use ($s_sort) {
		if ($s_sort === 'name') {
			return strnatcasecmp($a['label'], $b['label']);
		}
		if ($s_sort === 'outages') {
			return array($b['outages'], $b['longest']) <=> array($a['outages'], $a['longest']);
		}
		return array($a['percent'] ?? 101, -$a['outages']) <=> array($b['percent'] ?? 101, -$b['outages']);
	});
	$down = count(array_filter($stats['boxes'], function ($r) { return $r['down_now']; }));
	$first = (int)fleet_db()->query('SELECT MIN(t) FROM (SELECT MIN(time) AS t FROM samples UNION ALL SELECT MIN(time) FROM samples_hourly)')->fetchColumn();
	$tiles = array(
		array('fa-heart-pulse', 'pass', ($stats['percent'] === null) ? '-' : $stats['percent'] . ' %', gettext('Availability')),
		array('fa-plug-circle-xmark', ($stats['outages'] > 0) ? 'warn' : 'neutral', (int)$stats['outages'], gettext('Outages')),
		array('fa-hourglass-end', 'neutral', $dur((int)$stats['longest']), gettext('Longest outage')),
		array('fa-circle-xmark', $down ? 'block' : 'neutral', $down . ' / ' . (int)$stats['total'], gettext('Down now')),
	);
?>
	<h2 class="fs-fleet-section"><i class="fa-solid fa-heart-pulse" aria-hidden="true"></i><?=gettext('Availability')?></h2>
	<ul class="fs-fleet-strip fs-fleet-strip--quiet">
<?php foreach ($tiles as list($icon, $tone, $value, $label)): ?>
		<li><span class="fs-fleet-strip-item"><span class="fs-fleet-cp-icon fs-fc-<?=$tone?>"><i class="fa-solid <?=$icon?>" aria-hidden="true"></i></span>
			<span class="fs-fleet-strip-v"><?=$h($value)?></span><span class="fs-fleet-strip-l"><?=$h($label)?></span></span></li>
<?php endforeach; ?>
	</ul>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp"><?=$head('fa-chart-area', 'c1', gettext('Firewalls up'), 'up')?><div class="fs-fleet-cp-body" data-chart="up"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-plug-circle-xmark', 'block', gettext('Outages per day'), 'outages')?><div class="fs-fleet-cp-body" data-chart="outages"></div></section>
		<section class="fs-fleet-cp is-wide" id="fs-fleet-avail">
			<?=$head('fa-list-ol', 'neutral', gettext('Availability per firewall'))?>
			<div class="table-responsive"><table class="table fs-table mb-0">
				<thead><tr>
					<th><a href="<?=$url(array('s_sort' => 'name'), '#fs-fleet-avail')?>"<?=($s_sort === 'name') ? ' aria-current="true"' : ''?>><?=gettext('Firewall')?></a></th>
					<th><a href="<?=$url(array('s_sort' => null), '#fs-fleet-avail')?>"<?=($s_sort === 'avail') ? ' aria-current="true"' : ''?>><?=gettext('Availability')?></a></th>
					<th><a href="<?=$url(array('s_sort' => 'outages'), '#fs-fleet-avail')?>"<?=($s_sort === 'outages') ? ' aria-current="true"' : ''?>><?=gettext('Outages')?></a></th>
					<th><?=gettext('Longest')?></th><th><?=gettext('Last outage')?></th></tr></thead>
				<tbody>
<?php foreach ($show_all ? $rows : array_slice($rows, 0, 8) as $sr): $sp = $sr['percent']; ?>
				<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($sr['node'])?>&amp;view=stats"><?=$h($sr['label'])?></a><?=$sr['down_now'] ? ' ' . fs_badge('down', gettext('Down now')) : ''?></td>
					<td><?php if ($sp === null): ?><span class="fs-muted">-</span><?php else: ?><span class="fs-fleet-meter<?=($sp < 95) ? ' is-bad' : (($sp < 99.5) ? ' is-warn' : '')?>"><span style="width:<?=max(0, min(100, $sp))?>%"></span></span> <?=$sp?>%<?php endif; ?></td>
					<td><?=(int)$sr['outages']?></td>
					<td class="small"><?=$h($dur((int)$sr['longest']))?></td>
					<td class="small"><?=($sr['last'] === null) ? '<span class="fs-muted">' . gettext('none') . '</span>' : $h(date('Y-m-d H:i', $sr['last']))?></td></tr>
<?php endforeach; ?>
<?php if (empty($rows)): ?>
				<tr><td colspan="5" class="fs-muted"><?=gettext('No firewalls in this group.')?></td></tr>
<?php endif; ?>
				</tbody></table></div>
<?php if (!$show_all && (count($rows) > 8)): ?>
			<p class="mb-0 mt-2 small"><a href="<?=$url(array('all' => 1), '#fs-fleet-avail')?>"><?=$h(sprintf(gettext('Show all %d firewalls'), count($rows)))?></a></p>
<?php endif; ?>
		</section>
	</div>

	<h2 class="fs-fleet-section"><i class="fa-solid fa-gauge-high" aria-hidden="true"></i><?=gettext('Load')?></h2>
<?php if ($first === 0): ?>
	<p class="fs-fleet-lead small"><?=gettext('No load samples yet. The controller samples every online firewall every 5 minutes; a firewall needs System API level 11 or newer.')?></p>
<?php elseif ($first > $t['from']): ?>
	<p class="fs-fleet-lead small"><?=$h(sprintf(gettext('Sampling began %s; the load charts fill in as it runs. %d firewalls are sampled.'), date('Y-m-d H:i', $first), $t['sampled']))?></p>
<?php endif; ?>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp"><?=$head('fa-microchip', 'c1', gettext('CPU across the fleet'), 'cpu')?><div class="fs-fleet-cp-body" data-chart="cpu"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-memory', 'c3', gettext('Memory across the fleet'), 'mem')?><div class="fs-fleet-cp-body" data-chart="mem"></div></section>
		<section class="fs-fleet-cp is-wide"><?=$head('fa-fire', 'c2', gettext('CPU per firewall'), 'heat')?><div class="fs-fleet-cp-body" data-chart="heat"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-right-left', 'c6', gettext('WAN traffic, all firewalls'), 'traffic')?><div class="fs-fleet-cp-body" data-chart="traffic"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-table-list', 'c7', gettext('State table in use'), 'states')?><div class="fs-fleet-cp-body" data-chart="states_top"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-temperature-half', 'c8', gettext('Temperature'), 'temp')?><div class="fs-fleet-cp-body" data-chart="temp"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-ranking-star', 'c5', gettext('Busiest firewalls'))?><div class="fs-fleet-cp-body" data-chart="busiest"></div></section>
	</div>

	<h2 class="fs-fleet-section"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i><?=gettext('Activity')?></h2>
	<div class="fs-fleet-charts fs-fleet-charts--three">
		<section class="fs-fleet-cp"><?=$head('fa-bell', 'warn', gettext('Alerts per day'), 'alerts')?><div class="fs-fleet-cp-body" data-chart="alerts"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-list-check', 'info', gettext('Fleet operations per day'), 'ops')?><div class="fs-fleet-cp-body" data-chart="ops"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-box-archive', 'c4', gettext('Backups per day'), 'backups')?><div class="fs-fleet-cp-body" data-chart="backups"></div></section>
	</div>

	<h2 class="fs-fleet-section"><i class="fa-solid fa-layer-group" aria-hidden="true"></i><?=gettext('Make-up')?></h2>
	<div class="fs-fleet-charts">
		<section class="fs-fleet-cp"><?=$head('fa-code-branch', 'c1', gettext('System versions'), 'versions')?><div class="fs-fleet-cp-body" data-chart="versions"></div></section>
		<section class="fs-fleet-cp"><?=$head('fa-shield-halved', 'pass', gettext('Policy checks'), 'compliance')?><div class="fs-fleet-cp-body" data-chart="compliance"></div></section>
	</div>
	<script type="application/json" data-fleet-json><?=json_encode(array('trends' => $t), JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES)?></script>
<?php
};

/* A refresh of Overview or Trends: only the part. */
if ($ready && !empty($_GET['part']) && ($view !== 'firewalls')) {
	header('Cache-Control: no-cache');
	($view === 'overview') ? $overview() : $trends();
	exit;
}

if ($view === 'firewalls') {
	$data = $ready ? fleet_dashboard_data(
	    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
	    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), time(), fleet_groups_by_box(), fleet_ops_for_tiles(time()), fleet_ops_groups_running())
	    : fleet_dashboard_data(array(), 0, time());

	/* Text the script needs, so every word on the page is translated in one place. */
	$strings = array(
		'online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'),
		'version' => gettext('Version'), 'backup' => gettext('Last backup'), 'tunnel' => gettext('Tunnel'), 'seen' => gettext('Last seen'), 'never' => gettext('never'),
		'role' => gettext('Role'), 'managed' => gettext('Managed'), 'monitor' => gettext('Monitor only'), 'rollback' => gettext('No rollback'),
		'rollback_hint' => gettext('UFS: a failed update cannot roll back by itself'), 'carp' => gettext('CARP'),
		'breakglass' => gettext('Lock suspended'), 'checked' => gettext('Checked %s'), 'not_checked' => gettext('Not checked yet'),
		'stale' => gettext('Could not refresh. Showing the last known state.'),
		'ago_s' => gettext('%d s ago'), 'ago_m' => gettext('%d min ago'), 'ago_h' => gettext('%d h ago'), 'ago_d' => gettext('%d days ago'),
		'actions' => gettext('Actions'), 'actions_for' => gettext('Actions for %s'), 'open' => gettext('Open'), 'webui' => gettext('Open WebUI'),
		'events' => gettext('Events'), 'backup_now' => gettext('Back up now'), 'services' => gettext('Services'), 'reboot' => gettext('Reboot...'),
		'reboot_q' => gettext('Reboot %s?'), 'reboot_hint' => gettext('It stops forwarding for a minute or two and comes back by itself.'),
		'reboot_now' => gettext('Reboot now'), 'cancel' => gettext('Cancel'), 'rebooting' => gettext('Rebooting'), 'backing_up' => gettext('Backing up'),
		'action_failed' => gettext('The controller did not answer. Try again.'), 'secs' => gettext('%d s'), 'mins' => gettext('%d min %s s'),
		'details' => gettext('Details'), 'ungrouped' => gettext('Ungrouped'), 'none_search' => gettext('No firewall matches "%s".'), 'clear_search' => gettext('Clear the search'), 'only_group' => gettext('Show only this group'), 'group_activity' => gettext('Activity'),
		'change_group' => gettext('Change the group'), 'n_fw' => gettext('%d firewalls'), 'one_fw' => gettext('1 firewall'),
		'n_attention' => gettext('%d need attention'), 'one_attention' => gettext('1 needs attention'), 'all_ok' => gettext('All online'),
		'version_unknown' => gettext('Version unknown'), 'firewalls' => gettext('Firewalls'), 'collapse' => gettext('Show or hide %s'), 'backup_all' => gettext('Back up all now'), 'backup_group' => gettext('Back up %s now'), 'reboot_group' => gettext('Reboot %s...'),
		'update_group' => gettext('Update %s...'), 'updates' => gettext('Updates'), 'policy_fails' => gettext('Policy: %d failing'), 'policies' => gettext('Policies'),
		'none_match' => gettext('No firewall is %s.'), 'none_in_group' => gettext('No firewall in this group matches.'), 'show_all' => gettext('Show all'),
	);
	$filters = array(
		array('all', 'fa-server', gettext('Firewalls'), $data['total']),
		array('online', 'fa-circle-check', gettext('Online'), $data['counts']['online']),
		array('degraded', 'fa-triangle-exclamation', gettext('Degraded'), $data['counts']['degraded']),
		array('offline', 'fa-plug-circle-xmark', gettext('Offline'), $data['counts']['offline']),
		array('unprotected', 'fa-rotate-left', gettext('No rollback'), $data['counts']['unprotected']),
	);
}

fs_page_action(gettext('Open live view'), '/fleet/noc.php', 'fa-display', 'secondary', array('target' => '_blank', 'rel' => 'noopener'));
include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
if ($manage) {
	$tab_array = array(
		array(gettext('Dashboard'), true, '/fleet/fleet_dashboard.php'),
		array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
		array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
		array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
		array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
		array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
		array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
		array(gettext('Users'), false, '/fleet/fleet_users.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
echo fleet_dashboard_nav($view, $manage);
?>
<?php if (!$ready): ?>
<div class="fs-fleet-empty">
	<strong><?=gettext('This firewall is not a fleet controller')?></strong>
	<span><?=gettext('Turn on FreeSense Fleet to manage other firewalls from here.')?></span>
<?php if ($manage): ?>
	<a class="btn btn-primary" href="/fleet/fleet.php"><?=gettext('Open Fleet settings')?></a>
<?php endif; ?>
</div>
<?php include('foot.inc'); exit; endif; ?>

<?php if ($view !== 'firewalls'): ?>
<div id="fs-fleet-dash" class="fs-fleet-dash" data-view="<?=$view?>" data-part="<?=$url(array('part' => 1))?>" data-strings="<?=$h(json_encode($cstrings))?>">
	<form method="get" class="fs-fleet-dash-controls">
		<input type="hidden" name="view" value="<?=$view?>"/>
<?php if ($view === 'trends'): ?>
		<input type="hidden" name="range" value="<?=$h($range)?>"/>
		<nav class="btn-group btn-group-sm" aria-label="<?=gettext('Range')?>">
<?php foreach ($range_labels as $rk => $rl): ?>
			<a class="btn btn-outline-secondary" href="<?=$url(array('range' => $rk, 'all' => null))?>"<?=($rk === $range) ? ' aria-current="true"' : ''?>><?=$rl?></a>
<?php endforeach; ?>
		</nav>
<?php endif; ?>
<?php if (!empty($group_names)): ?>
		<label for="fs-dash-group" class="fs-muted"><i class="fa-solid fa-layer-group" aria-hidden="true"></i> <?=gettext('Group')?></label>
		<select class="form-select form-select-sm" id="fs-dash-group" name="group" onchange="this.form.submit()">
			<option value="0"><?=gettext('All firewalls')?></option>
<?php foreach ($group_names as $gid => $gname): ?>
			<option value="<?=(int)$gid?>"<?=($gid === $group) ? ' selected' : ''?>><?=$h($gname)?></option>
<?php endforeach; ?>
		</select><noscript><button class="btn btn-sm btn-link"><?=gettext('Show')?></button></noscript>
<?php endif; ?>
	</form>
	<div data-fleet-part aria-live="off">
<?php ($view === 'overview') ? $overview() : $trends(); ?>
	</div>
</div>
<script src="<?=$asset('fleet-charts.js')?>"></script>
<script src="<?=$asset('fleet-dashboard.js')?>"></script>
<?php include('foot.inc'); exit; endif; ?>

<div id="fs-fleet" data-src="/fleet/fleet_data.php" data-manage="<?=$manage ? '1' : '0'?>" data-strings="<?=$h(json_encode($strings))?>">
	<div class="fs-fleet-head">
		<div>
			<h2 class="fs-fleet-headline" data-fleet="headline" aria-live="polite"><?=$h(gettext($data['headline']))?></h2>
			<div class="fs-fleet-checked" data-fleet="checked" data-checked="<?=(int)$data['checked']?>" data-now="<?=(int)$data['now']?>"></div>
		</div>
		<div class="fs-fleet-actions">
<?php if ($manage && $data['counts']['pending'] > 0): ?>
			<a class="btn btn-primary" href="/fleet/fleet.php" data-fleet="pending"><i class="fa-solid fa-hourglass-half icon-embed-btn" aria-hidden="true"></i><?=sprintf(gettext('%d waiting for approval'), $data['counts']['pending'])?></a>
<?php endif; ?>
<?php if ($manage): ?>
			<form method="post" action="/fleet/fleet.php" id="fleet-backup-all" hidden><input type="hidden" name="backup_all" value="1"/><input type="hidden" name="group" value=""/></form>
			<div class="fs-fleet-menu fs-fleet-menu--page" data-fleet-menu>
				<button type="button" class="btn btn-outline-secondary fs-fleet-menu-btn" aria-haspopup="menu"><i class="fa-solid fa-ellipsis icon-embed-btn" aria-hidden="true"></i><?=gettext('Fleet actions')?></button>
				<ul class="fs-fleet-menu-list" role="menu">
					<li role="none"><button type="button" class="fs-fleet-menu-item" role="menuitem" tabindex="-1" data-submit="fleet-backup-all"<?=($data['total'] === 0) ? ' disabled' : ''?>><i class="fa-solid fa-floppy-disk" aria-hidden="true"></i><span data-fleet="backup-all-label"><?=gettext('Back up all now')?></span></button></li>
					<li role="none"><a class="fs-fleet-menu-item" role="menuitem" tabindex="-1" href="#" data-fleet="reboot-group" hidden><i class="fa-solid fa-power-off" aria-hidden="true"></i><span data-fleet="reboot-group-label"></span></a></li>
					<li role="none"><a class="fs-fleet-menu-item" role="menuitem" tabindex="-1" href="/fleet/fleet_activity.php"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i><?=gettext('Activity')?></a></li>
					<li role="separator" class="fs-fleet-menu-sep"></li>
					<li role="none"><a class="fs-fleet-menu-item" role="menuitem" tabindex="-1" href="/fleet/fleet.php"><i class="fa-solid fa-plus" aria-hidden="true"></i><?=gettext('Add a firewall')?></a></li>
					<li role="none"><a class="fs-fleet-menu-item" role="menuitem" tabindex="-1" href="/fleet/fleet.php?view=groups"><i class="fa-solid fa-layer-group" aria-hidden="true"></i><?=gettext('Groups')?></a></li>
					<li role="none"><a class="fs-fleet-menu-item" role="menuitem" tabindex="-1" href="/fleet/fleet.php?tab=settings"><i class="fa-solid fa-sliders" aria-hidden="true"></i><?=gettext('Settings')?></a></li>
				</ul>
			</div>
<?php endif; ?>
		</div>
	</div>

	<div class="fs-fleet-groupbar">
		<div class="fs-fleet-search fs-fleet-wallsearch">
			<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
			<input type="search" class="form-control form-control-sm" data-fleet="search" placeholder="<?=gettext('Search name, host, version, address...')?>" aria-label="<?=gettext('Search firewalls')?>" aria-keyshortcuts="/"/>
		</div>
<?php if (!empty($all_groups)): ?>
		<label for="fleet-group" class="fs-muted"><?=gettext('Group')?></label>
		<select id="fleet-group" class="form-select form-select-sm" data-fleet="group">
			<option value=""><?=gettext('All firewalls')?></option>
<?php foreach ($all_groups as $grp): ?>
			<option value="<?=(int)$grp['id']?>"><?=$h($grp['name'])?> (<?=(int)$grp['members']?>)</option>
<?php endforeach; ?>
		</select>
<?php endif; ?>
		<label for="fleet-by" class="fs-muted"><?=gettext('Group by')?></label>
		<select id="fleet-by" class="form-select form-select-sm fs-fleet-small" data-fleet="by">
			<option value="group"><?=gettext('Group')?></option>
			<option value="state"><?=gettext('State')?></option>
			<option value="version"><?=gettext('Version')?></option>
			<option value="none"><?=gettext('Nothing')?></option>
		</select>
		<label for="fleet-sort" class="fs-muted"><?=gettext('Sort')?></label>
		<select id="fleet-sort" class="form-select form-select-sm fs-fleet-small" data-fleet="sort">
			<option value="attention"><?=gettext('Needs attention first')?></option>
			<option value="name"><?=gettext('Name')?></option>
			<option value="seen"><?=gettext('Last seen')?></option>
		</select>
	</div>
	<div class="fs-tiles" role="group" aria-label="<?=gettext('Filter firewalls')?>">
<?php foreach ($filters as list($key, $icon, $label, $count)): ?>
		<button type="button" class="fs-tile fs-fleet-filter" data-filter="<?=$key?>" aria-pressed="<?=($key === 'all') ? 'true' : 'false'?>">
			<span class="fs-tile-label"><i class="fa-solid <?=$icon?> fs-fleet-tile-icon" aria-hidden="true"></i><?=$h($label)?></span>
			<span class="fs-tile-value" data-count="<?=$key?>"><?=(int)$count?></span>
		</button>
<?php endforeach; ?>
	</div>

<?php if ($data['total'] === 0): ?>
	<div class="fs-fleet-empty">
		<strong><?=gettext('No firewalls yet')?></strong>
		<span><?=gettext('Invite a firewall with a join link and key. It appears here as soon as it joins.')?></span>
<?php if ($manage): ?>
		<a class="btn btn-primary" href="/fleet/fleet.php"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add a firewall')?></a>
<?php endif; ?>
	</div>
<?php endif; ?>
	<div class="fs-fleet-activities" data-fleet="activity" aria-live="polite" hidden></div>
	<div class="fs-fleet-wsecs" data-fleet="wall"></div>
	<p class="fs-fleet-problem" data-fleet="filter-empty" hidden></p>
	<script type="application/json" id="fs-fleet-initial"><?=json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES)?></script>
</div>
<script src="<?=$asset('fleet.js')?>"></script>
<?php include('foot.inc');
