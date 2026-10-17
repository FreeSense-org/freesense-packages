<?php
/*
 * fleet_internet.php
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
 * Internet (a view of Firewalls): every gateway in the fleet with its
 * state, latency, jitter and loss, and each firewall's availability over
 * 24 hours. Filters, search and paging; the logic is fleet_inet.inc.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Firewalls'), gettext('Internet'));
include('head.inc');
?>
<link rel="stylesheet" href="/fleet/assets/fleet.css?v=<?=(int)@filemtime('/usr/local/www/fleet/assets/fleet.css')?>">
<?php
$tab_array = array(
	array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
	array(gettext('Activity'), false, '/fleet/fleet_activity.php'),
	array(gettext('Updates'), false, '/fleet/fleet_updates.php'),
	array(gettext('Schedules'), false, '/fleet/fleet_schedules.php'),
	array(gettext('Backups'), false, '/fleet/fleet_backups.php'),
	array(gettext('Policies'), false, '/fleet/fleet_policies.php'),
	array(gettext('Templates'), false, '/fleet/fleet_templates.php'),
	array(gettext('Users'), false, '/fleet/fleet_users.php'),
	array(gettext('Firewalls'), true, '/fleet/fleet.php'),
	array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
);
display_top_tabs($tab_array);
if (!$ready): ?>
<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php include('foot.inc'); exit; endif;
echo fleet_firewalls_nav('internet', (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn());

$h = function ($s) { return htmlspecialchars((string)$s); };
if (!fleet_inet_enabled()): ?>
<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-globe" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Internet connectivity is off')?></h2><p><?=gettext('Every firewall measures its gateways (latency, jitter and loss). Turn the option on and Fleet keeps that history for the whole fleet, shows which firewalls have a poor connection or none, and tells you when one loses its internet or moves to another WAN.')?></p>
		<p><a class="btn btn-sm btn-primary" href="/fleet/fleet.php?tab=settings&amp;view=monitoring"><i class="fa-solid fa-gear icon-embed-btn" aria-hidden="true"></i><?=gettext('Turn it on in Settings > Monitoring')?></a></p></div></header>
</section>
<?php include('foot.inc'); exit; endif;

$now = time();
$cur = fleet_inet_now();
$counts = fleet_inet_counts($cur);
$avail = fleet_inet_availability(86400, $now);
$boxes = fleet_db()->query('SELECT node_id, label, state FROM boxes ORDER BY label COLLATE NOCASE')->fetchAll();
$by_group = fleet_groups_by_box();
$fgroups = array();
foreach (fleet_groups_all() as $fg) {
	$fgroups[(string)$fg['id']] = $fg['name'];
}
$states = array_map('gettext', FLEET_INET_STATES);
$sorts = array('state' => gettext('Problems first'), 'score' => gettext('Lowest quality'), 'name' => gettext('Name'), 'loss' => gettext('Most loss'),
    'latency' => gettext('Highest latency'), 'flaps' => gettext('Most flaps'));
$ranges = array('24h' => gettext('Last 24 hours'), '7d' => gettext('Last 7 days'), '30d' => gettext('Last 30 days'));
$f = fleet_list_filters($_GET, array('q' => null, 'state' => $states, 'group' => $fgroups, 'sort' => $sorts, 'range' => $ranges));
$range = $f['range'] ?? '24h';
$rstats = fleet_inet_stats(FLEET_STATS_RANGES[$range], $now);
$fs = fleet_inet_fleet_stats($rstats);
$page = max(1, (int)($_GET['page'] ?? 1));

/* One row per gateway (the default first), from each firewall's last check. */
$rows = array();
$rank = array('down' => 0, 'degraded' => 1, 'unknown' => 2, 'up' => 3);
foreach ($boxes as $b) {
	$r = $cur[$b['node_id']] ?? null;
	$gws = ($r === null) ? array() : $r['gateways'];
	if (isset($f['group']) && !in_array((int)$f['group'], array_column($by_group[$b['node_id']] ?? array(), 'id'), true)) {
		continue;
	}
	if (empty($gws)) {
		$gws = array(array('name' => '-', 'iface' => '', 'descr' => '', 'default' => true, 'state' => 'unknown', 'reason' => ($b['state'] === 'online') ? gettext('not checked yet') : gettext('firewall not reachable'),
		    'delay_ms' => null, 'stddev_ms' => null, 'loss_pct' => null));
	}
	usort($gws, function ($x, $y) { return array(empty($x['default']), (string)$x['name']) <=> array(empty($y['default']), (string)$y['name']); });
	foreach ($gws as $gw) {
		$row = $gw + array('node' => $b['node_id'], 'label' => $b['label'], 'box_state' => ($r === null) ? 'unknown' : $r['state'], 'since' => ($r === null) ? null : (int)$r['since'],
		    'avail' => $avail[$b['node_id']] ?? null, 'checked' => ($r === null) ? null : (int)$r['checked'],
		    /* Range figures belong to the firewall's default gateway; other gateways show their live values only. */
		    'st' => !empty($gw['default']) ? ($rstats[$b['node_id']] ?? null) : null);
		if (isset($f['state']) && ($row['state'] !== $f['state'])) {
			continue;
		}
		if (isset($f['q']) && (stripos($b['label'] . ' ' . $gw['name'] . ' ' . $gw['iface'] . ' ' . $gw['descr'], $f['q']) === false)) {
			continue;
		}
		$rows[] = $row;
	}
}
$sort = $f['sort'] ?? 'state';
usort($rows, function ($a, $b) use ($sort, $rank) {
	switch ($sort) {
	case 'score':
		return array($a['st']['score'] ?? 101, strtolower($a['label'])) <=> array($b['st']['score'] ?? 101, strtolower($b['label']));
	case 'flaps':
		return array(-(int)($a['st']['flaps'] ?? 0), strtolower($a['label'])) <=> array(-(int)($b['st']['flaps'] ?? 0), strtolower($b['label']));
	case 'name':
		return array(strtolower($a['label']), empty($a['default'])) <=> array(strtolower($b['label']), empty($b['default']));
	case 'loss':
		return array(-(float)$a['loss_pct'], strtolower($a['label'])) <=> array(-(float)$b['loss_pct'], strtolower($b['label']));
	case 'latency':
		return array(-(float)$a['delay_ms'], strtolower($a['label'])) <=> array(-(float)$b['delay_ms'], strtolower($b['label']));
	}
	return array($rank[$a['state']] ?? 2, strtolower($a['label']), empty($a['default'])) <=> array($rank[$b['state']] ?? 2, strtolower($b['label']), empty($b['default']));
});
$pg = fleet_list_page(count($rows), $page);
$shown = array_slice($rows, $pg['offset'], $pg['per']);
$base = array();
$badge = array('up' => 'pass', 'degraded' => 'warn', 'down' => 'block', 'unknown' => 'neutral');
$num = function ($v, string $unit) { return ($v === null) ? '<span class="fs-muted">-</span>' : htmlspecialchars(fleet_inet_num((float)$v) . $unit); };
$backup = count(array_filter($cur, function ($r) { return strpos((string)$r['reason'], 'default gateway') === 0; }));
$fleet_avail = empty($avail) ? null : round(array_sum($avail) / count($avail), 1);
?>

<section class="fs-fleet-area">
	<header class="fs-fleet-area-head"><span class="fs-fleet-area-icon"><i class="fa-solid fa-globe" aria-hidden="true"></i></span>
		<div><h2><?=gettext('Internet connectivity')?></h2><p><?=htmlspecialchars(sprintf(gettext('Each firewall\'s gateways, read every %d minutes. A firewall is told about after %d bad checks in a row; the thresholds are under Settings > Monitoring.'),
		    fleet_opt('inet_interval'), fleet_opt('inet_grace')))?></p></div></header>
	<div class="fs-tiles fs-fleet-tiles-row">
		<a class="fs-tile" href="?state=up"><span class="fs-tile-label"><?=gettext('Internet up')?></span><span class="fs-tile-value"><?=(int)$counts['up']?></span></a>
		<a class="fs-tile" href="?state=degraded"><span class="fs-tile-label"><?=gettext('Poor connection')?></span><span class="fs-tile-value<?=$counts['degraded'] ? ' fs-fleet-warn-text' : ''?>"><?=(int)$counts['degraded']?></span><?php if ($backup): ?><span class="fs-tile-hint"><?=htmlspecialchars(sprintf(ngettext('%d on a backup WAN', '%d on a backup WAN', $backup), $backup))?></span><?php endif; ?></a>
		<a class="fs-tile" href="?state=down"><span class="fs-tile-label"><?=gettext('No internet')?></span><span class="fs-tile-value<?=$counts['down'] ? ' fs-fleet-problem' : ''?>"><?=(int)$counts['down']?></span></a>
		<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Internet up over 24 hours')?></span><span class="fs-tile-value"><?=($fleet_avail === null) ? '-' : $h($fleet_avail . '%')?></span></div>
		<div class="fs-tile"><span class="fs-tile-label"><?=$h(sprintf(gettext('Fleet quality, %s'), $ranges[$range]))?></span><span class="fs-tile-value<?=(($fs['score'] ?? 100) < 75) ? ' fs-fleet-warn-text' : ''?>"><?=($fs['score'] === null) ? '-' : (int)$fs['score']?></span>
			<span class="fs-tile-hint"><?=$h(sprintf(gettext('%1$s loss · %2$d flaps · %3$d min with loss'), ($fs['loss'] === null) ? '-' : fleet_inet_num((float)$fs['loss']) . ' %', $fs['flaps'], $fs['loss_min']))?></span></div>
	</div>
</section>

<div class="panel panel-default">
	<div class="panel-heading"><?=fleet_list_filterbar($base, $f, array('state' => array(gettext('Any state'), $states), 'group' => array(gettext('Any group'), $fgroups),
	    'sort' => array(gettext('Problems first'), array_slice($sorts, 1, null, true)), 'range' => array(gettext('Last 24 hours'), array_slice($ranges, 1, null, true))),
	    gettext('Search gateways'), gettext('Firewall, gateway or interface'))?></div>
	<div class="panel-body table-responsive"><table class="table fs-table">
		<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('Gateway')?></th><th><?=gettext('State')?></th><th class="text-end"><?=gettext('Latency')?></th>
			<th class="text-end"><?=gettext('Jitter')?></th><th class="text-end"><?=gettext('Loss')?></th>
			<th class="text-end" title="<?=gettext('0-100: loss, flaps, latency and jitter over the range')?>"><?=gettext('Quality')?></th><th class="text-end"><?=$h(sprintf(gettext('Loss, %s'), $range))?></th>
			<th class="text-end"><?=$h(sprintf(gettext('Flaps, %s'), $range))?></th><th class="text-end"><?=gettext('Minutes with loss')?></th><th class="text-end"><?=gettext('Up 24 h')?></th><th><?=gettext('Checked')?></th></tr></thead>
		<tbody>
<?php if (empty($shown)): ?>
		<tr><td colspan="12" class="fs-muted"><?=!empty($f) ? gettext('No gateway matches these filters.') : gettext('No checks yet: the first ones come within a few minutes of turning the option on.')?></td></tr>
<?php endif; ?>
<?php foreach ($shown as $r): ?>
		<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($r['node'])?>&amp;view=stats&amp;section=internet"><?=$h($r['label'])?></a></td>
			<td><span class="fs-mono"><?=$h($r['name'])?></span><?=!empty($r['default']) ? ' ' . fs_badge('neutral', gettext('default')) : ''?>
				<?php if ($r['iface'] !== '' || $r['descr'] !== ''): ?><div class="small fs-muted"><?=$h(trim($r['iface'] . ' ' . (($r['descr'] !== '') ? '· ' . $r['descr'] : '')))?></div><?php endif; ?></td>
			<td><?=fs_badge($badge[$r['state']] ?? 'neutral', gettext(FLEET_INET_STATES[$r['state']] ?? $r['state']))?><?php if ($r['reason'] !== ''): ?><div class="small fs-muted"><?=$h($r['reason'])?></div><?php endif; ?></td>
			<td class="text-end fs-mono"><?=$num($r['delay_ms'], ' ms')?></td>
			<td class="text-end fs-mono"><?=$num($r['stddev_ms'], ' ms')?></td>
			<td class="text-end fs-mono"><?=$num($r['loss_pct'], ' %')?></td>
			<td class="text-end"><?=fleet_inet_score_badge($r['st']['score'] ?? null)?></td>
			<td class="text-end fs-mono"><?=$num($r['st']['loss'] ?? null, ' %')?></td>
			<td class="text-end fs-mono<?=(($r['st']['flaps'] ?? 0) > 0) ? ' fs-fleet-warn-text' : ''?>"><?=($r['st'] === null) ? '<span class="fs-muted">-</span>' : (int)$r['st']['flaps']?></td>
			<td class="text-end fs-mono"><?=($r['st'] === null) ? '<span class="fs-muted">-</span>' : (int)$r['st']['loss_min']?></td>
			<td class="text-end fs-mono"><?=($r['avail'] === null) ? '<span class="fs-muted">-</span>' : $h($r['avail'] . ' %')?></td>
			<td class="small fs-muted"><?=($r['checked'] === null) ? '-' : $h(fleet_inet_ago($r['checked'], $now))?></td></tr>
<?php endforeach; ?>
		</tbody></table></div>
	<div class="panel-footer"><?=fleet_list_pager($pg, $base, $f)?></div>
</div>
<?php include('foot.inc');
