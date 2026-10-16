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
 * The fleet at a glance: one tile per firewall, worst state first. The page
 * renders once on the server; assets/fleet.js refreshes it from
 * fleet_data.php (every 10 s while visible, 60 s when the tab is hidden).
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'));
$s = fleet_ctl_settings();
$ready = $s['enable'] && is_file(FLEET_DATA . '/fleet.db');
$data = $ready ? fleet_dashboard_data(
    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status, update_info, (SELECT MAX(time) FROM backups b WHERE b.node_id = boxes.node_id) AS last_backup FROM boxes')->fetchAll(),
    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), time(), fleet_groups_by_box(), fleet_ops_for_tiles(time()), fleet_ops_groups_running())
    : fleet_dashboard_data(array(), 0, time());
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
$manage = isAllowedPage('fleet/fleet.php');

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
	array('all', gettext('Firewalls'), $data['total'], null),
	array('online', gettext('Online'), $data['counts']['online'], 'online'),
	array('degraded', gettext('Degraded'), $data['counts']['degraded'], 'degraded'),
	array('offline', gettext('Offline'), $data['counts']['offline'], 'offline'),
	array('unprotected', gettext('No rollback'), $data['counts']['unprotected'], null),
);

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
	echo fleet_dashboard_nav('overview');
}
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

<div id="fs-fleet" data-src="/fleet/fleet_data.php" data-manage="<?=$manage ? '1' : '0'?>" data-strings="<?=htmlspecialchars(json_encode($strings))?>">
	<div class="fs-fleet-head">
		<div>
			<h2 class="fs-fleet-headline" data-fleet="headline" aria-live="polite"><?=htmlspecialchars(gettext($data['headline']))?></h2>
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
<?php
	/* Availability: range, group and sort kept in the URL (s_ prefixed, apart from the live view's filters). */
	$s_range = in_array($_GET['s_range'] ?? '', array_keys(FLEET_STATS_RANGES), true) ? $_GET['s_range'] : '7d';
	$s_groups = array_column(fleet_groups_all(), 'name', 'id');
	$s_group = isset($s_groups[(int)($_GET['s_group'] ?? 0)]) ? (int)$_GET['s_group'] : 0;
	$s_sort = in_array($_GET['s_sort'] ?? '', array('avail', 'outages', 'name'), true) ? $_GET['s_sort'] : 'avail';
	$s_nodes = null;
	if ($s_group > 0) {
		$q = fleet_db()->prepare('SELECT node_id FROM box_groups WHERE group_id = ?');
		$q->execute(array($s_group));
		$s_nodes = $q->fetchAll(PDO::FETCH_COLUMN);
	}
	$stats = fleet_stats($s_range, $s_nodes);
	$s_rows = $stats['boxes'];
	usort($s_rows, function ($a, $b) use ($s_sort) {
		if ($s_sort === 'name') {
			return strnatcasecmp($a['label'], $b['label']);
		}
		if ($s_sort === 'outages') {
			return array($b['outages'], $b['longest']) <=> array($a['outages'], $a['longest']);
		}
		return array($a['percent'] ?? 101, -$a['outages']) <=> array($b['percent'] ?? 101, -$b['outages']);
	});
	$s_all = !empty($_GET['s_all']);
	$s_url = function (array $change) use ($s_range, $s_group, $s_sort, $s_all) {
		return '?' . htmlspecialchars(http_build_query(array_filter(array_merge(array('s_range' => $s_range, 's_group' => $s_group ?: null, 's_sort' => $s_sort,
		    's_all' => $s_all ? 1 : null), $change), function ($v) { return $v !== null; }))) . '#fs-fleet-stats';
	};
	$s_down = count(array_filter($stats['boxes'], function ($r) { return $r['down_now']; }));
	$s_dur = function (int $s) {
		return ($s <= 0) ? '-' : (($s < 3600) ? sprintf(gettext('%d min'), max(1, round($s / 60))) : fleet_uptime_text($s));
	};
	$s_labels = array('24h' => gettext('24 hours'), '7d' => gettext('7 days'), '30d' => gettext('30 days'));
?>
	<section class="panel panel-default fs-fleet-stats" id="fs-fleet-stats" aria-labelledby="fs-fleet-stats-title">
		<div class="panel-heading fs-fleet-heading-actions"><h2 class="panel-title" id="fs-fleet-stats-title"><i class="fa-solid fa-chart-line icon-embed-btn" aria-hidden="true"></i><?=gettext('Availability')?></h2>
			<div class="fs-fleet-stats-controls">
				<form method="get" class="d-inline"><input type="hidden" name="s_range" value="<?=htmlspecialchars($s_range)?>"/><input type="hidden" name="s_sort" value="<?=htmlspecialchars($s_sort)?>"/>
					<label class="visually-hidden" for="s-group"><?=gettext('Group')?></label>
					<select class="form-select form-select-sm" id="s-group" name="s_group" onchange="this.form.submit()">
						<option value="0"><?=gettext('All firewalls')?></option>
<?php foreach ($s_groups as $gid => $gname): ?>
						<option value="<?=(int)$gid?>"<?=($gid === $s_group) ? ' selected' : ''?>><?=htmlspecialchars($gname)?></option>
<?php endforeach; ?>
					</select><noscript><button class="btn btn-sm btn-link"><?=gettext('Show')?></button></noscript></form>
				<nav class="btn-group btn-group-sm" aria-label="<?=gettext('Range')?>">
<?php foreach ($s_labels as $rk => $rl): ?>
					<a class="btn btn-outline-secondary" href="<?=$s_url(array('s_range' => $rk))?>"<?=($rk === $s_range) ? ' aria-current="true" data-range aria-pressed="true"' : ''?>><?=$rl?></a>
<?php endforeach; ?>
				</nav>
			</div></div>
		<div class="panel-body fs-fleet-pad">
			<div class="fs-tiles fs-fleet-tiles-row">
				<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Availability')?></span><span class="fs-tile-value"><?=($stats['percent'] === null) ? '-' : $stats['percent'] . '%'?></span></div>
				<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Outages')?></span><span class="fs-tile-value"><?=(int)$stats['outages']?></span></div>
				<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Longest outage')?></span><span class="fs-tile-value fs-fleet-tile-text"><?=htmlspecialchars($s_dur($stats['longest']))?></span></div>
				<div class="fs-tile"><span class="fs-tile-label"><?=gettext('Down now')?></span><span class="fs-tile-value<?=$s_down ? ' fs-fleet-problem' : ''?>"><?=$s_down?> / <?=(int)$stats['total']?></span></div>
			</div>
			<h3 class="fs-fleet-subhead"><?=gettext('Firewalls up over time')?></h3>
			<div class="fs-fleet-stats-chart"><?=fleet_stats_svg($stats['timeline'], (int)$stats['total'], (int)$stats['from'], 1100, 170, function ($t) use ($s_range) {
				return ($s_range === '24h') ? date('H:i', $t) : date('M j', $t);
			}, gettext('Firewalls up over time'))?>
				<p class="fs-fleet-chart-legend small mb-0"><span class="fs-fleet-chart-key fs-fleet-chart-s1"></span><?=gettext('Up')?> <span class="fs-fleet-chart-key fs-fleet-chart-in-key"></span><?=gettext('In the fleet')?></p></div>
			<div class="table-responsive"><table class="table fs-table mb-0">
				<thead><tr>
					<th><a href="<?=$s_url(array('s_sort' => 'name'))?>"<?=($s_sort === 'name') ? ' aria-current="true"' : ''?>><?=gettext('Firewall')?></a></th>
					<th><a href="<?=$s_url(array('s_sort' => 'avail'))?>"<?=($s_sort === 'avail') ? ' aria-current="true"' : ''?>><?=gettext('Availability')?></a></th>
					<th><a href="<?=$s_url(array('s_sort' => 'outages'))?>"<?=($s_sort === 'outages') ? ' aria-current="true"' : ''?>><?=gettext('Outages')?></a></th>
					<th><?=gettext('Longest')?></th><th><?=gettext('Last outage')?></th></tr></thead>
				<tbody>
<?php foreach ($s_all ? $s_rows : array_slice($s_rows, 0, 8) as $sr): $sp = $sr['percent']; ?>
				<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode($sr['node'])?>"><?=htmlspecialchars($sr['label'])?></a><?=$sr['down_now'] ? ' ' . fs_badge('down', gettext('Down now')) : ''?></td>
					<td><?php if ($sp === null): ?><span class="fs-muted">-</span><?php else: ?><span class="fs-fleet-meter<?=($sp < 95) ? ' is-bad' : (($sp < 99.5) ? ' is-warn' : '')?>"><span style="width:<?=max(0, min(100, $sp))?>%"></span></span> <?=$sp?>%<?php endif; ?></td>
					<td><?=(int)$sr['outages']?></td>
					<td class="small"><?=htmlspecialchars($s_dur($sr['longest']))?></td>
					<td class="small"><?=($sr['last'] === null) ? '<span class="fs-muted">' . gettext('none') . '</span>' : htmlspecialchars(date('Y-m-d H:i', $sr['last']))?></td></tr>
<?php endforeach; ?>
<?php if (empty($s_rows)): ?>
				<tr><td colspan="5" class="fs-muted"><?=gettext('No firewalls in this group.')?></td></tr>
<?php endif; ?>
				</tbody></table></div>
<?php if (!$s_all && (count($s_rows) > 8)): ?>
			<p class="mb-0 mt-2 small"><a href="<?=$s_url(array('s_all' => 1))?>"><?=sprintf(gettext('Show all %d firewalls'), count($s_rows))?></a></p>
<?php endif; ?>
		</div>
	</section>
<?php list($ha_pairs, $ha_boxes) = fleet_ha_now(); if (!empty($ha_pairs)): ?>
	<section class="panel panel-default fs-fleet-ha" aria-labelledby="fs-fleet-ha-title">
		<div class="panel-heading"><h2 class="panel-title" id="fs-fleet-ha-title"><i class="fa-solid fa-clone icon-embed-btn" aria-hidden="true"></i><?=gettext('HA pairs')?> <span class="fs-count"><?=count($ha_pairs)?></span></h2></div>
		<div class="panel-body fs-fleet-pad"><p class="fs-fleet-lead small"><?=gettext('Firewalls that share CARP addresses. Fleet never works on both at once: the BACKUP goes first, the MASTER when its partner is back and the pair is healthy.')?></p>
		<ul class="fs-fleet-ha-list">
<?php foreach ($ha_pairs as $hp): ?>
			<li<?=($hp['problem'] !== null) ? ' class="is-problem"' : ''?>>
				<span class="fs-fleet-ha-state"><?=($hp['problem'] === null) ? fs_badge('pass', gettext('Healthy')) : fs_badge('down', ($hp['problem'][0] === 'split') ? gettext('Split-brain') : gettext('No MASTER'))?></span>
				<span class="fs-fleet-ha-members">
<?php $hp_nodes = $hp['nodes']; usort($hp_nodes, function ($x, $y) use ($ha_boxes) { return strnatcasecmp($ha_boxes[$x]['label'], $ha_boxes[$y]['label']); }); foreach ($hp_nodes as $hn): $hb = $ha_boxes[$hn]; ?>
					<a href="/fleet/fleet_box.php?id=<?=urlencode($hn)?>"><?=htmlspecialchars($hb['label'])?></a>
					<?=in_array($hn, $hp['masters'], true) ? fs_badge('info', 'MASTER') : fs_badge('neutral', 'BACKUP')?><?=($hb['state'] !== 'online') ? ' ' . fs_badge('warn', ucfirst($hb['state'])) : ''?>
<?php endforeach; ?>
				</span>
				<span class="small fs-muted"><?=($hp['problem'] !== null) ? htmlspecialchars(sprintf(($hp['problem'][0] === 'split') ? gettext('Both are MASTER for %s: check the link between them.') : gettext('Nobody is MASTER for %s.'), fleet_ha_vip_text($hp['problem'][1]))) :
				    (($hp['primary'] !== null) ? htmlspecialchars(sprintf(gettext('%s pushes its configuration by HA sync.'), $ha_boxes[$hp['primary']]['label'])) : gettext('No HA config sync.'))?></span>
			</li>
<?php endforeach; ?>
		</ul></div>
	</section>
<?php endif; ?>

<?php $all_groups = $ready ? fleet_groups_all() : array(); ?>
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
			<option value="<?=(int)$grp['id']?>"><?=htmlspecialchars($grp['name'])?> (<?=(int)$grp['members']?>)</option>
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
<?php foreach ($filters as list($key, $label, $count, $state)): ?>
		<button type="button" class="fs-tile fs-fleet-filter" data-filter="<?=$key?>" aria-pressed="<?=($key === 'all') ? 'true' : 'false'?>">
			<span class="fs-tile-label"><?=htmlspecialchars($label)?></span>
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
