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
	'update_group' => gettext('Update %s...'), 'updates' => gettext('Updates'),
	'none_match' => gettext('No firewall is %s.'), 'none_in_group' => gettext('No firewall in this group matches.'), 'show_all' => gettext('Show all'),
);

$filters = array(
	array('all', gettext('Firewalls'), $data['total'], null),
	array('online', gettext('Online'), $data['counts']['online'], 'online'),
	array('degraded', gettext('Degraded'), $data['counts']['degraded'], 'degraded'),
	array('offline', gettext('Offline'), $data['counts']['offline'], 'offline'),
	array('unprotected', gettext('No rollback'), $data['counts']['unprotected'], null),
);

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
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
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
