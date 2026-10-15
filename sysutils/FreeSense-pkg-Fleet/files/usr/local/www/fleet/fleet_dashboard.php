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
    fleet_db()->query('SELECT node_id, name, label, overlay, role, state, last_seen, error, status FROM boxes')->fetchAll(),
    (int)fleet_db()->query("SELECT COUNT(*) FROM enrollments WHERE state = 'pending'")->fetchColumn(), time())
    : fleet_dashboard_data(array(), 0, time());
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};
$manage = isAllowedPage('fleet/fleet.php');

/* Text the script needs, so every word on the page is translated in one place. */
$strings = array(
	'online' => gettext('Online'), 'degraded' => gettext('Degraded'), 'offline' => gettext('Offline'), 'new' => gettext('Joining'),
	'version' => gettext('Version'), 'tunnel' => gettext('Tunnel'), 'seen' => gettext('Last seen'), 'never' => gettext('never'),
	'managed' => gettext('Managed'), 'monitor' => gettext('Monitor only'), 'rollback' => gettext('No rollback'),
	'rollback_hint' => gettext('UFS: a failed update cannot roll back by itself'), 'carp' => gettext('CARP'),
	'breakglass' => gettext('Lock suspended'), 'checked' => gettext('Checked %s'), 'not_checked' => gettext('Not checked yet'),
	'stale' => gettext('Could not refresh. Showing the last known state.'),
	'ago_s' => gettext('%d s ago'), 'ago_m' => gettext('%d min ago'), 'ago_h' => gettext('%d h ago'), 'ago_d' => gettext('%d days ago'),
	'none_match' => gettext('No firewall is %s.'), 'show_all' => gettext('Show all'),
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
<?php if (!$ready): ?>
<div class="fs-fleet-empty">
	<strong><?=gettext('This firewall is not a fleet controller')?></strong>
	<span><?=gettext('Turn on FreeSense Fleet to manage other firewalls from here.')?></span>
<?php if ($manage): ?>
	<a class="btn btn-primary" href="/fleet/fleet.php"><?=gettext('Open Fleet settings')?></a>
<?php endif; ?>
</div>
<?php include('foot.inc'); exit; endif; ?>

<div id="fs-fleet" data-src="/fleet/fleet_data.php" data-strings="<?=htmlspecialchars(json_encode($strings))?>">
	<div class="fs-fleet-head">
		<div>
			<h2 class="fs-fleet-headline" data-fleet="headline" aria-live="polite"><?=htmlspecialchars(gettext($data['headline']))?></h2>
			<div class="fs-fleet-checked" data-fleet="checked" data-checked="<?=(int)$data['checked']?>" data-now="<?=(int)$data['now']?>"></div>
		</div>
		<div class="fs-fleet-actions">
<?php if ($manage && $data['counts']['pending'] > 0): ?>
			<a class="btn btn-primary" href="/fleet/fleet.php" data-fleet="pending"><i class="fa-solid fa-hourglass-half icon-embed-btn" aria-hidden="true"></i><?=sprintf(ngettext('%d waiting for approval', '%d waiting for approval', $data['counts']['pending']), $data['counts']['pending'])?></a>
<?php endif; ?>
<?php if ($manage): ?>
			<a class="btn btn-outline-secondary" href="/fleet/fleet.php"><i class="fa-solid fa-plus icon-embed-btn" aria-hidden="true"></i><?=gettext('Add a firewall')?></a>
<?php endif; ?>
		</div>
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
	<ul class="fs-fleet-wall" data-fleet="wall" aria-label="<?=gettext('Firewalls')?>"></ul>
	<p class="fs-fleet-problem" data-fleet="filter-empty" hidden></p>
	<script type="application/json" id="fs-fleet-initial"><?=json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES)?></script>
</div>
<script src="<?=$asset('fleet.js')?>"></script>
<?php include('foot.inc');
