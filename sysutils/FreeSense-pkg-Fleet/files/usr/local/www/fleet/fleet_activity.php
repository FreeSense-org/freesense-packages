<?php
/*
 * fleet_activity.php
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
 * Activity: every operation the controller ran on firewalls (a reboot, a
 * backup of all firewalls or a group), newest first, and the detail of one
 * with a row per firewall. Both have filters, search and paging (a fleet
 * runs thousands of operations). While something runs, assets/fleet-list.js
 * refreshes the results every 3 s; the filter bar stays as typed.
 */

require_once('guiconfig.inc');
require_once('fleet.inc');

$pgtitle = array(gettext('Status'), gettext('FreeSense Fleet'), gettext('Activity'));
$ready = fleet_ctl_settings()['enable'] && is_file(FLEET_DATA . '/fleet.db');
$manage = isAllowedPage('fleet/fleet.php');
$op = null;
if ($ready && isset($_GET['op'])) {
	$q = fleet_db()->prepare('SELECT * FROM ops WHERE id = ? AND parent IS NULL');
	$q->execute(array((int)$_GET['op']));
	$op = $q->fetch() ?: null;
}
$asset = function ($f) {
	return '/fleet/assets/' . $f . '?v=' . (int)@filemtime('/usr/local/www/fleet/assets/' . $f);
};

/* The state as a badge with words, never colour alone. */
$state_badge = function (string $state): string {
	$map = array('running' => array('info', gettext('Running')), 'queued' => array('neutral', gettext('Waiting')),
	    'done' => array('pass', gettext('Done')), 'failed' => array('block', gettext('Failed')), 'skipped' => array('neutral', gettext('Skipped')));
	list($kind, $label) = $map[$state] ?? array('neutral', $state);
	return fs_badge($kind, $label);
};
$when = function (int $t): string {
	return htmlspecialchars(date((date('Y-m-d') === date('Y-m-d', $t)) ? 'H:i:s' : 'Y-m-d H:i', $t));
};
$took = function (array $o): string {
	$end = $o['finished'] ? (int)$o['finished'] : time();
	return htmlspecialchars(fleet_op_duration($end - (int)$o['started']));
};
$what = function (array $o): string {
	if ($o['node_id'] === '') {
		return (string)$o['title'];
	}
	$kinds = array('reboot' => gettext('Reboot'), 'backup' => gettext('Back up'), 'restore' => gettext('Restore'), 'update' => gettext('Update'), 'template' => gettext('Apply template to'), 'users' => gettext('Sync users to'));
	return ($kinds[$o['kind']] ?? $o['kind']) . ' ' . ($o['label'] ?? $o['node_id']);
};
$now = time();
$page = max(1, (int)($_GET['page'] ?? 1));
$base = ($op !== null) ? array('op' => (int)$op['id']) : array();
$f = fleet_list_filters($_GET, ($op !== null)
    ? array('q' => null, 'state' => array('failed' => 1, 'done' => 1, 'running' => 1, 'skipped' => 1))
    : array('q' => null, 'state' => FLEET_OPS_STATES, 'kind' => FLEET_OPS_KINDS, 'since' => FLEET_OPS_SINCE));
$is_running = function (string $state): bool {
	return in_array($state, array('running', 'queued'), true);
};

if (!$ready) {
	$running = false;
} elseif ($op !== null) {
	$running = $is_running((string)$op['state']);
} else {
	$running = (int)fleet_db()->query("SELECT COUNT(*) FROM ops WHERE parent IS NULL AND state IN ('running', 'queued')")->fetchColumn() > 0;
}

/* The list's filters, carried to a detail page and back: only known keys. */
function fleet_activity_from(string $from): string {
	parse_str($from, $get);
	$keep = fleet_list_filters($get, array('q' => null, 'state' => FLEET_OPS_STATES, 'kind' => FLEET_OPS_KINDS, 'since' => FLEET_OPS_SINCE));
	if ((int)($get['page'] ?? 1) > 1) {
		$keep['page'] = (int)$get['page'];
	}
	return empty($keep) ? '' : '?' . http_build_query($keep);
}

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
if ($manage) {
	$tab_array = array(
		array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
		array(gettext('Activity'), true, '/fleet/fleet_activity.php'),
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
?>
<?php if ($ready && $op === null): ?>
<?=fleet_activity_nav('ops')?>
<?=fleet_list_filterbar($base, $f, array('state' => array(gettext('Any state'), FLEET_OPS_STATES), 'kind' => array(gettext('Any action'), FLEET_OPS_KINDS),
    'since' => array(gettext('Any time'), FLEET_OPS_SINCE)), gettext('Search activity'), gettext('Search firewall, action or person'))?>
<?php endif; ?>
<?php if ($op !== null && $op['node_id'] === ''): ?>
<?=fleet_list_filterbar($base, $f, array('state' => array(gettext('Any state'), array('failed' => 'Failed', 'skipped' => 'Skipped', 'done' => 'Done', 'running' => 'Running'))),
    gettext('Search firewalls'), gettext('Search firewall or result'))?>
<?php endif; ?>
<div id="fs-fleet-activity" data-running="<?=$running ? '1' : '0'?>">
<?php if (!$ready): ?>
	<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php elseif ($op !== null):
	$op['label'] = fleet_box_get((string)$op['node_id'])['label'] ?? null;
	$tasks = ($op['node_id'] === '') ? fleet_op_tasks((int)$op['id']) : array();
	$p = ($op['node_id'] === '') ? fleet_op_group_progress((int)$op['id']) : fleet_op_progress(array());
	/* Hundreds of firewalls: filter and page the rows (the bar always counts them all). */
	$shown = array_values(array_filter($tasks, function ($t) use ($f) {
		return (!isset($f['state']) || ($f['state'] === 'running' ? in_array($t['state'], array('running', 'queued'), true) : $t['state'] === $f['state'])) &&
		    (!isset($f['q']) || stripos((string)($t['label'] ?? $t['node_id']) . ' ' . $t['text'], $f['q']) !== false);
	}));
	$tpg = fleet_list_page(count($shown), $page);
	$shown = array_slice($shown, $tpg['offset'], $tpg['per']);
?>
	<p><a class="fs-fleet-back" href="/fleet/fleet_activity.php<?=htmlspecialchars(fleet_activity_from((string)($_GET['from'] ?? '')))?>"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=gettext('All activity')?></a></p>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($what($op))?> <?=$state_badge((string)$op['state'])?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<p class="fs-fleet-lead" aria-live="polite"><?=htmlspecialchars((string)$op['text'])?></p>
<?php if (!empty($tasks)): ?>
<?php endif; ?>
			<?=fleet_progress_bar((string)$op['state'], !empty($tasks) ? $p['percent'] : (isset($op['progress']) ? (int)$op['progress'] : null), gettext('Progress'), 'wide')?>
			<dl class="fs-fleet-facts fs-fleet-facts--inline">
				<dt><?=gettext('Started')?></dt><dd><?=$when((int)$op['started'])?></dd>
				<dt><?=gettext('By')?></dt><dd><?=htmlspecialchars((string)$op['who'])?></dd>
				<dt><?=$running ? gettext('Running for') : gettext('Took')?></dt><dd><?=$took($op)?></dd>
			</dl>
		</div>
	</div>
<?php if (!empty($tasks)): ?>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Firewalls')?> <span class="fs-badge fs-badge--neutral"><?=count($tasks)?></span></h2></div>
<?php if (empty($shown)): ?>
		<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('No firewall matches these filters.')?></p></div>
<?php else: ?>
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('State')?></th><th><?=gettext('Result')?></th><th class="text-end"><?=gettext('Took')?></th></tr></thead>
			<tbody>
<?php foreach ($shown as $t): ?>
			<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode((string)$t['node_id'])?>"><?=htmlspecialchars((string)($t['label'] ?? $t['node_id']))?></a></td>
				<td><?=$state_badge((string)$t['state'])?></td>
				<td><div class="fs-fleet-cellbar"><span><?=htmlspecialchars((string)$t['text'])?></span><?php if (in_array($t['state'], array('running', 'queued'), true)): ?><?=fleet_progress_bar((string)$t['state'], ($t['state'] === 'queued') ? 0 : (isset($t['progress']) ? (int)$t['progress'] : null), (string)($t['label'] ?? $t['node_id']), 'thin')?><?php endif; ?></div></td>
				<td class="text-end fs-muted"><?=($t['state'] === 'queued') ? '-' : $took($t)?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
<?php endif; ?>
		<div class="panel-footer"><?=fleet_list_pager($tpg, $base, $f)?></div>
	</div>
<?php endif; ?>
<?php else:
	list($history, $pg) = fleet_ops_find($f, $page, $now);
?>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Activity')?> <span class="fs-badge fs-badge--neutral"><?=(int)$pg['total']?></span></h2></div>
<?php if (empty($history)): ?>
		<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=!empty($f) ? gettext('Nothing matches these filters.') : gettext('Nothing has run yet. Reboots, backups and other actions on firewalls appear here with their progress.')?></p></div>
<?php else: ?>
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('What')?></th><th><?=gettext('State')?></th><th><?=gettext('Progress')?></th><th><?=gettext('Started')?></th><th><?=gettext('By')?></th><th class="text-end"><?=gettext('Took')?></th></tr></thead>
			<tbody>
<?php foreach ($history as $h): ?>
			<tr><td><a href="?op=<?=(int)$h['id']?>&amp;from=<?=urlencode(http_build_query($f + array('page' => $pg['page'])))?>"><?=htmlspecialchars($what($h))?></a></td>
				<td><?=$state_badge((string)$h['state'])?></td>
				<td><div class="fs-fleet-cellbar"><span><?=htmlspecialchars((string)$h['text'])?></span><?php if (in_array($h['state'], array('running', 'queued'), true)): ?><?=fleet_progress_bar((string)$h['state'], isset($h['progress']) ? (int)$h['progress'] : null, $what($h), 'thin')?><?php endif; ?></div></td>
				<td class="fs-muted"><?=$when((int)$h['started'])?></td>
				<td><?=htmlspecialchars((string)$h['who'])?></td>
				<td class="text-end fs-muted"><?=$took($h)?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
<?php endif; ?>
		<div class="panel-footer"><?=fleet_list_pager($pg, $base, $f)?></div>
	</div>
<?php endif; ?>
</div>
<script src="<?=$asset('fleet-list.js')?>"></script>
<?php include('foot.inc');
