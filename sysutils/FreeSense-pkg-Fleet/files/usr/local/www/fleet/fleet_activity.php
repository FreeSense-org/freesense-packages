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
 * with a row per firewall. While something runs, assets/fleet-activity.js
 * refreshes the block every 3 s.
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
	$kinds = array('reboot' => gettext('Reboot'), 'backup' => gettext('Back up'));
	return ($kinds[$o['kind']] ?? $o['kind']) . ' ' . ($o['label'] ?? $o['node_id']);
};
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

include('head.inc');
?>
<link rel="stylesheet" href="<?=$asset('fleet.css')?>">
<?php
if ($manage) {
	$tab_array = array(
		array(gettext('Dashboard'), false, '/fleet/fleet_dashboard.php'),
		array(gettext('Activity'), true, '/fleet/fleet_activity.php'),
		array(gettext('Firewalls'), false, '/fleet/fleet.php'),
		array(gettext('Settings'), false, '/fleet/fleet.php?tab=settings'),
	);
	display_top_tabs($tab_array);
}
?>
<div id="fs-fleet-activity" data-running="<?=$running ? '1' : '0'?>">
<?php if (!$ready): ?>
	<div class="fs-fleet-empty"><strong><?=gettext('This firewall is not a fleet controller')?></strong></div>
<?php elseif ($op !== null):
	$op['label'] = fleet_box_get((string)$op['node_id'])['label'] ?? null;
	$tasks = ($op['node_id'] === '') ? fleet_op_tasks((int)$op['id']) : array();
	$p = fleet_op_progress(array_column($tasks, 'state'));
?>
	<p><a class="fs-fleet-back" href="/fleet/fleet_activity.php"><i class="fa-solid fa-arrow-left" aria-hidden="true"></i><?=gettext('All activity')?></a></p>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=htmlspecialchars($what($op))?> <?=$state_badge((string)$op['state'])?></h2></div>
		<div class="panel-body fs-fleet-pad">
			<p class="fs-fleet-lead" aria-live="polite"><?=htmlspecialchars((string)$op['text'])?></p>
<?php if (!empty($tasks)): ?>
			<span class="fs-fleet-bar fs-fleet-bar--wide" role="progressbar" aria-valuenow="<?=$p['percent']?>" aria-valuemin="0" aria-valuemax="100" aria-label="<?=gettext('Progress')?>" data-state="<?=htmlspecialchars((string)$op['state'])?>"><span class="fs-fleet-bar-fill" style="width: <?=$p['percent']?>%"></span></span>
<?php endif; ?>
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
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('Firewall')?></th><th><?=gettext('State')?></th><th><?=gettext('Result')?></th><th class="text-end"><?=gettext('Took')?></th></tr></thead>
			<tbody>
<?php foreach ($tasks as $t): ?>
			<tr><td><a href="/fleet/fleet_box.php?id=<?=urlencode((string)$t['node_id'])?>"><?=htmlspecialchars((string)($t['label'] ?? $t['node_id']))?></a></td>
				<td><?=$state_badge((string)$t['state'])?></td>
				<td><?=htmlspecialchars((string)$t['text'])?></td>
				<td class="text-end fs-muted"><?=($t['state'] === 'queued') ? '-' : $took($t)?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
	</div>
<?php endif; ?>
<?php else:
	$history = fleet_ops_history(50);
?>
	<div class="panel panel-default">
		<div class="panel-heading"><h2 class="panel-title"><?=gettext('Activity')?></h2></div>
<?php if (empty($history)): ?>
		<div class="panel-body fs-fleet-pad"><p class="fs-fleet-hint"><?=gettext('Nothing has run yet. Reboots, backups and other actions on firewalls appear here with their progress.')?></p></div>
<?php else: ?>
		<div class="panel-body table-responsive"><table class="table fs-table">
			<thead><tr><th><?=gettext('What')?></th><th><?=gettext('State')?></th><th><?=gettext('Progress')?></th><th><?=gettext('Started')?></th><th><?=gettext('By')?></th><th class="text-end"><?=gettext('Took')?></th></tr></thead>
			<tbody>
<?php foreach ($history as $h): ?>
			<tr><td><a href="?op=<?=(int)$h['id']?>"><?=htmlspecialchars($what($h))?></a></td>
				<td><?=$state_badge((string)$h['state'])?></td>
				<td><?=htmlspecialchars((string)$h['text'])?></td>
				<td class="fs-muted"><?=$when((int)$h['started'])?></td>
				<td><?=htmlspecialchars((string)$h['who'])?></td>
				<td class="text-end fs-muted"><?=$took($h)?></td></tr>
<?php endforeach; ?>
			</tbody></table></div>
<?php endif; ?>
		<div class="panel-footer small fs-muted"><?=gettext('The last 50 operations. Each firewall\'s own actions are also in its Events.')?></div>
	</div>
<?php endif; ?>
</div>
<script src="<?=$asset('fleet-activity.js')?>"></script>
<?php include('foot.inc');
